package requests

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"log"
)

type authType string

const (
	noAuth    authType = ""
	basicAuth authType = "basic"
)

// HTTPClient represents a client for making requests to a web service or
// website. The client includes default options that are relevant for all
// requests (but can be overriden per-request).
type HTTPClient struct {
	baseURL              string                   // base URL for all HTTP requests
	httpCli              *http.Client             // underlying net/http client
	noTLSVerify          bool                     // are we verifying TLS certificates?
	renegotiationSupport tls.RenegotiationSupport // support for tls renegotiation
	authType             authType                 // default authentication type for all requests (defaults to no authentication)
	authUser             string                   // default username for all requests
	authPass             string                   // default password for all requests
	authHeader           string                   // header name for authentication (defaults to 'Authorization')
	customHeaders        map[string]string        // default headers for all requests
	accept               string                   // default expected response content type for all requests
	timeout              time.Duration            // default timeout for all requests
	retryLimit           uint8                    // default retry limit for all requests
	errorHandler         func(io.Reader) error    // default error handler for all requests returning unexpected status
	bodyHandler          BodyHandlerFunc          // default body handler for requests (when Content-Type is not automatically handled by this library)
	logger               *zap.Logger              // logger to use (only debug messages are printed by the library; defaults to noop logger)
	certPEMBlock         []byte
	keyPEMBlock          []byte
	caCert               []byte
}

// HTTPRequest represents a single HTTP request to the web service defined
// in the client.
type HTTPRequest struct {
	cli            *HTTPClient           // the HTTPClient this request belongs to
	method         string                // HTTP method/verb to use (GET, POST, PUT, etc.)
	path           string                // request path (will be appended to the client's base URL)
	queryParams    url.Values            // URL query parameters for the request
	cookies        []*http.Cookie        // cookies to send with the HTTP request
	contentType    string                // content type of the request's body
	body           []byte                // reader for the request's body
	into           interface{}           // pointer to a variable where the response will be loaded into
	headersInto    map[string]*string    // map of header names to pointers where response header values will be loaded into
	statusInto     *int                  // pointer where response status code will be loaded
	cookiesInto    *[]*http.Cookie       // pointer where response cookies will be loaded
	expectedStatus int                   // expected status code from the server (defaults to 200)
	err            error                 // error encountered during building the request
	authType       authType              // authentication type for the request (defaults to no authentication)
	authUser       string                // username for the request
	authPass       string                // password for the request
	authHeader     string                // header used for authentication (defaults to 'Authorization')
	customHeaders  map[string]string     // headers for the request (headers from the client will be used as well, but headers defined here take precedence)
	accept         string                // expected response content type
	timeout        time.Duration         // timeout for the request
	retryLimit     uint8                 // retry limit for the request
	sizeLimit      int64                 // reject responses whose body size exceeds this value
	errorHandler   func(io.Reader) error // error handler for request if returned status is not the expected one
	bodyHandler    BodyHandlerFunc       // body handler for request (when Content-Type is not automatically handled by this library)
	logger         *zap.Logger           // logger to use (only debug messages are printed by the library; defaults to noop logger)
}

// BodyHandlerFunc is a function that processes the request body and reads
// it into the target variable. It receives the content type of the response
// (from the Content-Type header), the body reader, and the target variable
// (which is whatever was provided to the Into() method). It is not necessary
// to close the body or read it to its entirety.
type BodyHandlerFunc func(contentType string, body io.Reader, target interface{}) error

var (
	ErrSizeExceeded   = errors.New("response size exceeded limit")
	ErrTimeoutReached = errors.New("timeout reached")
)

func NewClient(baseURL string) *HTTPClient {
	return &HTTPClient{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		authType: noAuth,
		timeout:  time.Minute * 2,
	}
}

func (cli *HTTPClient) Accept(accept string) *HTTPClient {
	cli.accept = accept
	return cli
}

func (cli *HTTPClient) Timeout(dur time.Duration) *HTTPClient {
	cli.timeout = dur
	return cli
}

func (cli *HTTPClient) RetryLimit(limit uint8) *HTTPClient {
	cli.retryLimit = limit
	return cli
}

func (cli *HTTPClient) Logger(logger *zap.Logger) *HTTPClient {
	cli.logger = logger
	return cli
}

func (cli *HTTPClient) getLogger() *zap.Logger {
	if cli.logger == nil {
		cli.logger = zap.NewNop()
	}
	return cli.logger
}

func (cli *HTTPClient) BasicAuth(user, pass, header string) *HTTPClient {
	cli.authType = "basic"
	cli.authUser = user
	cli.authPass = pass
	cli.authHeader = header
	return cli
}

func (cli *HTTPClient) Header(key, value string) *HTTPClient {
	if cli.customHeaders == nil {
		cli.customHeaders = make(map[string]string)
	}
	cli.customHeaders[key] = value
	return cli
}

func (cli *HTTPClient) ErrorHandler(handler func(io.Reader) error) *HTTPClient {
	cli.errorHandler = handler
	return cli
}

func (cli *HTTPClient) BodyHandler(handler BodyHandlerFunc) *HTTPClient {
	cli.bodyHandler = handler
	return cli
}

func (cli *HTTPClient) NoTLSVerify(enabled bool) *HTTPClient {
	if cli.httpCli != nil {
		transport, ok := cli.httpCli.Transport.(*http.Transport)
		if ok {
			transport.TLSClientConfig.InsecureSkipVerify = enabled
		} else {
			// just nil out the client so a new one is created
			cli.httpCli = nil
		}
	}
	cli.noTLSVerify = enabled
	return cli
}

func (cli *HTTPClient) SetRenegotiation(support tls.RenegotiationSupport) *HTTPClient {
	cli.renegotiationSupport = support
	return cli
}

func (cli *HTTPClient) NewRequest(method, path string) *HTTPRequest {
	return &HTTPRequest{
		cli:    cli,
		path:   path,
		method: method,
		logger: cli.getLogger().With(
			zap.String("path", path),
			zap.String("method", method),
		),
	}
}

func (cli *HTTPClient) SetTLS(certPEMBlock, keyPEMBlock, caCert []byte) *HTTPClient {
	cli.caCert = caCert
	cli.keyPEMBlock = keyPEMBlock
	cli.certPEMBlock = certPEMBlock

	return cli
}

func (cli *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	return cli.retryRequest(
		context.Background(),
		cli.logger,
		req,
		nil,
		cli.timeout,
		cli.retryLimit+1,
	)
}

func (cli *HTTPClient) retryRequest(
	parentCtx context.Context,
	logger *zap.Logger,
	req *http.Request,
	body []byte,
	timeout time.Duration,
	attempts uint8,
) (res *http.Response, err error) {
	if cli.httpCli == nil {
		if cli.certPEMBlock == nil {
			cli.httpCli = &http.Client{
				Transport: DefaultTransport(cli.noTLSVerify, cli.renegotiationSupport),
			}
		} else {
			cli.httpCli = &http.Client{
				Transport: TLSTransport(cli.certPEMBlock, cli.keyPEMBlock, cli.caCert, cli.noTLSVerify, cli.renegotiationSupport),
			}
		}
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	delay := 2 * time.Second

	for attempt := uint8(1); attempt <= attempts; attempt++ {
		if body != nil {
			req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		}

		res, err = cli.doRequest(parentCtx, req, timeout)
		// we retry requests if an error is returned from net/http, or if
		// the status of the response is 502, 503 or 504, which are all proxy
		// errors that may be temporary
		if err == nil &&
			res.StatusCode != http.StatusBadGateway &&
			res.StatusCode != http.StatusServiceUnavailable &&
			res.StatusCode != http.StatusGatewayTimeout {
			break
		}

		// failed this attempt, sleep 2*attempt seconds and try again
		if attempt < attempts {
			logger.Debug(
				"Request failed, will retry",
				zap.Uint8("attempt", attempt),
				zap.Uint8("limit", attempts),
				zap.Duration("delay", delay),
				zap.Error(err),
			)
			time.Sleep(delay)
			delay *= 2
		}
	}

	return res, err
}

func (cli *HTTPClient) doRequest(
	parentCtx context.Context,
	req *http.Request,
	timeout time.Duration,
) (res *http.Response, err error) {
	if cli.httpCli == nil {
		if cli.certPEMBlock == nil {
			cli.httpCli = &http.Client{
				Transport: DefaultTransport(cli.noTLSVerify, cli.renegotiationSupport),
			}
		} else {
			cli.httpCli = &http.Client{
				Transport: TLSTransport(cli.certPEMBlock, cli.keyPEMBlock, cli.caCert, cli.noTLSVerify, cli.renegotiationSupport),
			}
		}
	}

	// initiate the request
	req = req.WithContext(parentCtx)

	if timeout > 0 {
		ctx, _ := context.WithTimeout(parentCtx, timeout)
		req = req.WithContext(ctx)
	}

	res, err = cli.httpCli.Do(req)
	if err != nil {
		if urlErr, ok := err.(*url.Error); ok {
			if urlErr.Err == context.DeadlineExceeded {
				err = ErrTimeoutReached
			}
		}
	}

	return res, err
}

/******************************************************************************/
/*                                REQUESTS                                    */
/******************************************************************************/

func (req *HTTPRequest) QueryParam(key, value string) *HTTPRequest {
	if req.queryParams == nil {
		req.queryParams = url.Values{}
	}
	req.queryParams.Add(key, value)
	return req
}

func (req *HTTPRequest) Cookie(cookie *http.Cookie) *HTTPRequest {
	req.cookies = append(req.cookies, cookie)
	return req
}

func (req *HTTPRequest) Body(body []byte, contentType string) *HTTPRequest {
	req.body = body
	req.contentType = contentType
	return req
}

func (req *HTTPRequest) JSONBody(body interface{}) *HTTPRequest {
	var err error
	req.body, err = json.Marshal(body)
	if err != nil {
		req.err = errors.Wrap(err, "failed processing JSON body")
	}
	req.contentType = "application/json; charset=UTF-8"
	return req
}

func (req *HTTPRequest) Accept(accept string) *HTTPRequest {
	req.accept = accept
	return req
}

func (req *HTTPRequest) Timeout(dur time.Duration) *HTTPRequest {
	req.timeout = dur
	return req
}

func (req *HTTPRequest) RetryLimit(limit uint8) *HTTPRequest {
	req.retryLimit = limit
	return req
}

func (req *HTTPRequest) SizeLimit(limit int64) *HTTPRequest {
	req.sizeLimit = limit
	return req
}

func (req *HTTPRequest) Into(into interface{}) *HTTPRequest {
	req.into = into
	return req
}

func (req *HTTPRequest) HeaderInto(header string, into *string) *HTTPRequest {
	if req.headersInto == nil {
		req.headersInto = make(map[string]*string)
	}
	req.headersInto[header] = into
	return req
}

func (req *HTTPRequest) StatusInto(into *int) *HTTPRequest {
	req.statusInto = into
	return req
}

func (req *HTTPRequest) CookiesInto(into *[]*http.Cookie) *HTTPRequest {
	req.cookiesInto = into
	return req
}

func (req *HTTPRequest) ExpectedStatus(status int) *HTTPRequest {
	req.expectedStatus = status
	return req
}

func (req *HTTPRequest) BasicAuth(user, pass, header string) *HTTPRequest {
	req.authType = "basic"
	req.authUser = user
	req.authPass = pass
	req.authHeader = header
	return req
}

func (req *HTTPRequest) Header(key, value string) *HTTPRequest {
	if req.customHeaders == nil {
		req.customHeaders = make(map[string]string)
	}
	req.customHeaders[key] = value
	return req
}

func (req *HTTPRequest) ErrorHandler(handler func(io.Reader) error) *HTTPRequest {
	req.errorHandler = handler
	return req
}

func (req *HTTPRequest) BodyHandler(handler BodyHandlerFunc) *HTTPRequest {
	req.bodyHandler = handler
	return req
}

func (req *HTTPRequest) Run() error {
	return req.RunContext(context.Background())
}

func (req *HTTPRequest) RunContext(ctx context.Context) error {
	// did we fail during building the request? if so, return the error
	if req.err != nil {
		return req.err
	}

	// if no expected status is set, expect 200 OK
	if req.expectedStatus == 0 {
		req.expectedStatus = http.StatusOK
	}

	// build the request URL from the client's base URL and the request's
	// path, plus add any query parameters defined
	if !strings.HasPrefix(req.path, "/") {
		req.path = fmt.Sprintf("/%s", req.path)
	}
	reqURL := req.cli.baseURL + req.path
	if req.queryParams != nil {
		if queryParams := req.queryParams.Encode(); queryParams != "" {
			reqURL += "?" + queryParams
		}
	}

	// create the net/http.Request object
	r, err := http.NewRequest(req.method, reqURL, nil)
	if err != nil {
		return errors.Wrap(err, "failed creating request")
	}

	// add cookies
	for _, c := range req.cookies {
		r.AddCookie(c)
	}

	// are we using basic authentication?
	if req.authType == basicAuth || req.cli.authType == basicAuth {
		// take user, password and authentication header from the
		// request if provided, otherwise from the client
		user := req.authUser
		pass := req.authPass
		header := req.authHeader
		if user == "" {
			user = req.cli.authUser
		}
		if pass == "" {
			pass = req.cli.authPass
		}
		if header == "" {
			header = req.cli.authHeader
		}
		if header == "" {
			header = "Authorization"
		}

		r.Header.Add(header, "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	}

	// what is the content type of our body?
	if req.contentType != "" {
		r.Header.Add("Content-Type", req.contentType)
	}

	// add custom headers from the client, then from the request (headers from
	// the request itself override those from the client)
	if req.cli.customHeaders != nil {
		for key, value := range req.cli.customHeaders {
			r.Header.Add(key, value)
		}
	}
	if req.customHeaders != nil {
		for key, value := range req.customHeaders {
			r.Header.Add(key, value)
		}
	}

	// what content type are we expecting to get back? if nothing is defined,
	// use application/json. Add this content type in an Accept header.
	if req.accept == "" {
		req.accept = req.cli.accept
		if req.accept == "" {
			req.accept = "application/json"
		}
	}
	r.Header.Add("Accept", req.accept)

	// how many attempts are we gonna make?
	var attempts = uint8(1)
	if req.retryLimit > 0 {
		attempts += req.retryLimit
	} else if req.cli.retryLimit > 0 {
		attempts += req.cli.retryLimit
	}

	// what is the request timeout?
	timeout := req.timeout
	if req.timeout == 0 && req.cli.timeout > 0 {
		timeout = req.cli.timeout
	}

	// run the request
	res, err := req.cli.retryRequest(ctx, req.logger, r, req.body, timeout, attempts)
	if err != nil {
		if err == ErrTimeoutReached {
			return err
		}
		return errors.Wrap(err, "request failed")
	}

	// make sure to read the entire body and close the request once we're
	// done, this is important in order to reuse connections and prevent
	// connection leaks
	defer func() {
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()
	}()

	if req.sizeLimit > 0 && res.ContentLength > req.sizeLimit {
		return ErrSizeExceeded
	}

	// are there any headers from the response we need to read?
	if req.headersInto != nil {
		for key, into := range req.headersInto {
			*into = res.Header.Get(key)
		}
	}

	// do we need to return the status code?
	if req.statusInto != nil {
		*req.statusInto = res.StatusCode
	}

	if req.cookiesInto != nil {
		*req.cookiesInto = res.Cookies()
	}

	// did the response return with the expected status code? if not,
	// and there's an error handler, call it with the body, otherwise
	// return a generic error
	if res.StatusCode != req.expectedStatus {
		handler := req.errorHandler
		if handler == nil {
			handler = req.cli.errorHandler
		}
		if handler != nil {
			return handler(res.Body)
		}
		return errors.Errorf("server returned unexpected status %d", res.StatusCode)
	}

	// what are we loading the response into and how? make sure we're only
	// doing this if there is a response content
	if res.StatusCode != http.StatusNoContent && req.into != nil && res.ContentLength > 0 {
		var handler BodyHandlerFunc
		if req.bodyHandler != nil {
			handler = req.bodyHandler
		} else if req.cli.bodyHandler != nil {
			handler = req.cli.bodyHandler
		} else {
			handler = defaultBodyHandler
		}
		err = handler(res.Header.Get("Content-Type"), res.Body, req.into)
	}
	return err
}

func defaultBodyHandler(
	contentType string,
	body io.Reader,
	target interface{},
) (err error) {
	cType := strings.Split(contentType, ";")
	switch cType[0] {
	case "text/plain":
		v := reflect.ValueOf(target)
		if v.Kind() != reflect.Ptr || v.IsNil() {
			return errors.Wrap(err, "invalid target variable")
		}

		data, err := ioutil.ReadAll(body)
		if err != nil {
			return errors.Wrap(err, "failed reading server response")
		}

		switch v := target.(type) {
		case *string:
			*v = strings.TrimRightFunc(string(data), unicode.IsSpace)
		default:
			return errors.New("target variable is not a string pointer")
		}
	default:
		// default to JSON, regardless of returned Content-Type
		err = json.NewDecoder(body).Decode(target)
		if err != nil {
			return errors.Wrap(err, "failed decoding server response")
		}
	}

	return nil
}

func DefaultTransport(tlsNoVerify bool, renegotiationSupport tls.RenegotiationSupport) http.RoundTripper {
	// this is a modification of Golang's default HTTP transport
	// (https://golang.org/pkg/net/http/#RoundTripper) with options
	// to ignore invalid or self-signed TLS certificates and to configure
	// timeouts.
	// see https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
	// for more details about client timeouts

	var tlsConfig *tls.Config
	tlsConfig = &tls.Config{
		InsecureSkipVerify: tlsNoVerify,
		Renegotiation:      renegotiationSupport,
	}

	var transport http.RoundTripper = buildTransport(tlsConfig)
	return transport
}

func TLSTransport(certPEMBlock, keyPEMBlock, caCert []byte, TLSNoVerify bool, renegotiationSupport tls.RenegotiationSupport) http.RoundTripper {

	// Load client Certificate
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	var tlsConfig *tls.Config
	// Setup HTTPS client
	tlsConfig = &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: TLSNoVerify,
		Renegotiation:      renegotiationSupport,
	}
	tlsConfig.BuildNameToCertificate()

	var transport http.RoundTripper = buildTransport(tlsConfig)
	return transport
}

func buildTransport(tlsconfig *tls.Config) http.RoundTripper {

	var transport http.RoundTripper = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second, // time spent establishing a TCP connection (if a new one is needed)
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second, // time spent performing the TLS handshake
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsconfig,
	}
	return transport
}
