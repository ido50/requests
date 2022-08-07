// Package requests is a high-level, API-centric HTTP client for Go projects. It
// is meant to provide a more comfortable mechanism to perform requests to HTTP
// APIs (rather than making general requests), and to prevent common mistakes
// made when using net/http directly.
//
// With requests, one must not need to remember to read HTTP responses in full
// (so Go can reuse TCP connections), nor to close response bodies. Handling of
// JSON data - be it in requests or responses - is made easier by way of built-in
// encoders/decoders. An automatic retry mechanism is also included.
//
// The library allows a "DRY" (Dont Repeat Yourself) approach to REST API usage
// by introducing API-specific dependencies into the client object. For example,
// authorization headers and response handlers can be set in the client object,
// and all generated requests will automatically include them.
//
//
//
// Usage
//
//
//
//		package main
//
//		import (
//			"fmt"
//			"net/http"
//			"time"
//
//			"github.com/ido50/requests"
//		)
//
//		const apiURL = "https://my.api.com/v2"
//
//		type RequestBody struct {
//			Title   string   `json:"title"`
//			Tags    []string `json:"tags"`
//			Publish bool     `json:"publish"`
//		}
//
//		type ResponseBody struct {
//			ID   int64     `json:"id"`
//			Date time.Time `json:"date"`
//		}
//
//		func main() {
//			client := requests.
//				NewClient(apiURL).
//				Accept("application/json").
//				BasicAuth("user", "pass").
//				RetryLimit(3)
//
//			var res ResponseBody
//
//			err := client.
//				NewRequest("POST", "/articles").
//				JSONBody(RequestBody{
//					Title:   "Test Title",
//					Tags:    []string{"test", "stories"},
//					Publish: true,
//				}).
//				ExpectedStatus(http.StatusCreated).
//				Into(&res).
//				Run()
//			if err != nil {
//				panic(err)
//			}
//
//			fmt.Printf(
//				"Created article %d on %s\n",
//				res.ID, res.Date.Format(time.RFC3339),
//			)
//		}
package requests

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	pathtools "path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode"

	"go.uber.org/zap"
)

type authType string

const (
	noAuth    authType = ""
	basicAuth authType = "basic"
)

const defaultAuthHeader = "Authorization"

// CompressionAlgorithm denotes compression algorithms supported by the library
// for compressed request bodies.
type CompressionAlgorithm string

const (
	// CompressionAlgorithmNone represents no compression
	CompressionAlgorithmNone CompressionAlgorithm = ""

	// CompressionAlgorithmGzip represents the gzip compression algorithm
	CompressionAlgorithmGzip CompressionAlgorithm = "gzip"

	// CompressionAlgorithmDeflate represents the deflate compression algorithm
	CompressionAlgorithmDeflate CompressionAlgorithm = "deflate"
)

// HTTPClient represents a client for making requests to a web service or
// website. The client includes default options that are relevant for all
// requests (but can be overridden per-request).
type HTTPClient struct {
	// base URL for all HTTP requests
	baseURL string

	// default authentication type for all requests (defaults to no authentication)
	authType authType

	// default username for all requests
	authUser string

	// default password for all requests
	authPass string

	// header name for authentication (defaults to 'Authorization')
	authHeader string

	// default expected response content type for all requests
	accept string

	// default timeout for all requests
	timeout time.Duration

	// default error handler for all requests returning unexpected status
	errorHandler ErrorHandlerFunc

	// default body handler for requests (when Content-Type is not automatically handled by this library)
	bodyHandler BodyHandlerFunc

	// default headers for all requests
	customHeaders map[string]string

	// custom TLS attributes
	certPEMBlock         []byte
	keyPEMBlock          []byte
	caCert               []byte
	renegotiationSupport tls.RenegotiationSupport
	noTLSVerify          bool

	// default retry limit for all requests
	retryLimit uint8

	// optional compression algorithm for all requests
	compressionAlgorithm CompressionAlgorithm

	// logger to use (only debug messages are printed by the library; defaults to noop logger)
	logger *zap.Logger

	// underlying net/http client
	httpCli *http.Client
}

// HTTPRequest represents a single HTTP request to the web service defined
// in the client.
type HTTPRequest struct {
	// the HTTPClient this request belongs to
	cli *HTTPClient

	// HTTP method/verb to use (GET, POST, PUT, etc.)
	method string

	// request path (will be appended to the client's base URL)
	path string

	// URL query parameters for the request
	queryParams url.Values

	// cookies to send with the HTTP request
	cookies []*http.Cookie

	// content type of the request's body
	contentType string

	// bodySrc is a ReadCloser from which the request's body is read by us
	bodySrc io.ReadCloser

	// bodyDst is a buffer into which the final request body is written (i.e.
	// after optional compression or other processing), and which is read by the
	// underlying net/http client
	bodyDst bytes.Buffer

	// pointer to a variable where the response body will be loaded into
	into interface{}

	// map of header names to pointers where response header values will be loaded into
	headersInto map[string]*string

	// pointer where response status code will be loaded
	statusInto *int

	// pointer where response cookies will be loaded
	cookiesInto *[]*http.Cookie

	// expected status codes from the server (defaults to any 2xx status)
	expectedStatuses []int

	// error encountered during building the request
	err error

	// authentication type for the request (defaults to no authentication)
	authType authType

	// username for the request
	authUser string

	// password for the request
	authPass string

	// header used for authentication (defaults to 'Authorization')
	authHeader string

	// headers for the request (headers from the client will be used as well, but headers defined here take precedence)
	customHeaders map[string]string

	// expected response content type
	accept string

	// timeout for the request
	timeout time.Duration

	// retry limit for the request
	retryLimit uint8

	// reject responses whose body size exceeds this value
	sizeLimit int64

	// optional compression algorithm for the request
	compressionAlgorithm CompressionAlgorithm

	// error handler for the request if returned status is not the expected one(s)
	errorHandler ErrorHandlerFunc

	// body handler for the request (when Content-Type is not automatically handled by this library)
	bodyHandler BodyHandlerFunc

	// logger to use (only debug messages are printed by the library; defaults to noop logger)
	logger *zap.Logger
}

// BodyHandlerFunc is a function that processes the response body and reads
// it into the target variable. It receives the status and content type of the
// response (the latter taken from the Content-Type header), the body reader,
// and the target variable (which is whatever was provided to the Into()
// method). It is not necessary to close the body or read it to its entirety.
type BodyHandlerFunc func(
	httpStatus int,
	contentType string,
	body io.Reader,
	target interface{},
) error

// ErrorHandlerFunc is similar to BodyHandler, but is called when requests generate
// an unsuccessful response (defined as anything that is not one of the
// expected statuses). It receives the same parameters except "target", and is
// expected to return a formatted error to the client
type ErrorHandlerFunc func(
	httpStatus int,
	contentType string,
	body io.Reader,
) error

var (
	// ErrSizeExceeded is the error returned when the size of an HTTP response
	// is larger than the set limit
	ErrSizeExceeded = errors.New("response size exceeded limit")

	// ErrTimeoutReached is the error returned when a request times out
	ErrTimeoutReached = errors.New("timeout reached")

	// ErrNotAPointer is an error returned when the target variable provided for
	// a request's Run method is not a pointer.
	ErrNotAPointer = errors.New("target variable is not a string pointer")

	// ErrUnsupportedCompression is an error returned when attempting to send
	// requests with a compression algorithm unsupported by the library
	ErrUnsupportedCompression = errors.New("unsupported compression algorithm")

	// ErrUnsupportedBody is an error returned when the value provided to the
	// request's Body method is unsupported, i.e. it is not a byte string, a
	// string, or a reader
	ErrUnsupportedBody = errors.New("unsupported body")
)

// DefaultTimeout is the default timeout for requests made by the library. This
// can be overridden on a per-client and per-request basis.
var DefaultTimeout = 2 * time.Minute

// BaseDelay is the base delay for retrying requests. The library uses a
// backoff strategy, multiplying the delay between each attempt.
var BaseDelay = 2 * time.Second

// NewClient creates a new HTTP client for the API whose base URL is provided.
func NewClient(baseURL string) *HTTPClient {
	return &HTTPClient{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		authType: noAuth,
		timeout:  DefaultTimeout,
	}
}

// Accept sets the response MIME type accepted by the client. Defaults to
// "application/json".
func (cli *HTTPClient) Accept(accept string) *HTTPClient {
	cli.accept = accept
	return cli
}

// Timeout sets the total timeout for requests made by the client. The default
// timeout is 2 minutes.
func (cli *HTTPClient) Timeout(dur time.Duration) *HTTPClient {
	cli.timeout = dur
	return cli
}

// RetryLimit sets the maximum amount of times requests that failed due to
// connection issues should be retried. Defaults to 0. Requests are retried with
// a backoff strategy, with the first retry attempt occurring two seconds after
// the original request, and the delay before each subsequent attempt is
// multiplied by two.
func (cli *HTTPClient) RetryLimit(limit uint8) *HTTPClient {
	cli.retryLimit = limit
	return cli
}

// Logger sets the logger used by the library. Currently, requests uses
// go.uber.org/zap for logging purposes. All log messages are in the DEBUG level.
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

// BasicAuth sets basic authentication headers for all HTTP requests made by the
// client (requests can override this on an individual basis). If a header name
// is provided as the third argument, the authentication data will be set into
// that header instead of the standard "Authorization" header. This is mostly
// useful for Proxy-Authorization or custom headers.
func (cli *HTTPClient) BasicAuth(
	user string,
	pass string,
	headerName ...string,
) *HTTPClient {
	cli.authType = "basic"
	cli.authUser = user
	cli.authPass = pass

	if len(headerName) > 0 {
		cli.authHeader = headerName[0]
	} else {
		cli.authHeader = defaultAuthHeader
	}

	return cli
}

// Header sets a common header value for all requests made by the client.
func (cli *HTTPClient) Header(key, value string) *HTTPClient {
	if cli.customHeaders == nil {
		cli.customHeaders = make(map[string]string)
	}

	cli.customHeaders[key] = value

	return cli
}

// CompressWith sets a compression algorithm to apply to all request bodies.
// Compression is optional, in that if it fails, for any reason, requests will
// not fail, but instead be sent without compression.
// Note that there is no need to use this to support decompression of responses,
// the library handles decompressions automatically.
func (cli *HTTPClient) CompressWith(alg CompressionAlgorithm) *HTTPClient {
	cli.compressionAlgorithm = alg
	return cli
}

// ErrorHandler sets a custom handler function for all requests made by the
// client. Whenever a request is answered with an error response (or optionally
// in an unexpected status), the handler is called. This allows parsing API
// error structures so more information can be returned in case of failure.
func (cli *HTTPClient) ErrorHandler(handler ErrorHandlerFunc) *HTTPClient {
	cli.errorHandler = handler
	return cli
}

// BodyHandler sets a customer handler function for all requests made by the
// client. If provided, the handler will be called with the response status,
// content type, and body reader. This allows customizing the way response
// bodies are parsed, for example if the API does not use JSON serialization.
// Usually, the library's internal handler is sufficient for API usage.
func (cli *HTTPClient) BodyHandler(handler BodyHandlerFunc) *HTTPClient {
	cli.bodyHandler = handler
	return cli
}

// CustomHTTPClient sets a custom HTTP client for the underlaying net layer
func (cli *HTTPClient) CustomHTTPClient(cl *http.Client) *HTTPClient {
	cli.httpCli = cl
	return cli
}

// NoTLSVerify allows ignoring invalid or self-signed TLS certificates presented
// by HTTPS servers.
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

// SetRenegotiation allows setting the TLS renegotiation level. See crypto/tls
// for more information.
func (cli *HTTPClient) SetRenegotiation(support tls.RenegotiationSupport) *HTTPClient {
	cli.renegotiationSupport = support
	return cli
}

// SetTLS allows creating a custom TLS transport. Often combined with
// SetRenegotiation.
func (cli *HTTPClient) SetTLS(
	certPEMBlock, keyPEMBlock, caCert []byte,
) *HTTPClient {
	cli.caCert = caCert
	cli.keyPEMBlock = keyPEMBlock
	cli.certPEMBlock = certPEMBlock

	return cli
}

// Do performs an HTTP request represented as a net/http.Request object. This
// method was added so that an HTTPClient object will implement a common interface
// for HTTP clients. Generally, there is no need to use this method.
func (cli *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	ctx := context.Background()

	if cli.timeout > 0 {
		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, cli.timeout)
		defer cancel()
	}

	return cli.retryRequest(
		ctx,
		cli.logger,
		req,
		nil,
		cli.retryLimit+1,
	)
}

func (cli *HTTPClient) retryRequest(
	ctx context.Context,
	logger *zap.Logger,
	req *http.Request,
	body *bytes.Buffer,
	attempts uint8,
) (res *http.Response, err error) {
	if cli.httpCli == nil {
		if cli.certPEMBlock == nil {
			cli.httpCli = &http.Client{
				Transport: defaultTransport(cli.noTLSVerify, cli.renegotiationSupport),
			}
		} else {
			cli.httpCli = &http.Client{
				Transport: tlsTransport(
					cli.certPEMBlock,
					cli.keyPEMBlock,
					cli.caCert,
					cli.noTLSVerify,
					cli.renegotiationSupport,
				),
			}
		}
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	delay := BaseDelay

	for attempt := uint8(1); attempt <= attempts; attempt++ {
		if body != nil {
			req.Body = ioutil.NopCloser(body)
		}

		req = req.WithContext(ctx)

		res, err = cli.httpCli.Do(req)
		if err != nil {
			if urlErr, ok := err.(*url.Error); ok {
				if errors.Is(urlErr.Err, context.DeadlineExceeded) {
					err = ErrTimeoutReached
				}
			}
		}

		// we retry requests if an error is returned from net/http, or if
		// the status of the response is 502, 503, 429 or 504, which are all proxy
		// errors that may be temporary
		if err == nil &&
			res.StatusCode != http.StatusBadGateway &&
			res.StatusCode != http.StatusServiceUnavailable &&
			res.StatusCode != http.StatusTooManyRequests &&
			res.StatusCode != http.StatusGatewayTimeout {
			break
		}

		// failed this attempt, sleep 2*attempt seconds and try again
		if attempt < attempts {
			// make sure to close the body
			if res != nil {
				closeBody(res.Body)
			}

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

/******************************************************************************/
/*                                REQUESTS                                    */
/******************************************************************************/

// NewRequest creates a new request object. Requests are progressively
// composed using a builder/method-chain pattern. The HTTP method and path
// within the API must be provided. Remember that the client already includes
// a base URL, so the request URL will be a concatenation of the base URL and
// the provided path. `path` can be empty.
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

// QueryParam adds a query parameter and value to the request.
func (req *HTTPRequest) QueryParam(key, value string) *HTTPRequest {
	if req.queryParams == nil {
		req.queryParams = url.Values{}
	}

	req.queryParams.Add(key, value)

	return req
}

// Cookie sets a cookie for the request.
func (req *HTTPRequest) Cookie(cookie *http.Cookie) *HTTPRequest {
	req.cookies = append(req.cookies, cookie)
	return req
}

// ReaderBody sets a custom body for the request from an io.ReadCloser,
// io.Reader, []byte or string. The content type of the data must be provided.
func (req *HTTPRequest) Body(body interface{}, contentType string) *HTTPRequest {
	if rc, ok := body.(io.ReadCloser); ok {
		req.bodySrc = rc
	} else if r, ok := body.(io.Reader); ok {
		req.bodySrc = ioutil.NopCloser(r)
	} else if b, ok := body.([]byte); ok {
		req.bodySrc = ioutil.NopCloser(bytes.NewReader(b))
	} else if s, ok := body.(string); ok {
		req.bodySrc = ioutil.NopCloser(strings.NewReader(s))
	} else {
		req.err = ErrUnsupportedBody
	}

	req.contentType = contentType

	return req
}

// JSONBody encodes the provided Go value into JSON and sets it as the request
// body.
func (req *HTTPRequest) JSONBody(body interface{}) *HTTPRequest {
	encodedBody, err := json.Marshal(body)
	if err != nil {
		req.err = fmt.Errorf("failed encoding JSON body: %w", err)
	}

	return req.Body(encodedBody, "application/json; charset=UTF-8")
}

// FileBody sets the request body to be read from the provided filesystem and
// file path. The content type must be provided.
func (req *HTTPRequest) FileBody(fsys fs.FS, filepath, contentType string) *HTTPRequest {
	var err error
	req.bodySrc, err = fsys.Open(filepath)
	if err != nil {
		req.err = fmt.Errorf("failed opening body file %q: %w", filepath, err)
	}

	req.contentType = contentType

	return req
}

// MultipartBody creates a multipart/form-data body from one or more sources,
// which may be file objects, bytes, strings or any reader.
func (req *HTTPRequest) MultipartBody(srcs ...*multipartSrc) *HTTPRequest {
	var output bytes.Buffer
	writer := multipart.NewWriter(&output)

	for _, src := range srcs {
		formFile, err := writer.CreateFormFile(src.fieldname, src.filename)
		if err != nil {
			req.err = fmt.Errorf(
				"failed creating form file %q: %w",
				src.fieldname, err,
			)
			return req
		}

		var srcReader io.ReadCloser
		if src.filepath != "" {
			srcReader, err = src.filesystem.Open(src.filepath)
			if err != nil {
				req.err = fmt.Errorf(
					"failed opening source file %q: %w",
					src.filepath, err,
				)
				return req
			}
		} else {
			if rc, ok := src.body.(io.ReadCloser); ok {
				srcReader = rc
			} else if r, ok := src.body.(io.Reader); ok {
				srcReader = ioutil.NopCloser(r)
			} else if b, ok := src.body.([]byte); ok {
				srcReader = ioutil.NopCloser(bytes.NewReader(b))
			} else if s, ok := src.body.(string); ok {
				srcReader = ioutil.NopCloser(strings.NewReader(s))
			} else {
				req.err = ErrUnsupportedBody
				return req
			}
		}

		_, err = io.Copy(formFile, srcReader)
		srcReader.Close()
		if err != nil {
			req.err = fmt.Errorf(
				"failed reading form file %q: %w",
				src.fieldname, err,
			)
			return req
		}
	}

	err := writer.Close()
	if err != nil {
		req.err = fmt.Errorf("failed closing multipart message: %w", err)
		return req
	}

	return req.Body(&output, writer.FormDataContentType())
}

type multipartSrc struct {
	fieldname  string
	filename   string
	body       interface{}
	filesystem fs.FS
	filepath   string
}

// MultipartPart adds a new part to a multipart request with the provided field
// name, file name, and body, which may be a []byte value, a string, or a reader.
func MultipartPart(fieldname, filename string, body interface{}) *multipartSrc {
	return &multipartSrc{fieldname: fieldname, filename: filename, body: body}
}

// MultipartFile adds a new part to a multipart request from the provided file
// in a filesystem.
func MultipartFile(fieldname string, fsys fs.FS, filepath string) *multipartSrc {
	return &multipartSrc{
		fieldname:  fieldname,
		filename:   pathtools.Base(filepath),
		filesystem: fsys,
		filepath:   filepath,
	}
}

// Accept sets the accepted MIME type for the request. This takes precedence
// over the MIME type provided to the client object itself.
func (req *HTTPRequest) Accept(accept string) *HTTPRequest {
	req.accept = accept
	return req
}

// Timeout sets the timeout for the request. This takes precedence over the
// timeout provided to the client object itself.
func (req *HTTPRequest) Timeout(dur time.Duration) *HTTPRequest {
	req.timeout = dur
	return req
}

// RetryLimit sets the maximum amount of retries for the request. This takes
// precedence over the limit provided to the client object itself.
func (req *HTTPRequest) RetryLimit(limit uint8) *HTTPRequest {
	req.retryLimit = limit
	return req
}

// SizeLimit allows limiting the size of response bodies accepted by the client.
// If the response size is larger than the limit, `ErrSizeExceeded` will be
// returned.
func (req *HTTPRequest) SizeLimit(limit int64) *HTTPRequest {
	req.sizeLimit = limit
	return req
}

// Into sets the target variable to which the response body should be parsed.
// If the API returns JSON, then this should be a pointer to a struct that
// represents the expected format. If using a custom body handler, this variable
// will be provided to the handler.
func (req *HTTPRequest) Into(into interface{}) *HTTPRequest {
	req.into = into
	return req
}

// HeaderInto allows storing the value of a header from the response into a
// string variable. Since the requests library is made to quickly perform
// requests to REST APIs, and only a small number of response headers is usually
// read by application code (if at all), there is no response object that allows
// viewing headers. Therefore, any code that is interested in reading a response
// header must declare that in advance and provide a target variable.
func (req *HTTPRequest) HeaderInto(header string, into *string) *HTTPRequest {
	if req.headersInto == nil {
		req.headersInto = make(map[string]*string)
	}

	req.headersInto[header] = into

	return req
}

// StatusInto allows storing the status of the response into a variable. The
// same comments as for HeaderInto apply here as well.
func (req *HTTPRequest) StatusInto(into *int) *HTTPRequest {
	req.statusInto = into
	return req
}

// CookiesInto allows storing cookies in the response into a slice of cookies.
// The same comments as for HeaderInto apply here as well.
func (req *HTTPRequest) CookiesInto(into *[]*http.Cookie) *HTTPRequest {
	req.cookiesInto = into
	return req
}

// ExpectedStatus sets the HTTP status that the application expects to receive
// for the request. If the status received is different than the expected status,
// the library will return an error, and the error handler will be executed.
func (req *HTTPRequest) ExpectedStatus(status int) *HTTPRequest {
	req.expectedStatuses = []int{status}
	return req
}

// ExpectedStatuses is the same as ExpectedStatus, but allows setting multiple
// expected statuses.
func (req *HTTPRequest) ExpectedStatuses(statuses ...int) *HTTPRequest {
	req.expectedStatuses = statuses
	return req
}

// BasicAuth allows setting basic authentication header for the request.
// Usually, this will be done on the client object rather than the request
// object, but this method allows overriding authentication for specific
// requests.
func (req *HTTPRequest) BasicAuth(
	user, pass string,
	headerName ...string,
) *HTTPRequest {
	req.authType = "basic"
	req.authUser = user
	req.authPass = pass

	if len(headerName) > 0 {
		req.authHeader = headerName[0]
	} else {
		req.authHeader = defaultAuthHeader
	}

	return req
}

// Header sets the value of a header for the request.
func (req *HTTPRequest) Header(key, value string) *HTTPRequest {
	if req.customHeaders == nil {
		req.customHeaders = make(map[string]string)
	}

	req.customHeaders[key] = value

	return req
}

// CompressWith sets a compression algorithm to apply to all request bodies.
// Compression is optional, in that if it fails, for any reason, requests will
// not fail, but instead be sent without compression.
// Note that there is no need to use this to support decompression of responses,
// the library handles decompressions automatically.
func (req *HTTPRequest) CompressWith(alg CompressionAlgorithm) *HTTPRequest {
	req.compressionAlgorithm = alg
	return req
}

// ErrorHandler sets a custom error handler for the request.
func (req *HTTPRequest) ErrorHandler(handler ErrorHandlerFunc) *HTTPRequest {
	req.errorHandler = handler
	return req
}

// BodyHandler sets a custom body handler for the request.
func (req *HTTPRequest) BodyHandler(handler BodyHandlerFunc) *HTTPRequest {
	req.bodyHandler = handler
	return req
}

// Run finalizes the request and executes it. The returned error will be `nil`
// only if the request was successfully created, sent and a successful (or
// expected) status code was returned from the server.
func (req *HTTPRequest) Run() error {
	return req.RunContext(context.Background())
}

// RunContext is the same as Run, but executes the request with the provided
// context value.
func (req *HTTPRequest) RunContext(ctx context.Context) error {
	// did we fail during building the request? if so, return the error
	if req.err != nil {
		return req.err
	}

	// create the request
	r, err := req.createRequest()
	if err != nil {
		return err
	}

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

	if timeout > 0 {
		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// run the request
	res, err := req.cli.retryRequest(ctx, req.logger, r, &req.bodyDst, attempts)
	if err != nil {
		if errors.Is(err, ErrTimeoutReached) {
			return err
		}

		return fmt.Errorf("request failed: %w", err)
	}

	// make sure to read the entire body and close the request once we're
	// done, this is important in order to reuse connections and prevent
	// connection leaks
	defer closeBody(res.Body)

	// make sure response size does not exceed the limit
	if req.sizeLimit > 0 && res.ContentLength > req.sizeLimit {
		return ErrSizeExceeded
	}

	return req.parseResponse(res)
}

func (req *HTTPRequest) createRequest() (r *http.Request, err error) {
	// build the request URL from the client's base URL and the request's
	// path, plus add any query parameters defined
	if req.path != "" && !strings.HasPrefix(req.path, "/") {
		req.path = fmt.Sprintf("/%s", req.path)
	}

	reqURL := req.cli.baseURL + req.path

	if req.queryParams != nil {
		if queryParams := req.queryParams.Encode(); queryParams != "" {
			reqURL += "?" + queryParams
		}
	}

	// create the net/http.Request object
	r, err = http.NewRequest(req.method, reqURL, nil)
	if err != nil {
		return r, fmt.Errorf("failed creating request: %w", err)
	}

	// add cookies
	for _, c := range req.cookies {
		r.AddCookie(c)
	}

	// are we using basic authentication?
	if req.authType == basicAuth || req.cli.authType == basicAuth {
		setBasicAuth(req, r)
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

	// are we compressing requests
	err = req.compress(r)
	if err != nil {
		// log this, but do not fail
		req.logger.Warn(
			"Failed compressing request, will send uncompressed",
			zap.Error(err),
		)
	}

	return r, nil
}

func (req *HTTPRequest) compress(r *http.Request) error {
	alg := req.cli.compressionAlgorithm
	if req.compressionAlgorithm != CompressionAlgorithmNone {
		alg = req.compressionAlgorithm
	}

	if req.bodySrc == nil {
		return nil
	}

	var compressor io.Writer

	switch alg {
	case CompressionAlgorithmGzip:
		w := gzip.NewWriter(&req.bodyDst)
		defer w.Close()
		compressor = w
	case CompressionAlgorithmDeflate:
		w := zlib.NewWriter(&req.bodyDst)
		defer w.Close()
		compressor = w
	case CompressionAlgorithmNone:
		compressor = &req.bodyDst
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedCompression, alg)
	}

	tee := io.TeeReader(req.bodySrc, compressor)

	defer req.bodySrc.Close()

	_, err := io.ReadAll(tee)
	if err != nil {
		return fmt.Errorf("failed compressing body via %s: %w", alg, err)
	}

	if alg != CompressionAlgorithmNone {
		r.Header.Set("Content-Encoding", string(alg))
	}

	return nil
}

func (req *HTTPRequest) parseResponse(res *http.Response) error {
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
	var successful bool
	if len(req.expectedStatuses) > 0 {
		successful = contains(req.expectedStatuses, res.StatusCode)
	} else {
		successful = res.StatusCode >= http.StatusOK &&
			res.StatusCode < http.StatusMultipleChoices
	}

	if !successful {
		var handler ErrorHandlerFunc

		switch {
		case req.errorHandler != nil:
			handler = req.errorHandler
		case req.cli.errorHandler != nil:
			handler = req.cli.errorHandler
		default:
			handler = defaultErrorHandler
		}

		return handler(
			res.StatusCode,
			res.Header.Get("Content-Type"),
			res.Body,
		)
	}

	// what are we loading the response into and how? make sure we're only
	// doing this if there is a response content
	if res.StatusCode != http.StatusNoContent &&
		req.into != nil &&
		(res.Header.Get("Content-Length") == "" || res.ContentLength > 0) {
		var handler BodyHandlerFunc

		switch {
		case req.bodyHandler != nil:
			handler = req.bodyHandler
		case req.cli.bodyHandler != nil:
			handler = req.cli.bodyHandler
		default:
			handler = defaultBodyHandler
		}

		return handler(
			res.StatusCode,
			res.Header.Get("Content-Type"),
			res.Body,
			req.into,
		)
	}

	return nil
}

func setBasicAuth(req *HTTPRequest, r *http.Request) {
	// take user, password and authentication header from the
	// request if provided, otherwise from the client
	user := req.authUser
	if user == "" {
		user = req.cli.authUser
	}

	pass := req.authPass
	if pass == "" {
		pass = req.cli.authPass
	}

	header := req.authHeader
	if header == "" {
		header = req.cli.authHeader
	}

	if header == "" {
		header = defaultAuthHeader
	}

	r.Header.Add(header, "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
}

func defaultBodyHandler(
	_ int,
	contentType string,
	body io.Reader,
	target interface{},
) (err error) {
	cType := strings.Split(contentType, ";")
	switch cType[0] {
	case "text/plain":
		v := reflect.ValueOf(target)
		if v.Kind() != reflect.Ptr || v.IsNil() {
			return fmt.Errorf("invalid target variable: %w", err)
		}

		data, err := ioutil.ReadAll(body)
		if err != nil {
			return fmt.Errorf("failed reading server response: %w", err)
		}

		switch v := target.(type) {
		case *string:
			*v = strings.TrimRightFunc(string(data), unicode.IsSpace)
		default:
			return ErrNotAPointer
		}
	default:
		// default to JSON, regardless of returned Content-Type
		err = json.NewDecoder(body).Decode(target)
		if err != nil {
			return fmt.Errorf("failed decoding server response: %w", err)
		}
	}

	return nil
}

func defaultErrorHandler(
	status int,
	_ string,
	_ io.Reader,
) (err error) {
	// nolint: goerr113
	return fmt.Errorf("server returned unexpected status %d", status)
}

// defaultTransport returns the library's default HTTP transport. It is a
// modification of Go's default transport (https://golang.org/pkg/net/http/#RoundTripper)
// with options to ignore invalid or self-signed TLS certificates and to
// configure timeouts.
// See https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
// for more details about client timeouts.
func defaultTransport(
	tlsNoVerify bool,
	renegotiationSupport tls.RenegotiationSupport,
) http.RoundTripper {
	return buildTransport(&tls.Config{
		InsecureSkipVerify: tlsNoVerify,
		Renegotiation:      renegotiationSupport,
	})
}

func tlsTransport(
	certPEMBlock, keyPEMBlock, caCert []byte,
	tlsNoVerify bool,
	renegotiationSupport tls.RenegotiationSupport,
) http.RoundTripper {
	// Load client certificate
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: tlsNoVerify,
		Renegotiation:      renegotiationSupport,
	}
	tlsConfig.BuildNameToCertificate()

	return buildTransport(tlsConfig)
}

func buildTransport(tlsconfig *tls.Config) http.RoundTripper {
	// nolint: gomnd
	return &http.Transport{
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
}

func contains(slice []int, wanted int) bool {
	for _, s := range slice {
		if s == wanted {
			return true
		}
	}

	return false
}

func closeBody(body io.ReadCloser) {
	// nolint: errcheck
	io.Copy(ioutil.Discard, body)
	body.Close()
}
