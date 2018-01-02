package requests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/pkg/errors"
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
	baseURL       string                // base URL for all HTTP requests
	httpCli       *http.Client          // underlying net/http client
	authType      authType              // default authentication type for all requests (defaults to no authentication)
	authUser      string                // default username for all requests
	authPass      string                // default password for all requests
	authHeader    string                // header name for authentication (defaults to 'Authorization')
	customHeaders map[string]string     // default headers for all requests
	accept        string                // default expected response content type for all requests
	timeout       time.Duration         // default timeout for all requests
	errorHandler  func(io.Reader) error // default error handler for all requests returning unexpected status
}

// HTTPRequest represents a single HTTP request to the web service defined
// in the client.
type HTTPRequest struct {
	cli            *HTTPClient           // the HTTPClient this request belongs to
	method         string                // HTTP method/verb to use (GET, POST, PUT, etc.)
	path           string                // request path (will be appended to the client's base URL)
	queryParams    url.Values            // URL query parameters for the request
	contentType    string                // content type of the request's body
	body           io.ReadWriter         // reader for the request's body
	into           interface{}           // pointer to a variable where the response will be loaded into
	headersInto    map[string]*string    // map of header names to pointers where response header values will be loaded into
	statusInto     *int                  // pointer where response status code will be loaded
	expectedStatus int                   // expected status code from the server (defaults to 200)
	err            error                 // error encountered during building the request
	authType       authType              // authentication type for the request (defaults to no authentication)
	authUser       string                // username for the request
	authPass       string                // password for the request
	authHeader     string                // header used for authentication (defaults to 'Authorization')
	customHeaders  map[string]string     // headers for the request (headers from the client will be used as well, but headers defined here take precedence)
	accept         string                // expected response content type
	errorHandler   func(io.Reader) error // error handler for request if returned status is not the expected one
}

func NewClient(baseURL string) *HTTPClient {
	return &HTTPClient{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		authType: noAuth,
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

func (cli *HTTPClient) NewRequest(method, path string) *HTTPRequest {
	if cli.httpCli == nil {
		cli.httpCli = &http.Client{
			Timeout: cli.timeout,
		}
	}

	return &HTTPRequest{
		cli:    cli,
		path:   path,
		method: method,
	}
}

func (req *HTTPRequest) QueryParam(key, value string) *HTTPRequest {
	if req.queryParams == nil {
		req.queryParams = url.Values{}
	}
	req.queryParams.Add(key, value)
	return req
}

func (req *HTTPRequest) Body(body []byte, contentType string) *HTTPRequest {
	req.body = bytes.NewBuffer(body)
	req.contentType = contentType
	return req
}

func (req *HTTPRequest) JSONBody(body interface{}) *HTTPRequest {
	req.body = &bytes.Buffer{}
	err := json.NewEncoder(req.body).Encode(body)
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

func (req *HTTPRequest) Run() error {
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
	reqURL := req.cli.baseURL + req.path
	if req.queryParams != nil {
		if queryParams := req.queryParams.Encode(); queryParams != "" {
			reqURL += "?" + queryParams
		}
	}

	// create the net/http.Request object
	r, err := http.NewRequest(req.method, reqURL, req.body)
	if err != nil {
		return errors.Wrap(err, "failed creating request")
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

	// initiate the request
	res, err := req.cli.httpCli.Do(r)
	if err != nil {
		return errors.Wrap(err, "request failed")
	}

	// make sure to read the entire body and close the request once we're
	// done, this is important in order to reuse connections and prevent
	// connection leaks
	defer func() {
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()
	}()

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
	if res.StatusCode != http.StatusNoContent && req.into != nil {
		switch req.accept {
		case "text/plain":
			v := reflect.ValueOf(req.into)
			if v.Kind() != reflect.Ptr || v.IsNil() {
				return errors.Wrap(err, "invalid target variable")
			}

			data, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return errors.Wrap(err, "failed reading server response")
			}

			switch v := req.into.(type) {
			case *string:
				*v = strings.TrimRightFunc(string(data), unicode.IsSpace)
			default:
				return errors.New("target variable is not a string pointer")
			}
		default:
			err = json.NewDecoder(res.Body).Decode(req.into)
			if err != nil {
				return errors.Wrap(err, "failed decoding server response")
			}
		}
	}
	return nil
}
