package requests

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jgroeneveld/trial/assert"
	"github.com/spf13/afero"
)

func TestPlainTextResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	cli := NewClient(ts.URL).Accept("text/plain")

	var text string
	var status int
	err := cli.NewRequest("GET", "/").
		Into(&text).
		StatusInto(&status).
		Run()
	if err != nil {
		t.Fatalf("Failed request: %s", err)
	}

	if text != "Hello, client" {
		t.Errorf("Failed reading plain text body: got %+q, expected %+q", text, "Hello, client")
	}

	if status != 200 {
		t.Errorf("Failed to read status: got %d, expected 200", status)
	}
}

func TestJSONResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "encoding/json")
		fmt.Fprintln(w, `{ "message": "Hello, client" }`)
	}))
	defer ts.Close()

	cli := NewClient(ts.URL)

	var response struct {
		Message string `json:"message"`
	}

	err := cli.NewRequest("GET", "/").
		Into(&response).
		Run()
	if err != nil {
		t.Fatalf("Failed request: %s", err)
	}

	if response.Message != "Hello, client" {
		t.Errorf("Failed reading JSON body: got %#v, expected %+q", response, "Hello, client")
	}
}

func TestResponseHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Custom-Header", "bla")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	cli := NewClient(ts.URL)

	var customHeader string
	err := cli.NewRequest("GET", "/").
		HeaderInto("Custom-Header", &customHeader).
		ExpectedStatus(http.StatusNoContent).
		Run()
	if err != nil {
		t.Fatalf("Failed request: %s", err)
	}

	if customHeader != "bla" {
		t.Errorf("Failed reading custom header: got %+q, expected %+q", customHeader, "bla")
	}
}

func TestErrorResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer ts.Close()

	cli := NewClient(ts.URL)

	var status int
	err := cli.NewRequest("GET", "/").
		StatusInto(&status).
		ExpectedStatus(http.StatusBadRequest).
		Run()
	if err != nil {
		t.Fatalf("Failed request: %s", err)
	}

	if status != http.StatusBadRequest {
		t.Errorf("Failed reading non-200 status code: got %d, expected %d", status, http.StatusBadRequest)
	}
}

//func TestNoTLSVerify(t *testing.T) {
//cli := NewClient("")
//cli.NewRequest("GET", "/")

//transport := cli.httpCli.Transport.(*http.Transport)
//if transport.TLSClientConfig.InsecureSkipVerify {
//t.Fatal("Transport should verify TLS connections but isn't")
//}

//cli.NoTLSVerify(true).NewRequest("GET", "/")
//transport = cli.httpCli.Transport.(*http.Transport)
//if !transport.TLSClientConfig.InsecureSkipVerify {
//t.Fatal("Transport shouldn't verify TLS connections but is")
//}
//}

func TestResponseSizeLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "Lorem ipsum dolor sit amet")
	}))
	defer ts.Close()

	var data string

	cli := NewClient(ts.URL)
	err := cli.NewRequest("GET", "/").SizeLimit(5).Into(&data).Run()
	if err != ErrSizeExceeded {
		t.Fatal("Response size was not limited as expected")
	}
}

func TestRequestTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "Lorem ipsum dolor sit amet")
	}))
	defer ts.Close()

	err := NewClient(ts.URL).
		NewRequest("GET", "/").
		Timeout(1 * time.Second).
		Run()
	if err == nil {
		t.Fatal("Response succeeded but should have timed out")
	} else if err != ErrTimeoutReached {
		t.Fatalf("Request failed but not with timeout error: %s", err)
	}
}

func TestRequestRetries(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "Lorem ipsum dolor sit amet")
	}))
	ts.Close() // this is on purpose

	cli := NewClient(ts.URL)
	start := time.Now()
	err := cli.NewRequest("GET", "/").RetryLimit(2).Run()
	end := time.Now()
	if err == nil {
		t.Fatal("Request did not fail as expected")
	} else if end.Sub(start) < 6*time.Second {
		t.Fatal("Request was not retried as expected")
	}
}

func TestCustomBodyHandler(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x.rot13")
		fmt.Fprintln(w, "Hello, World")
	}))
	defer ts.Close()

	var data []byte

	err := NewClient(ts.URL).
		NewRequest("GET", "/").
		BodyHandler(func(status int, cType string, reader io.Reader, target interface{}) error {
			if cType != "application/x.rot13" {
				return fmt.Errorf("unexpected content type %s returned", cType)
			}
			b, err := ioutil.ReadAll(reader)
			if err != nil {
				return fmt.Errorf("failed reading response body: %w", err)
			}
			t := target.(*[]byte)
			*t = rot13(b[:len(b)-1]) // chomp newline
			return nil
		}).
		Into(&data).
		Run()
	if err != nil {
		t.Fatalf("Failed custom body handler: %s", err)
	} else if string(data) != "Uryyb, Jbeyq" {
		t.Fatalf("Body handler returned wrong content: %q", string(data))
	}
}

func TestTLSConnection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "Lorem ipsum dolor sit amet")
	}))
	defer ts.Close()

	certpem := `-----BEGIN CERTIFICATE-----
MIIC+TCCAeGgAwIBAgIRAJTH5D+Q6YNUn+jnF1TDxikwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xODA3MTExNDM1MjBaFw0xOTA3MTExNDM1
MjBaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQCzd/q1zkG6XODPKBVI8gjV12JBIusZHyeF/fefvCzTqOhWUP3+VDOa
3JOQqe06qiXfe3fbWGtqLhVWvo48RMtQCAq+nfbdH5peSfHTHqe3x1WtgVAqPsRx
nP0TZ9MQvMfJDvyMuJtowVTktOSKIEX6DYct3v6OJrdnFq/SB1gxdcjP03Gvr688
PN15llTtPuWxcmim7uTQHJZ4ep1xsD7XiqCfU8nAM9FCi5Nsm+Lu4tPbN8JH6g58
2VnPtsrbHmG7i5t3a3c6MDN11SR7C/76CsjQ09FHCCzPMoXguPCW5Xh813vfYFvE
9Yi8k1rE4ahDQGYTgSmzSdtGqjAXj+LFAgMBAAGjSjBIMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBMGA1UdEQQMMAqC
CHRlc3QuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQB7VS4V7itZM3m8oNuzvsD2l0Fu
V1UWB9SLM0kapdIyunrsa0zKQduJEJgYpzBSu9azys+R2wugU+lxnp7zW2uhQ+Q7
aaqw24KUxgxc8CNWnf5OXgRkhsBkxV7S5q9eOkq1T66hVVSYr10eNT2t3q0cjLdL
KOflrMgjTwE+XGdIAmsNK+M0D3ld67sDT8IgvwEPkdbcA4XcTTbQtN1weZigg+mz
3PAk6vuH5wdd+D9RcbsVh+qJpO3HLsncA6jHEGsWpuOR/CYdmPl3qNvCRl6Y/fO3
QBmIap3791SIZWRPp43E+g7U21ctQggmGZ2dQ9njiOlQesCDn447AX5CgyW9
-----END CERTIFICATE-----`

	keypem := `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAs3f6tc5BulzgzygVSPII1ddiQSLrGR8nhf33n7ws06joVlD9
/lQzmtyTkKntOqol33t321hrai4VVr6OPETLUAgKvp323R+aXknx0x6nt8dVrYFQ
Kj7EcZz9E2fTELzHyQ78jLibaMFU5LTkiiBF+g2HLd7+jia3Zxav0gdYMXXIz9Nx
r6+vPDzdeZZU7T7lsXJopu7k0ByWeHqdcbA+14qgn1PJwDPRQouTbJvi7uLT2zfC
R+oOfNlZz7bK2x5hu4ubd2t3OjAzddUkewv++grI0NPRRwgszzKF4LjwluV4fNd7
32BbxPWIvJNaxOGoQ0BmE4Eps0nbRqowF4/ixQIDAQABAoIBAFMMZ0jwTDwoNKPI
IalizzHdfIs11GMIpqp7rrYNRxUfKXyf+BlT75lvDx43dB7ck7AKG5m2HebBsoA0
p+89ynObdRVmVdFXiYCuaShQHD6QEJa8q1MRPqhwhDARsHsjULQ6qiWYW9oq9NTs
3IEKlDc1QWO5uEQhqGcc+XmQioBAAXyjnEGtBHlyrraKLaFJuLeZJshKjTonlTP3
sokuA8Xs+wU68U0nYsNESzcDRz7erFpDU7ypydvGS4x2X+0NK5hLbjoETN9KZXAG
8ksWM5BAP41ZLMfe+bl02F94u3nWATU3RuFeS9OwLx0i+1T4ll5wwh1yfacP6Egz
Ybqw0EECgYEAzPrjCZuforDiHxHyr0stiTvCmWIbBawwz5rFTJ2FfmKcYfwlnX9+
9FLnDAIwx9nramUbKd4Y9b/PiDfDGN+eROxU5mxDUZF87Ayy8Ejst2n0dEDQ9izJ
XXcafi0UU0ShCSqovya24N+Ul6bLOMwFkvjzwO+/VA7wHJTCtknVArECgYEA4COJ
EZpg8woINisf02xenbmuxs6R/+dQXFClap446IUQaDwHF+8Fv50nUr0/uUEQijbY
wKC9cwN9A8VVSDethXpYLDKQniu3P6hwtsQRiBWha275YAtmLNykpacw8YtIzpz+
cY3p5xAxZuGLyki3HaFJQWMHOKvB38i1AXapXlUCgYB5kg8XgrIiFpB15votVwQR
0VywBcyLB74HUv7TWtVyyN+BCb/xck2EcKrRp3bxAOErv/1lTnE1R2a5noDafr3q
mNQduXYPqZ8SjNGPy2CBw5iVXl/QsW1YPqx6yxez7w8nVaKxhC+QnWoOq4D6FZ70
tSw0cLzkCNwFx4DYBmAMcQKBgB/ISi5p0qeD26g6szeanUwGQWdFcWR1G2sLsHkO
2Ij4HVx6bpMRPKJwGVxdI4UUWdEPd+rQoCyH6Rk4ySAFbSCJOamCvgj/r+th6iGw
ab//OTVvtgLNev6PhvVKYOFPW9KYZmgZtHokTK0G/HiBmR2leirAbQy3JjWiUzBS
8C9FAoGAfG4or+rOZYYcjZgpgORip97ugPzK0OPp1Z6wPF3Nhv3cxhU/DbcprNjM
aUz5HXBcNYdNTwmMhJeR+2PjQLwK8XKQyR/OXPwgpDhYdpI8jx4AV4VakekES2Mx
0soArFGOSvrfeB0pT7L6hzoCS806+qZPiHpag+h2iFnooNQWvC8=
-----END RSA PRIVATE KEY-----`

	cli := NewClient(ts.URL).Accept("text/plain").SetTLS([]byte(certpem),
		[]byte(keypem), []byte(certpem))

	var text string
	var status int
	err := cli.NewRequest("GET", "/").
		Into(&text).
		StatusInto(&status).
		Run()
	if err != nil {
		t.Fatalf("Failed request: %s", err)
	}

	if text != "Lorem ipsum dolor sit amet" {
		t.Errorf("Failed reading plain text body: got %+q, expected %+q", text, "Hello, client")
	}

	if status != 200 {
		t.Errorf("Failed to read status: got %d, expected 200", status)
	}
}

func rot13(b []byte) []byte {
	for i, r := range b {
		switch {
		case r >= 'A' && r <= 'Z':
			b[i] = 'A' + (((r - 'A') + 13) % 26)
		case r >= 'a' && r <= 'z':
			b[i] = 'a' + (((r - 'a') + 13) % 26)
		default:
			b[i] = r
		}
	}

	return b
}

func TestCompressedRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		cr, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Failed creating gzip reader: %s\n", err)
			return
		}

		defer cr.Close()

		content, err := io.ReadAll(cr)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Failed reading request body: %s\n", err)
			return
		}

		fmt.Fprintln(w, string(content))
	}))

	defer ts.Close()

	cli := NewClient(ts.URL).
		Accept("text/plain").
		CompressWith(CompressionAlgorithmGzip)

	for i, input := range []string{"hello world", "bla", "AAABBb"} {
		var output string
		err := cli.NewRequest("GET", "/").
			Into(&output).
			Body([]byte(input), "text/plain").
			Run()
		if err != nil {
			t.Fatalf("Failed request: %s", err)
		}

		if output != input {
			t.Errorf("Compression test %d: got %+q, expected %+q", i, output, input)
		}
	}
}

func TestBodySources(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		io.ReadAll(io.TeeReader(r.Body, w))
	}))

	defer ts.Close()

	var testFS = afero.NewMemMapFs()
	err := afero.WriteFile(testFS, "hello", []byte("Hello world"), 0655)
	assert.MustBeNil(t, err, "must create file successfully")

	cli := NewClient(ts.URL)

	type bodySrcTest struct {
		desc        string
		body        interface{}
		file        string
		contentType string
		expErr      error
		expBody     string
	}

	for _, test := range []bodySrcTest{
		{
			desc:        "A []byte value",
			body:        []byte("Hello world"),
			contentType: "text/plain",
			expBody:     "Hello world",
		},
		{
			desc:        "A string value",
			body:        "Hello world",
			contentType: "text/plain",
			expBody:     "Hello world",
		},
		{
			desc:        "A simple io.Reader",
			body:        bytes.NewReader([]byte("Hello world")),
			contentType: "text/plain",
			expBody:     "Hello world",
		},
		{
			desc:        "A simple io.ReadCloser",
			body:        io.NopCloser(bytes.NewReader([]byte("Hello world"))),
			contentType: "text/plain",
			expBody:     "Hello world",
		},
		{
			desc:        "An unsupported value",
			body:        3,
			contentType: "text/plain",
			expErr:      ErrUnsupportedBody,
		},
		{
			desc:        "A file",
			file:        "hello",
			contentType: "text/plain",
			expBody:     "Hello world",
		},
		{
			desc:        "A non-existent file",
			file:        "doesnt-exist",
			contentType: "text/plain",
			expErr:      errors.New("file does not exist"),
		},
	} {
		var resBody, resContentType string
		req := cli.NewRequest("POST", "/").
			Accept(test.contentType).
			Into(&resBody).
			HeaderInto("Content-Type", &resContentType)

		if test.file != "" {
			req.FileBody(afero.NewIOFS(testFS), test.file, "text/plain")
		} else {
			req.Body(test.body, test.contentType)
		}

		err := req.Run()

		if test.expErr != nil {
			assert.MustNotBeNil(t, err)
			assert.MustBeTrue(
				t,
				errors.Is(
					err,
					test.expErr) ||
					strings.Contains(err.Error(), test.expErr.Error()),
			)
		} else {
			assert.MustBeNil(t, err)
			assert.MustBeEqual(t, test.contentType, resContentType)
			assert.MustBeEqual(t, test.expBody, resBody)
		}
	}
}

func TestMultipartBody(t *testing.T) {
	type part struct {
		Fieldname string `json:"fieldname"`
		Filename  string `json:"filename"`
		Content   string `json:"content"`
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(
				w,
				"Invalid content type %q: %s",
				r.Header.Get("Content-Type"), err,
			)
			return
		}

		mr := multipart.NewReader(r.Body, params["boundary"])
		var output []part
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			} else if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "Failed getting next part: %s", err)
				return
			}

			b, err := io.ReadAll(p)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "Failed reading part body: %s", err)
				return
			}

			output = append(output, part{
				Fieldname: p.FormName(),
				Filename:  p.FileName(),
				Content:   string(b),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(output)
	}))

	defer ts.Close()

	var testFS = afero.NewMemMapFs()
	err := afero.WriteFile(testFS, "hello", []byte("HELLO"), 0655)
	assert.MustBeNil(t, err, "must create file successfully")
	err = afero.WriteFile(testFS, "world", []byte("WORLD"), 0655)
	assert.MustBeNil(t, err, "must create file successfully")

	var res []part

	iofs := afero.NewIOFS(testFS)

	err = NewClient(ts.URL).NewRequest("POST", "/").
		Into(&res).
		MultipartBody(
			MultipartPart("header", "title.txt", "Hello world"),
			MultipartFile("body", iofs, "hello"),
			MultipartFile("footer", iofs, "world"),
		).
		Run()

	assert.MustBeNil(t, err)
	assert.MustBeDeepEqual(t, []part{
		{
			Fieldname: "header",
			Filename:  "title.txt",
			Content:   "Hello world",
		},
		{
			Fieldname: "body",
			Filename:  "hello",
			Content:   "HELLO",
		},
		{
			Fieldname: "footer",
			Filename:  "world",
			Content:   "WORLD",
		},
	}, res)
}

func TestRequestBodyProcessor(t *testing.T) {
	var body []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}))

	defer ts.Close()

	fn := func(r io.Reader, w io.Writer) error {
		fmt.Fprint(w, `{"items":`)
		tee := io.TeeReader(r, w)
		_, err := io.ReadAll(tee)
		if err != nil {
			return err
		}
		fmt.Fprint(w, `}`)
		return nil
	}

	cli := NewClient(ts.URL)

	// First run without the body processor
	err := cli.NewRequest("POST", "/").
		JSONBody([]string{"one", "two", "three"}).
		ExpectedStatus(http.StatusNoContent).
		Run()
	assert.MustBeNil(t, err)
	assert.MustBeEqual(t, `["one","two","three"]`, string(body))

	// Now with the processor
	err = cli.NewRequest("POST", "/").
		ReqBodyProcessor(fn).
		JSONBody([]string{"one", "two", "three"}).
		ExpectedStatus(http.StatusNoContent).
		Run()
	assert.MustBeNil(t, err)
	assert.MustBeEqual(t, `{"items":["one","two","three"]}`, string(body))
}
