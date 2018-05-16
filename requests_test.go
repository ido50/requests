package requests

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pkg/errors"
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
		BodyHandler(func(cType string, reader io.Reader, target interface{}) error {
			if cType != "application/x.rot13" {
				return errors.Errorf("unexpected content type %s returned", cType)
			}
			b, err := ioutil.ReadAll(reader)
			if err != nil {
				return errors.Wrap(err, "failed reading response body")
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
