package requests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
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
