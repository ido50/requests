<h2 align="center"><strong>requests</strong></h2>
<p align="center">high-level HTTP client for Go.</p>
<p align="center">
	<a href="https://godoc.org/github.com/ido50/requests"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
    <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg"></a>
	<a href="https://goreportcard.com/report/ido50/requests"><img src="https://goreportcard.com/badge/github.com/ido50/requests"></a>
    <a href="https://github.com/ido50/requests/actions"><img src="https://github.com/ido50/requests/workflows/build/badge.svg"></a>
</p>

---

`requests` is a high-level, API-centric HTTP client for Go projects. It is meant
to provide a more comfortable mechanism to perform requests to HTTP APIs (rather
than making general requests), and to prevent common mistakes made when using
`net/http` directly.

With `requests`, one must not need to remember to read HTTP responses in full (so
Go can reuse TCP connections), nor to close response bodies. Handling of JSON
data - be it in requests or responses - is made easier by way of built-in
encoders/decoders. An automatic retry mechanism is also included.

The library allows a "DRY" (Dont Repeat Yourself) approach to REST API usage by
introducing API-specific dependencies into the client object. For example,
authorization headers and response handlers can be set in the client object,
and all generated requests will automatically include them.

# Install

```
go get -u github.com/ido50/requests
```

# Usage

```go
package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ido50/requests"
)

const apiURL = "https://my.api.com/v2"

type RequestBody struct {
	Title   string   `json:"title"`
	Tags    []string `json:"tags"`
	Publish bool     `json:"publish"`
}

type ResponseBody struct {
	ID   int64     `json:"id"`
	Date time.Time `json:"date"`
}

func main() {
	client := requests.
		NewClient(apiURL).
		Accept("application/json").
		BasicAuth("user", "pass").
		RetryLimit(3)

	var res ResponseBody

	err := client.
		NewRequest("POST", "/articles").
		JSONBody(RequestBody{
			Title:   "Test Title",
			Tags:    []string{"test", "stories"},
			Publish: true,
		}).
		ExpectedStatus(http.StatusCreated).
		Into(&res).
		Run()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Created article %d on %s\n", res.ID, res.Date.Format(time.RFC3339))
}
```
