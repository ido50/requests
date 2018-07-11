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

func TestTLSConnection (t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "Lorem ipsum dolor sit amet")
	}))
	defer ts.Close()

	certpem :=`-----BEGIN CERTIFICATE-----
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
		[]byte(keypem),[]byte(certpem))

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
