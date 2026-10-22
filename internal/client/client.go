// Threats: calls the operator's systemapi with one credential: the
// device-login bearer (Authorization: Bearer) or the API key (X-API-Key). The
// credential is a header, never a query parameter, and it is never copied into
// an error string. http (and ws) is accepted only for a loopback IP or the name
// localhost. https and wss use the system CA pool and TLS 1.3 or newer.
// Redirects are refused and the environment proxy is ignored. Query keys
// api_key, access_token, token, and device_code are refused. The terminal
// ticket is the only query secret, it is single-use, and it is never printed.
// The bearer is bound to the origin that issued it and is refused for any
// other origin. Every dial re-checks the resolved address (DialGuard), which
// defeats DNS rebinding to metadata or link-local addresses. Resolve and
// Ticket validate host names and host ids against
// [A-Za-z0-9._-]{1,253} before they reach a URL. Does NOT open a shell itself;
// sahconnect ssh executes the adssh binary the operator already has.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarksys/sahmesh/internal/token"
)

const maxBody = 256 << 10
const maxResponse = 1 << 20

// Error is a fixed failure code. It does not carry a URL or a key.
type Error struct{ Code string }

func (e *Error) Error() string {
	if e == nil || e.Code == "" {
		return "request_failed"
	}
	return e.Code
}

func code(c string) error { return &Error{Code: c} }

// ValidateBase accepts an http(s) origin with no userinfo, query, or path.
// Plain http is only valid for loopback.
func ValidateBase(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > 200 {
		return nil, code("invalid_url")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, code("invalid_url")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, code("invalid_url")
	}
	if strings.ContainsAny(u.Host, " \t\r\n") {
		return nil, code("invalid_url")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return nil, code("invalid_url")
		}
	default:
		return nil, code("invalid_url")
	}
	if badName(u.Hostname()) {
		return nil, code("invalid_url")
	}
	return u, nil
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func badName(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	switch h {
	case "metadata.google.internal", "metadata.goog":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if ip.IsLoopback() {
			return false
		}
		if ip.Equal(net.ParseIP("fd00:ec2::254")) || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return true
		}
	}
	return false
}

// ValidPath is an absolute path with no dot-dot, backslash, or query.
func ValidPath(p string) bool {
	if len(p) == 0 || len(p) > 512 || !strings.HasPrefix(p, "/") {
		return false
	}
	if strings.Contains(p, "..") || strings.Contains(p, "//") || strings.Contains(p, "\\") || strings.Contains(p, "?") || strings.Contains(p, "#") {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

// ValidQuery rejects credential-bearing keys.
func ValidQuery(raw string) error {
	if len(raw) > 2048 {
		return code("invalid_query")
	}
	if raw == "" {
		return nil
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return code("invalid_query")
	}
	for key := range q {
		switch strings.ToLower(key) {
		case "api_key", "access_token", "token", "device_code":
			return code("invalid_query")
		}
	}
	return nil
}

var methods = map[string]struct{}{
	http.MethodGet: {}, http.MethodPost: {}, http.MethodPut: {},
	http.MethodPatch: {}, http.MethodDelete: {},
}

// Auth carries the credential for one request. Bearer is the device-login
// token and wins when both are set; it is sent only when BearerOrigin equals
// the request's origin. APIKey is sent as X-API-Key.
type Auth struct {
	Bearer       string
	BearerOrigin string // canonical origin the bearer was issued by
	APIKey       string
}

func validSecret(s string) bool {
	if strings.TrimSpace(s) == "" || len(s) > 512 {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

func (a Auth) apply(h http.Header, base *url.URL) error {
	switch {
	case a.Bearer != "":
		if !validSecret(a.Bearer) {
			return code("token_rejected")
		}
		if a.BearerOrigin == "" || a.BearerOrigin != token.Origin(base) {
			return code("token_origin_mismatch")
		}
		h.Set("Authorization", "Bearer "+a.Bearer)
	case a.APIKey != "":
		if !validSecret(a.APIKey) {
			return code("key_rejected")
		}
		h.Set("X-API-Key", a.APIKey)
	default:
		return code("credentials_missing")
	}
	return nil
}

// NewHTTPClient returns the guarded client: TLS 1.3 or newer, no proxy, no
// redirects. roots nil means the system CA pool; tests pass a test CA.
// timeout 0 means no client timeout (the caller uses a context).
// Every dial goes through DialGuard, so a name that resolves (or rebinds) to
// a metadata, link-local, multicast or unspecified address is refused at
// connect time. The WebSocket client uses this same client.
func NewHTTPClient(roots *x509.CertPool, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: DialGuard}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirect
		},
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dialer.DialContext,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

// ErrRedirect is returned (wrapped) when a server answers with a redirect.
var ErrRedirect = errors.New("redirect_denied")

// DialGuard is a net.Dialer Control hook. It refuses the resolved address
// when it is link-local (which covers 169.254.169.254), the AWS IPv6 metadata
// address, multicast, or unspecified.
func DialGuard(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return code("dial_refused")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return code("dial_refused")
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.Equal(net.ParseIP("fd00:ec2::254")) {
		return code("dial_refused")
	}
	return nil
}

// Client is one validated origin plus one credential.
type Client struct {
	Base *url.URL
	Auth Auth
	HTTP *http.Client // nil means NewHTTPClient(nil, 20s)
}

// Do performs one request. key is sent as X-API-Key. Errors are codes.
func Do(ctx context.Context, base *url.URL, key, method, path, rawQuery string, body []byte) (int, []byte, error) {
	if strings.TrimSpace(key) == "" {
		return 0, nil, code("key_rejected")
	}
	c := &Client{Base: base, Auth: Auth{APIKey: key}}
	return c.Do(ctx, method, path, rawQuery, body)
}

// Do performs one request with the client's credential. Errors are codes and
// never contain the credential or the URL.
func (c *Client) Do(ctx context.Context, method, path, rawQuery string, body []byte) (int, []byte, error) {
	if c == nil || c.Base == nil {
		return 0, nil, code("invalid_url")
	}
	method = strings.ToUpper(method)
	if _, ok := methods[method]; !ok {
		return 0, nil, code("bad_method")
	}
	if !ValidPath(path) {
		return 0, nil, code("bad_path")
	}
	if err := ValidQuery(rawQuery); err != nil {
		return 0, nil, err
	}
	if len(body) > maxBody {
		return 0, nil, code("too_large")
	}
	u := *c.Base
	u.Path = path
	u.RawQuery = rawQuery
	u.Fragment = ""
	u.User = nil
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return 0, nil, code("request_failed")
	}
	if err := c.Auth.apply(req.Header, c.Base); err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = NewHTTPClient(nil, 20*time.Second)
	}
	resp, err := hc.Do(req)
	if err != nil {
		if errors.Is(err, ErrRedirect) {
			return 0, nil, code("redirect_denied")
		}
		return 0, nil, code("request_failed")
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return 0, nil, code("request_failed")
	}
	if len(buf) > maxResponse {
		return 0, nil, code("response_too_large")
	}
	return resp.StatusCode, buf, nil
}

// LookAdssh resolves an explicit binary or adssh on PATH.
func LookAdssh(explicit string) (string, error) {
	if explicit != "" {
		if strings.Contains(explicit, "\x00") {
			return "", code("adssh_missing")
		}
		st, err := os.Stat(explicit)
		if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
			return "", code("adssh_missing")
		}
		return explicit, nil
	}
	p, err := exec.LookPath("adssh")
	if err != nil {
		return "", code("adssh_missing")
	}
	return p, nil
}

// RunAdssh executes adssh with the operator's stdio. It does not add arguments.
func RunAdssh(ctx context.Context, bin string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if bin == "" {
		return code("adssh_missing")
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit
		}
		return code("adssh_failed")
	}
	return nil
}
