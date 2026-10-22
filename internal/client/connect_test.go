package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahmesh/internal/token"
)

const bearer = "BEARER-SENTINEL-0123456789"

func fakeAPI(t *testing.T, seen *[]*http.Request, bodies *[]string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*seen = append(*seen, r)
		*bodies = append(*bodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/hosts/resolve":
			switch r.URL.Query().Get("name") {
			case "web1", "WEB1", "h-0001":
				_, _ = w.Write([]byte(`{"host_id":"h-0001","hostname":"web1","tenant":"acme","status":"online"}`))
			case "dup":
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"ambiguous","matches":3}`))
			case "bad.name":
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_name"}`))
			case "evil":
				_, _ = w.Write([]byte(`{"host_id":"../../x","hostname":"evil"}`))
			case "denied":
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"not_found"}`))
			}
		case "/api/v1/ws-ticket":
			var req map[string]string
			_ = json.Unmarshal(b, &req)
			if req["purpose"] == PurposeRoot && r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"scope_denied"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ticket":"stk_abc123","expires_at":"2026-10-14T12:00:00Z"}`))
		}
	}))
	t.Cleanup(srv.Close)
	base, err := ValidateBase(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{Base: base, Auth: Auth{Bearer: bearer, BearerOrigin: token.Origin(base), APIKey: "KEY-SENTINEL"}}
}

func TestResolve(t *testing.T) {
	var seen []*http.Request
	var bodies []string
	c := fakeAPI(t, &seen, &bodies)
	h, err := c.Resolve(context.Background(), "web1")
	if err != nil || h.HostID != "h-0001" || h.Hostname != "web1" || h.Status != "online" {
		t.Fatalf("200: %+v %v", h, err)
	}
	r := seen[0]
	if r.Header.Get("Authorization") != "Bearer "+bearer || r.Header.Get("X-API-Key") != "" {
		t.Fatal("bearer must win over the API key, and only one credential is sent")
	}
	if r.URL.RawQuery != "name=web1" {
		t.Fatalf("query %q", r.URL.RawQuery)
	}
	var re *ResolveError
	if _, err := c.Resolve(context.Background(), "nope"); !errors.As(err, &re) || re.Code != "not_found" {
		t.Fatalf("404: %v", err)
	}
	_, err = c.Resolve(context.Background(), "dup")
	if !errors.As(err, &re) || re.Code != "ambiguous" || re.Matches != 3 || !strings.Contains(err.Error(), "use the host_id") {
		t.Fatalf("409: %v", err)
	}
	if _, err := c.Resolve(context.Background(), "bad.name"); !errors.As(err, &re) || re.Code != "invalid_name" {
		t.Fatalf("400: %v", err)
	}
	if _, err := c.Resolve(context.Background(), "denied"); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("403: %v", err)
	}
	if _, err := c.Resolve(context.Background(), "evil"); err == nil {
		t.Fatal("unsafe host_id from server accepted")
	}
	n := len(seen)
	for _, bad := range []string{"", "a b", "web1;rm", "../x", strings.Repeat("a", 254), "web1?x=1"} {
		if _, err := c.Resolve(context.Background(), bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if len(seen) != n {
		t.Fatal("an invalid name was sent to the server")
	}
}

func TestTicket(t *testing.T) {
	var seen []*http.Request
	var bodies []string
	c := fakeAPI(t, &seen, &bodies)
	tk, err := c.Ticket(context.Background(), "h-0001", PurposeOpen)
	if err != nil || tk.Value != "stk_abc123" {
		t.Fatalf("ticket %+v %v", tk, err)
	}
	if seen[0].Method != http.MethodPost || seen[0].URL.RawQuery != "" {
		t.Fatal("ticket must be a POST with no query")
	}
	var body map[string]string
	if json.Unmarshal([]byte(bodies[0]), &body) != nil || body["host_id"] != "h-0001" || body["purpose"] != "terminal:open" || len(body) != 2 {
		t.Fatalf("body %s", bodies[0])
	}
	if _, err := c.Ticket(context.Background(), "h-0001", PurposeRoot); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bodies[1], `"terminal:root"`) {
		t.Fatalf("root body %s", bodies[1])
	}
	keyOnly := &Client{Base: c.Base, Auth: Auth{APIKey: "KEY-SENTINEL"}}
	_, err = keyOnly.Ticket(context.Background(), "h-0001", PurposeRoot)
	var te *TicketError
	if !errors.As(err, &te) || te.Code != "scope_denied" || strings.Contains(err.Error(), "KEY-SENTINEL") {
		t.Fatalf("refused: %v", err)
	}
	if seen[2].Header.Get("X-API-Key") != "KEY-SENTINEL" || seen[2].Header.Get("Authorization") != "" {
		t.Fatal("API key fallback header")
	}
	if _, err := c.Ticket(context.Background(), "h-0001", "terminal:admin"); err == nil {
		t.Fatal("unknown purpose accepted")
	}
	if _, err := c.Ticket(context.Background(), "../h", PurposeOpen); err == nil {
		t.Fatal("bad host id accepted")
	}
	none := &Client{Base: c.Base}
	if _, err := none.Ticket(context.Background(), "h-0001", PurposeOpen); err == nil || err.Error() != "credentials_missing" {
		t.Fatalf("no credential: %v", err)
	}
	bad := &Client{Base: c.Base, Auth: Auth{Bearer: "has space", BearerOrigin: token.Origin(c.Base)}}
	if _, err := bad.Resolve(context.Background(), "web1"); err == nil || strings.Contains(err.Error(), "has space") {
		t.Fatalf("bad bearer: %v", err)
	}
}

func TestTerminalURL(t *testing.T) {
	base, _ := ValidateBase("https://cp.example")
	u, err := TerminalURL(base, "h-0001", "stk_abc", PurposeOpen, 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != "wss://cp.example/api/v1/systems/terminal/h-0001?cols=80&purpose=terminal%3Aopen&rows=24&ticket=stk_abc" {
		t.Fatalf("url %s", u)
	}
	local, _ := ValidateBase("http://127.0.0.1:3003")
	u, err = TerminalURL(local, "h-0001", "stk_abc", PurposeRoot, 0, 0)
	if err != nil || u.Scheme != "ws" || u.Query().Has("rows") {
		t.Fatalf("loopback %v %v", u, err)
	}
	// A base that skipped ValidateBase still cannot produce plain ws off-box.
	for _, raw := range []string{"http://cp.example", "https://169.254.169.254", "https://metadata.google.internal"} {
		b, _ := url.Parse(raw)
		if _, err := TerminalURL(b, "h", "stk_abc", PurposeOpen, 0, 0); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, err := TerminalURL(base, "h/../x", "stk_abc", PurposeOpen, 0, 0); err == nil {
		t.Fatal("path injection accepted")
	}
}

func TestBearerNeverSentToAnotherOrigin(t *testing.T) {
	var seen []*http.Request
	var bodies []string
	c := fakeAPI(t, &seen, &bodies)
	// A production token presented to a staging URL.
	stolen := &Client{Base: c.Base, Auth: Auth{Bearer: bearer, BearerOrigin: "https://prod.example"}}
	_, err := stolen.Resolve(context.Background(), "web1")
	if err == nil || err.Error() != "token_origin_mismatch" || strings.Contains(err.Error(), bearer) {
		t.Fatalf("mismatch: %v", err)
	}
	unbound := &Client{Base: c.Base, Auth: Auth{Bearer: bearer}}
	if _, err := unbound.Resolve(context.Background(), "web1"); err == nil {
		t.Fatal("unbound bearer sent")
	}
	if len(seen) != 0 {
		t.Fatal("a request carrying the bearer reached the wrong origin")
	}
}

func TestDialGuard(t *testing.T) {
	for _, a := range []string{"169.254.169.254:80", "[fe80::1]:443", "[fd00:ec2::254]:80", "0.0.0.0:443", "224.0.0.1:80", "[::ffff:169.254.169.254]:80", "nohost"} {
		if DialGuard("tcp", a, nil) == nil {
			t.Fatalf("allowed %s", a)
		}
	}
	for _, a := range []string{"127.0.0.1:3003", "[::1]:80", "10.0.0.5:443", "93.184.216.34:443"} {
		if err := DialGuard("tcp", a, nil); err != nil {
			t.Fatalf("refused %s: %v", a, err)
		}
	}
	// The guard is on the real transport: a numeric metadata host is refused
	// at dial time even when the URL checks are bypassed.
	hc := NewHTTPClient(nil, 2*time.Second)
	for _, u := range []string{"http://169.254.169.254/latest/meta-data/", "http://[fe80::1]/", "http://0.0.0.0:1/"} {
		resp, err := hc.Get(u)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("dialed %s", u)
		}
		if !strings.Contains(err.Error(), "dial_refused") {
			t.Fatalf("%s: %v", u, err)
		}
	}
}

func TestTicketRateLimited(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
	}))
	defer srv.Close()
	base, _ := ValidateBase(srv.URL)
	c := &Client{Base: base, Auth: Auth{APIKey: "KEY-SENTINEL"}}
	_, err := c.Ticket(context.Background(), "h-1", PurposeOpen)
	var te *TicketError
	if !errors.As(err, &te) || te.Code != "rate_limited" || err.Error() != "too many terminal requests for this host; try again shortly" {
		t.Fatalf("429: %v", err)
	}
	if calls != 1 {
		t.Fatalf("retried: %d calls", calls)
	}
}
