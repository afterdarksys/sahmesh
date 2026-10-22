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
)

func meshAPI(t *testing.T, bodies *[]string, status int, reply string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*bodies = append(*bodies, r.Method+" "+r.URL.Path+" "+string(b))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	base, err := ValidateBase(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{Base: base, Auth: Auth{APIKey: "k-0123456789abcdef"}, HTTP: srv.Client()}
}

func TestMeshTicketBodyAndResponse(t *testing.T) {
	var bodies []string
	c := meshAPI(t, &bodies, 200, `{"ticket":"stk_mesh1","expires_at":"2026-10-22T12:00:00Z","expires_in":60,"host_id":"h-0001","purpose":"mesh:open"}`)
	tk, err := c.MeshTicket(context.Background(), "h-0001")
	if err != nil {
		t.Fatal(err)
	}
	if tk.Value != "stk_mesh1" {
		t.Fatalf("ticket %q", tk.Value)
	}
	if len(bodies) != 1 || !strings.HasPrefix(bodies[0], "POST /api/v1/ws-ticket ") {
		t.Fatalf("requests %v", bodies)
	}
	var req map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(bodies[0], "POST /api/v1/ws-ticket ")), &req); err != nil {
		t.Fatal(err)
	}
	if req["host_id"] != "h-0001" || req["purpose"] != "mesh:open" || len(req) != 2 {
		t.Fatalf("body %v", req)
	}
}

func TestMeshTicketRefusals(t *testing.T) {
	cases := []struct {
		status int
		reply  string
		code   string
	}{
		{403, `{"error":"scope_denied"}`, "scope_denied"},
		{429, `{"error":"rate_limited"}`, "rate_limited"},
		{404, `{"error":"not_found"}`, "not_found"},
		{403, `{"error":"<b>html</b>"}`, ""},
	}
	for _, tc := range cases {
		var bodies []string
		c := meshAPI(t, &bodies, tc.status, tc.reply)
		_, err := c.MeshTicket(context.Background(), "h-0001")
		var te *TicketError
		if !errors.As(err, &te) || te.Status != tc.status || te.Code != tc.code {
			t.Fatalf("status %d: got %v", tc.status, err)
		}
	}
}

func TestMeshTicketBadResponses(t *testing.T) {
	cases := []string{
		`{"ticket":"stk_x","host_id":"h-0002","purpose":"mesh:open","expires_in":60}`,
		`{"ticket":"stk_x","host_id":"h-0001","purpose":"tcp:open","expires_in":60}`,
		`{"ticket":"stk_x","host_id":"h-0001","purpose":"mesh:open","expires_in":600}`,
		`{"ticket":"","host_id":"h-0001","purpose":"mesh:open"}`,
		`{"ticket":"bad ticket","host_id":"h-0001","purpose":"mesh:open"}`,
		`not json`,
	}
	for _, reply := range cases {
		var bodies []string
		c := meshAPI(t, &bodies, 200, reply)
		_, err := c.MeshTicket(context.Background(), "h-0001")
		var ce *Error
		if !errors.As(err, &ce) || ce.Code != "bad_response" {
			t.Fatalf("reply %s: got %v", reply, err)
		}
	}
	var bodies []string
	c := meshAPI(t, &bodies, 200, `{}`)
	if _, err := c.MeshTicket(context.Background(), "../x"); err == nil || len(bodies) != 0 {
		t.Fatalf("bad host id must not reach the server: %v %v", err, bodies)
	}
}

func TestMeshURL(t *testing.T) {
	base, _ := url.Parse("https://sah.example")
	u, err := MeshURL(base, "h-0001", "stk_abc")
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "wss" || u.Path != "/api/v1/systems/mesh/h-0001" {
		t.Fatalf("url %s", u)
	}
	q := u.Query()
	if q.Get("ticket") != "stk_abc" || q.Get("purpose") != PurposeMesh || len(q) != 2 {
		t.Fatalf("query %v", q)
	}
	loop, _ := url.Parse("http://127.0.0.1:8080")
	if u, err := MeshURL(loop, "h-0001", "stk_abc"); err != nil || u.Scheme != "ws" {
		t.Fatalf("loopback http: %v %v", u, err)
	}
	plain, _ := url.Parse("http://sah.example")
	if _, err := MeshURL(plain, "h-0001", "stk_abc"); err == nil {
		t.Fatal("plain http off loopback must be refused")
	}
	if _, err := MeshURL(base, "../x", "stk_abc"); err == nil {
		t.Fatal("bad host id")
	}
	if _, err := MeshURL(base, "h-0001", "bad ticket"); err == nil {
		t.Fatal("bad ticket")
	}
	if _, err := MeshURL(nil, "h-0001", "stk_abc"); err == nil {
		t.Fatal("nil base")
	}
}
