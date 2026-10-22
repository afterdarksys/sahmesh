package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateBase(t *testing.T) {
	if _, err := ValidateBase("https://cp.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateBase("http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateBase("http://localhost:3000"); err != nil {
		t.Fatal(err)
	}
	bad := []string{
		"http://cp.example",
		"https://user:pass@cp.example",
		"https://cp.example/api",
		"https://cp.example?api_key=secret",
		"https://169.254.169.254",
		"https://metadata.google.internal",
		"ftp://127.0.0.1",
		"",
	}
	for _, raw := range bad {
		if _, err := ValidateBase(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestQueryAndPath(t *testing.T) {
	if err := ValidQuery("limit=1"); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"api_key=secret", "access_token=abc", "token=abc", "device_code=abc", "API_KEY=secret"} {
		if err := ValidQuery(q); err == nil {
			t.Fatalf("accepted query %s", q)
		}
	}
	if ValidPath("/api/v1/fleet") != true {
		t.Fatal("fleet path")
	}
	for _, p := range []string{"api", "/../etc/passwd", "/a//b", "http://evil/x", "/a?api_key=1"} {
		if ValidPath(p) {
			t.Fatalf("accepted path %s", p)
		}
	}
}

func TestDoSendsKeyHeaderAndRefusesRedirect(t *testing.T) {
	const key = "SENTINELKEY1234567890"
	var sawQuery, sawKey string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawQuery = r.URL.RawQuery
		sawKey = r.Header.Get("X-API-Key")
		if r.URL.Path == "/go" {
			http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()
	base, err := ValidateBase(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	status, body, err := Do(context.Background(), base, key, "GET", "/api/v1/fleet", "limit=1&api_key=nope", nil)
	if err == nil {
		t.Fatal("api_key query was sent")
	}
	if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "nope") {
		t.Fatalf("error leaked secret: %v", err)
	}
	status, body, err = Do(context.Background(), base, key, "GET", "/api/v1/fleet", "limit=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 || string(body) != `{"ok":true}` {
		t.Fatalf("status %d body %s", status, body)
	}
	if sawKey != key {
		t.Fatal("key header missing")
	}
	if sawQuery != "limit=1" {
		t.Fatalf("query %q", sawQuery)
	}
	_, _, err = Do(context.Background(), base, key, "GET", "/go", "", nil)
	if err == nil || err.Error() != "redirect_denied" {
		t.Fatalf("redirect err %v", err)
	}
	if strings.Contains(err.Error(), key) {
		t.Fatal("redirect error leaked key")
	}
	huge := make([]byte, maxBody+1)
	if _, _, err := Do(context.Background(), base, key, "POST", "/api/v1/fleet", "", huge); err == nil || err.Error() != "too_large" {
		t.Fatalf("oversize %v", err)
	}
	if _, _, err := Do(context.Background(), base, "bad key", "GET", "/api/v1/fleet", "", nil); err == nil {
		t.Fatal("whitespace key accepted")
	}
	if _, _, err := Do(context.Background(), base, key, "CONNECT", "/api/v1/fleet", "", nil); err == nil || err.Error() != "bad_method" {
		t.Fatalf("method %v", err)
	}
}
