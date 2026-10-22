package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Purposes a terminal ticket may carry (terminal protocol §2).
const (
	PurposeOpen = "terminal:open"
	PurposeRoot = "terminal:root"
)

var (
	hostNameRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)
	errorCodeRE = regexp.MustCompile(`^[a-z_]{1,64}$`)
)

// ValidHostName mirrors the server's resolve rule: 1-253 characters from
// [A-Za-z0-9._-]. It also gates host_id values before they enter a URL path.
func ValidHostName(name string) bool { return hostNameRE.MatchString(name) }

// Host is the resolve answer.
type Host struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Tenant   string `json:"tenant"`
	Status   string `json:"status"`
}

// ResolveError carries the server's refusal. Matches is set for ambiguous.
type ResolveError struct {
	Code    string
	Status  int
	Matches int
}

func (e *ResolveError) Error() string {
	switch e.Code {
	case "not_found":
		return "host not found"
	case "ambiguous":
		return fmt.Sprintf("host name is ambiguous (%d matches); use the host_id", e.Matches)
	case "invalid_name":
		return "invalid host name"
	}
	return statusText(e.Status)
}

func statusText(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "unauthorized (run sahconnect login, or set SYSTEMAPI_API_KEY)"
	case http.StatusForbidden:
		return "forbidden (the credential lacks the scope, or the token expired: run sahconnect login)"
	}
	return "unexpected_status " + strconv.Itoa(status)
}

type errBody struct {
	Error   string `json:"error"`
	Matches int    `json:"matches"`
}

// Resolve maps a name or host_id to exactly one host.
func (c *Client) Resolve(ctx context.Context, name string) (*Host, error) {
	if !ValidHostName(name) {
		return nil, &ResolveError{Code: "invalid_name", Status: http.StatusBadRequest}
	}
	status, body, err := c.Do(ctx, http.MethodGet, "/api/v1/hosts/resolve", "name="+url.QueryEscape(name), nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		var h Host
		if json.Unmarshal(body, &h) != nil || !ValidHostName(h.HostID) {
			return nil, code("bad_response")
		}
		return &h, nil
	case http.StatusNotFound, http.StatusConflict, http.StatusBadRequest:
		var eb errBody
		_ = json.Unmarshal(body, &eb) // the status alone decides; the body only adds detail
		refusal := map[int]string{404: "not_found", 409: "ambiguous", 400: "invalid_name"}[status]
		return nil, &ResolveError{Code: refusal, Status: status, Matches: eb.Matches}
	}
	return nil, &ResolveError{Status: status}
}

// Ticket is the single-use terminal ticket. It is a secret for 60 s: it goes
// only into the terminal URL and is never printed.
type Ticket struct {
	Value string
}

// TicketError is a refused ticket request.
type TicketError struct {
	Status int
	Code   string
}

func (e *TicketError) Error() string {
	if e.Status == http.StatusTooManyRequests {
		// Contract §2: 429 rate_limited. Reported once; the caller does not retry.
		return "too many terminal requests for this host; try again shortly"
	}
	if e.Code != "" && e.Status != http.StatusUnauthorized {
		return "ticket refused: " + e.Code + " (" + statusText(e.Status) + ")"
	}
	return "ticket refused: " + statusText(e.Status)
}

// Ticket requests a terminal ticket for one host and purpose.
func (c *Client) Ticket(ctx context.Context, hostID, purpose string) (*Ticket, error) {
	if !ValidHostName(hostID) {
		return nil, code("invalid_host_id")
	}
	if purpose != PurposeOpen && purpose != PurposeRoot {
		return nil, code("invalid_purpose")
	}
	req, _ := json.Marshal(map[string]string{"host_id": hostID, "purpose": purpose})
	status, body, err := c.Do(ctx, http.MethodPost, "/api/v1/ws-ticket", "", req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		var eb errBody
		_ = json.Unmarshal(body, &eb) // detail only; the status already refused
		if !errorCodeRE.MatchString(eb.Error) {
			eb.Error = ""
		}
		return nil, &TicketError{Status: status, Code: eb.Error}
	}
	var out struct {
		Ticket string `json:"ticket"`
	}
	if json.Unmarshal(body, &out) != nil || !validSecret(out.Ticket) {
		return nil, code("bad_response")
	}
	// expires_at is not checked: the server enforces the 60 s lifetime, and a
	// local check would only add clock-skew failures.
	return &Ticket{Value: out.Ticket}, nil
}

// TerminalURL builds the terminal WebSocket URL from a validated base. https
// maps to wss; http (loopback only, by ValidateBase) maps to ws. The ticket is
// the only secret in the query. The result is re-checked by ValidateWS.
func TerminalURL(base *url.URL, hostID, ticket, purpose string, rows, cols int) (*url.URL, error) {
	if base == nil {
		return nil, code("invalid_url")
	}
	if !ValidHostName(hostID) {
		return nil, code("invalid_host_id")
	}
	if !validSecret(ticket) {
		return nil, code("invalid_ticket")
	}
	if purpose != PurposeOpen && purpose != PurposeRoot {
		return nil, code("invalid_purpose")
	}
	u := *base
	switch base.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return nil, code("invalid_url")
	}
	u.Path = "/api/v1/systems/terminal/" + hostID
	q := url.Values{}
	q.Set("ticket", ticket)
	q.Set("purpose", purpose)
	if rows >= 1 && rows <= 1000 && cols >= 1 && cols <= 1000 {
		q.Set("rows", strconv.Itoa(rows))
		q.Set("cols", strconv.Itoa(cols))
	}
	u.RawQuery = q.Encode()
	u.User = nil
	u.Fragment = ""
	if err := ValidateWS(&u); err != nil {
		return nil, err
	}
	return &u, nil
}

// ValidateWS applies the HTTP guards to a WebSocket URL: wss anywhere, ws only
// to loopback, no userinfo, no metadata or link-local host.
func ValidateWS(u *url.URL) error {
	if u == nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return code("invalid_url")
	}
	if strings.ContainsAny(u.Host, " \t\r\n") {
		return code("invalid_url")
	}
	switch u.Scheme {
	case "wss":
	case "ws":
		if !loopback(u.Hostname()) {
			return code("invalid_url")
		}
	default:
		return code("invalid_url")
	}
	if badName(u.Hostname()) {
		return code("invalid_url")
	}
	return nil
}
