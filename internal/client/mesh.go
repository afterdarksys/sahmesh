package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// PurposeMesh is the only purpose sahmesh requests (mesh contract §2).
const PurposeMesh = "mesh:open"

// MeshTicket requests one single-use mesh:open ticket bound to the host. No
// target is sent: each stream names its own at mesh_open. The ticket value
// goes only into the WebSocket query and is never printed.
func (c *Client) MeshTicket(ctx context.Context, hostID string) (*Ticket, error) {
	if c == nil || c.Base == nil {
		return nil, code("invalid_url")
	}
	if !ValidHostName(hostID) {
		return nil, code("invalid_host_id")
	}
	req, err := json.Marshal(struct {
		HostID  string `json:"host_id"`
		Purpose string `json:"purpose"`
	}{HostID: hostID, Purpose: PurposeMesh})
	if err != nil {
		return nil, code("bad_request")
	}
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
		Ticket    string `json:"ticket"`
		HostID    string `json:"host_id"`
		Purpose   string `json:"purpose"`
		ExpiresIn *int   `json:"expires_in"`
	}
	if json.Unmarshal(body, &out) != nil || !validSecret(out.Ticket) {
		return nil, code("bad_response")
	}
	if out.HostID != hostID || out.Purpose != PurposeMesh {
		return nil, code("bad_response")
	}
	if out.ExpiresIn != nil && *out.ExpiresIn != 60 {
		return nil, code("bad_response")
	}
	return &Ticket{Value: out.Ticket}, nil
}

// MeshURL builds the mesh WebSocket URL. The ticket is the only query secret.
func MeshURL(base *url.URL, hostID, ticket string) (*url.URL, error) {
	if base == nil {
		return nil, code("invalid_url")
	}
	if !ValidHostName(hostID) {
		return nil, code("invalid_host_id")
	}
	if !validSecret(ticket) {
		return nil, code("invalid_ticket")
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
	u.Path = "/api/v1/systems/mesh/" + hostID
	q := url.Values{}
	q.Set("ticket", ticket)
	q.Set("purpose", PurposeMesh)
	u.RawQuery = q.Encode()
	u.User = nil
	u.Fragment = ""
	if err := ValidateWS(&u); err != nil {
		return nil, err
	}
	for key := range q {
		switch key {
		case "ticket", "purpose":
		default:
			return nil, code("invalid_query")
		}
	}
	return &u, nil
}
