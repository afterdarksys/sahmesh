// Package target decides whether a TCP target may be sent to SystemAPI.
//
// Threats: a forward is an SSRF pivot from the operator's session into
// whatever the agent can dial. Phase 0 of the TCP contract allows only the
// spelling "local" (the agent dials 127.0.0.1) or an IP literal. DNS names
// are refused so a rebinding name never reaches the server. Loopback literals
// are refused because "local" is the only loopback spelling. The address
// classes in sah-tcp-protocol.md §4 are refused here as well as on the
// server; this package does not replace the server check. No policy override
// exists in the client. Does NOT decide server allowlists or the agent
// allowlist; those come back as target_denied and target_denied_agent.
package target

import (
	"net"
	"strings"
)

// Codes are the contract's refusal names. Callers print the code and do not
// attach the address to a credential error.
const (
	CodeBad       = "bad_target"
	CodeForbidden = "target_forbidden"
)

// Error is a target the client will not send.
type Error struct{ Code string }

func (e *Error) Error() string {
	if e == nil || e.Code == "" {
		return CodeBad
	}
	return e.Code
}

func bad() error       { return &Error{Code: CodeBad} }
func forbidden() error { return &Error{Code: CodeForbidden} }

// Check accepts "local" or an IP literal the contract allows the agent to dial.
// host has no brackets and no zone id. IPv4-mapped IPv6 is normalized to IPv4
// before the checks.
func Check(host string) error {
	if host == "local" {
		return nil
	}
	if host == "" || len(host) > 253 {
		return bad()
	}
	if strings.Contains(host, "%") || strings.Contains(host, "/") || strings.Contains(host, "[") || strings.Contains(host, "]") || strings.Contains(host, " ") {
		return bad()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return bad()
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() {
		return bad()
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0:
			return forbidden()
		case v4[0] == 169 && v4[1] == 254:
			return forbidden()
		case v4[0] >= 224 && v4[0] <= 239:
			return forbidden()
		case v4[0] >= 240:
			return forbidden()
		case v4[0] == 100 && v4[1] == 100 && v4[2] == 100 && v4[3] == 200:
			return forbidden()
		}
		return nil
	}
	if ip.Equal(net.ParseIP("fd00:ec2::254")) || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return forbidden()
	}
	return nil
}
