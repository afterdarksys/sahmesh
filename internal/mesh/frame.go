// Package mesh is the sahmesh client for sah-mesh-protocol.md: one WebSocket
// per host carrying many TCP streams.
//
// Threats: a server (or a man in the middle that the TLS layer did not stop)
// sending more than the credit this client granted, reusing or inventing
// stream ids, or sending frames out of their allowed order. Every such
// violation (contract §3.2, mirrored for the server's side) drops the whole
// session with protocol_error and fails every stream. Inbound bytes per
// stream are bounded by the credit window, so a local application that stops
// reading stalls only its own stream and never the socket's read loop. Bytes
// go out only after connected, never after a local EOF, and only inside the
// server's credit. Payloads stay at or under 64 KiB. Tickets and WebSocket
// URLs never appear in errors or log lines; a dial error says what failed,
// not where. Does NOT verify leases, inspect content, resolve names, or
// open any listener; the agent and the server enforce policy.
package mesh

import "encoding/binary"

// MaxPayload is the largest binary payload on any hop (contract §3.1).
const MaxPayload = 64 << 10

// DefaultWindow is the per-stream credit window per direction (§6). The
// server announces the value it uses in mesh_ready.
const DefaultWindow = 256 << 10

const idLen = 4

// StatusError is a contract error code or close reason other than closed.
type StatusError struct{ Code string }

func (e *StatusError) Error() string {
	if e == nil || e.Code == "" {
		return "internal"
	}
	return e.Code
}

// EncodeData builds one binary frame: 4-byte big-endian stream id, then the
// payload. p must be at most MaxPayload; callers split before encoding.
func EncodeData(id uint32, p []byte) []byte {
	out := make([]byte, idLen+len(p))
	binary.BigEndian.PutUint32(out, id)
	copy(out[idLen:], p)
	return out
}

// DecodeData splits one binary frame. ok is false for a frame shorter than
// the id, an id of zero, or a payload over MaxPayload. The returned payload
// aliases b.
func DecodeData(b []byte) (id uint32, p []byte, ok bool) {
	if len(b) < idLen || len(b)-idLen > MaxPayload {
		return 0, nil, false
	}
	id = binary.BigEndian.Uint32(b)
	if id == 0 {
		return 0, nil, false
	}
	return id, b[idLen:], true
}

// Text frames (contract §3.1). One struct covers every shape; unused fields
// stay zero.
type frame struct {
	Type    string   `json:"type"`
	Stream  *uint64  `json:"stream,omitempty"`
	Target  *target  `json:"target,omitempty"`
	Bytes   *int64   `json:"bytes,omitempty"`
	Payload *payload `json:"payload,omitempty"`
}

type target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type payload struct {
	Status    string `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Peer      string `json:"peer,omitempty"`
	Reason    string `json:"reason,omitempty"`
	BytesIn   int64  `json:"bytes_in"`
	BytesOut  int64  `json:"bytes_out"`
	Window    int64  `json:"window,omitempty"`
	Streams   int64  `json:"streams,omitempty"`
}
