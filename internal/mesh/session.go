package mesh

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	defaultHandshakeWait = 30 * time.Second
	defaultPingEvery     = 30 * time.Second
	defaultPingWait      = 10 * time.Second
	// MinWindow and MaxWindow bound the per-stream window a server may
	// announce in mesh_ready. Outside the range is protocol_error.
	MinWindow   = 4 << 10
	MaxWindow   = 1 << 20
	maxStreamID = 1<<32 - 1
)

// CloseInfo reports the end of a stream that had reached connected, from
// the client's point of view. A stream that never connected reports its
// failure to the Open caller instead.
type CloseInfo struct {
	Stream    uint32
	SessionID string // the stream's tcs_ id
	Reason    string // a close reason or an error code
	BytesIn   int64
	BytesOut  int64
}

// Options controls one session.
type Options struct {
	// OnClose is called once per connected stream the server ended or
	// failed. It is not called for a stream the client closed itself, nor
	// for one that never reached connected.
	OnClose func(CloseInfo)
	// Log receives one line per ignored frame type (contract §3.2), once
	// per type per session. The argument is the sanitized type name.
	Log func(ignoredType string)
	// HandshakeWait bounds the WebSocket dial, mesh_ready, each stream's
	// connected wait, and each socket write. Zero is 30 s.
	HandshakeWait time.Duration
	// PingEvery and PingWait drive the liveness ping: one ping every
	// PingEvery (zero: 30 s) that must be answered within PingWait (zero:
	// 10 s), else the session ends with internal.
	PingEvery time.Duration
	PingWait  time.Duration
}

func (o Options) wait() time.Duration {
	if o.HandshakeWait <= 0 {
		return defaultHandshakeWait
	}
	return o.HandshakeWait
}

func (o Options) pingEvery() time.Duration {
	if o.PingEvery <= 0 {
		return defaultPingEvery
	}
	return o.PingEvery
}

func (o Options) pingWait() time.Duration {
	if o.PingWait <= 0 {
		return defaultPingWait
	}
	return o.PingWait
}

// Session is one mesh:open WebSocket to one host.
type Session struct {
	conn   *websocket.Conn
	id     string
	window int
	opt    Options
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	streams map[uint32]*Stream
	last    uint32 // the highest stream id opened in this session
	ended   bool
	endCode string
	ignored map[string]bool
	done    chan struct{}
	endOnce sync.Once
	// writeMu orders every frame on the socket. Open allocates the stream
	// id while holding it, so ids leave strictly increasing.
	writeMu sync.Mutex
}

// Dial opens the socket, waits for mesh_ready, and starts the read loop.
// Errors never contain the URL or the ticket.
func Dial(ctx context.Context, wsURL string, httpClient *http.Client, opt Options) (*Session, error) {
	if httpClient == nil || wsURL == "" {
		return nil, &StatusError{Code: "internal"}
	}
	hctx, hcancel := context.WithTimeout(ctx, opt.wait())
	conn, resp, err := websocket.Dial(hctx, wsURL, &websocket.DialOptions{HTTPClient: httpClient})
	hcancel()
	if err != nil {
		return nil, dialError(resp, err)
	}
	conn.SetReadLimit(MaxPayload + idLen)
	rctx, rcancel := context.WithTimeout(ctx, opt.wait())
	typ, data, err := conn.Read(rctx)
	rcancel()
	if err != nil {
		conn.CloseNow()
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, &StatusError{Code: "connect_timeout"}
		}
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		return nil, &StatusError{Code: "protocol_error"}
	}
	var f frame
	if typ != websocket.MessageText || len(data) > MaxPayload || json.Unmarshal(data, &f) != nil || f.Type == "" {
		_ = conn.Close(websocket.StatusProtocolError, "protocol_error")
		return nil, &StatusError{Code: "protocol_error"}
	}
	if f.Type == "mesh_status" && f.Stream == nil && f.Payload != nil && f.Payload.Error != "" {
		conn.CloseNow()
		return nil, &StatusError{Code: safeCode(f.Payload.Error)}
	}
	if f.Type != "mesh_ready" || f.Payload == nil || !validSessionID(f.Payload.SessionID, "msh_") ||
		f.Payload.Window < MinWindow || f.Payload.Window > MaxWindow {
		_ = conn.Close(websocket.StatusProtocolError, "protocol_error")
		return nil, &StatusError{Code: "protocol_error"}
	}
	sctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		conn:    conn,
		id:      f.Payload.SessionID,
		window:  int(f.Payload.Window),
		opt:     opt,
		ctx:     sctx,
		cancel:  cancel,
		streams: map[uint32]*Stream{},
		ignored: map[string]bool{},
		done:    make(chan struct{}),
	}
	go s.readLoop()
	go s.pingLoop()
	return s, nil
}

// ID is the msh_ session id. It is not a secret.
func (s *Session) ID() string { return s.id }

// Window is the per-stream credit window the server announced.
func (s *Session) Window() int { return s.window }

// Done is closed when the session has ended for any reason.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err is the session's end code once Done is closed: a *StatusError, or nil
// after Close.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ended || s.endCode == "" {
		return nil
	}
	return &StatusError{Code: s.endCode}
}

// Open opens one stream to target host:port and waits for connected. host
// is "local" or an IP literal; the server validates it. A refused stream
// returns a *StatusError with the contract code.
func (s *Session) Open(ctx context.Context, host string, port int) (*Stream, error) {
	if host == "" || len(host) > 64 || port < 1 || port > 65535 {
		return nil, &StatusError{Code: "bad_target"}
	}
	// The id is allocated and the frame written under one lock, so a
	// concurrent Open cannot put a higher id on the wire first.
	s.writeMu.Lock()
	s.mu.Lock()
	if s.ended {
		code := s.endCode
		s.mu.Unlock()
		s.writeMu.Unlock()
		if code == "" {
			code = "stopped"
		}
		return nil, &StatusError{Code: code}
	}
	if s.last >= maxStreamID {
		s.mu.Unlock()
		s.writeMu.Unlock()
		return nil, &StatusError{Code: "cap_reached"}
	}
	s.last++
	id := s.last
	st := newStream(s, id)
	s.streams[id] = st
	s.mu.Unlock()
	err := s.writeTextLocked(frame{Type: "mesh_open", Stream: u64(id), Target: &target{Host: host, Port: port}})
	s.writeMu.Unlock()
	if err != nil {
		s.remove(id)
		s.end("internal", false)
		return nil, s.endedOr("internal")
	}
	timer := time.NewTimer(s.opt.wait())
	defer timer.Stop()
	select {
	case <-st.connCh:
	case <-ctx.Done():
		st.abandon()
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.endedOr("internal")
	case <-timer.C:
		st.abandon()
		// A silent server may be a half-open socket: prove it is alive or
		// end the session so the next stream re-dials.
		go s.ping()
		return nil, &StatusError{Code: "connect_timeout"}
	}
	st.mu.Lock()
	code := st.failCode
	st.mu.Unlock()
	if code != "" {
		return nil, &StatusError{Code: code}
	}
	return st, nil
}

// Close ends the session in order: every live stream is closed (the server
// sees mesh_close for each) and the socket is closed normally.
func (s *Session) Close() error {
	s.mu.Lock()
	live := make([]*Stream, 0, len(s.streams))
	for _, st := range s.streams {
		live = append(live, st)
	}
	s.mu.Unlock()
	for _, st := range live {
		_ = st.Close()
	}
	s.end("", false)
	return nil
}

func (s *Session) endedOr(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended && s.endCode != "" {
		return &StatusError{Code: s.endCode}
	}
	return &StatusError{Code: code}
}

func (s *Session) lookup(id uint32) (st *Stream, known bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st = s.streams[id]
	return st, id <= s.last
}

func (s *Session) remove(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// writeTextLocked writes one text frame; the caller holds writeMu.
func (s *Session) writeTextLocked(f frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(s.ctx, s.opt.wait())
	defer cancel()
	return s.conn.Write(wctx, websocket.MessageText, b)
}

func (s *Session) writeText(f frame) error {
	s.writeMu.Lock()
	err := s.writeTextLocked(f)
	s.writeMu.Unlock()
	if err != nil && s.ctx.Err() == nil {
		// A write that fails or times out leaves the socket in an unknown
		// state. End the session so nothing waits on it.
		s.end("internal", false)
	}
	return err
}

// writeBinary writes one data frame within deadline (zero: the handshake
// wait). A failed or timed-out write ends the session.
func (s *Session) writeBinary(deadline time.Time, b []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var wctx context.Context
	var cancel context.CancelFunc
	if deadline.IsZero() {
		wctx, cancel = context.WithTimeout(s.ctx, s.opt.wait())
	} else {
		wctx, cancel = context.WithDeadline(s.ctx, deadline)
	}
	defer cancel()
	err := s.conn.Write(wctx, websocket.MessageBinary, b)
	if err != nil && s.ctx.Err() == nil {
		s.end("internal", false)
	}
	return err
}

// ping proves the peer is alive within PingWait, else ends the session.
func (s *Session) ping() {
	pctx, cancel := context.WithTimeout(s.ctx, s.opt.pingWait())
	defer cancel()
	if err := s.conn.Ping(pctx); err != nil && s.ctx.Err() == nil {
		s.end("internal", false)
	}
}

func (s *Session) pingLoop() {
	t := time.NewTicker(s.opt.pingEvery())
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.ping()
		}
	}
}

// end finishes the session once. code "" is an orderly client close.
func (s *Session) end(code string, violation bool) {
	s.endOnce.Do(func() {
		s.mu.Lock()
		s.ended = true
		s.endCode = code
		live := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			live = append(live, st)
		}
		s.streams = map[uint32]*Stream{}
		s.mu.Unlock()
		failCode := code
		if failCode == "" {
			failCode = "client_closed"
		}
		for _, st := range live {
			st.fail(failCode, false)
		}
		switch {
		case violation:
			_ = s.conn.Close(websocket.StatusProtocolError, "protocol_error")
		case code == "":
			_ = s.conn.Close(websocket.StatusNormalClosure, "")
		default:
			s.conn.CloseNow()
		}
		s.cancel()
		close(s.done)
	})
}

func (s *Session) protocolError() {
	s.end("protocol_error", true)
}

func (s *Session) readLoop() {
	for {
		typ, data, err := s.conn.Read(s.ctx)
		if err != nil {
			// A socket that closes without mesh_end is a failure; a close
			// after mesh_end or Close is already recorded.
			s.end("internal", false)
			return
		}
		switch typ {
		case websocket.MessageBinary:
			s.onData(data)
		case websocket.MessageText:
			s.onText(data)
		default:
			s.protocolError()
		}
		select {
		case <-s.done:
			return
		default:
		}
	}
}

func (s *Session) onData(data []byte) {
	id, p, ok := DecodeData(data)
	if !ok {
		s.protocolError()
		return
	}
	st, known := s.lookup(id)
	if st == nil {
		if !known {
			s.protocolError()
		}
		return // a frame for a stream that has since closed
	}
	if !st.push(p) {
		s.protocolError()
	}
}

// knownTypes are the text frames this client decodes. Anything else is
// ignored and logged once per type (contract §3.2).
var knownTypes = map[string]bool{
	"mesh_status": true, "mesh_eof": true, "mesh_close": true, "mesh_credit": true, "mesh_end": true,
}

func (s *Session) onText(data []byte) {
	if len(data) > MaxPayload {
		s.protocolError()
		return
	}
	// Decode the type alone first, so an unknown frame with any payload
	// shape is skipped rather than refused.
	var head struct {
		Type *string `json:"type"`
	}
	if err := json.Unmarshal(data, &head); err != nil || head.Type == nil {
		s.protocolError()
		return
	}
	if !knownTypes[*head.Type] {
		s.ignore(*head.Type)
		return
	}
	var f frame
	if json.Unmarshal(data, &f) != nil {
		s.protocolError()
		return
	}
	pl := f.Payload
	if pl == nil {
		pl = &payload{}
	}
	if f.Type == "mesh_end" {
		s.end(safeCode(firstNonEmpty(pl.Reason, "stopped")), false)
		return
	}
	if f.Type == "mesh_status" && f.Stream == nil {
		s.end(safeCode(firstNonEmpty(pl.Error, "internal")), false)
		return
	}
	if f.Stream == nil || *f.Stream < 1 || *f.Stream > maxStreamID {
		s.protocolError()
		return
	}
	id := uint32(*f.Stream)
	st, known := s.lookup(id)
	if st == nil {
		if !known {
			s.protocolError()
		}
		return
	}
	switch f.Type {
	case "mesh_status":
		switch {
		case pl.Error != "":
			st.fail(safeCode(pl.Error), true)
		case pl.Status == "connecting":
		case pl.Status == "connected":
			if !validSessionID(pl.SessionID, "tcs_") || !st.connected(pl.SessionID, pl.Peer) {
				s.protocolError()
			}
		default:
			s.protocolError()
		}
	case "mesh_eof":
		st.remoteEOF()
	case "mesh_close":
		st.closedByServer(safeCode(firstNonEmpty(pl.Reason, "closed")), pl.SessionID, pl.BytesIn, pl.BytesOut)
	case "mesh_credit":
		if f.Bytes == nil || *f.Bytes <= 0 || *f.Bytes > MaxWindow || !st.grant(int(*f.Bytes)) {
			s.protocolError()
		}
	}
}

// ignore logs an unknown frame type once per session. The name is reduced
// to printable [A-Za-z0-9_] and 32 bytes before it reaches a log line.
func (s *Session) ignore(typ string) {
	name := sanitizeType(typ)
	s.mu.Lock()
	seen := s.ignored[name]
	s.ignored[name] = true
	s.mu.Unlock()
	if !seen && s.opt.Log != nil {
		s.opt.Log(name)
	}
}

func sanitizeType(t string) string {
	out := make([]byte, 0, 32)
	for i := 0; i < len(t) && len(out) < 32; i++ {
		c := t[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
			out = append(out, c)
		default:
			out = append(out, '?')
		}
	}
	if len(out) == 0 {
		return "empty"
	}
	return string(out)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func u64(id uint32) *uint64 {
	v := uint64(id)
	return &v
}

func validSessionID(s, prefix string) bool {
	if len(s) < len(prefix)+16 || len(s) > len(prefix)+64 || s[:len(prefix)] != prefix {
		return false
	}
	for _, c := range s[len(prefix):] {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// safeCode keeps a server code printable: lowercase and underscore only.
func safeCode(s string) string {
	if len(s) == 0 || len(s) > 64 {
		return "protocol_error"
	}
	for _, c := range s {
		if c != '_' && (c < 'a' || c > 'z') {
			return "protocol_error"
		}
	}
	return s
}

// dialError describes a failed WebSocket dial without the URL or ticket.
func dialError(resp *http.Response, err error) error {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}
	if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("mesh handshake refused (HTTP %d)", resp.StatusCode)
	}
	var cv *tls.CertificateVerificationError
	if errors.As(err, &cv) {
		return errors.New("mesh connection failed: TLS certificate verification failed")
	}
	var rh tls.RecordHeaderError
	if errors.As(err, &rh) {
		return errors.New("mesh connection failed: TLS handshake failed")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("mesh connection failed: handshake timed out")
	}
	if errors.Is(err, context.Canceled) {
		// The library's error wraps the URL, which carries the ticket.
		return context.Canceled
	}
	return errors.New("mesh connection failed")
}
