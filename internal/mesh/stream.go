package mesh

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Stream is one TCP stream inside a session. It is a net.Conn: Read and
// Write may be called from different goroutines; Close may be called at
// any time.
type Stream struct {
	s  *Session
	id uint32

	mu        sync.Mutex
	cond      *sync.Cond
	writeMu   sync.Mutex // keeps one Write's chunks in order
	sessionID string
	peer      string
	isConn    bool
	connCh    chan struct{}
	connOnce  sync.Once
	failCode  string // set when the server refused or ended the stream with an error
	queue     [][]byte
	inCredit  *Credit // what we granted the server (server -> client)
	outCredit *Credit // what the server granted us (client -> server)
	remEOF    bool
	locEOF    bool
	closed    bool
	byClient  bool
	bytesIn   int64
	bytesOut  int64
	rdl, wdl  time.Time
	rtimer    *time.Timer
	wtimer    *time.Timer
}

func newStream(s *Session, id uint32) *Stream {
	st := &Stream{
		s:         s,
		id:        id,
		connCh:    make(chan struct{}),
		inCredit:  NewCredit(s.window),
		outCredit: NewCredit(s.window),
	}
	st.cond = sync.NewCond(&st.mu)
	return st
}

// ID is the client-chosen stream id.
func (st *Stream) ID() uint32 { return st.id }

// SessionID is the stream's tcs_ id, "" before connected.
func (st *Stream) SessionID() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.sessionID
}

// Peer is the address the agent dialed, "" before connected.
func (st *Stream) Peer() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.peer
}

func (st *Stream) signalConn() { st.connOnce.Do(func() { close(st.connCh) }) }

// connected records the server's connected frame. False when it repeats.
func (st *Stream) connected(sessionID, peer string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.isConn {
		return false
	}
	st.isConn = true
	st.sessionID = sessionID
	st.peer = peer
	st.signalConn()
	return true
}

// push takes bytes from the server. False is a violation: data before
// connected, after the target's EOF, or past the granted window.
func (st *Stream) push(p []byte) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return true
	}
	if !st.isConn || st.remEOF {
		return false
	}
	if !st.inCredit.Receive(len(p)) {
		return false
	}
	if len(p) > 0 {
		st.queue = append(st.queue, append([]byte(nil), p...))
		st.bytesIn += int64(len(p))
		st.cond.Broadcast()
	}
	return true
}

func (st *Stream) grant(n int) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return true
	}
	if !st.outCredit.Grant(n) {
		return false
	}
	st.cond.Broadcast()
	return true
}

func (st *Stream) remoteEOF() {
	st.mu.Lock()
	st.remEOF = true
	st.cond.Broadcast()
	st.mu.Unlock()
}

// closedByServer handles mesh_close. Before connected it is a failed Open:
// the reason is the error, or internal for a bare "closed".
func (st *Stream) closedByServer(reason, sessionID string, in, out int64) {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	st.closed = true
	wasConn := st.isConn
	if !wasConn && reason == "closed" {
		reason = "internal"
	}
	if reason != "closed" {
		st.failCode = reason
	}
	st.cond.Broadcast()
	st.signalConn()
	st.mu.Unlock()
	st.s.remove(st.id)
	if wasConn && st.s.opt.OnClose != nil {
		st.s.opt.OnClose(CloseInfo{Stream: st.id, SessionID: sessionID, Reason: reason, BytesIn: in, BytesOut: out})
	}
}

// fail ends the stream with an error code (a mesh_status error, or the
// session ending). report says whether OnClose should hear about it; a
// stream that never connected reports through Open instead.
func (st *Stream) fail(code string, report bool) {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	st.closed = true
	st.failCode = code
	sid := st.sessionID
	in, out := st.bytesIn, st.bytesOut
	wasConn := st.isConn
	st.cond.Broadcast()
	st.signalConn()
	st.mu.Unlock()
	st.s.remove(st.id)
	if report && wasConn && st.s.opt.OnClose != nil {
		st.s.opt.OnClose(CloseInfo{Stream: st.id, SessionID: sid, Reason: code, BytesIn: in, BytesOut: out})
	}
}

// abandon is Open giving up before connected.
func (st *Stream) abandon() {
	_ = st.Close()
}

func (st *Stream) sendCredit(n int) {
	if n <= 0 {
		return
	}
	b := int64(n)
	_ = st.s.writeText(frame{Type: "mesh_credit", Stream: u64(st.id), Bytes: &b})
}

// Read returns bytes from the target. After the target's FIN and the queue
// is drained it returns io.EOF. A stream the server ended with a reason other
// than closed returns that reason as a *StatusError.
func (st *Stream) Read(b []byte) (int, error) {
	st.mu.Lock()
	for len(st.queue) == 0 && !st.remEOF && !st.closed && !st.pastLocked(st.rdl) {
		st.cond.Wait()
	}
	if len(st.queue) > 0 {
		n := copy(b, st.queue[0])
		if n == len(st.queue[0]) {
			st.queue = st.queue[1:]
		} else {
			st.queue[0] = st.queue[0][n:]
		}
		st.mu.Unlock()
		st.sendCredit(st.inCredit.Drain(n))
		return n, nil
	}
	if st.closed {
		err := st.endErrLocked()
		st.mu.Unlock()
		return 0, err
	}
	if st.remEOF {
		st.mu.Unlock()
		return 0, io.EOF
	}
	st.mu.Unlock()
	return 0, os.ErrDeadlineExceeded
}

// WriteTo drains the stream into w and returns credit to the server only
// after each chunk has been written to w, so a slow local reader holds the
// server's window instead of growing a queue here. io.Copy uses it, which
// is the relay path. Read, for other callers, returns credit at read time.
func (st *Stream) WriteTo(w io.Writer) (int64, error) {
	var total int64
	for {
		st.mu.Lock()
		for len(st.queue) == 0 && !st.remEOF && !st.closed && !st.pastLocked(st.rdl) {
			st.cond.Wait()
		}
		if len(st.queue) == 0 {
			var err error
			switch {
			case st.closed:
				err = st.endErrLocked()
			case st.remEOF:
				err = io.EOF
			default:
				err = os.ErrDeadlineExceeded
			}
			st.mu.Unlock()
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
		chunk := st.queue[0]
		st.queue = st.queue[1:]
		st.mu.Unlock()
		n, err := w.Write(chunk)
		total += int64(n)
		st.sendCredit(st.inCredit.Drain(n))
		if err != nil {
			return total, err
		}
		if n < len(chunk) {
			return total, io.ErrShortWrite
		}
	}
}

func (st *Stream) endErrLocked() error {
	if st.failCode != "" {
		return &StatusError{Code: st.failCode}
	}
	if st.byClient {
		return net.ErrClosed
	}
	return io.EOF
}

// Write sends bytes to the target inside the server's credit. It blocks while
// no credit is left and refuses after CloseWrite.
func (st *Stream) Write(p []byte) (int, error) {
	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		st.mu.Lock()
		for !st.closed && !st.locEOF && st.isConn && st.outCredit.Sendable(MaxPayload) == 0 && !st.pastLocked(st.wdl) {
			st.cond.Wait()
		}
		switch {
		case st.closed:
			err := st.endErrLocked()
			if err == io.EOF {
				err = net.ErrClosed
			}
			st.mu.Unlock()
			return written, err
		case st.locEOF || !st.isConn:
			st.mu.Unlock()
			return written, net.ErrClosed
		}
		want := len(p)
		if want > MaxPayload {
			want = MaxPayload
		}
		n := st.outCredit.Sendable(want)
		if n <= 0 {
			st.mu.Unlock()
			return written, os.ErrDeadlineExceeded
		}
		st.outCredit.Take(n)
		st.bytesOut += int64(n)
		wdl := st.wdl
		st.mu.Unlock()
		if err := st.s.writeBinary(wdl, EncodeData(st.id, p[:n])); err != nil {
			return written, &StatusError{Code: "internal"}
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite sends the local FIN (mesh_eof). Reads continue.
func (st *Stream) CloseWrite() error {
	st.mu.Lock()
	if st.closed || st.locEOF {
		st.mu.Unlock()
		return nil
	}
	st.locEOF = true
	st.cond.Broadcast()
	st.mu.Unlock()
	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	return st.s.writeText(frame{Type: "mesh_eof", Stream: u64(st.id)})
}

// Close abandons the stream. The server hears mesh_close unless it already
// ended the stream. Readers and writers are released.
func (st *Stream) Close() error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	st.closed = true
	st.byClient = true
	st.cond.Broadcast()
	st.signalConn()
	st.mu.Unlock()
	st.s.remove(st.id)
	_ = st.s.writeText(frame{Type: "mesh_close", Stream: u64(st.id)})
	return nil
}

type meshAddr string

func (a meshAddr) Network() string { return "mesh" }
func (a meshAddr) String() string  { return string(a) }

// LocalAddr names the session and stream.
func (st *Stream) LocalAddr() net.Addr { return meshAddr(st.s.id) }

// RemoteAddr is the peer the agent dialed, once connected.
func (st *Stream) RemoteAddr() net.Addr { return meshAddr(st.Peer()) }

func (st *Stream) pastLocked(t time.Time) bool { return !t.IsZero() && !time.Now().Before(t) }

// SetDeadline sets both deadlines.
func (st *Stream) SetDeadline(t time.Time) error {
	_ = st.SetReadDeadline(t)
	return st.SetWriteDeadline(t)
}

// SetReadDeadline bounds Read.
func (st *Stream) SetReadDeadline(t time.Time) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.rdl = t
	st.rtimer = st.armLocked(st.rtimer, t)
	return nil
}

// SetWriteDeadline bounds Write.
func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.wdl = t
	st.wtimer = st.armLocked(st.wtimer, t)
	return nil
}

func (st *Stream) armLocked(old *time.Timer, t time.Time) *time.Timer {
	if old != nil {
		old.Stop()
	}
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d < 0 {
		d = 0
	}
	return time.AfterFunc(d, func() {
		st.mu.Lock()
		st.cond.Broadcast()
		st.mu.Unlock()
	})
}
