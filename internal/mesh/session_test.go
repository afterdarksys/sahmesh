package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const msh = "msh_0123456789abcdef"
const tcs = "tcs_0123456789abcdef"

// fakeConn is the server end of one mesh socket under test control.
type fakeConn struct {
	t    *testing.T
	c    *websocket.Conn
	text chan frame
	data chan dataFrame
	gone chan error
}

type dataFrame struct {
	id uint32
	p  []byte
}

type fakeServer struct {
	srv   *httptest.Server
	conns chan *fakeConn
	paths chan string
}

func newFake(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{conns: make(chan *fakeConn, 4), paths: make(chan string, 4)}
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.paths <- r.URL.Path + "?" + r.URL.RawQuery
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		c.SetReadLimit(MaxPayload + 4)
		fc := &fakeConn{t: t, c: c, text: make(chan frame, 64), data: make(chan dataFrame, 1024), gone: make(chan error, 1)}
		fs.conns <- fc
		for {
			typ, b, err := c.Read(context.Background())
			if err != nil {
				fc.gone <- err
				return
			}
			if typ == websocket.MessageBinary {
				id, p, ok := DecodeData(b)
				if !ok {
					t.Errorf("fake server: bad binary frame")
					return
				}
				fc.data <- dataFrame{id, append([]byte(nil), p...)}
				continue
			}
			var f frame
			if err := json.Unmarshal(b, &f); err != nil {
				t.Errorf("fake server: bad text %q", b)
				return
			}
			fc.text <- f
		}
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *fakeServer) wsURL() string {
	return "ws" + strings.TrimPrefix(fs.srv.URL, "http") + "/api/v1/systems/mesh/h-0001?ticket=stk_secret&purpose=mesh:open"
}

func (fs *fakeServer) accept(t *testing.T) *fakeConn {
	t.Helper()
	select {
	case fc := <-fs.conns:
		return fc
	case <-time.After(3 * time.Second):
		t.Fatal("no connection")
		return nil
	}
}

func (fc *fakeConn) send(v any) {
	b, _ := json.Marshal(v)
	if err := fc.c.Write(context.Background(), websocket.MessageText, b); err != nil {
		fc.t.Logf("fake send: %v", err)
	}
}

func (fc *fakeConn) sendData(id uint32, p []byte) {
	_ = fc.c.Write(context.Background(), websocket.MessageBinary, EncodeData(id, p))
}

func (fc *fakeConn) ready(window int) {
	fc.send(map[string]any{"type": "mesh_ready", "payload": map[string]any{"session_id": msh, "window": window}})
}

func (fc *fakeConn) expect(typ string) frame {
	fc.t.Helper()
	select {
	case f := <-fc.text:
		if f.Type != typ {
			fc.t.Fatalf("expected %s, got %s", typ, f.Type)
		}
		return f
	case <-time.After(3 * time.Second):
		fc.t.Fatalf("timed out waiting for %s", typ)
		return frame{}
	}
}

func (fc *fakeConn) expectData() dataFrame {
	fc.t.Helper()
	select {
	case d := <-fc.data:
		return d
	case <-time.After(3 * time.Second):
		fc.t.Fatal("timed out waiting for data")
		return dataFrame{}
	}
}

func (fc *fakeConn) noData(d time.Duration) {
	fc.t.Helper()
	select {
	case got := <-fc.data:
		fc.t.Fatalf("unexpected data %d bytes on stream %d", len(got.p), got.id)
	case <-time.After(d):
	}
}

// connectStream answers one mesh_open with connecting and connected.
func (fc *fakeConn) connectStream(peer string) uint64 {
	fc.t.Helper()
	f := fc.expect("mesh_open")
	id := *f.Stream
	fc.send(map[string]any{"type": "mesh_status", "stream": id, "payload": map[string]any{"status": "connecting"}})
	fc.send(map[string]any{"type": "mesh_status", "stream": id, "payload": map[string]any{"status": "connected", "session_id": tcs, "peer": peer}})
	return id
}

func (fc *fakeConn) closeStatus() websocket.StatusCode {
	select {
	case err := <-fc.gone:
		return websocket.CloseStatus(err)
	case <-time.After(3 * time.Second):
		fc.t.Fatal("socket did not close")
		return -1
	}
}

func dialReady(t *testing.T, window int, opt Options) (*Session, *fakeConn) {
	t.Helper()
	fs := newFake(t)
	done := make(chan *fakeConn, 1)
	go func() {
		fc := fs.accept(t)
		fc.ready(window)
		done <- fc
	}()
	s, err := Dial(context.Background(), fs.wsURL(), fs.srv.Client(), opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, <-done
}

func openConnected(t *testing.T, s *Session, fc *fakeConn, host string, port int) (*Stream, uint64) {
	t.Helper()
	var st *Stream
	var oerr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); st, oerr = s.Open(context.Background(), host, port) }()
	id := fc.connectStream("127.0.0.1:5432")
	wg.Wait()
	if oerr != nil {
		t.Fatal(oerr)
	}
	return st, id
}

func readAll(t *testing.T, st *Stream, n int) []byte {
	t.Helper()
	buf := make([]byte, 0, n)
	tmp := make([]byte, 4096)
	_ = st.SetReadDeadline(time.Now().Add(3 * time.Second))
	for len(buf) < n {
		k, err := st.Read(tmp)
		buf = append(buf, tmp[:k]...)
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(buf), err)
		}
	}
	_ = st.SetReadDeadline(time.Time{})
	return buf
}

func TestReadyWindowAndIDs(t *testing.T) {
	s, fc := dialReady(t, 5, Options{})
	if s.ID() != msh || s.Window() != 5 {
		t.Fatalf("session %s window %d", s.ID(), s.Window())
	}
	_, id1 := openConnected(t, s, fc, "local", 22)
	_, id2 := openConnected(t, s, fc, "10.0.0.7", 3389)
	if id1 != 1 || id2 != 2 {
		t.Fatalf("ids %d %d", id1, id2)
	}
}

func TestTwoStreamsInterleaved(t *testing.T) {
	s, fc := dialReady(t, DefaultWindow, Options{})
	a, ida := openConnected(t, s, fc, "local", 5432)
	b, idb := openConnected(t, s, fc, "local", 22)
	if a.SessionID() != tcs || a.Peer() != "127.0.0.1:5432" || a.RemoteAddr().String() != "127.0.0.1:5432" {
		t.Fatal("stream metadata")
	}
	if _, err := a.Write([]byte("alpha")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("bravo")); err != nil {
		t.Fatal(err)
	}
	got := map[uint32]string{}
	for i := 0; i < 2; i++ {
		d := fc.expectData()
		got[d.id] = string(d.p)
	}
	if got[uint32(ida)] != "alpha" || got[uint32(idb)] != "bravo" {
		t.Fatalf("server saw %v", got)
	}
	fc.sendData(uint32(idb), []byte("B1"))
	fc.sendData(uint32(ida), []byte("A1"))
	fc.sendData(uint32(idb), []byte("B2"))
	if string(readAll(t, a, 2)) != "A1" || string(readAll(t, b, 4)) != "B1B2" {
		t.Fatal("streams mixed")
	}
}

func TestStreamErrorLeavesOtherAlive(t *testing.T) {
	var closes []CloseInfo
	var mu sync.Mutex
	s, fc := dialReady(t, DefaultWindow, Options{OnClose: func(ci CloseInfo) { mu.Lock(); closes = append(closes, ci); mu.Unlock() }})
	a, ida := openConnected(t, s, fc, "local", 5432)
	errCh := make(chan error, 1)
	go func() { _, err := s.Open(context.Background(), "10.0.0.9", 1); errCh <- err }()
	f := fc.expect("mesh_open")
	fc.send(map[string]any{"type": "mesh_status", "stream": *f.Stream, "payload": map[string]any{"error": "target_denied"}})
	var se *StatusError
	if err := <-errCh; !errors.As(err, &se) || se.Code != "target_denied" {
		t.Fatalf("got %v", err)
	}
	// The other stream still works.
	_, _ = a.Write([]byte("x"))
	if d := fc.expectData(); d.id != uint32(ida) || string(d.p) != "x" {
		t.Fatal("stream 1 broken")
	}
	select {
	case <-s.Done():
		t.Fatal("session ended")
	default:
	}
	mu.Lock()
	defer mu.Unlock()
	if len(closes) != 1 || closes[0].Reason != "target_denied" || closes[0].Stream != 2 {
		t.Fatalf("closes %v", closes)
	}
}

func TestServerOverrunIsProtocolError(t *testing.T) {
	s, fc := dialReady(t, 10, Options{})
	a, ida := openConnected(t, s, fc, "local", 5432)
	fc.sendData(uint32(ida), bytes.Repeat([]byte{1}, 10))
	fc.sendData(uint32(ida), []byte{2})
	select {
	case <-s.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session did not end")
	}
	var se *StatusError
	if err := s.Err(); !errors.As(err, &se) || se.Code != "protocol_error" {
		t.Fatalf("session err %v", err)
	}
	buf := make([]byte, 64)
	n, _ := a.Read(buf)
	if n != 10 {
		t.Fatalf("read %d", n)
	}
	if _, err := a.Read(buf); !errors.As(err, &se) || se.Code != "protocol_error" {
		t.Fatalf("stream err %v", err)
	}
	if st := fc.closeStatus(); st != websocket.StatusProtocolError {
		t.Fatalf("close status %d", st)
	}
	if _, err := s.Open(context.Background(), "local", 1); !errors.As(err, &se) || se.Code != "protocol_error" {
		t.Fatalf("open after end %v", err)
	}
}

func TestClientRespectsCredit(t *testing.T) {
	s, fc := dialReady(t, 10, Options{})
	a, ida := openConnected(t, s, fc, "local", 5432)
	wrote := make(chan error, 1)
	go func() { _, err := a.Write(bytes.Repeat([]byte{7}, 25)); wrote <- err }()
	if d := fc.expectData(); d.id != uint32(ida) || len(d.p) != 10 {
		t.Fatalf("first chunk %d", len(d.p))
	}
	fc.noData(150 * time.Millisecond)
	fc.send(map[string]any{"type": "mesh_credit", "stream": ida, "bytes": 10})
	if d := fc.expectData(); len(d.p) != 10 {
		t.Fatalf("second chunk %d", len(d.p))
	}
	fc.noData(150 * time.Millisecond)
	fc.send(map[string]any{"type": "mesh_credit", "stream": ida, "bytes": 10})
	if d := fc.expectData(); len(d.p) != 5 {
		t.Fatalf("third chunk %d", len(d.p))
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	// Credit past the window from the server is a violation.
	fc.send(map[string]any{"type": "mesh_credit", "stream": ida, "bytes": 10})
	fc.send(map[string]any{"type": "mesh_credit", "stream": ida, "bytes": 1})
	<-s.Done()
	if fc.closeStatus() != websocket.StatusProtocolError {
		t.Fatal("credit overflow not refused")
	}
}

func TestCreditReturnedOnRead(t *testing.T) {
	s, fc := dialReady(t, 8, Options{})
	a, ida := openConnected(t, s, fc, "local", 5432)
	fc.sendData(uint32(ida), []byte("12345678"))
	got := readAll(t, a, 8)
	if string(got) != "12345678" {
		t.Fatal(string(got))
	}
	total := int64(0)
	for total < 8 {
		f := fc.expect("mesh_credit")
		if *f.Stream != ida || f.Bytes == nil || *f.Bytes <= 0 {
			t.Fatalf("credit frame %+v", f)
		}
		total += *f.Bytes
	}
	if total != 8 {
		t.Fatalf("returned %d", total)
	}
	// The window is open again.
	fc.sendData(uint32(ida), []byte("abcdefgh"))
	if string(readAll(t, a, 8)) != "abcdefgh" {
		t.Fatal("second window")
	}
	select {
	case <-s.Done():
		t.Fatal("session ended")
	default:
	}
}

func TestHalfCloseBothWays(t *testing.T) {
	var closes []CloseInfo
	var mu sync.Mutex
	s, fc := dialReady(t, DefaultWindow, Options{OnClose: func(ci CloseInfo) { mu.Lock(); closes = append(closes, ci); mu.Unlock() }})
	a, ida := openConnected(t, s, fc, "local", 5432)
	if err := a.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if f := fc.expect("mesh_eof"); *f.Stream != ida {
		t.Fatal("eof stream")
	}
	if _, err := a.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after CloseWrite: %v", err)
	}
	fc.sendData(uint32(ida), []byte("tail"))
	fc.send(map[string]any{"type": "mesh_eof", "stream": ida})
	if string(readAll(t, a, 4)) != "tail" {
		t.Fatal("tail")
	}
	if _, err := a.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
	fc.send(map[string]any{"type": "mesh_close", "stream": ida, "payload": map[string]any{"session_id": tcs, "reason": "closed", "bytes_in": 4, "bytes_out": 0}})
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	if len(closes) != 1 || closes[0].Reason != "closed" || closes[0].BytesIn != 4 || closes[0].SessionID != tcs {
		t.Fatalf("closes %+v", closes)
	}
	mu.Unlock()
	// Close after the server ended it sends nothing more.
	_ = a.Close()
	select {
	case f := <-fc.text:
		t.Fatalf("unexpected frame %s", f.Type)
	case <-time.After(100 * time.Millisecond):
	}
	// A late frame for the closed id is ignored; an unknown id is not.
	fc.sendData(uint32(ida), []byte("late"))
	fc.send(map[string]any{"type": "mesh_credit", "stream": ida, "bytes": 5})
	time.Sleep(50 * time.Millisecond)
	select {
	case <-s.Done():
		t.Fatal("late frames ended the session")
	default:
	}
	fc.sendData(99, []byte("x"))
	<-s.Done()
	if fc.closeStatus() != websocket.StatusProtocolError {
		t.Fatal("unknown id accepted")
	}
}

func TestServerCloseWithReason(t *testing.T) {
	s, fc := dialReady(t, DefaultWindow, Options{})
	a, ida := openConnected(t, s, fc, "local", 5432)
	fc.send(map[string]any{"type": "mesh_close", "stream": ida, "payload": map[string]any{"reason": "idle_timeout"}})
	var se *StatusError
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := a.Read(make([]byte, 1)); !errors.As(err, &se) || se.Code != "idle_timeout" {
		t.Fatalf("got %v", err)
	}
	if _, err := a.Write([]byte("x")); !errors.As(err, &se) || se.Code != "idle_timeout" {
		t.Fatalf("write got %v", err)
	}
}

func TestClientCloseSendsMeshClose(t *testing.T) {
	s, fc := dialReady(t, DefaultWindow, Options{})
	a, ida := openConnected(t, s, fc, "local", 5432)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if f := fc.expect("mesh_close"); *f.Stream != ida {
		t.Fatal("close stream")
	}
	if _, err := a.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close %v", err)
	}
	// The next stream gets a fresh id; ids never go back.
	_, id2 := openConnected(t, s, fc, "local", 5432)
	if id2 != 2 {
		t.Fatal("id reused")
	}
	// Session.Close closes the socket normally.
	_ = s.Close()
	fc.expect("mesh_close")
	if fc.closeStatus() != websocket.StatusNormalClosure {
		t.Fatal("close status")
	}
}

func TestMeshEndFailsStreams(t *testing.T) {
	s, fc := dialReady(t, DefaultWindow, Options{})
	a, _ := openConnected(t, s, fc, "local", 5432)
	fc.send(map[string]any{"type": "mesh_end", "payload": map[string]any{"session_id": msh, "reason": "stopped", "streams": 1}})
	<-s.Done()
	var se *StatusError
	if err := s.Err(); !errors.As(err, &se) || se.Code != "stopped" {
		t.Fatalf("session %v", err)
	}
	if _, err := a.Read(make([]byte, 1)); !errors.As(err, &se) || se.Code != "stopped" {
		t.Fatalf("stream %v", err)
	}
}

func TestSessionErrorFrame(t *testing.T) {
	s, fc := dialReady(t, DefaultWindow, Options{})
	fc.send(map[string]any{"type": "mesh_status", "payload": map[string]any{"error": "agent_offline"}})
	<-s.Done()
	var se *StatusError
	if err := s.Err(); !errors.As(err, &se) || se.Code != "agent_offline" {
		t.Fatalf("session %v", err)
	}
}

func TestDialRefusals(t *testing.T) {
	fs := newFake(t)
	go func() {
		fc := fs.accept(t)
		fc.send(map[string]any{"type": "mesh_status", "payload": map[string]any{"error": "ticket_invalid"}})
	}()
	var se *StatusError
	if _, err := Dial(context.Background(), fs.wsURL(), fs.srv.Client(), Options{}); !errors.As(err, &se) || se.Code != "ticket_invalid" {
		t.Fatalf("session error before ready: %v", err)
	}
	go func() {
		fc := fs.accept(t)
		fc.send(map[string]any{"type": "mesh_ready", "payload": map[string]any{"session_id": "bad", "window": 10}})
	}()
	if _, err := Dial(context.Background(), fs.wsURL(), fs.srv.Client(), Options{}); !errors.As(err, &se) || se.Code != "protocol_error" {
		t.Fatalf("bad ready: %v", err)
	}
	go func() {
		fc := fs.accept(t)
		fc.sendData(1, []byte("x"))
	}()
	if _, err := Dial(context.Background(), fs.wsURL(), fs.srv.Client(), Options{}); !errors.As(err, &se) || se.Code != "protocol_error" {
		t.Fatalf("binary before ready: %v", err)
	}
	go func() { fs.accept(t) }()
	if _, err := Dial(context.Background(), fs.wsURL(), fs.srv.Client(), Options{HandshakeWait: 200 * time.Millisecond}); !errors.As(err, &se) || se.Code != "connect_timeout" {
		t.Fatalf("no ready: %v", err)
	}
	// The ticket and URL never appear in an error.
	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer refuse.Close()
	u := "ws" + strings.TrimPrefix(refuse.URL, "http") + "/api/v1/systems/mesh/h?ticket=stk_secret&purpose=mesh:open"
	_, err := Dial(context.Background(), u, refuse.Client(), Options{})
	if err == nil || strings.Contains(err.Error(), "stk_secret") || strings.Contains(err.Error(), "127.0.0.1") || err.Error() != "mesh handshake refused (HTTP 403)" {
		t.Fatalf("dial error %v", err)
	}
	if _, err := Dial(context.Background(), "", refuse.Client(), Options{}); err == nil {
		t.Fatal("empty url")
	}
}

func TestDataBeforeConnectedAndBadStatus(t *testing.T) {
	s, fc := dialReady(t, DefaultWindow, Options{})
	errCh := make(chan error, 1)
	go func() { _, err := s.Open(context.Background(), "local", 1); errCh <- err }()
	f := fc.expect("mesh_open")
	fc.sendData(uint32(*f.Stream), []byte("early"))
	var se *StatusError
	if err := <-errCh; !errors.As(err, &se) || se.Code != "protocol_error" {
		t.Fatalf("open got %v", err)
	}
	if fc.closeStatus() != websocket.StatusProtocolError {
		t.Fatal("close status")
	}
	s2, fc2 := dialReady(t, DefaultWindow, Options{})
	go func() { _, err := s2.Open(context.Background(), "local", 1); errCh <- err }()
	f = fc2.expect("mesh_open")
	fc2.send(map[string]any{"type": "mesh_status", "stream": *f.Stream, "payload": map[string]any{"status": "connected", "session_id": "nope", "peer": "x"}})
	if err := <-errCh; !errors.As(err, &se) || se.Code != "protocol_error" {
		t.Fatalf("bad session id got %v", err)
	}
}

func TestOpenTimeoutAndContext(t *testing.T) {
	s, fc := dialReady(t, DefaultWindow, Options{HandshakeWait: 200 * time.Millisecond})
	var se *StatusError
	if _, err := s.Open(context.Background(), "local", 1); !errors.As(err, &se) || se.Code != "connect_timeout" {
		t.Fatalf("timeout got %v", err)
	}
	fc.expect("mesh_open")
	fc.expect("mesh_close")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if _, err := s.Open(ctx, "local", 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel got %v", err)
	}
	if _, err := s.Open(context.Background(), "", 1); !errors.As(err, &se) || se.Code != "bad_target" {
		t.Fatal("bad target shape")
	}
	if _, err := s.Open(context.Background(), "local", 70000); !errors.As(err, &se) || se.Code != "bad_target" {
		t.Fatal("bad port")
	}
}

func TestUnknownTypesIgnoredAndBadTextRefused(t *testing.T) {
	s, fc := dialReady(t, DefaultWindow, Options{})
	_, ida := openConnected(t, s, fc, "local", 5432)
	fc.send(map[string]any{"type": "mesh_future", "stream": ida})
	time.Sleep(50 * time.Millisecond)
	select {
	case <-s.Done():
		t.Fatal("unknown type ended the session")
	default:
	}
	_ = fc.c.Write(context.Background(), websocket.MessageText, []byte("not json"))
	<-s.Done()
	if fc.closeStatus() != websocket.StatusProtocolError {
		t.Fatal("bad json accepted")
	}
}

func TestReadDeadline(t *testing.T) {
	s, fc := dialReady(t, DefaultWindow, Options{})
	a, _ := openConnected(t, s, fc, "local", 5432)
	_ = a.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := a.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if a.LocalAddr().String() != msh || a.LocalAddr().Network() != "mesh" {
		t.Fatal("local addr")
	}
}
