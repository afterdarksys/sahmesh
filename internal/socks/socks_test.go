package socks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/sahmesh/internal/mesh"
	"github.com/afterdarksys/sahmesh/internal/routes"
)

type dialCall struct {
	agent, host string
	port        int
}

// rig serves one listener with a recording dialer. dial returns a pipe
// whose other end the test holds, or the error the test set.
type rig struct {
	t      *testing.T
	ln     net.Listener
	mu     sync.Mutex
	calls  []dialCall
	fail   error
	peers  chan net.Conn
	errs   chan error
	cancel context.CancelFunc
}

func newRig(t *testing.T, tb *routes.Table) *rig {
	t.Helper()
	ln, err := ListenLocal("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, ln: ln, peers: make(chan net.Conn, 8), errs: make(chan error, 1)}
	if tb == nil {
		tb = routes.New()
	}
	// Targets are real TCP sockets so half-close can be observed.
	tln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tln.Close() })
	go func() {
		for {
			p, err := tln.Accept()
			if err != nil {
				return
			}
			r.peers <- p
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	t.Cleanup(cancel)
	go func() {
		r.errs <- Serve(ctx, ln, tb, func(ctx context.Context, agent, host string, port int) (net.Conn, error) {
			r.mu.Lock()
			r.calls = append(r.calls, dialCall{agent, host, port})
			fail := r.fail
			r.mu.Unlock()
			if fail != nil {
				return nil, fail
			}
			return net.Dial("tcp", tln.Addr().String())
		})
	}()
	return r
}

func (r *rig) client() net.Conn {
	r.t.Helper()
	c, err := net.Dial("tcp", r.ln.Addr().String())
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	return c
}

func (r *rig) lastCall() dialCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		return dialCall{}
	}
	return r.calls[len(r.calls)-1]
}

func must(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read %d: %v", n, err)
	}
	return buf
}

func handshake(t *testing.T, c net.Conn) {
	t.Helper()
	must(t, c, []byte{5, 1, 0})
	if got := read(t, c, 2); !bytes.Equal(got, []byte{5, 0}) {
		t.Fatalf("method reply %x", got)
	}
}

func connectDomain(name string, port int) []byte {
	b := []byte{5, 1, 0, 3, byte(len(name))}
	b = append(b, name...)
	return append(b, byte(port>>8), byte(port))
}

func connectIP(ip string, port int) []byte {
	a := netip.MustParseAddr(ip)
	var b []byte
	if a.Is4() {
		b = []byte{5, 1, 0, 1}
	} else {
		b = []byte{5, 1, 0, 4}
	}
	b = append(b, a.AsSlice()...)
	return append(b, byte(port>>8), byte(port))
}

func reply(t *testing.T, c net.Conn) byte {
	t.Helper()
	head := read(t, c, 4)
	if head[0] != 5 || head[2] != 0 {
		t.Fatalf("reply head %x", head)
	}
	switch head[3] {
	case 1:
		read(t, c, 6)
	case 4:
		read(t, c, 18)
	default:
		t.Fatalf("reply atyp %d", head[3])
	}
	return head[1]
}

func TestCanceledServeAfterRefusal(t *testing.T) {
	r := newRig(t, nil)
	r.mu.Lock()
	r.fail = &mesh.StatusError{Code: "target_denied"}
	r.mu.Unlock()
	c := r.client()
	handshake(t, c)
	must(t, c, connectDomain("web1.sah", 5432))
	if rep := reply(t, c); rep != ReplyNotAllowed {
		t.Fatalf("reply %d", rep)
	}
	r.cancel()
	select {
	case err := <-r.errs:
		if err != nil {
			t.Fatalf("clean shutdown after refusal: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

func TestListenerFailureIsReturned(t *testing.T) {
	r := newRig(t, nil)
	_ = r.ln.Close()
	select {
	case err := <-r.errs:
		if err == nil {
			t.Fatal("listener failure was hidden")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener failure timed out")
	}
}

func TestDomainRoutesToAgentLocal(t *testing.T) {
	r := newRig(t, nil)
	c := r.client()
	handshake(t, c)
	must(t, c, connectDomain("web1.sah", 5432))
	if rep := reply(t, c); rep != 0 {
		t.Fatalf("reply %d", rep)
	}
	if got := r.lastCall(); got != (dialCall{"web1", "local", 5432}) {
		t.Fatalf("dial %+v", got)
	}
	peer := <-r.peers
	must(t, c, []byte("hello"))
	if string(read(t, peer, 5)) != "hello" {
		t.Fatal("bytes to target")
	}
	must(t, peer, []byte("world"))
	if string(read(t, c, 5)) != "world" {
		t.Fatal("bytes to client")
	}
	// Half close from the client reaches the target as EOF; bytes still flow back.
	_ = c.(*net.TCPConn).CloseWrite()
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("peer EOF: %v", err)
	}
	must(t, peer, []byte("late"))
	if string(read(t, c, 4)) != "late" {
		t.Fatal("late bytes")
	}
	peer.Close()
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("client EOF: %v", err)
	}
}

func TestIPLiteralUsesRoutes(t *testing.T) {
	tb := routes.New()
	if err := tb.AddFlag("10.0.0.0/24=gw1"); err != nil {
		t.Fatal(err)
	}
	if err := tb.AddFlag("2001:db8::/32=gw6"); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, tb)
	c := r.client()
	handshake(t, c)
	must(t, c, connectIP("10.0.0.7", 3389))
	if rep := reply(t, c); rep != 0 {
		t.Fatalf("reply %d", rep)
	}
	if got := r.lastCall(); got != (dialCall{"gw1", "10.0.0.7", 3389}) {
		t.Fatalf("dial %+v", got)
	}
	<-r.peers
	c2 := r.client()
	handshake(t, c2)
	must(t, c2, connectIP("2001:db8::7", 22))
	if rep := reply(t, c2); rep != 0 {
		t.Fatalf("v6 reply %d", rep)
	}
	if got := r.lastCall(); got != (dialCall{"gw6", "2001:db8::7", 22}) {
		t.Fatalf("v6 dial %+v", got)
	}
	<-r.peers
	// IPv4-mapped IPv6 is routed as IPv4 and sent as the dotted quad.
	c3 := r.client()
	handshake(t, c3)
	must(t, c3, connectIP("::ffff:10.0.0.8", 80))
	if rep := reply(t, c3); rep != 0 {
		t.Fatalf("mapped reply %d", rep)
	}
	if got := r.lastCall(); got != (dialCall{"gw1", "10.0.0.8", 80}) {
		t.Fatalf("mapped dial %+v", got)
	}
}

func TestRefusedDestinations(t *testing.T) {
	tb := routes.New()
	_ = tb.AddFlag("10.0.0.0/8=gw1")
	r := newRig(t, tb)
	cases := []struct {
		name string
		req  []byte
		want byte
	}{
		{"public dns name", connectDomain("example.com", 443), 2},
		{"localhost", connectDomain("localhost", 22), 2},
		{"bare name", connectDomain("web1", 22), 2},
		{"bad label", connectDomain("we b1.sah", 22), 2},
		{"empty label", connectDomain(".sah", 22), 2},
		{"nested", connectDomain("a.b.sah", 22), 2},
		{"loopback ip", connectIP("127.0.0.1", 22), 2},
		{"metadata", connectIP("169.254.169.254", 80), 2},
		{"unrouted", connectIP("192.168.1.1", 80), 2},
		{"port zero", connectDomain("web1.sah", 0), 2},
		{"bind", []byte{5, 2, 0, 3, 8, 'w', 'e', 'b', '1', '.', 's', 'a', 'h', 0, 22}, 7},
		{"udp", []byte{5, 3, 0, 3, 8, 'w', 'e', 'b', '1', '.', 's', 'a', 'h', 0, 22}, 7},
	}
	for _, tc := range cases {
		c := r.client()
		handshake(t, c)
		must(t, c, tc.req)
		if rep := reply(t, c); rep != tc.want {
			t.Fatalf("%s: reply %d want %d", tc.name, rep, tc.want)
		}
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatalf("%s: connection left open", tc.name)
		}
	}
	r.mu.Lock()
	n := len(r.calls)
	r.mu.Unlock()
	if n != 0 {
		t.Fatalf("refused destinations reached the dialer: %d", n)
	}
}

func TestDialErrorsMapToReplies(t *testing.T) {
	r := newRig(t, nil)
	cases := map[string]byte{
		"target_denied":       2,
		"target_denied_agent": 2,
		"target_forbidden":    2,
		"bad_target":          2,
		"scope_denied":        2,
		"host_unreachable":    4,
		"connect_refused":     5,
		"connect_timeout":     6,
		"cap_reached":         1,
		"agent_offline":       1,
		"internal":            1,
	}
	for code, want := range cases {
		r.mu.Lock()
		r.fail = &mesh.StatusError{Code: code}
		r.mu.Unlock()
		c := r.client()
		handshake(t, c)
		must(t, c, connectDomain("web1.sah", 22))
		if rep := reply(t, c); rep != want {
			t.Fatalf("%s: reply %d want %d", code, rep, want)
		}
	}
	r.mu.Lock()
	r.fail = errors.New("something else")
	r.mu.Unlock()
	c := r.client()
	handshake(t, c)
	must(t, c, connectDomain("web1.sah", 22))
	if rep := reply(t, c); rep != 1 {
		t.Fatalf("generic: reply %d", rep)
	}
}

func TestHandshakeRefusals(t *testing.T) {
	r := newRig(t, nil)
	c := r.client()
	must(t, c, []byte{5, 1, 2}) // username/password only
	if got := read(t, c, 2); !bytes.Equal(got, []byte{5, 0xff}) {
		t.Fatalf("auth-only reply %x", got)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("left open")
	}
	c2 := r.client()
	must(t, c2, []byte{4, 1, 0, 22, 1, 2, 3, 4, 0}) // SOCKS4
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("socks4 accepted")
	}
	c3 := r.client()
	handshake(t, c3)
	must(t, c3, []byte{4, 1, 0, 1, 1, 2, 3, 4, 0, 22}) // wrong version in request
	if _, err := c3.Read(make([]byte, 1)); err == nil {
		t.Fatal("bad request version accepted")
	}
	c4 := r.client()
	must(t, c4, []byte{5, 0}) // zero methods
	if _, err := c4.Read(make([]byte, 1)); err == nil {
		t.Fatal("zero methods accepted")
	}
}

func TestHandshakeTimeout(t *testing.T) {
	old := handshakeWait.Load()
	handshakeWait.Store(int64(100 * time.Millisecond))
	defer handshakeWait.Store(old)
	r := newRig(t, nil)
	c := r.client()
	must(t, c, []byte{5})
	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("slow handshake accepted")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout too slow")
	}
}

func TestResolve(t *testing.T) {
	tb := routes.New()
	_ = tb.AddFlag("10.0.0.0/8=gw1")
	ok := func(d Dest, agent, host string) {
		t.Helper()
		a, h, err := Resolve(tb, d)
		if err != nil || a != agent || h != host {
			t.Fatalf("%+v: got %q %q %v", d, a, h, err)
		}
	}
	bad := func(d Dest) {
		t.Helper()
		if _, _, err := Resolve(tb, d); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("%+v: got %v", d, err)
		}
	}
	ok(Dest{Domain: "web1.sah", Port: 1}, "web1", "local")
	ok(Dest{Domain: "WEB1.SAH", Port: 1}, "WEB1", "local")
	ok(Dest{Domain: "h-01_x.sah", Port: 1}, "h-01_x", "local")
	ok(Dest{Addr: netip.MustParseAddr("10.1.2.3"), Port: 1}, "gw1", "10.1.2.3")
	bad(Dest{Domain: "sah", Port: 1})
	bad(Dest{Domain: "web1.sah.", Port: 1})
	bad(Dest{Domain: "web1.sahx", Port: 1})
	bad(Dest{Domain: "web1.sah", Port: 0})
	bad(Dest{Domain: "web1.sah", Port: 65536})
	bad(Dest{Domain: "", Port: 1})
	bad(Dest{Addr: netip.MustParseAddr("10.1.2.3"), Domain: "web1.sah", Port: 1})
	bad(Dest{Addr: netip.MustParseAddr("11.1.2.3"), Port: 1})
	bad(Dest{Addr: netip.MustParseAddr("::1"), Port: 1})
	bad(Dest{Port: 1})
}

func TestListenLocal(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "localhost:0", "10.0.0.1:0", "[::]:0", "127.0.0.1", "127.0.0.1:70000", ""} {
		if _, err := ListenLocal(addr); err == nil || err.Error() != "bind_refused" {
			t.Fatalf("%q: %v", addr, err)
		}
	}
	ln, err := ListenLocal("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	ln6, err := ListenLocal("[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	ln6.Close()
}
