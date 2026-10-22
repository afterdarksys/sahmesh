// Package socks is sahmesh's SOCKS5 front: the loopback listener that
// applications point at, and the rules that turn a destination into an
// agent and a target (sah-mesh-protocol.md §16).
//
// Threats: a local process using the proxy as a pivot into the fleet. The
// listener binds a loopback address only, with no flag that widens it, and
// a connection whose remote address is not loopback is dropped. There is no
// authentication: the account that can reach loopback can already run
// sahmesh with its own credential. Only CONNECT is served; BIND and UDP
// ASSOCIATE are refused. No name is resolved: a domain must be NAME.sah and
// NAME must satisfy the suite host-name rule; an IP literal must match a
// configured route and passes target.Check locally (loopback and the refused
// classes never leave this process). The handshake is bounded by a timeout
// and fixed-size reads. Contract errors come back as the SOCKS reply codes of
// §16 and never carry a ticket, URL or address. Does NOT decide what the
// server or the agent allow, and does NOT inspect or record relayed bytes.
package socks

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/afterdarksys/sahmesh/internal/client"
	"github.com/afterdarksys/sahmesh/internal/mesh"
	"github.com/afterdarksys/sahmesh/internal/routes"
	"github.com/afterdarksys/sahmesh/internal/target"
)

// Suffix is the domain suffix that names an agent.
const Suffix = ".sah"

// SOCKS5 reply codes (RFC 1928 §6).
const (
	ReplySuccess         byte = 0x00
	ReplyFailure         byte = 0x01
	ReplyNotAllowed      byte = 0x02
	ReplyNetUnreach      byte = 0x03
	ReplyHostUnreach     byte = 0x04
	ReplyRefused         byte = 0x05
	ReplyTTLExpired      byte = 0x06
	ReplyCmdUnsupported  byte = 0x07
	ReplyAddrUnsupported byte = 0x08
)

// ErrNotAllowed is a destination the ruleset refuses (reply 0x02).
var ErrNotAllowed = errors.New("not_allowed")

// handshakeWait bounds the method and request exchange, in nanoseconds.
// Tests shorten it.
var handshakeWait atomic.Int64

func init() { handshakeWait.Store(int64(10 * time.Second)) }

// Dest is a parsed CONNECT destination: exactly one of Addr or Domain.
type Dest struct {
	Addr   netip.Addr
	Domain string
	Port   int
}

// Dialer opens one mesh stream to agent with target host:port.
type Dialer func(ctx context.Context, agent, host string, port int) (net.Conn, error)

// Resolve applies the §16 name and route rules. host is "local" or the IP
// literal the agent should dial.
func Resolve(tb *routes.Table, d Dest) (agent, host string, err error) {
	if d.Port < 1 || d.Port > 65535 {
		return "", "", ErrNotAllowed
	}
	if d.Addr.IsValid() && d.Domain != "" {
		return "", "", ErrNotAllowed
	}
	if d.Domain != "" {
		if len(d.Domain) <= len(Suffix) || !strings.EqualFold(d.Domain[len(d.Domain)-len(Suffix):], Suffix) {
			return "", "", ErrNotAllowed
		}
		name := d.Domain[:len(d.Domain)-len(Suffix)]
		if strings.Contains(name, ".") || !client.ValidHostName(name) {
			return "", "", ErrNotAllowed
		}
		return name, "local", nil
	}
	if !d.Addr.IsValid() {
		return "", "", ErrNotAllowed
	}
	addr := d.Addr.Unmap()
	if tb == nil {
		return "", "", ErrNotAllowed
	}
	via, ok := tb.Lookup(addr)
	if !ok {
		return "", "", ErrNotAllowed
	}
	host = addr.String()
	if err := target.Check(host); err != nil {
		return "", "", ErrNotAllowed
	}
	return via, host, nil
}

// ReplyFor maps a dial error to a SOCKS reply (§16).
func ReplyFor(err error) byte {
	if errors.Is(err, ErrNotAllowed) {
		return ReplyNotAllowed
	}
	var se *mesh.StatusError
	if !errors.As(err, &se) {
		return ReplyFailure
	}
	switch se.Code {
	case "target_denied", "target_denied_agent", "target_forbidden", "bad_target", "scope_denied":
		return ReplyNotAllowed
	case "host_unreachable":
		return ReplyHostUnreach
	case "connect_refused":
		return ReplyRefused
	case "connect_timeout":
		return ReplyTTLExpired
	}
	return ReplyFailure
}

type bindError struct{}

func (bindError) Error() string { return "bind_refused" }

func isLoopbackHost(host string) bool {
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.Unmap().IsLoopback() && ip.Zone() == ""
}

// ListenLocal binds addr, which must be a loopback IP literal with a port.
// "localhost", 0.0.0.0, ::, and any non-loopback address are bind_refused.
func ListenLocal(addr string) (net.Listener, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil || !isLoopbackHost(host) {
		return nil, bindError{}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, bindError{}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, bindError{}
	}
	if h, _, err := net.SplitHostPort(ln.Addr().String()); err != nil || !isLoopbackHost(h) {
		_ = ln.Close()
		return nil, bindError{}
	}
	return ln, nil
}

// Serve accepts on ln until ctx is cancelled. Every accepted connection runs
// the SOCKS5 handshake and, on CONNECT, relays to the conn dial returns.
// A dial error is remembered and returned when the listener stops, so the
// process can exit non-zero. A cancelled context alone is a clean stop.
func Serve(ctx context.Context, ln net.Listener, tb *routes.Table, dial Dialer) error {
	if ln == nil || dial == nil {
		return errors.New("internal")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed error
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return failed
			}
			return err
		}
		if h, _, err := net.SplitHostPort(c.RemoteAddr().String()); err != nil || !isLoopbackHost(h) {
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			if err := serveConn(ctx, c, tb, dial); err != nil && !errors.Is(err, context.Canceled) {
				mu.Lock()
				if failed == nil {
					failed = err
				}
				mu.Unlock()
			}
		}()
	}
}

func serveConn(ctx context.Context, c net.Conn, tb *routes.Table, dial Dialer) error {
	_ = c.SetDeadline(time.Now().Add(time.Duration(handshakeWait.Load())))
	rd := bufio.NewReaderSize(c, 512)
	head := make([]byte, 2)
	if _, err := io.ReadFull(rd, head); err != nil || head[0] != 5 || head[1] == 0 {
		return nil
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(rd, methods); err != nil {
		return nil
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		_, _ = c.Write([]byte{5, 0xff})
		return nil
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return nil
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(rd, req); err != nil || req[0] != 5 || req[2] != 0 {
		return nil
	}
	var d Dest
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(rd, b); err != nil {
			return nil
		}
		d.Addr = netip.AddrFrom4([4]byte(b))
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(rd, b); err != nil {
			return nil
		}
		d.Addr = netip.AddrFrom16([16]byte(b))
	case 3:
		n, err := rd.ReadByte()
		if err != nil {
			return nil
		}
		b := make([]byte, int(n))
		if _, err := io.ReadFull(rd, b); err != nil {
			return nil
		}
		d.Domain = string(b)
	default:
		_, _ = c.Write(replyBytes(ReplyAddrUnsupported))
		return nil
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(rd, pb); err != nil {
		return nil
	}
	d.Port = int(pb[0])<<8 | int(pb[1])
	if req[1] != 1 {
		_, _ = c.Write(replyBytes(ReplyCmdUnsupported))
		return nil
	}
	agent, host, err := Resolve(tb, d)
	if err != nil {
		_, _ = c.Write(replyBytes(ReplyNotAllowed))
		return nil
	}
	_ = c.SetDeadline(time.Time{})
	up, err := dial(ctx, agent, host, d.Port)
	if err != nil {
		_, _ = c.Write(replyBytes(ReplyFor(err)))
		return err
	}
	defer up.Close()
	if _, err := c.Write(replyBytes(ReplySuccess)); err != nil {
		return nil
	}
	relay(c, rd, up)
	return nil
}

func replyBytes(code byte) []byte {
	return []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}
}

type closeWriter interface{ CloseWrite() error }

// relay copies both ways, propagating half-close, until both directions are
// done or either side errors.
func relay(c net.Conn, buffered io.Reader, up net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(up, buffered)
		if cw, ok := up.(closeWriter); ok && err == nil {
			_ = cw.CloseWrite()
		} else {
			_ = up.Close()
			_ = c.Close()
		}
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(c, up)
		if cw, ok := c.(closeWriter); ok && err == nil {
			_ = cw.CloseWrite()
		} else {
			_ = c.Close()
			_ = up.Close()
		}
	}()
	wg.Wait()
}
