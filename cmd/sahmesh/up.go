package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/afterdarksys/sahmesh/internal/client"
	"github.com/afterdarksys/sahmesh/internal/config"
	"github.com/afterdarksys/sahmesh/internal/mesh"
	"github.com/afterdarksys/sahmesh/internal/routes"
	"github.com/afterdarksys/sahmesh/internal/socks"
)

func cmdUp(args []string, stdout, stderr io.Writer, env func(string) string) int {
	o, err := parseUp(args)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		if err.Error() == "usage" {
			usage(stderr)
		}
		return 2
	}
	probe, err := socks.ListenLocal(o.listen)
	if err != nil {
		// Validate the bind address before any credential is read or any
		// request is made. The probe listener is closed at once.
		fmt.Fprintln(stderr, "bind_refused")
		return 2
	}
	_ = probe.Close()
	routesPath := o.routesFile
	if routesPath == "" {
		p, perr := routes.DefaultPath(env)
		if perr != nil {
			fmt.Fprintln(stderr, perr.Error())
			return 2
		}
		routesPath = p
	}
	if err := o.table.LoadFile(routesPath); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	cfg, err := config.Load(env)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	if cfg.SystemAPIURL == "" {
		fmt.Fprintln(stderr, "systemapi_url is not set")
		return 2
	}
	base, err := client.ValidateBase(cfg.SystemAPIURL)
	if err != nil {
		fmt.Fprintln(stderr, codeOf(err))
		return 2
	}
	auth, note, err := client.LoadAuth(cfg, base)
	if note != "" {
		fmt.Fprintln(stderr, note)
	}
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	api := &client.Client{Base: base, Auth: auth, HTTP: client.NewHTTPClient(nil, 20*time.Second)}
	ln, err := socks.ListenLocal(o.listen)
	if err != nil {
		fmt.Fprintln(stderr, "bind_refused")
		return 1
	}
	defer ln.Close()
	fmt.Fprintln(stdout, ln.Addr().String())
	ctx, stop := signalContext()
	defer stop()
	pool := &sessions{api: api, ws: client.NewHTTPClient(nil, 0), stderr: stderr, hosts: map[string]*entry{}}
	err = socks.Serve(ctx, ln, o.table, pool.dial)
	pool.closeAll()
	if err != nil {
		return 1
	}
	return 0
}

// entry is one agent's resolved host id and live session.
type entry struct {
	mu      sync.Mutex // held across a dial so two first streams share one ticket
	hostID  string
	session *mesh.Session
}

// sessions keeps one mesh session per agent, dialed on first use and again
// after it ends.
type sessions struct {
	api    *client.Client
	ws     *http.Client
	stderr io.Writer

	mu    sync.Mutex
	hosts map[string]*entry
}

func (p *sessions) dial(ctx context.Context, agent, host string, port int) (net.Conn, error) {
	s, err := p.session(ctx, agent)
	if err != nil {
		p.report(agent, err)
		return nil, err
	}
	st, err := s.Open(ctx, host, port)
	if err != nil {
		p.report(agent, err)
		return nil, err
	}
	return st, nil
}

// session returns the live session for agent, dialing one when none is up.
// One dial runs at a time per agent, so two first connections to the same
// host share one ticket; dials to different hosts run in parallel.
func (p *sessions) session(ctx context.Context, agent string) (*mesh.Session, error) {
	p.mu.Lock()
	e := p.hosts[agent]
	if e == nil {
		e = &entry{}
		p.hosts[agent] = e
	}
	p.mu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hostID == "" {
		h, err := p.api.Resolve(ctx, agent)
		if err != nil {
			return nil, err
		}
		e.hostID = h.HostID
	}
	if e.session != nil {
		select {
		case <-e.session.Done():
			e.session = nil
		default:
			return e.session, nil
		}
	}
	tk, err := p.api.MeshTicket(ctx, e.hostID)
	if err != nil {
		return nil, err
	}
	u, err := client.MeshURL(p.api.Base, e.hostID, tk.Value)
	if err != nil {
		return nil, err
	}
	s, err := mesh.Dial(ctx, u.String(), p.ws, mesh.Options{OnClose: func(ci mesh.CloseInfo) {
		fmt.Fprintf(p.stderr, "mesh_close host=%s stream=%d reason=%s bytes_in=%d bytes_out=%d\n", agent, ci.Stream, ci.Reason, ci.BytesIn, ci.BytesOut)
	}})
	if err != nil {
		return nil, err
	}
	e.session = s
	fmt.Fprintf(p.stderr, "mesh_session host=%s state=up session=%s\n", agent, s.ID())
	go func() {
		<-s.Done()
		reason := "closed"
		if err := s.Err(); err != nil {
			reason = err.Error()
		}
		fmt.Fprintf(p.stderr, "mesh_session host=%s state=down reason=%s\n", agent, reason)
	}()
	return s, nil
}

func (p *sessions) report(agent string, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	fmt.Fprintf(p.stderr, "mesh_error host=%s code=%s\n", agent, codeOf(err))
}

func (p *sessions) closeAll() {
	p.mu.Lock()
	entries := make([]*entry, 0, len(p.hosts))
	for _, e := range p.hosts {
		entries = append(entries, e)
	}
	p.mu.Unlock()
	for _, e := range entries {
		e.mu.Lock()
		s := e.session
		e.mu.Unlock()
		if s != nil {
			_ = s.Close()
		}
	}
}

// codeOf turns an error into one printable code word. A message that could
// carry a URL or a ticket is replaced.
func codeOf(err error) string {
	var se *mesh.StatusError
	var ce *client.Error
	var tk *client.TicketError
	var re *client.ResolveError
	switch {
	case errors.As(err, &se):
		return se.Code
	case errors.As(err, &ce):
		return ce.Code
	case errors.As(err, &tk):
		if tk.Code != "" {
			return tk.Code
		}
		if tk.Status == http.StatusTooManyRequests {
			return "rate_limited"
		}
		if tk.Status == http.StatusUnauthorized || tk.Status == http.StatusForbidden {
			return "scope_denied"
		}
		return "ticket_invalid"
	case errors.As(err, &re):
		if re.Code != "" {
			return re.Code
		}
		return "resolve_failed"
	case errors.Is(err, socks.ErrNotAllowed):
		return "not_allowed"
	}
	msg := err.Error()
	if strings.Contains(msg, "ticket=") || strings.Contains(msg, "://") || strings.ContainsAny(msg, " \n") {
		return "mesh_connection_failed"
	}
	return msg
}

func signalContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		select {
		case <-ch:
			cancel()
		case <-done:
		}
	}()
	return ctx, func() {
		signal.Stop(ch)
		close(done)
		cancel()
	}
}
