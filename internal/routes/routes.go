// Package routes maps IP literal destinations to the agent that should dial
// them (the TCP contract's --via), for sahmesh's SOCKS proxy.
//
// Threats: a route is a standing permission for any local application to
// reach an address inside an agent's network, so the table is small, explicit
// and checked. Only CIDR prefixes with no host bits are accepted; the agent
// name must satisfy the suite host-name rule; prefixes inside the refused
// classes of sah-tcp-protocol.md §4 (loopback, link-local, unspecified,
// multicast, metadata, the v4-in-v6 ranges) and the two catch-all prefixes
// (0.0.0.0/0, ::/0) are refused so a route can never widen the policy the
// server enforces; a duplicate prefix is a startup error rather than a silent
// override. The routes file is read with the sahconnect config checks (no
// symlink, owner, no group or world write, parent directory the same,
// unknown keys refused, 64 KiB cap). Does NOT decide what the server or the
// agent allow; the destination still passes target.Check locally and the
// policy checks on the server for every stream.
package routes

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/afterdarksys/sahmesh/internal/client"
	"github.com/afterdarksys/sahmesh/internal/secfile"
)

// Codes.
const (
	CodeBad       = "bad_route"
	CodeDuplicate = "duplicate_route"
)

const maxRoutes = 1024

// Route is one prefix and the agent that dials inside it.
type Route struct {
	Prefix netip.Prefix
	Via    string
}

// Table is an ordered route table: longest prefix first.
type Table struct {
	routes []Route
}

// New returns an empty table.
func New() *Table { return &Table{} }

// Len is the number of routes.
func (t *Table) Len() int { return len(t.routes) }

// Routes returns a copy of the table, longest prefix first.
func (t *Table) Routes() []Route { return append([]Route(nil), t.routes...) }

var refused = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
		"100.100.100.200/32", "168.63.129.16/32",
		"::/96", "fe80::/10", "ff00::/8", "fd00:ec2::254/128", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Add appends one route. The prefix must be canonical (no host bits), not a
// catch-all, and outside every refused class.
func (t *Table) Add(prefix netip.Prefix, via string) error {
	if !prefix.IsValid() || prefix.Bits() == 0 || !client.ValidHostName(via) {
		return errors.New(CodeBad)
	}
	prefix = normalize(prefix)
	if prefix != prefix.Masked() {
		return errors.New(CodeBad)
	}
	for _, r := range refused {
		if r.Addr().Is4() == prefix.Addr().Is4() && (r.Overlaps(prefix)) {
			return errors.New(CodeBad)
		}
	}
	for _, r := range t.routes {
		if r.Prefix == prefix {
			return errors.New(CodeDuplicate)
		}
	}
	if len(t.routes) >= maxRoutes {
		return errors.New(CodeBad)
	}
	t.routes = append(t.routes, Route{Prefix: prefix, Via: via})
	sort.SliceStable(t.routes, func(i, j int) bool { return t.routes[i].Prefix.Bits() > t.routes[j].Prefix.Bits() })
	return nil
}

// AddFlag parses "CIDR=AGENT".
func (t *Table) AddFlag(spec string) error {
	eq := strings.IndexByte(spec, '=')
	if eq <= 0 || eq == len(spec)-1 || strings.Count(spec, "=") != 1 {
		return errors.New(CodeBad)
	}
	prefix, err := netip.ParsePrefix(spec[:eq])
	if err != nil {
		return errors.New(CodeBad)
	}
	return t.Add(prefix, spec[eq+1:])
}

// Lookup returns the agent for addr by longest prefix. IPv4-mapped IPv6 is
// matched as IPv4.
func (t *Table) Lookup(addr netip.Addr) (via string, ok bool) {
	if !addr.IsValid() {
		return "", false
	}
	addr = addr.Unmap()
	for _, r := range t.routes {
		if r.Prefix.Contains(addr) {
			return r.Via, true
		}
	}
	return "", false
}

func normalize(p netip.Prefix) netip.Prefix {
	a := p.Addr()
	if a.Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p
}

type file struct {
	Route []struct {
		CIDR string `toml:"cidr"`
		Via  string `toml:"via"`
	} `toml:"route"`
}

// LoadFile reads a routes file. A missing file is not an error. Every file
// check of the sahconnect config applies.
func (t *Table) LoadFile(path string) error {
	fh, st, err := secfile.OpenNoFollow(path, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("routes: %w", err)
	}
	defer fh.Close()
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("routes %s: refusing a group- or world-writable file (chmod go-w)", path)
	}
	if st.Size() > 64<<10 {
		return fmt.Errorf("routes %s: larger than 64 KiB", path)
	}
	if _, err := secfile.CheckDir(filepath.Dir(path), true); err != nil {
		return fmt.Errorf("routes %s: %w", path, err)
	}
	var f file
	md, err := toml.NewDecoder(io.LimitReader(fh, 64<<10)).Decode(&f)
	if err != nil {
		return fmt.Errorf("routes %s: %w", path, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, 0, len(und))
		for _, k := range und {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return fmt.Errorf("routes %s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	for _, r := range f.Route {
		prefix, perr := netip.ParsePrefix(r.CIDR)
		if perr != nil {
			return errors.New(CodeBad)
		}
		if err := t.Add(prefix, r.Via); err != nil {
			return err
		}
	}
	return nil
}

// Env abstracts os.Getenv for tests.
type Env func(string) string

// DefaultPath is $XDG_CONFIG_HOME/sahmesh/routes.toml, else
// ~/.config/sahmesh/routes.toml.
func DefaultPath(env Env) (string, error) {
	if x := env("XDG_CONFIG_HOME"); x != "" {
		if !filepath.IsAbs(x) {
			return "", errors.New("XDG_CONFIG_HOME must be absolute")
		}
		return filepath.Join(x, "sahmesh", "routes.toml"), nil
	}
	home := env("HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil || h == "" {
			return "", errors.New("cannot find the home directory")
		}
		home = h
	}
	return filepath.Join(home, ".config", "sahmesh", "routes.toml"), nil
}
