// Command sahmesh is a loopback SOCKS5 proxy over the SystemAPI mesh channel
// (sah-mesh-protocol.md). Applications dial NAME.sah:PORT and reach the host
// whose agent is NAME, over one multiplexed WebSocket per host.
//
// Threats: see internal/socks (the listener), internal/mesh (the channel),
// internal/routes (the route table) and internal/client (credentials and
// TLS). This command adds: no ticket, bearer, API key or WebSocket URL is
// ever printed; a refusal is one code word on stderr; the listener address
// is validated before anything is dialed; Ctrl-C closes every session so
// the server sees mesh_close for every stream. Does NOT log in (that stays
// sahconnect login) and does NOT open any listener but the SOCKS one.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/afterdarksys/sahmesh/internal/routes"
)

const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func run(args []string, stdout, stderr io.Writer, env func(string) string) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, "sahmesh "+version)
		return 0
	case "help", "-h", "--help":
		usage(stderr)
		return 0
	case "up":
		return cmdUp(args[1:], stdout, stderr, env)
	}
	fmt.Fprintln(stderr, "usage")
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprint(w, `sahmesh `+version+` — SOCKS5 proxy over the SystemAPI mesh channel

  sahmesh up [--listen 127.0.0.1:1080] [--route CIDR=AGENT]... [--routes FILE]
  sahmesh version

Point an application at the printed address as a SOCKS5 proxy. A destination
NAME.sah:PORT reaches port PORT on the host whose agent is NAME. An IP literal
reaches that address through the agent of the matching --route. Nothing else
is routed. Login stays sahconnect login. See docs/usage.md.
`)
}

type upOpts struct {
	listen     string
	routesFile string
	table      *routes.Table
}

type usageError struct{ code string }

func (e usageError) Error() string { return e.code }

func parseUp(args []string) (*upOpts, error) {
	o := &upOpts{listen: "127.0.0.1:1080", table: routes.New()}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--listen":
			if i+1 >= len(args) {
				return nil, usageError{"usage"}
			}
			i++
			o.listen = args[i]
		case "--route":
			if i+1 >= len(args) {
				return nil, usageError{"usage"}
			}
			i++
			if err := o.table.AddFlag(args[i]); err != nil {
				return nil, usageError{err.Error()}
			}
		case "--routes":
			if i+1 >= len(args) {
				return nil, usageError{"usage"}
			}
			i++
			o.routesFile = args[i]
		default:
			return nil, usageError{"usage"}
		}
	}
	if !strings.Contains(o.listen, ":") {
		return nil, usageError{"bind_refused"}
	}
	return o, nil
}
