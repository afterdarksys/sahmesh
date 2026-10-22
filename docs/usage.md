# sahmesh usage

Module `github.com/afterdarksys/sahmesh`. Version 0.1.0. One command does the work: `up`.

## Start the proxy

1. `sahmesh up` binds `127.0.0.1:1080` and prints the bound address on stdout. It needs `SYSTEMAPI_URL` (or `systemapi_url` in sahconnect's `config.toml`) and either the sahconnect token file for that origin or `SYSTEMAPI_API_KEY`.
2. `--listen ADDR` changes the address. `ADDR` is exactly `127.0.0.1:PORT` or `[::1]:PORT`; port `0` picks a free one and the printed line tells you which. `localhost`, `0.0.0.0`, `::`, other `127.x` addresses, and anything else are `bind_refused`, exit 2.
3. `--route CIDR=AGENT` sends IP literals in `CIDR` through agent `AGENT`. Repeat the flag for more routes. Longest prefix wins. A duplicate CIDR, across flags and the file, is `duplicate_route`, exit 2. An `AGENT` that is not a valid host name, a prefix with host bits set, a catch-all (`0.0.0.0/0`, `::/0`), or a prefix that overlaps loopback, link-local, multicast, cloud metadata, or the IPv4-in-IPv6 ranges is `bad_route`, exit 2. `NAME.sah` matching is case-insensitive on the suffix.
4. `--routes FILE` reads routes from a TOML file instead of the default `~/.config/sahmesh/routes.toml` (`XDG_CONFIG_HOME` is respected). A missing default file is fine; a missing file named with `--routes` is `routes_missing`, exit 2. The file is opened without following symlinks and must be a regular file owned by you or root, not group- or world-writable, in a directory that is not group- or world-writable. Unknown keys are refused.

```toml
[[route]]
cidr = "10.0.0.0/24"
via = "gw1"

[[route]]
cidr = "2001:db8::/32"
via = "gw6"
```

5. `sahmesh version` prints `sahmesh 0.1.0`. `sahmesh help` prints the usage.
6. Ctrl-C closes the listener and every session, sending `mesh_close` for every open stream, and exits 0. Stream and session outcomes are stderr lines, not exit codes. Exit 1 means sahmesh stopped on its own because the listener failed. Exit 2 is a usage or startup refusal.

## What a destination means

sahmesh is a SOCKS5 server. The destination in the CONNECT request decides where the stream goes. sahmesh never resolves DNS.

| Destination | Stream |
|---|---|
| `NAME.sah:PORT` | agent `NAME`, target `local:PORT` (the agent dials `127.0.0.1`) |
| IPv4 or IPv6 literal with a matching route | that route's agent, the literal as the target |
| any other domain name, `localhost`, a bare `NAME`, a loopback literal, a refused address class, an IP with no route | refused, SOCKS reply `0x02` |

`NAME` follows the suite host-name rule. The server validates the target again against the host's `tcp_policy`; a refusal there is also `0x02`.

Use a client that sends the name to the proxy (SOCKS5h, "remote DNS"): `curl --socks5-hostname`, `ALL_PROXY=socks5h://127.0.0.1:1080`, `ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p'`, Firefox with "Proxy DNS when using SOCKS v5". A client that resolves `web1.sah` itself will fail to resolve it, which is the intended outcome.

## SOCKS5 details

- Methods: no authentication (`0x00`) only. A client offering only other methods gets `0xFF`.
- Commands: CONNECT (`0x01`) only. BIND and UDP ASSOCIATE get `0x07`.
- Address types: IPv4, IPv6, and domain.
- The handshake must finish within 10 s.
- Success reply is `0x00` with bind address `0.0.0.0:0`.

Contract errors map to replies:

| Error | Reply |
|---|---|
| `target_denied`, `target_denied_agent`, `target_forbidden`, `bad_target`, `scope_denied`, no route, bad name | `0x02` not allowed by ruleset |
| `host_unreachable` | `0x04` host unreachable |
| `connect_refused` | `0x05` connection refused |
| `connect_timeout` | `0x06` TTL expired |
| everything else (`agent_offline`, `agent_unsupported`, `cap_reached`, `lease_required`, `protocol_error`, `internal`) | `0x01` general failure |

## Sessions and streams

- The first stream to an agent resolves its name, gets one `mesh:open` ticket, and opens one WebSocket. Later streams to the same agent share it. A dropped session is re-opened, with a new ticket, on the next stream.
- Each stream has its own signed lease, policy check, idle timeout, byte cap, and audit rows on the server. Server limits are in the contract §5; sahmesh does not change them.
- Credit runs per stream in both directions. A stalled application stalls only its own stream.
- A stream error closes one local socket. A session error, or a server frame the contract calls fatal, closes every local socket of that session.

## What stderr says

One line per event, no tickets, no URLs:

- `mesh_session host=NAME state=up session=msh_...`
- `mesh_session host=NAME state=down reason=REASON` (`closed` for an orderly stop)
- `mesh_close host=NAME stream=N reason=REASON bytes_in=N bytes_out=N`
- `mesh_error host=NAME code=CODE` for a stream that never reached `connected`, or a session that failed
- `mesh_ignored host=NAME type=TYPE` once per unknown frame type the server sent
- one code word for a startup refusal (`usage`, `bind_refused`, `bad_route`, `duplicate_route`, `routes_missing`), or the credential message sahconnect prints

## Scope

Opening a mesh needs the `mesh:open` scope. It is an operator scope and separate from `tcp:open`: an API key can hold either without the other. Losing the scope ends every stream and the session within a renewal.
