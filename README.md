# sahmesh

Loopback SOCKS5 proxy that reaches every host with a SystemAPI agent by name. An application dials `web1.sah:5432` and sahmesh carries the connection to `web1` over one multiplexed WebSocket per host. **sah** means Service Automation Hub. The hub encompasses the platform and the suite of utilities.

Version 0.1.0. Login stays `sahconnect login`. The wire contract is `~/development/systemapi.io/docs/sah-mesh-protocol.md`. The suite contract is `~/development/systemapi.io/docs/sah-suite.md`. The design is `docs/plans/2026-10-22-sahmesh-design.md`.

```bash
go install ./cmd/sahmesh
export SYSTEMAPI_URL=https://systemapi.example
sahmesh up                                   # prints 127.0.0.1:1080
sahmesh up --listen 127.0.0.1:1085 --route 10.0.0.0/24=gw1
curl --socks5-hostname 127.0.0.1:1080 http://web1.sah:8080/healthz
psql "host=db1.sah port=5432"                # with ALL_PROXY=socks5h://127.0.0.1:1080 or a SOCKS-aware client
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' web1.sah
```

Every flag and the name rules are in `docs/usage.md`.

- **Names.** `NAME.sah` is agent `NAME` with target `local`. An IPv4 or IPv6 literal is sent through the agent of its longest matching route. Nothing else is routed: no DNS is resolved, `localhost` and bare names are refused, and the SOCKS reply says so.
- **One socket per host.** A `mesh:open` ticket opens one WebSocket to a host. Every connection to that host is a stream on it, with its own signed lease, its own policy check, and its own audit rows. Streams have credit in both directions, so one stalled application stalls only its own stream.
- **Credentials.** The token file records the origin that issued it, and its bearer goes only to that origin. Otherwise `SYSTEMAPI_API_KEY` is sent as `X-API-Key`. Neither is printed, and neither goes in a URL. The ticket is the only query-string secret.
- **Transport.** Plain `http` and `ws` are accepted only for loopback. Everything else is TLS 1.3 with system CAs, no proxy, and no redirects.
- **Listener.** `127.0.0.1` or `::1` only. No authentication: the account that can reach loopback can already run sahmesh. CONNECT only; BIND and UDP are refused.
- **Config.** sahconnect's `config.toml` and token file, through `XDG_CONFIG_HOME`. Routes come from `--route` flags and `~/.config/sahmesh/routes.toml`, read with the same owner, mode, and symlink checks.

`internal/client`, `internal/config`, `internal/token`, `internal/secfile`, and `internal/target` are copied from sahlink (which copied them from sahconnect) and must not be weakened.

## What the client tests

The tests speak the contract to a fake mesh server and drive the proxy with a real SOCKS5 client. They check the client, not the server or the agent.

- A non-`.sah` name, `localhost`, a bare name, a loopback literal, a refused address class, and an IP with no route are refused before any frame is sent.
- A bind address other than loopback is refused.
- Two streams on one socket carry distinct bytes both ways.
- A stream error closes one local socket and leaves the other stream alive.
- The client never sends past its credit and resumes after `mesh_credit`; server bytes past the window drop the session with `protocol_error`.
- Stream ids strictly increase and are never reused; late frames for a closed id are ignored.
- Local EOF becomes `mesh_eof` and reads continue; a server `mesh_eof` becomes a local half-close.
- `mesh_end` and a session error fail every open stream with that code.
- A ticket error for another origin is never sent; no error string carries a ticket or a URL.
- Every refusal exits non-zero or answers SOCKS with one code.

## What the server contract owns

Not implemented here, and the tests do not pretend they are: target policy, scope checks, lease signing and renewal, caps, audit rows, and the agent's own allowlist. See `sah-mesh-protocol.md` §13.

## Next

`go test ./...`
