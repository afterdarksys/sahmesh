# AGENTS.md

sahmesh is a loopback SOCKS5 proxy over the SystemAPI mesh channel. Version 0.1.0.

Usage: `docs/usage.md`. Wire contract: `~/development/systemapi.io/docs/sah-mesh-protocol.md`. Suite contract: `~/development/systemapi.io/docs/sah-suite.md`. Design: `docs/plans/2026-10-22-sahmesh-design.md`. Security rules: `~/development/ads-fable-utils/SECURITY-RULES.md`.

## Do this

1. Read `docs/usage.md` and the contract before changing a flag, a frame, or a reply code.
2. A change to framing, credit, the name rules, or the listener includes a negative test: a frame past the window, a reused stream id, a non-`.sah` name, a non-loopback bind, a refused address class. Done when `go vet ./... && go test ./...` reports ok.
3. A change to the wire format edits `sah-mesh-protocol.md` and the server in the same change, and the Wired join line in `sah-suite.md`.

## Rules

- The listener binds `127.0.0.1` or `::1` only. Do not add a flag for any other address. Do not add SOCKS authentication to justify one.
- CONNECT only. BIND and UDP ASSOCIATE answer `0x07`. Reverse listeners are out of the contract (TCP §10, mesh §10).
- Resolve no DNS. `NAME.sah` names an agent; an IP literal needs a route. Everything else is `0x02`. The server validates the target again; the local `target.Check` does not replace it.
- Never send a byte before `connected`, after your own `mesh_eof`, or past your send credit. Never return more credit than you were sent. Stream ids strictly increase and are never reused.
- Every server violation of §3.2 drops the session with `protocol_error`. Do not tolerate a frame the contract says is fatal.
- `internal/client`, `internal/config`, `internal/token`, `internal/secfile`, and `internal/target` are copied from sahlink. Do not weaken `DialGuard`, `ValidateWS`, the ticket checks, or the token-file checks. Do not add a second login. Login stays `sahconnect login`.
- Do not log a ticket or a WebSocket URL. A dial error says `mesh connection failed` or an HTTP status, not the URL.
- Routes files get the same owner, mode, and symlink checks as the config. A duplicate CIDR is a startup error, not a warning.
- Fail closed: an unknown frame type is ignored and logged, everything else malformed ends the stream or the session.

## Next

`go vet ./... && go test ./...`
