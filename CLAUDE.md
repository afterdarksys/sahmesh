# CLAUDE.md

Read `AGENTS.md`. It wins if this file disagrees.

sahmesh is a loopback SOCKS5 proxy: `NAME.sah:PORT` reaches a SystemAPI host over one multiplexed WebSocket per host. It resolves no DNS, binds loopback only, speaks CONNECT only, and opens no reverse listener. The wire contract is `~/development/systemapi.io/docs/sah-mesh-protocol.md`. The suite contract is `~/development/systemapi.io/docs/sah-suite.md`.

## Next

`go vet ./... && go test ./...`
