# sahmesh design

Status: accepted 2026-10-22 (owner decisions in `~/development/systemapi.io/docs/sah-mesh-protocol.md` §15). This note says what sahmesh is, what it reuses, and what it refuses. The wire contract is `sah-mesh-protocol.md`; this file does not repeat it.

**sah** means Service Automation Hub. sahmesh is the many-to-many piece of the suite: a loopback SOCKS5 proxy that turns every host with a SystemAPI agent into a reachable name, over one multiplexed WebSocket per host.

## Why this shape

The suite is hub-and-spoke: one client, one control plane, one agent, one WebSocket per TCP connection, no host-to-host, no reverse. The original `IDEA.md` (2026-10-14) asked for tunnels, file transfer, protocol helpers, and a virtual network. Three of those exist now: `sahlink` forwards one port, `sahsync` and `sahxfer` move files, `sahconnect` is the shell. The one gap is the network: an application that dials many hosts and many ports without a `sahlink` per port.

Three facts made the design small:

1. The server↔agent hop is already multiplexed. `tcp.js` keeps 64 credit-windowed streams per agent socket. The agent needs no change.
2. Hosts cannot get inbound ports, and the TCP contract refuses reverse listeners. A userspace proxy on the operator's machine is the only network shape the suite allows.
3. A mesh stream can *be* a TCP session. Everything per stream (policy, lease, renewal, idle, byte cap, caps, audit) is `TcpChannels` code. The mesh adds stream ids, credit toward the client, and a session wrapper.

## Components

- **systemapi.io `playground/mesh.js`**: the `mesh:open` upgrade, `mesh_ready`, the stream table, strictly increasing ids, per-stream client credit (both directions, `CreditStream`), frame decode and encode, session re-check every 30 s, session idle and max timers, `mesh_start` and `mesh_end` rows. Each stream is started through `TcpChannels.startSession(client, …)` with a per-stream client view object in place of a WebSocket.
- **systemapi.io `playground/tcp.js`**: `open()` split into the upgrade path and `startSession()`. Sessions gain `purpose` (scope re-checked at renewal), `mesh` and `stream` (audit payload), and the per-stream credit hooks. No behaviour change for `tcp:open`.
- **systemapi.io `playground/channel.js`**: `ClientSink` takes an optional frame encoder and an optional send-credit ledger.
- **systemapi.io scope plumbing**: `mesh:open` in `authz.js` (ALL and OPERATOR), `channels.js` (purpose sets, scopes, binding-less validation, target policy per stream), `tickets.js` (no binding), `router.js` (purpose set, TCP budget).
- **sahmesh `internal/mesh`**: one `Session` per agent, lazily dialed, re-dialed after a drop; `Stream` is a `net.Conn`; credit both ways; every §3.2 violation drops the session.
- **sahmesh `internal/socks`**: SOCKS5 on loopback, no-auth, CONNECT only; `NAME.sah` and the route table decide the agent and target; contract errors map to SOCKS replies (§16).
- **sahmesh `internal/routes`**: `--route CIDR=AGENT` and `~/.config/sahmesh/routes.toml` through `secfile`.
- **sahmesh `internal/client`, `config`, `token`, `secfile`, `target`**: copied from sahlink; not weakened. Login stays `sahconnect login`.

## Data flow

1. `sahmesh up` binds `127.0.0.1:1080` and prints the address.
2. An app sends SOCKS5 CONNECT `web1.sah:5432`. sahmesh maps it to agent `web1`, target `local:5432`.
3. No session for `web1` yet: resolve the name, get a `mesh:open` ticket, dial `/api/v1/systems/mesh/<host_id>`, wait for `mesh_ready`.
4. `mesh_open` stream 1. The server validates the target, checks policy and caps, signs a `tcp` lease, sends `tcp_open` to the agent, answers `connecting` then `connected`.
5. sahmesh replies SOCKS success; bytes flow with 4-byte stream prefixes, inside credit both ways.
6. A second CONNECT to `web1.sah:22` is stream 2 on the same socket. A CONNECT to `db2.sah` opens a second session.
7. Local EOF is `mesh_eof`; target EOF is `mesh_eof` back and `CloseWrite`; both seen is `mesh_close closed`. A local reset is `mesh_close` from the client.

## Error handling

- A stream failure (`target_denied`, `connect_refused`, `cap_reached`) becomes one SOCKS failure reply and closes one local socket. The session and the other streams continue.
- A session failure or a §3.2 violation closes every local socket of that session; the next CONNECT re-dials with a new ticket.
- Every refusal prints one code word on stderr, never a ticket or URL.
- Fail closed everywhere: unknown target class, unparsable frame, credit overrun, scope loss.

## Testing

- Server: `tests/mesh.test.js` on the existing fake-agent rig, covering every §14 case that lives on the server; existing TCP tests must stay green unchanged.
- Client: a fake mesh server in Go for `internal/mesh`; a real SOCKS5 client against `internal/socks`; table tests for routes and name rules; negative tests for every §3.2 rule, loopback-only bind, and secret hygiene.
- Agent: untouched; its existing tests stand.

## Out of scope

Reverse listeners, DNS resolution, UDP, SOCKS authentication, a tun device, host-to-host without an agent hop, and any change to the agent.
