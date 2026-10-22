# IDEA.md (history)

2026-10-14: sahmesh was proposed as "deep tunneling via sah, HTTP-driven virtual networks", with primitives for tunnels, file transfer, protocol helpers (rsync, scp, ssh, https, grpc, rdp), and a mesh status API on custom headers.

2026-10-22: scoped against the suite. Tunnels are sahlink, file transfer is sahsync and sahxfer, the shell is sahconnect, and RDP lines are `sahlink rdp`. Hosts take no inbound ports and reverse listeners are out of the TCP contract, so the "virtual network" became a loopback SOCKS5 proxy over one multiplexed WebSocket per host. The custom-header protocol was dropped for the suite's ticket, WebSocket, JSON-frame, and signed-lease shape, and a distinct `mesh:open` scope.

Design: `docs/plans/2026-10-22-sahmesh-design.md`. Contract: `~/development/systemapi.io/docs/sah-mesh-protocol.md`.
