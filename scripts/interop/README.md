# Interop smoke test

Proves the Go client and the Node server agree on `sah-mesh-protocol.md` without a real host: it boots the systemapi control plane in-process with its HTTP routes, enrolls a scripted agent that relays `tcp_open` streams to a local HTTP server, runs `sahmesh up` against it, and drives it with curl. The scripted agent verifies no lease; this is a protocol check, not a security test.

```
SYSTEMAPI_DIR=~/development/systemapi.io scripts/interop/run.sh
```

Expect: two 200s, `big OK`, three curl exit 97 (SOCKS refusals), and an audit dump with `mesh_start`, per-stream `tcp_start`/`tcp_end` carrying `mesh` and `stream`, `mesh_end`, and `VERIFY {"ok":true,...}`. `sahmesh` exits 0: refused streams are stderr lines, not exit codes.
