#!/bin/zsh
set -u
S=$(dirname "$0"); cd "$S"
export SYSTEMAPI_DIR=${SYSTEMAPI_DIR:-$HOME/development/systemapi.io}
WWW_PORT=18099; DENY_PORT=18100
nap() { python3 -c "import time; time.sleep($1)"; }
( cd www && python3 -m http.server $WWW_PORT --bind 127.0.0.1 >/dev/null 2>&1 ) & WWW=$!
ALLOW_PORT=$WWW_PORT node server.js > rig.log 2>&1 & RIG=$!
for i in $(seq 1 50); do grep -q '^ready port=' rig.log && break; nap 0.2; done
PORT=$(sed -n 's/^ready port=//p' rig.log | head -1)
echo "rig port=$PORT"
( cd "$S/../.." && go build -o "$S/sahmesh" ./cmd/sahmesh ) || exit 1
HOME_T=$(mktemp -d); export HOME=$HOME_T XDG_CONFIG_HOME=$HOME_T/.config
SYSTEMAPI_URL=http://127.0.0.1:$PORT SYSTEMAPI_API_KEY=op-key ./sahmesh up --listen 127.0.0.1:0 > mesh.out 2> mesh.err & MESH=$!
for i in $(seq 1 50); do [ -s mesh.out ] && break; nap 0.2; done
SOCKS=$(head -1 mesh.out); echo "socks=$SOCKS"
echo "--- curl 1 (allowed)"; curl -s --max-time 10 --socks5-hostname "$SOCKS" http://web1.sah:$WWW_PORT/index.html; echo " [rc=$?]"
echo "--- curl 2 (same host, second stream)"; curl -s --max-time 10 --socks5-hostname "$SOCKS" -o /dev/null -w 'http=%{http_code} bytes=%{size_download}\n' http://web1.sah:$WWW_PORT/; echo " [rc=$?]"
echo "--- curl 3 (port denied by policy)"; curl -s --max-time 10 --socks5-hostname "$SOCKS" http://web1.sah:$DENY_PORT/; echo " [rc=$? expect 97]"
echo "--- curl 4 (non-.sah name refused)"; curl -s --max-time 10 --socks5-hostname "$SOCKS" http://example.com/; echo " [rc=$? expect 97]"
echo "--- curl 5 (unknown host)"; curl -s --max-time 10 --socks5-hostname "$SOCKS" http://nohost.sah:$WWW_PORT/; echo " [rc=$? expect 97]"
echo "--- big transfer (1 MiB, exercises credit)"; head -c 1048576 /dev/urandom > www/big.bin; curl -s --max-time 30 --socks5-hostname "$SOCKS" http://web1.sah:$WWW_PORT/big.bin | cmp - www/big.bin && echo "big OK"
nap 0.5
kill -INT $MESH; wait $MESH; echo "sahmesh exit=$?"
echo "--- sahmesh stderr"; cat mesh.err
kill -TERM $RIG; wait $RIG
echo "--- audit"; sed -n '/^AUDIT/,$p' rig.log
kill $WWW 2>/dev/null; rm -rf "$HOME_T" www/big.bin
