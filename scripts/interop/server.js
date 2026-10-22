'use strict';
// Interop smoke rig: real router + FleetManager + a scripted agent that
// relays tcp_open streams to 127.0.0.1:<port>. Test-only; no lease checks.
process.chdir(process.env.SYSTEMAPI_DIR);
const http = require('node:http');
const net = require('node:net');
const express = require(process.env.SYSTEMAPI_DIR + '/node_modules/express');
const WebSocket = require(process.env.SYSTEMAPI_DIR + '/node_modules/ws');
const FleetManager = require(process.env.SYSTEMAPI_DIR + '/playground/fleet');
const { mount } = require(process.env.SYSTEMAPI_DIR + '/controlplane/router');
const { MemoryRegistry } = require(process.env.SYSTEMAPI_DIR + '/controlplane/registry');
const { TEST_SEED, privateKeyFromSeed, rawPublicKey, buildSigner } = require(process.env.SYSTEMAPI_DIR + '/controlplane/keys');
const { OPERATOR } = require(process.env.SYSTEMAPI_DIR + '/controlplane/authz');

const HOST_A = '11111111-1111-4111-8111-111111111111';
const ALLOW_PORT = Number(process.env.ALLOW_PORT);

function opensshEd25519(raw32) {
  const name = Buffer.from('ssh-ed25519');
  const buf = Buffer.alloc(4 + name.length + 4 + 32);
  buf.writeUInt32BE(name.length, 0); name.copy(buf, 4);
  buf.writeUInt32BE(32, 4 + name.length); raw32.copy(buf, 4 + name.length + 4);
  return `ssh-ed25519 ${buf.toString('base64')} test@systemapi`;
}
function data(sid, bytes) {
  const id = Buffer.from(sid, 'latin1');
  return Buffer.concat([Buffer.from([id.length]), id, Buffer.from(bytes)]);
}

(async () => {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  const server = http.createServer(app);
  const fm = new FleetManager(server, null, 'systemapi', null);
  fm.env = { NODE_ENV: 'test' };
  const key = privateKeyFromSeed(TEST_SEED);
  fm.signer = buildSigner(key, rawPublicKey(key));
  fm.tickets = new Map();
  fm.registry = new MemoryRegistry({ NODE_ENV: 'test' });
  fm.metrics = { executionsTotal: { inc() {} } };
  fm.auditRetryDelaysMs = [10, 10];
  fm.verifyApiKey = async (k) => {
    if (k === 'op-key') return { key_id: 'ak_op', user_id: 'op-1' };
    if (k === 'agent-key') return { key_id: 'k1', user_id: 'admin-1' };
    return null;
  };
  mount(app, fm);
  const pub = opensshEd25519(fm.signer.publicKeyRaw);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  // Scripted agent.
  const ws = new WebSocket(`ws://127.0.0.1:${port}/api/v1/systems/stream`, { headers: {
    authorization: 'Bearer agent-key', 'x-systemapi-tenant': 'acme', 'x-systemapi-host-id': HOST_A,
    'x-systemapi-hostname': 'web1', 'x-systemapi-ssh-pubkey': pub, 'x-systemapi-capabilities': 'pty,tcp' } });
  const streams = new Map(); // sid -> {sock, credit, in, out}
  const send = (o) => ws.send(JSON.stringify(o));
  ws.on('message', (buf, isBinary) => {
    if (isBinary) {
      const b = Buffer.from(buf); const n = b[0]; const sid = b.toString('latin1', 1, 1 + n); const p = b.subarray(1 + n);
      const s = streams.get(sid); if (!s) return;
      s.out += p.length; s.sock.write(p); send({ type: 'tcp_credit', session_id: sid, bytes: p.length });
      return;
    }
    const m = JSON.parse(buf.toString());
    if (m.type === 'enrolled') {
      (async () => {
        await fm.registry.addMember('acme', 'op-1', 'operator', 'op@example');
        await fm.registry.setScopes('ak_op', OPERATOR);
        await fm.registry.setTenantChannelPolicy('acme', { tcp_policy: { allow: [{ local: true, ports: [ALLOW_PORT] }] } });
        console.log(`ready port=${port}`);
      })().catch((e) => { console.error('setup failed', e); process.exit(1); });
      return;
    }
    if (m.type === 'enroll_error') { console.log('enroll_error ' + JSON.stringify(m)); return; }
    if (m.type === 'tcp_open') {
      const sid = m.session_id; const s = { sock: null, credit: 256 * 1024, in: 0, out: 0, reason: 'closed' };
      const sock = net.connect({ host: '127.0.0.1', port: m.target.port });
      s.sock = sock; streams.set(sid, s);
      sock.on('connect', () => send({ type: 'tcp_status', session_id: sid, payload: { status: 'connected', peer: `127.0.0.1:${m.target.port}` } }));
      sock.on('data', (chunk) => {
        s.in += chunk.length; s.credit -= chunk.length;
        for (let i = 0; i < chunk.length; i += 65536) ws.send(data(sid, chunk.subarray(i, i + 65536)));
        if (s.credit <= 0) sock.pause();
      });
      sock.on('end', () => send({ type: 'tcp_eof', session_id: sid }));
      sock.on('error', (e) => { s.reason = e.code === 'ECONNREFUSED' ? 'connect_refused' : 'reset'; if (e.code === 'ECONNREFUSED') send({ type: 'tcp_status', session_id: sid, payload: { error: 'connect_refused' } }); });
      sock.on('close', () => { if (streams.delete(sid) && s.reason !== 'connect_refused') send({ type: 'tcp_closed', session_id: sid, payload: { reason: s.reason, bytes_in: s.in, bytes_out: s.out } }); });
      return;
    }
    const s = streams.get(m.session_id); if (!s) return;
    if (m.type === 'tcp_credit') { s.credit += m.bytes; if (s.credit > 0) s.sock.resume(); }
    if (m.type === 'tcp_eof') s.sock.end();
    if (m.type === 'tcp_stop') { s.reason = 'stopped'; s.sock.destroy(); }
  });
  process.on('SIGTERM', async () => {
    const rows = fm.registry.audit.map((r) => `${r.action} ${JSON.stringify(r.payload)}`);
    console.log('AUDIT\n' + rows.join('\n'));
    console.log('VERIFY ' + JSON.stringify(await fm.registry.verifyAudit()));
    process.exit(0);
  });
})().catch((e) => { console.error('rig failed', e); process.exit(1); });
