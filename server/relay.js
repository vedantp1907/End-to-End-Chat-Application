/**
 * Zero-knowledge relay.
 * - Accounts live in MongoDB (users only). The WebSocket requires a valid login token.
 * - The directory maps usernames to PUBLIC keys. No private keys, session keys or plaintext ever reach the server.
 * - Login proves key ownership with an RSA-OAEP challenge.
 * - Handshake and message envelopes are forwarded as-is: the server only sees ciphertext, IV and HMAC tag.
 * - Demo attacker (ALLOW_TAMPER_DEMO): can corrupt, drop or delay the next message of the user who armed it.
 * - Serves over TLS (https/wss) when certs exist.
 */
import express from 'express';
import http from 'http';
import https from 'https';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import { createAuth } from './auth.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const isB64 = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && /^[A-Za-z0-9+/]+=*$/.test(s);
const validSpki = (b64) => {
  try { crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' }); return true; }
  catch { return false; }
};

const ATTACKS = ['corrupt', 'drop', 'delay'];

export async function createRelay({ User, secret, keyFile, certFile, allowTamper = true, delayMs = 15000 }) {
  const useTLS = !!(keyFile && certFile && fs.existsSync(keyFile) && fs.existsSync(certFile));
  const users = new Map();   // username -> { publicKey, signKey, sock }
  const queues = new Map();  // username -> envelopes held for an offline user
  const relayLog = [];
  const attacks = new Map();   // username -> 'corrupt' | 'drop' | 'delay': what the demo attacker does to that user's NEXT message
  const timers = new Set();    // pending delayed deliveries

  // restore the public-key directory from the database
  for (const u of await User.find({ publicKey: { $ne: null } })) users.set(u.username, { publicKey: u.publicKey, signKey: u.signKey, sock: null });

  const auth = createAuth({ User, secret });
  const app = express();
  app.get('/api/health', (_req, res) => res.json({ ok: true, tls: useTLS }));
  app.use('/api/auth', auth.router);
  // Both demo endpoints need a valid login token. The log only shows traffic the caller sent or received.
  const requireAuth = (req, res, next) => {
    const payload = auth.verify((req.headers.authorization || '').replace(/^Bearer /, ''));
    if (!payload) return res.status(401).json({ error: 'Login required.' });
    req.username = payload.u;
    next();
  };
  app.get('/api/relay-log', requireAuth, (req, res) => res.json({
    entries: relayLog.filter((e) => e.from === req.username || e.to === req.username).slice(-40),
    armed: attacks.get(req.username) || null, delayMs, tamperAllowed: allowTamper, tls: useTLS,
  }));
  app.post('/api/tamper', requireAuth, express.json({ limit: '1kb' }), (req, res) => {
    if (!allowTamper) return res.status(403).json({ error: 'disabled' });
    const mode = req.body?.mode ?? 'corrupt';
    if (!ATTACKS.includes(mode)) return res.status(400).json({ error: 'Unknown attack.' });
    attacks.set(req.username, mode);
    res.json({ armed: mode });
  });
  const dist = path.join(root, 'client/dist');
  if (fs.existsSync(dist)) {
    app.use(express.static(dist));
    app.get('*', (_req, res) => res.sendFile(path.join(dist, 'index.html')));
  }

  const server = useTLS
    ? https.createServer({ key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) }, app)
    : http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 64 * 1024 });

  const send = (ws, obj) => ws.readyState === 1 && ws.send(JSON.stringify(obj));
  const directory = () => [...users].map(([username, u]) => ({ username, publicKey: u.publicKey, signKey: u.signKey, online: !!u.sock }));
  const broadcastPresence = () => {
    const msg = { type: 'presence', users: directory() };
    for (const u of users.values()) if (u.sock) send(u.sock, msg);
  };
  const fatal = (ws, message, code) => send(ws, { type: 'error', fatal: true, code, message });

  function log(env, delivered, note) {
    const clip = (s) => (s.length > 44 ? s.slice(0, 44) + '…' : s);
    relayLog.push({
      t: Date.now(), type: env.type, from: env.from, to: env.to, delivered, note, bytes: JSON.stringify(env).length,
      fields: Object.fromEntries(Object.entries(env).filter(([k]) => !['type', 'from', 'to'].includes(k)).map(([k, v]) => [k, clip(String(v))])),
    });
    if (relayLog.length > 200) relayLog.shift();
  }

  // Hand an envelope to its recipient now, or queue it if they are offline. Returns true when it was queued.
  function deliver(env, note) {
    const to = users.get(env.to);
    if (to?.sock) { send(to.sock, env); log(env, true, note); return false; }
    const q = queues.get(env.to) || [];
    if (q.length < 200) q.push(env);
    queues.set(env.to, q);
    log(env, false, note);
    return true;
  }

  function relay(from, m) {
    const to = users.get(m.to);
    if (!to || m.to === from) return null;
    let env;
    if (m.type === 'handshake') {
      if (!isB64(m.wrappedKey, 2000) || !isB64(m.sig, 2000) || !Number.isFinite(m.ts)) return null;
      env = { type: 'handshake', from, to: m.to, wrappedKey: m.wrappedKey, ts: m.ts, sig: m.sig };
    } else {
      if (!isB64(m.iv, 64) || !isB64(m.ct, 40000) || !isB64(m.tag, 64) || typeof m.id !== 'string' || !Number.isFinite(m.ts)) return null;
      env = { type: 'message', from, to: m.to, id: m.id.slice(0, 64), ts: m.ts, iv: m.iv, ct: m.ct, tag: m.tag };
    }

    // Demo: the relay turns active attacker for the next message of the user who armed it (one shot).
    const mode = m.type === 'message' && allowTamper ? attacks.get(from) : null;
    if (mode) attacks.delete(from);
    if (mode === 'drop') {                         // availability attack: discard silently, the sender still gets a normal ack
      log(env, false, 'DROPPED by the relay (attack demo). Neither user was told.');
      return { queued: false };
    }
    if (mode === 'delay') {                        // availability attack: hold the message back, then release it unchanged
      log(env, false, `HELD by the relay for ${delayMs / 1000} s (attack demo)`);
      const t = setTimeout(() => { timers.delete(t); deliver(env, 'released after the delay'); }, delayMs);
      timers.add(t);
      return { queued: false };
    }
    if (mode === 'corrupt') {                      // integrity attack: flip one bit of the ciphertext
      const b = Buffer.from(env.ct, 'base64'); b[0] ^= 0x01; env.ct = b.toString('base64');
    }
    return { queued: deliver(env, mode === 'corrupt' ? 'CORRUPTED by the relay (attack demo)' : undefined) };
  }

  wss.on('connection', (ws) => {
    const s = { user: null, nonce: null, pending: null };

    ws.on('message', async (raw) => {
      let m; try { m = JSON.parse(raw); } catch { return; }
      if (!m || typeof m.type !== 'string') return;
      try {
        if (m.type === 'hello') {
          const payload = auth.verify(String(m.token || ''));
          if (!payload) return fatal(ws, 'Your session has expired. Please log in again.', 'auth');
          if (!isB64(m.publicKey, 1500) || !isB64(m.signKey, 1500) || !validSpki(m.publicKey) || !validSpki(m.signKey)) return fatal(ws, 'Invalid public key.', 'key');
          const account = await User.findById(payload.sub);
          if (!account) return fatal(ws, 'This account no longer exists.', 'auth');
          if (users.get(account.username)?.sock) return fatal(ws, `"${account.username}" is already signed in in another window.`, 'dup');
          s.nonce = crypto.randomBytes(32);
          s.pending = { name: account.username, id: account._id, publicKey: m.publicKey, signKey: m.signKey };
          const enc = crypto.publicEncrypt(
            { key: crypto.createPublicKey({ key: Buffer.from(m.publicKey, 'base64'), format: 'der', type: 'spki' }), padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, s.nonce);
          return send(ws, { type: 'challenge', data: enc.toString('base64') });
        }

        if (m.type === 'challenge_response' && s.pending) {
          const got = Buffer.from(String(m.nonce || ''), 'base64');
          if (got.length !== 32 || !crypto.timingSafeEqual(got, s.nonce)) return fatal(ws, 'Key ownership check failed.', 'key');
          const { name, id, publicKey, signKey } = s.pending;
          s.pending = null; s.nonce = null;
          const prev = users.get(name);
          // A password-authenticated login on a new browser brings a new key. Store it; contacts get a "keys changed" warning.
          if (!prev || prev.publicKey !== publicKey || prev.signKey !== signKey) await User.updateOne({ _id: id }, { $set: { publicKey, signKey } });
          s.user = name;
          users.set(name, { publicKey, signKey, sock: ws });
          send(ws, { type: 'ready', you: name, users: directory() });
          for (const env of queues.get(name) || []) send(ws, env);
          queues.delete(name);
          return broadcastPresence();
        }

        if (!s.user) return;
        if (m.type === 'handshake' || m.type === 'message') {
          const r = relay(s.user, m);
          if (!r) return send(ws, { type: 'error', message: 'Could not deliver: unknown recipient or malformed message.' });
          if (m.type === 'message') send(ws, { type: 'ack', id: m.id, queued: r.queued });
        }
      } catch (e) {
        console.error('ws error:', e.message);
        fatal(ws, 'Server error. Try again.', 'server');
      }
    });

    ws.on('close', () => {
      if (!s.user) return;
      const u = users.get(s.user);
      if (u && u.sock === ws) { u.sock = null; broadcastPresence(); }
    });
  });

  return {
    server, useTLS,
    listen: (port) => new Promise((res) => server.listen(port, () => res(server.address().port))),
    close: () => new Promise((res) => { timers.forEach(clearTimeout); wss.clients.forEach((c) => c.terminate()); server.close(res); }),
  };
}
