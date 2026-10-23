// End-to-end test: accounts, token-gated WebSocket, signed handshake, encrypted chat, tamper detection.
// Runs the real relay in-process. MongoDB is replaced by an in-memory stand-in exposing the same few methods the server uses.
import WebSocket from 'ws';
import assert from 'node:assert/strict';
import * as C from '../client/src/lib/crypto.js';
import { createRelay } from '../server/relay.js';
import { migrate } from '../server/migrate.js';

class FakeUser {
  static docs = [];
  static matches(d, q) {
    if (q.$or) return q.$or.some((c) => FakeUser.matches(d, c));
    return Object.entries(q).every(([k, v]) => (v && typeof v === 'object' && '$ne' in v ? d[k] != null : String(d[k]) === String(v)));
  }
  static async create(o) {
    for (const k of ['username', 'email']) if (FakeUser.docs.some((d) => d[k] === o[k])) throw Object.assign(new Error('E11000'), { code: 11000, keyPattern: { [k]: 1 } });
    const d = { _id: String(FakeUser.docs.length + 1), publicKey: null, signKey: null, ...o };
    FakeUser.docs.push(d); return d;
  }
  static async findOne(q) { return FakeUser.docs.find((d) => FakeUser.matches(d, q)) || null; }
  static async findById(id) { return FakeUser.docs.find((d) => d._id === String(id)) || null; }
  static async find(q) { return FakeUser.docs.filter((d) => FakeUser.matches(d, q)); }
  static collection = { async updateMany() { for (const d of FakeUser.docs) delete d.usernameLower; } };
  static async updateOne(q, u) { Object.assign(FakeUser.docs.find((d) => d._id === String(q._id)), u.$set); }
}

FakeUser.docs.push({ _id: '0', username: 'LegacyUser', usernameLower: 'legacyuser', email: 'legacy@example.com', passwordHash: 'x', publicKey: null, signKey: null });
await migrate(FakeUser);
assert.equal(FakeUser.docs[0].usernameLower, undefined);
console.log('✓ migration removes the leftover usernameLower field');

const DELAY = 600;
const relay = await createRelay({ User: FakeUser, secret: 'x'.repeat(48), delayMs: DELAY });
const port = await relay.listen(0);
const BASE = `127.0.0.1:${port}`;
const post = (p, body) => fetch(`http://${BASE}/api/auth/${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const ok = (m) => console.log('✓', m);

/* ---------- accounts ---------- */
const sfx = Math.random().toString(36).slice(2, 6);
const signup = (u, e = `${u}@example.com`, p = 'correct horse battery') => post('signup', { username: u, email: e, password: p });

let r = await signup('Bad Name!', 'nope', 'short');
assert.equal(r.status, 400); const bad = await r.json();
assert.ok(bad.fields.username && bad.fields.email && bad.fields.password);
ok('signup validation rejects bad username, email and password');

const aliceName = `Alice_${sfx}`, bobName = `Bob_${sfx}`;
r = await signup(aliceName); assert.equal(r.status, 201); const aliceAcct = await r.json();
assert.ok(aliceAcct.token && !JSON.stringify(aliceAcct).includes('passwordHash'));
r = await signup(bobName); const bobAcct = await r.json();
ok('signup creates accounts and returns a token');

assert.equal((await signup(aliceName, 'other@example.com')).status, 409);
assert.equal((await signup('someone_else', `${aliceName}@example.com`)).status, 409);
ok('exact duplicate username and duplicate email are rejected');

r = await post('signup', { username: aliceName.toUpperCase(), email: 'upper@example.com', password: 'correct horse battery' });
assert.equal(r.status, 201);
r = await post('signup', { username: `MixedCase_${sfx}`, email: 'mixed@example.com', password: 'correct horse battery' });
assert.equal((await r.json()).user.username, `MixedCase_${sfx}`);
r = await signup(`mixedCASE_${sfx}`, 'mixed2@example.com'); assert.equal(r.status, 201);
assert.equal((await r.json()).user.username, `mixedCASE_${sfx}`);
r = await post('login', { identifier: `MixedCase_${sfx}`, password: 'correct horse battery' }); assert.equal(r.status, 200);
assert.equal((await r.json()).user.username, `MixedCase_${sfx}`);
r = await post('login', { identifier: `MIXEDCASE_${sfx}`, password: 'correct horse battery' }); assert.equal(r.status, 401);
r = await signup(`MixedCase_${sfx}`, 'mixed3@example.com'); assert.equal(r.status, 409);
ok('usernames are case-sensitive: Sam and sam are separate accounts, exact name required to log in, exact duplicate rejected');

const stored = FakeUser.docs.find((d) => d.username === aliceName);
assert.ok(stored.passwordHash.startsWith('$2') && !JSON.stringify(stored).includes('correct horse'));
ok('password is stored only as a bcrypt hash');

r = await post('login', { identifier: aliceName, password: 'wrong password!' }); assert.equal(r.status, 401);
const e1 = (await r.json()).error;
r = await post('login', { identifier: 'nobody_here', password: 'whatever123' }); assert.equal(r.status, 401);
assert.equal((await r.json()).error, e1);
ok('wrong password and unknown user give the same generic error');

r = await post('login', { identifier: `${aliceName}@example.com`, password: 'correct horse battery' }); assert.equal(r.status, 200);
r = await post('login', { identifier: { $ne: '' }, password: { $ne: '' } }); assert.notEqual(r.status, 200);
ok('login works with email; NoSQL-operator payload does not log in');

r = await fetch(`http://${BASE}/api/auth/me`, { headers: { Authorization: `Bearer ${aliceAcct.token}` } }); assert.equal((await r.json()).user.username, aliceName);
r = await fetch(`http://${BASE}/api/auth/me`, { headers: { Authorization: 'Bearer garbage' } }); assert.equal(r.status, 401);
ok('/me accepts a valid token and rejects a bad one');

/* ---------- websocket ---------- */
const connect = async (token, id) => {
  const pub = await C.exportPublic(id);
  const ws = new WebSocket(`ws://${BASE}/ws`);
  const q = [], waiters = [];
  ws.on('message', (d) => { const m = JSON.parse(d); const w = waiters.findIndex((x) => x.t === m.type); w >= 0 ? waiters.splice(w, 1)[0].r(m) : q.push(m); });
  const next = (t) => { const i = q.findIndex((m) => m.type === t); return i >= 0 ? Promise.resolve(q.splice(i, 1)[0]) : new Promise((res) => waiters.push({ t, r: res })); };
  await new Promise((res) => ws.on('open', res));
  ws.send(JSON.stringify({ type: 'hello', token, ...pub }));
  return { ws, pub, id, next, send: (o) => ws.send(JSON.stringify(o)) };
};
const join = async (token, id) => {
  const c = await connect(token, id);
  const ch = await c.next('challenge');
  c.send({ type: 'challenge_response', nonce: await C.answerChallenge(id, ch.data) });
  await c.next('ready'); return c;
};

const bad1 = await connect('not-a-token', await C.generateIdentity());
const err = await bad1.next('error'); assert.ok(err.fatal && err.code === 'auth'); bad1.ws.close();
ok('websocket refuses a missing/invalid token');

const idA = await C.generateIdentity(), idB = await C.generateIdentity();
const A = await join(aliceAcct.token, idA), B = await join(bobAcct.token, idB);
ok('both users authenticated: token + RSA-OAEP key-ownership challenge');

const dup = await connect(aliceAcct.token, await C.generateIdentity());
assert.equal((await dup.next('error')).code, 'dup'); dup.ws.close();
ok('same account cannot be online twice');

const { handshake, keys: ka } = await C.createSession(idA, { from: aliceName, to: bobName, peerPublicKey: B.pub.publicKey });
A.send({ type: 'handshake', to: bobName, ...handshake });
const hs = await B.next('handshake');
assert.equal(hs.from, aliceName);
const kb = await C.acceptSession(idB, { ...hs, to: bobName, peerSignKey: A.pub.signKey });
ok('signed handshake relayed; bob unwrapped the session key');

const e = await C.encryptMessage(ka, { from: aliceName, to: bobName, text: 'top secret plan' });
A.send({ type: 'message', to: bobName, ...e });
assert.equal(await C.decryptMessage(kb, await B.next('message')), 'top secret plan');
const bearer = (t) => ({ Authorization: `Bearer ${t}` });
assert.equal((await fetch(`http://${BASE}/api/relay-log`)).status, 401);
assert.equal((await fetch(`http://${BASE}/api/relay-log`, { headers: bearer('bad') })).status, 401);
assert.equal((await fetch(`http://${BASE}/api/tamper`, { method: 'POST' })).status, 401);
ok('relay-log and tamper endpoints reject requests without a valid token');
const log = await (await fetch(`http://${BASE}/api/relay-log`, { headers: bearer(aliceAcct.token) })).json();
assert.ok(!JSON.stringify(log).includes('top secret plan'));
assert.ok(!JSON.stringify(FakeUser.docs).includes('top secret plan'));
ok('message decrypted by bob; neither relay log nor database contain plaintext');

await fetch(`http://${BASE}/api/tamper`, { method: 'POST', headers: bearer(aliceAcct.token) });
const e2 = await C.encryptMessage(ka, { from: aliceName, to: bobName, text: 'pay alice $10' });
A.send({ type: 'message', to: bobName, ...e2 });
await assert.rejects(async () => C.decryptMessage(kb, await B.next('message')), /integrity/);
ok('relay-tampered message rejected by HMAC');

/* ---------- availability attacks: drop and delay ---------- */
const arm = async (mode) => (await fetch(`http://${BASE}/api/tamper`, { method: 'POST', headers: { ...bearer(aliceAcct.token), 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }) })).status;
assert.equal(await arm('explode'), 400);
const logNotes = async () => (await (await fetch(`http://${BASE}/api/relay-log`, { headers: bearer(aliceAcct.token) })).json()).entries.map((x) => x.note).filter(Boolean);

assert.equal(await arm('drop'), 200);
const dropped = await C.encryptMessage(ka, { from: aliceName, to: bobName, text: 'this never arrives' });
A.send({ type: 'message', to: bobName, ...dropped });
const after = await C.encryptMessage(ka, { from: aliceName, to: bobName, text: 'this one does' });
A.send({ type: 'message', to: bobName, ...after });
assert.equal(await C.decryptMessage(kb, await B.next('message')), 'this one does');   // the dropped message was never delivered
assert.ok((await logNotes()).some((n) => n.includes('DROPPED')));
ok('relay drops the next message silently; only the following message reaches bob (one-shot)');

assert.equal(await arm('delay'), 200);
const slow = await C.encryptMessage(ka, { from: aliceName, to: bobName, text: 'late but intact' });
const t0 = Date.now();
A.send({ type: 'message', to: bobName, ...slow });
const got = await B.next('message');
assert.ok(Date.now() - t0 >= DELAY - 50, 'delivered too early');
assert.equal(await C.decryptMessage(kb, got), 'late but intact');                      // delayed, not altered
assert.ok((await logNotes()).some((n) => n.includes('HELD')));
ok('relay delays the next message, then delivers it unchanged (integrity holds, timing does not)');

/* ---------- key persistence / rotation ---------- */
assert.equal(FakeUser.docs.find((d) => d.username === aliceName).publicKey, A.pub.publicKey);
A.ws.close(); await new Promise((res) => setTimeout(res, 100));
const idA2 = await C.generateIdentity();               // alice logs in from a new browser
const A2 = await join(aliceAcct.token, idA2);
assert.equal(FakeUser.docs.find((d) => d.username === aliceName).publicKey, (await C.exportPublic(idA2)).publicKey);
const pres = await B.next('presence');
ok('public key is saved on the account; a login with a new browser key replaces it and notifies contacts');

A2.ws.close(); B.ws.close(); await relay.close(); process.exit(0);
