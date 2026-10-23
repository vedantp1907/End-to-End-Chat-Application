/**
 * All cryptography runs in the browser (Web Crypto API). The server never sees any of this key material.
 *
 *  Identity     : RSA-OAEP-3072 (key exchange) + RSA-PSS-3072 (signs handshakes). Private keys are non-extractable.
 *  Handshake    : initiator picks a random 256-bit static session key K, wraps it with the peer's RSA-OAEP public key
 *                 and signs the handshake, so the peer knows who it came from.
 *  Key schedule : HKDF-SHA256(K) -> AES-256 key + separate HMAC-SHA256 key (derived keys are non-extractable).
 *  Message      : AES-256-CBC with a fresh random 16-byte IV, then HMAC-SHA256 (encrypt-then-MAC) over
 *                 sender | recipient | id | timestamp | IV | ciphertext. Tag is verified before decrypting.
 *  Limitation   : K never changes, so there is NO forward secrecy and NO post-compromise security.
 */
const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();
const VERSION = 'e2ee-chat/v1';
const RSA = { modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };

export const b64 = (buf) => {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
};
export const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

/* ---------- identity ---------- */
export async function generateIdentity() {
  const enc = await subtle.generateKey({ name: 'RSA-OAEP', ...RSA }, false, ['encrypt', 'decrypt']);
  const sign = await subtle.generateKey({ name: 'RSA-PSS', ...RSA }, false, ['sign', 'verify']);
  return { enc, sign };
}
export async function exportPublic(id) {
  return {
    publicKey: b64(await subtle.exportKey('spki', id.enc.publicKey)),
    signKey: b64(await subtle.exportKey('spki', id.sign.publicKey)),
  };
}
const bundleString = (b) => `${b.publicKey}|${b.signKey}`;

/** Short fingerprint of a user's public keys, shown as groups of 4 hex characters. */
export async function fingerprint(bundle) {
  const h = hex(await subtle.digest('SHA-256', te.encode(bundleString(bundle)))).slice(0, 32);
  return h.match(/.{4}/g).join(' ');
}
/** Safety number: both users compute the same 6 groups of digits from the two key bundles. */
export async function safetyNumber(a, b) {
  const joined = [bundleString(a), bundleString(b)].sort().join('#');
  const d = new Uint8Array(await subtle.digest('SHA-256', te.encode(joined)));
  const v = new DataView(d.buffer);
  return Array.from({ length: 6 }, (_, i) => String(v.getUint32(i * 4) % 100000).padStart(5, '0'));
}

/** Login proof: the server encrypts a random nonce to our public key; only the private-key holder can read it. */
export async function answerChallenge(id, dataB64) {
  const nonce = await subtle.decrypt({ name: 'RSA-OAEP' }, id.enc.privateKey, unb64(dataB64));
  return b64(nonce);
}

/* ---------- session key ---------- */
async function deriveKeys(raw) {
  const ikm = await subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
  const base = { name: 'HKDF', hash: 'SHA-256', salt: te.encode(VERSION) };
  const aes = await subtle.deriveKey({ ...base, info: te.encode('aes-256-cbc') }, ikm, { name: 'AES-CBC', length: 256 }, false, ['encrypt', 'decrypt']);
  const mac = await subtle.deriveKey({ ...base, info: te.encode('hmac-sha256') }, ikm, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign', 'verify']);
  raw.fill(0);
  return { aes, mac };
}
const handshakeBytes = ({ from, to, ts, wrappedKey }) => te.encode(`handshake|${VERSION}|${from}|${to}|${ts}|${wrappedKey}`);

/** Initiator: create K, wrap it for the peer, sign the handshake. */
export async function createSession(id, { from, to, peerPublicKey }) {
  const raw = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const peer = await subtle.importKey('spki', unb64(peerPublicKey), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const wrappedKey = b64(await subtle.encrypt({ name: 'RSA-OAEP' }, peer, raw));
  const ts = Date.now();
  const sig = b64(await subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, id.sign.privateKey, handshakeBytes({ from, to, ts, wrappedKey })));
  return { handshake: { wrappedKey, ts, sig }, keys: await deriveKeys(raw) };
}
/** Responder: verify the sender's signature, then unwrap K. Throws if the signature is invalid. */
export async function acceptSession(id, { from, to, wrappedKey, ts, sig, peerSignKey }) {
  const vk = await subtle.importKey('spki', unb64(peerSignKey), { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
  const ok = await subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, vk, unb64(sig), handshakeBytes({ from, to, ts, wrappedKey }));
  if (!ok) throw new Error('bad-signature');
  const raw = new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, id.enc.privateKey, unb64(wrappedKey)));
  return deriveKeys(raw);
}

/* ---------- messages ---------- */
const macInput = ({ from, to, id, ts, iv, ct }) => concat(te.encode(`${VERSION}|${from}|${to}|${id}|${ts}|`), iv, ct);

export async function encryptMessage(keys, { from, to, text }) {
  const id = globalThis.crypto.randomUUID();
  const ts = Date.now();
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));        // unique IV for every message
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, keys.aes, te.encode(text)));
  const tag = await subtle.sign('HMAC', keys.mac, macInput({ from, to, id, ts, iv, ct }));
  return { id, ts, iv: b64(iv), ct: b64(ct), tag: b64(tag) };
}

/** Verifies the HMAC first (constant time), and only then decrypts. Throws 'integrity' on any modification. */
export async function decryptMessage(keys, env) {
  let iv, ct, tag;
  try { iv = unb64(env.iv); ct = unb64(env.ct); tag = unb64(env.tag); } catch { throw new Error('integrity'); }
  if (iv.length !== 16 || ct.length === 0 || ct.length % 16 !== 0) throw new Error('integrity');
  const ok = await subtle.verify('HMAC', keys.mac, tag, macInput({ from: env.from, to: env.to, id: env.id, ts: env.ts, iv, ct }));
  if (!ok) throw new Error('integrity');
  return td.decode(await subtle.decrypt({ name: 'AES-CBC', iv }, keys.aes, ct));
}
