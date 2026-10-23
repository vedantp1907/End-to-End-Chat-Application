// Offline self-test of the crypto layer (Node 20+): handshake, round-trip, tamper, replay-binding, bad signature.
import * as C from '../client/src/lib/crypto.js';
import assert from 'node:assert/strict';

const a = await C.generateIdentity(), b = await C.generateIdentity(), m = await C.generateIdentity();
const pa = await C.exportPublic(a), pb = await C.exportPublic(b), pm = await C.exportPublic(m);

const { handshake, keys: ka } = await C.createSession(a, { from: 'alice', to: 'bob', peerPublicKey: pb.publicKey });
const kb = await C.acceptSession(b, { from: 'alice', to: 'bob', ...handshake, peerSignKey: pa.signKey });

const env = await C.encryptMessage(ka, { from: 'alice', to: 'bob', text: 'hello bob 👋' });
assert.equal(await C.decryptMessage(kb, { ...env, from: 'alice', to: 'bob' }), 'hello bob 👋');
console.log('✓ handshake + AES/HMAC round trip');

const env2 = await C.encryptMessage(ka, { from: 'alice', to: 'bob', text: 'hello bob 👋' });
assert.notEqual(env.iv, env2.iv); assert.notEqual(env.ct, env2.ct);
console.log('✓ unique IV → different ciphertext for identical plaintext');

const flipped = Buffer.from(env.ct, 'base64'); flipped[0] ^= 1;
await assert.rejects(C.decryptMessage(kb, { ...env, ct: flipped.toString('base64'), from: 'alice', to: 'bob' }), /integrity/);
await assert.rejects(C.decryptMessage(kb, { ...env, from: 'bob', to: 'alice' }), /integrity/);
console.log('✓ modified ciphertext and reflected message are rejected by HMAC');

await assert.rejects(C.acceptSession(b, { from: 'alice', to: 'bob', ...handshake, peerSignKey: pm.signKey }), /bad-signature/);
await assert.rejects(C.acceptSession(b, { from: 'mallory', to: 'bob', ...handshake, peerSignKey: pa.signKey }), /bad-signature/);
console.log('✓ forged / re-attributed handshake is rejected');

/* stolen session key: a static key exposes past AND future messages; a new session key only protects what comes after */
const stolen = { aes: kb.aes, mac: kb.mac };                  // what an attacker who copied the key holds
const past = await C.encryptMessage(ka, { from: 'alice', to: 'bob', text: 'old secret' });
const later = await C.encryptMessage(ka, { from: 'alice', to: 'bob', text: 'later secret' });
assert.equal(await C.decryptMessage(stolen, { ...past, from: 'alice', to: 'bob' }), 'old secret');
assert.equal(await C.decryptMessage(stolen, { ...later, from: 'alice', to: 'bob' }), 'later secret');
const { keys: ka2 } = await C.createSession(a, { from: 'alice', to: 'bob', peerPublicKey: pb.publicKey });
const fresh = await C.encryptMessage(ka2, { from: 'alice', to: 'bob', text: 'after re-key' });
await assert.rejects(C.decryptMessage(stolen, { ...fresh, from: 'alice', to: 'bob' }), /integrity/);
assert.equal(await C.decryptMessage(stolen, { ...past, from: 'alice', to: 'bob' }), 'old secret');
console.log('✓ stolen key reads past and future messages (no forward secrecy); a new session key locks it out of later ones only');

const [s1, s2] = [await C.safetyNumber(pa, pb), await C.safetyNumber(pb, pa)];
assert.deepEqual(s1, s2);
console.log('✓ safety number matches on both sides:', s1.join(' '));
