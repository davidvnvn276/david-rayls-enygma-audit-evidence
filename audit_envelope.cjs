'use strict';

// Local format demonstration using ephemeral test-only keys, never live testnet ciphertexts.
const assert = require('node:assert/strict');
const {
  generateKeyPairSync, encapsulate, decapsulate, hkdfSync, randomBytes,
  createCipheriv, createDecipheriv,
} = require('node:crypto');

const LABEL = Buffer.from('enygma-audit-view-key-v1', 'utf8');
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const fixture = Buffer.from(Array.from({length: 64}, (_, n) => n));

function derive(secret) {
  return Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), LABEL, 32));
}

function protect(recipient, data) {
  const {sharedKey, ciphertext: capsule} = encapsulate(recipient);
  const nonce = randomBytes(NONCE_BYTES);
  const encoder = createCipheriv('aes-256-gcm', derive(sharedKey), nonce, {authTagLength: TAG_BYTES});
  encoder.setAAD(capsule);
  const encrypted = Buffer.concat([encoder.update(data), encoder.final()]);
  return {capsule, payload: Buffer.concat([nonce, encrypted, encoder.getAuthTag()])};
}

function open(priv, capsule, payload) {
  const secret = decapsulate(priv, capsule);
  const nonce = payload.subarray(0, NONCE_BYTES);
  const body = payload.subarray(NONCE_BYTES, -TAG_BYTES);
  const tag = payload.subarray(-TAG_BYTES);
  const decoder = createDecipheriv('aes-256-gcm', derive(secret), nonce, {authTagLength: TAG_BYTES});
  decoder.setAAD(capsule);
  decoder.setAuthTag(tag);
  return Buffer.concat([decoder.update(body), decoder.final()]);
}

function checkSynthetic() {
  const authorized = generateKeyPairSync('ml-kem-768');
  const unrelated = generateKeyPairSync('ml-kem-768');
  const a = protect(authorized.publicKey, fixture);
  const b = protect(authorized.publicKey, Buffer.alloc(64, 0x7b));
  assert.equal(a.capsule.length, 1088);
  assert.equal(a.payload.length, 92);
  assert.deepEqual(open(authorized.privateKey, a.capsule, a.payload), fixture);
  assert.throws(() => open(unrelated.privateKey, a.capsule, a.payload), /authenticate/i);
  const modified = Buffer.from(a.payload);
  modified[NONCE_BYTES] ^= 1;
  assert.throws(() => open(authorized.privateKey, a.capsule, modified), /authenticate/i);
  assert.throws(() => open(authorized.privateKey, b.capsule, a.payload), /authenticate/i);
  console.log('PASS: synthetic envelope opens with the matching key; wrong key, changed byte and a different capsule fail authentication.');
}

checkSynthetic();
