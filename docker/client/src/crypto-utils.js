'use strict';

/**
 * Crypto helpers matching the Go encryptproxy implementation.
 *
 * Curve    : P-256 (prime256v1)
 * PubKey   : uncompressed 65 bytes = 04 || x || y, hex-encoded
 * kdfSK    : HKDF-SHA256(ikm=sharedSecret, salt="encryptserver-v1", info="aes-key")  → 32 B
 * kdfRK    : HKDF-SHA256(ikm=dhOutput,     salt=rootKey,             info="DoubleRatchetV1") → 64 B
 * kdfCK    : HMAC-SHA256(chainKey, [0x01]) → MK;  HMAC-SHA256(chainKey, [0x02]) → nextCK
 * Cipher   : AES-256-GCM, nonce=12 B random, AAD=JSON.stringify(header), tag=16 B separate
 */

const crypto = require('crypto');

// ── ECDH P-256 ────────────────────────────────────────────────────────────────

/**
 * Generate a P-256 key pair.
 * @returns {{ ecdh: crypto.ECDH, pubHex: string }}
 */
function generateDH() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  // getPublicKey() returns uncompressed format (04 || x || y), 65 bytes
  const pubHex = ecdh.getPublicKey('hex');
  return { ecdh, pubHex };
}

/**
 * ECDH shared secret (x-coordinate only, 32 bytes for P-256).
 * @param {crypto.ECDH} localECDH
 * @param {string}      remotePubHex  hex-encoded uncompressed P-256 public key
 * @returns {Buffer}
 */
function dhCompute(localECDH, remotePubHex) {
  const remotePub = Buffer.from(remotePubHex, 'hex');
  return localECDH.computeSecret(remotePub);
}

// ── KDF ───────────────────────────────────────────────────────────────────────

/**
 * Derive SK from ECDH shared secret.
 * HKDF-SHA256(ikm=sharedSecret, salt="encryptserver-v1", info="aes-key") → 32 B
 */
function kdfSK(sharedSecret) {
  return Buffer.from(
    crypto.hkdfSync(
      'sha256',
      sharedSecret,
      Buffer.from('encryptserver-v1'),
      Buffer.from('aes-key'),
      32,
    ),
  );
}

/**
 * Root-key KDF step.
 * HKDF-SHA256(ikm=dhOutput, salt=rootKey, info="DoubleRatchetV1") → 64 B → [newRK(32), newCK(32)]
 */
function kdfRK(rootKey, dhOutput) {
  const out = Buffer.from(
    crypto.hkdfSync(
      'sha256',
      dhOutput,
      rootKey,
      Buffer.from('DoubleRatchetV1'),
      64,
    ),
  );
  return { newRK: out.subarray(0, 32), newCK: out.subarray(32, 64) };
}

/**
 * Chain-key KDF step.
 * mk      = HMAC-SHA256(chainKey, [0x01])
 * nextCK  = HMAC-SHA256(chainKey, [0x02])
 */
function kdfCK(chainKey) {
  const ck = Buffer.from(chainKey);
  const mk     = crypto.createHmac('sha256', ck).update(Buffer.from([0x01])).digest();
  const nextCK = crypto.createHmac('sha256', ck).update(Buffer.from([0x02])).digest();
  return { mk, nextCK };
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

/**
 * Encrypt with AES-256-GCM.
 * Returns { ct, nonce, tag } — all Buffers; tag is 16 bytes, separate from ciphertext.
 */
function encryptAES(key, plaintext, aad) {
  const nonce  = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const ct  = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  return { ct, nonce, tag };
}

/**
 * Decrypt with AES-256-GCM.
 * @returns {Buffer} plaintext
 */
function decryptAES(key, ct, nonce, tag, aad) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

module.exports = { generateDH, dhCompute, kdfSK, kdfRK, kdfCK, encryptAES, decryptAES };
