'use strict';

/**
 * Double Ratchet session — Alice side (client).
 *
 * Mirrors the Go RatchetSession / InitBob / Encrypt / Decrypt logic exactly.
 * Alice = client (initiator), Bob = server.
 *
 * Wire format matches Go EncryptedPacket:
 *   { header: { dh, pn, n }, ciphertext, nonce, tag }   — all base64 except dh (hex)
 */

const { generateDH, dhCompute, kdfRK, kdfCK, encryptAES, decryptAES } = require('./crypto-utils');

const MAX_SKIP = 500;

class RatchetSession {
  constructor() {
    /** @type {Buffer} Root key */
    this.RK      = null;
    /** @type {Buffer} Sending chain key */
    this.CKs     = null;
    /** @type {Buffer} Receiving chain key */
    this.CKr     = null;
    /** @type {{ ecdh: import('crypto').ECDH, pubHex: string }} Current DH sending key pair */
    this.DHs     = null;
    /** @type {string} Last known remote DH public key (hex) */
    this.DHrHex  = null;
    /** @type {number} Sent messages counter */
    this.Ns      = 0;
    /** @type {number} Received messages counter */
    this.Nr      = 0;
    /** @type {number} Previous sending chain length */
    this.PN      = 0;
    /** @type {Map<string, Buffer>} Skipped message keys: "pubHex:N" → mk */
    this.Skipped = new Map();
  }

  /**
   * Alice initialization (client side).
   *
   * Matches the Signal spec "Alice init":
   *   1. RK = SK
   *   2. DHs = new P-256 key pair (Alice's ratchet key)
   *   3. DHrHex = serverRatchetPubHex
   *   4. Initial DH ratchet step → establish CKs
   *      dhOut = ECDH(DHs.priv, serverRatchet.pub)
   *      RK, CKs = kdfRK(SK, dhOut)
   *
   * @param {Buffer|Uint8Array} SK
   * @param {string}            serverRatchetPubHex  hex, server's ratchet public key
   */
  initAlice(SK, serverRatchetPubHex) {
    this.RK     = Buffer.from(SK);
    this.DHs    = generateDH();        // Alice's initial ratchet key pair
    this.DHrHex = serverRatchetPubHex;

    // Initial DH ratchet step: establish sending chain
    const dhOut            = dhCompute(this.DHs.ecdh, serverRatchetPubHex);
    const { newRK, newCK } = kdfRK(this.RK, dhOut);
    this.RK  = newRK;
    this.CKs = newCK;

    this.Ns = 0;
    this.Nr = 0;
    this.PN = 0;
    this.Skipped.clear();
  }

  /**
   * Encrypt plaintext, advance sending chain.
   * Returns an object matching Go EncryptedPacket (ready to JSON-encode).
   *
   * @param {string|Buffer} plaintext
   * @returns {{ header: {dh:string,pn:number,n:number}, ciphertext:string, nonce:string, tag:string }}
   */
  encrypt(plaintext) {
    if (!this.CKs) throw new Error('RatchetSession: no sending chain key — call initAlice first');

    const { mk, nextCK } = kdfCK(this.CKs);
    this.CKs = nextCK;

    const header = { dh: this.DHs.pubHex, pn: this.PN, n: this.Ns };
    this.Ns++;

    const aad              = Buffer.from(JSON.stringify(header));
    const buf              = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext);
    const { ct, nonce, tag } = encryptAES(mk, buf, aad);

    return {
      header,
      ciphertext: ct.toString('base64'),
      nonce:      nonce.toString('base64'),
      tag:        tag.toString('base64'),
    };
  }

  /**
   * Decrypt an incoming EncryptedPacket, advance receiving chain.
   * Mirrors Go RatchetSession.Decrypt exactly.
   *
   * @param {{ header:{dh:string,pn:number,n:number}, ciphertext:string, nonce:string, tag:string }} pkt
   * @returns {Buffer} plaintext
   */
  decrypt(pkt) {
    const { header } = pkt;
    const aad    = Buffer.from(JSON.stringify(header));
    const ct     = Buffer.from(pkt.ciphertext, 'base64');
    const nonce  = Buffer.from(pkt.nonce,      'base64');
    const tag    = Buffer.from(pkt.tag,        'base64');

    // 1. Check skipped message keys
    const skipKey = `${header.dh}:${header.n}`;
    if (this.Skipped.has(skipKey)) {
      const mk = this.Skipped.get(skipKey);
      this.Skipped.delete(skipKey);
      return decryptAES(mk, ct, nonce, tag, aad);
    }

    // 2. DH ratchet step if the remote key changed
    if (header.dh !== this.DHrHex) {
      this._skipMsgKeys(this.DHrHex, header.pn);
      this._dhRatchet(header.dh);
    }

    // 3. Skip out-of-order messages
    this._skipMsgKeys(header.dh, header.n);

    // 4. Advance receiving chain
    const { mk, nextCK } = kdfCK(this.CKr);
    this.CKr = nextCK;
    this.Nr++;

    return decryptAES(mk, ct, nonce, tag, aad);
  }

  /**
   * DH ratchet step — mirrors Go dhRatchet.
   *
   *  recv:  dhOut1 = ECDH(DHs, newDHrHex)
   *         rk1, CKr = kdfRK(RK, dhOut1)
   *  new DHs key pair
   *  send:  dhOut2 = ECDH(newDHs, newDHrHex)
   *         RK, CKs = kdfRK(rk1, dhOut2)
   *
   * @param {string} newDHrHex
   */
  _dhRatchet(newDHrHex) {
    this.PN = this.Ns;
    this.Ns = 0;
    this.Nr = 0;

    // Receiving ratchet step
    const dhOut1              = dhCompute(this.DHs.ecdh, newDHrHex);
    const { newRK: rk1, newCK: newCKr } = kdfRK(this.RK, dhOut1);

    // New DH sending key pair
    const newDHs = generateDH();

    // Sending ratchet step
    const dhOut2              = dhCompute(newDHs.ecdh, newDHrHex);
    const { newRK: rk2, newCK: newCKs } = kdfRK(rk1, dhOut2);

    this.DHrHex = newDHrHex;
    this.DHs    = newDHs;
    this.RK     = rk2;
    this.CKr    = newCKr;
    this.CKs    = newCKs;
  }

  /**
   * Buffer skipped message keys up to `until`.
   * @param {string|null} dhrHex
   * @param {number}      until
   */
  _skipMsgKeys(dhrHex, until) {
    if (!this.CKr || !dhrHex) return;
    if (this.Nr + MAX_SKIP < until) {
      throw new Error(`Too many skipped messages (${this.Nr} → ${until})`);
    }
    while (this.Nr < until) {
      const { mk, nextCK } = kdfCK(this.CKr);
      this.CKr = nextCK;
      this.Skipped.set(`${dhrHex}:${this.Nr}`, mk);
      this.Nr++;
    }
  }
}

module.exports = { RatchetSession };
