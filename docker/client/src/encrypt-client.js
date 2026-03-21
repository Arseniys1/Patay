'use strict';

/**
 * EncryptedClient — axios wrapper for the Encrypt Proxy.
 *
 * Protocol flow:
 *   1. GET /ratchet/init             → { sessionId, ecdhPublicKey, ratchetPublicKey }
 *   2. Compute ECDH shared secret    → derive SK via kdfSK
 *   3. Init Double Ratchet (Alice)   → establish sending chain
 *   4. Every request:
 *      POST /ratchet/api  X-Session-ID: <sessionId>
 *      body: { ecdhPublicKey (first req only), header, ciphertext, nonce, tag }
 *      response: { header, ciphertext, nonce, tag }  → decrypt → { status, headers, body }
 */

const axios   = require('axios');
const { generateDH, dhCompute, kdfSK } = require('./crypto-utils');
const { RatchetSession }               = require('./ratchet');

class EncryptedClient {
  /**
   * @param {string} proxyUrl  Base URL of the encrypt proxy, e.g. "http://proxy:8080"
   * @param {object} [opts]
   * @param {number} [opts.timeout=10000]   axios timeout ms
   */
  constructor(proxyUrl, opts = {}) {
    this._base    = proxyUrl.replace(/\/+$/, '');
    this._timeout = opts.timeout ?? 10_000;

    this._sessionId      = null;
    this._ratchet        = null;
    this._ecdhKeyPair    = null;
    this._isFirstRequest = true;
    this._initialized    = false;

    this._http = axios.create({ baseURL: this._base, timeout: this._timeout });
  }

  // ── Initialization ──────────────────────────────────────────────────────────

  /**
   * Perform the handshake with the proxy.
   * Must be called before any request.
   * @returns {this}
   */
  async init() {
    // 1. Generate client ECDH key pair
    this._ecdhKeyPair = generateDH();

    // 2. Fetch server public keys
    const { data } = await this._http.get('/ratchet/init');
    const { sessionId, ecdhPublicKey, ratchetPublicKey } = data;

    if (!sessionId || !ecdhPublicKey || !ratchetPublicKey) {
      throw new Error(`Invalid /ratchet/init response: ${JSON.stringify(data)}`);
    }
    this._sessionId = sessionId;

    // 3. ECDH key agreement → SK
    const sharedSecret = dhCompute(this._ecdhKeyPair.ecdh, ecdhPublicKey);
    const SK           = kdfSK(sharedSecret);

    // 4. Init Double Ratchet as Alice
    this._ratchet        = new RatchetSession();
    this._ratchet.initAlice(SK, ratchetPublicKey);
    this._isFirstRequest = true;
    this._initialized    = true;

    return this;
  }

  /** Session ID assigned by the server after init(). */
  get sessionId() { return this._sessionId; }

  // ── Encrypted request/response ─────────────────────────────────────────────

  /**
   * Send an encrypted request through the proxy.
   *
   * @param {object} opts
   * @param {string} opts.method    HTTP method (GET, POST, …)
   * @param {string} opts.path      Target path on the backend, e.g. "/api/users"
   * @param {object} [opts.headers] Extra headers to forward to the backend
   * @param {any}    [opts.body]    Request body (will be JSON-serialised)
   * @returns {Promise<{ status: number, headers: object, body: string }>}
   */
  async request({ method, path, headers = {}, body = null }) {
    if (!this._initialized) throw new Error('Call init() first');

    // Build the plaintext payload that the server will forward to the backend
    const encBody = {
      method:  method.toUpperCase(),
      path,
      headers,
      body: body != null ? JSON.stringify(body) : '',
    };

    // Encrypt with Double Ratchet
    const pkt = this._ratchet.encrypt(JSON.stringify(encBody));

    // Compose the API request
    const apiReq = { ...pkt };
    if (this._isFirstRequest) {
      // ecdhPublicKey is only required in the very first request
      apiReq.ecdhPublicKey = this._ecdhKeyPair.pubHex;
      this._isFirstRequest = false;
    }

    const { data: encResp } = await this._http.post('/ratchet/api', apiReq, {
      headers: { 'X-Session-ID': this._sessionId },
    });

    // Decrypt the response
    const plaintext = this._ratchet.decrypt(encResp);
    return JSON.parse(plaintext.toString('utf8'));
  }

  // ── Convenience methods ─────────────────────────────────────────────────────

  /** @returns {Promise<{ status, headers, body }>} */
  async get(path, headers = {}) {
    return this.request({ method: 'GET', path, headers });
  }

  /** @returns {Promise<{ status, headers, body }>} */
  async post(path, body, headers = {}) {
    return this.request({ method: 'POST', path, headers, body });
  }

  /** @returns {Promise<{ status, headers, body }>} */
  async put(path, body, headers = {}) {
    return this.request({ method: 'PUT', path, headers, body });
  }

  /** @returns {Promise<{ status, headers, body }>} */
  async delete(path, headers = {}) {
    return this.request({ method: 'DELETE', path, headers });
  }

  /**
   * Helper: decode the JSON body from a backend response.
   * Backend always returns body as a string; this parses it.
   * @param {{ body: string }} response
   */
  static parseBody(response) {
    if (typeof response.body === 'string' && response.body.length > 0) {
      try { return JSON.parse(response.body); } catch { /* fallthrough */ }
    }
    return response.body;
  }
}

module.exports = { EncryptedClient };
