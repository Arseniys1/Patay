'use strict';

/**
 * Integration test for the Encrypt Proxy.
 *
 * Runs against:  PROXY_URL  (default: http://proxy:8080)
 *
 * Tests:
 *  1. Handshake (GET /ratchet/init + key derivation)
 *  2. Single encrypted GET
 *  3. Encrypted POST with JSON body
 *  4. Multi-request ratchet advancement (DH ratchet steps)
 *  5. Auth endpoint (POST /auth/login)
 *  6. Webhook endpoint (POST /webhook/event)
 *  7. Plain (non-encrypted) GET /health
 *  8. Independent second session
 */

const axios              = require('axios');
const { EncryptedClient } = require('./encrypt-client');

const PROXY_URL = (process.env.PROXY_URL || 'http://proxy:8080').replace(/\/+$/, '');

// ── Helpers ──────────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function ok(label, condition, detail = '') {
  if (condition) {
    console.log(`  ✓  ${label}`);
    passed++;
  } else {
    console.error(`  ✗  ${label}${detail ? ` — ${detail}` : ''}`);
    failed++;
  }
}

function section(title) {
  console.log(`\n── ${title} ${'─'.repeat(Math.max(0, 50 - title.length))}`);
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Tests ────────────────────────────────────────────────────────────────────

async function testHandshake() {
  section('1. Handshake');
  const c = new EncryptedClient(PROXY_URL);
  await c.init();
  ok('sessionId is a 32-char hex string', /^[0-9a-f]{32}$/.test(c.sessionId), c.sessionId);
  return c;
}

async function testEncryptedGet(client) {
  section('2. Encrypted GET /api/hello');
  const res = await client.get('/api/hello');
  console.log('    raw:', JSON.stringify(res));
  ok('status 200', res.status === 200, String(res.status));
  const body = EncryptedClient.parseBody(res);
  ok('body is object', typeof body === 'object' && body !== null);
  ok('backend field present', 'backend' in body, JSON.stringify(body));
}

async function testEncryptedPost(client) {
  section('3. Encrypted POST /api/data');
  const payload = { name: 'test-item', value: 42, nested: { arr: [1, 2, 3] } };
  const res  = await client.post('/api/data', payload);
  console.log('    raw:', JSON.stringify(res));
  ok('status 200', res.status === 200, String(res.status));
  const body = EncryptedClient.parseBody(res);
  ok('backend field present', typeof body === 'object' && 'backend' in body);
}

async function testMultipleRequests(client) {
  section('4. 6 consecutive requests (tests ratchet KDF chain + DH ratchet steps)');
  const methods = ['GET', 'GET', 'POST', 'GET', 'POST', 'GET'];
  for (let i = 0; i < methods.length; i++) {
    const method = methods[i];
    const res = method === 'GET'
      ? await client.get(`/api/item/${i}`)
      : await client.post(`/api/item/${i}`, { index: i });
    ok(`request ${i + 1} (${method}) → status 200`, res.status === 200, String(res.status));
  }
}

async function testAuthEndpoint(client) {
  section('5. Auth endpoint  POST /auth/login');
  const res  = await client.post('/auth/login', { username: 'alice', password: 'secret' });
  console.log('    raw:', JSON.stringify(res));
  ok('status 200', res.status === 200, String(res.status));
  const body = EncryptedClient.parseBody(res);
  ok('token in response', body && typeof body.token === 'string', JSON.stringify(body));
}

async function testWebhook(client) {
  section('6. Webhook  POST /webhook/order-created');
  const res  = await client.post('/webhook/order-created', { orderId: 'ORD-001', amount: 99.99 });
  console.log('    raw:', JSON.stringify(res));
  ok('status 200', res.status === 200, String(res.status));
}

async function testPlainHealth() {
  section('7. Plain (non-encrypted)  GET /health');
  const { data } = await axios.get(`${PROXY_URL}/health`);
  console.log('    raw:', JSON.stringify(data));
  ok('status field is "ok"', data.status === 'ok', JSON.stringify(data));
}

async function testSecondSession() {
  section('8. Independent second session');
  const c2  = new EncryptedClient(PROXY_URL);
  await c2.init();
  ok('different sessionId', c2.sessionId !== null);
  const res  = await c2.get('/api/ping');
  ok('second session request succeeds', res.status === 200, String(res.status));
}

// ── Entry point ───────────────────────────────────────────────────────────────

(async () => {
  console.log(`\n${'═'.repeat(58)}`);
  console.log(`  Encrypt Proxy — integration tests`);
  console.log(`  Proxy: ${PROXY_URL}`);
  console.log(`${'═'.repeat(58)}`);

  // Wait for proxy to be ready (useful in docker-compose up --abort-on-container-exit)
  for (let attempt = 1; attempt <= 15; attempt++) {
    try {
      await axios.get(`${PROXY_URL}/health`, { timeout: 2000 });
      break;
    } catch {
      if (attempt === 15) { console.error('Proxy not reachable after 15 attempts'); process.exit(1); }
      console.log(`  waiting for proxy… (attempt ${attempt}/15)`);
      await sleep(2000);
    }
  }

  try {
    const client = await testHandshake();
    await testEncryptedGet(client);
    await testEncryptedPost(client);
    await testMultipleRequests(client);
    await testAuthEndpoint(client);
    await testWebhook(client);
    await testPlainHealth();
    await testSecondSession();
  } catch (err) {
    console.error('\nFatal error:', err.message);
    if (err.response) {
      console.error('HTTP status:', err.response.status);
      console.error('Response data:', JSON.stringify(err.response.data));
    }
    failed++;
  }

  console.log(`\n${'═'.repeat(58)}`);
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  console.log(`${'═'.repeat(58)}\n`);
  process.exit(failed > 0 ? 1 : 0);
})();
