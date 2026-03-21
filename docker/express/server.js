const express = require('express');
const app = express();

app.use(express.json());
app.use(express.text());

// Log all requests
app.use((req, _res, next) => {
  console.log(`[express] ${req.method} ${req.path}`);
  next();
});

// API — returns request details
app.all('/api/*', (req, res) => {
  res.json({
    backend: 'express',
    method: req.method,
    path: req.path,
    query: req.query,
    body: req.body || null,
    timestamp: new Date().toISOString(),
  });
});

// Auth endpoint
app.post('/auth/login', (req, res) => {
  const { username } = req.body || {};
  res.json({
    backend: 'express',
    token: `fake-jwt-for-${username || 'anonymous'}`,
    expiresIn: 3600,
  });
});

app.put('/auth/refresh', (_req, res) => {
  res.json({ backend: 'express', token: 'refreshed-token', expiresIn: 3600 });
});

// Webhook endpoint
app.post('/webhook/*', (req, res) => {
  console.log('[express] webhook payload:', JSON.stringify(req.body));
  res.json({ backend: 'express', received: true, path: req.path });
});

// Health
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', backend: 'express', uptime: process.uptime() });
});

// Static files (plain proxy)
app.get('/static/*', (req, res) => {
  res.type('text/plain').send(`Static: ${req.path}`);
});

// Home page
app.get('/', (_req, res) => {
  res.type('html').send('<html><body><h1>Express Backend</h1><p>Encrypt Proxy test backend</p></body></html>');
});

const PORT = parseInt(process.env.PORT || '8090', 10);
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Express backend listening on :${PORT}`);
});
