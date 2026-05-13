const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json({ limit: '5mb' }));

const FUNCTIONS_DIR = path.join(__dirname, 'netlify', 'functions');

function loadHandlers() {
  const handlers = {};
  if (!fs.existsSync(FUNCTIONS_DIR)) return handlers;
  const files = fs.readdirSync(FUNCTIONS_DIR);
  for (const f of files) {
    if (!f.endsWith('.js')) continue;
    const name = f.replace(/\.js$/, '');
    try {
      const mod = require(path.join(FUNCTIONS_DIR, f));
      handlers[name] = mod.handler || mod.default || mod;
    } catch (e) {
      console.error('Failed to load function', f, e && e.message);
    }
  }
  return handlers;
}

const handlers = loadHandlers();

app.all('/.netlify/functions/:name', async (req, res) => {
  const name = req.params.name;
  const fn = handlers[name];
  if (!fn) return res.status(404).json({ error: 'Function not found' });

  const event = {
    httpMethod: req.method,
    headers: req.headers,
    queryStringParameters: req.query,
    body: typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {}),
    path: req.path,
  };

  try {
    const result = await fn(event, {});
    if (!result) return res.status(500).json({ error: 'No response from function' });
    const status = result.statusCode || 200;
    if (result.headers) {
      for (const k of Object.keys(result.headers)) res.setHeader(k, result.headers[k]);
    }
    const body = result.body == null ? '' : result.body;
    if (typeof body === 'string') {
      const trimmed = body.trim();
      if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        try { return res.status(status).json(JSON.parse(trimmed)); } catch (e) {}
      }
      return res.status(status).send(body);
    }
    return res.status(status).send(body);
  } catch (e) {
    console.error('Function execution error for', name, e && e.stack || e);
    return res.status(500).json({ error: 'Function execution error' });
  }
});

// Prefer adapters in `api/*.js` when available (supports ESM via dynamic import),
// otherwise fallback to the Netlify-style functions under `/.netlify/functions/:name`.
app.all('/api/:name', async (req, res) => {
  const name = req.params.name;
  const apiPath = path.join(__dirname, 'api', `${name}.js`);
  if (fs.existsSync(apiPath)) {
    try {
      const fileUrl = `file://${apiPath}`;
      const mod = await import(fileUrl);
      const handler = mod && (mod.default || mod.handler);
      if (typeof handler === 'function') return handler(req, res);
    } catch (e) {
      console.error('Failed to load api adapter', apiPath, e && e.message);
      // fallthrough to netlify handler
    }
  }

  // fallback: proxy to Netlify function handler
  const fn = handlers[name];
  if (!fn) return res.status(404).json({ error: 'Function not found' });
  const event = {
    httpMethod: req.method,
    headers: req.headers,
    queryStringParameters: req.query,
    body: typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {}),
    path: req.path,
  };
  try {
    const result = await fn(event, {});
    if (!result) return res.status(500).json({ error: 'No response from function' });
    const status = result.statusCode || 200;
    if (result.headers) {
      for (const k of Object.keys(result.headers)) res.setHeader(k, result.headers[k]);
    }
    const body = result.body == null ? '' : result.body;
    if (typeof body === 'string') {
      const trimmed = body.trim();
      if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        try { return res.status(status).json(JSON.parse(trimmed)); } catch (e) {}
      }
      return res.status(status).send(body);
    }
    return res.status(status).send(body);
  } catch (e) {
    console.error('Function execution error for', name, e && e.stack || e);
    return res.status(500).json({ error: 'Function execution error' });
  }
});

// Health and listing endpoints
app.get('/__functions', (req, res) => {
  const list = Object.keys(handlers).map((k) => ({ name: k, netlify: `/.netlify/functions/${k}`, api: `/api/${k}` }));
  res.json({ ok: true, functions: list });
});

const PORT = process.env.PORT || 8888;
app.listen(PORT, () => {
  console.log(`Local Netlify Functions server running on http://localhost:${PORT}`);
  console.log('Available endpoints:');
  for (const k of Object.keys(handlers)) console.log(`  POST http://localhost:${PORT}/.netlify/functions/${k}`);
  // list api adapters when present
  const apiDir = path.join(__dirname, 'api');
  if (fs.existsSync(apiDir)) {
    const apiFiles = fs.readdirSync(apiDir).filter((f) => f.endsWith('.js'));
    for (const f of apiFiles) {
      const name = f.replace(/\.js$/, '');
      console.log(`  POST http://localhost:${PORT}/api/${name}`);
    }
  }
  console.log('Health: GET http://localhost:' + PORT + '/__functions');
});
