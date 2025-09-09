import express from 'express';
import path from 'path';
import fs from 'fs';

const app = express();
const port = process.env.PORT || 3000;

// Resolve dist relative to the current working directory to match Render's build location
const distDir = path.resolve(process.cwd(), 'dist');

// Serve static assets if available
if (fs.existsSync(distDir)) {
  app.use(express.static(distDir, { maxAge: '1d' }));
} else {
  console.warn('[server] dist directory not found at', distDir);
}

// Basic health check
app.get('/health', (req, res) => {
  res.json({ ok: true, uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// Debug: show which env vars are present (does NOT reveal secret values)
app.get('/api/env', (req, res) => {
  const vars = [
    'SUPABASE_URL',
    'SUPABASE_ANON_KEY',
    'SUPABASE_SERVICE_KEY',
    'VITE_SUPABASE_URL',
    'VITE_SUPABASE_ANON_KEY',
    'OPENAI_API_KEY',
    'SMTP_HOST',
    'SMTP_USER',
    'SMTP_PASS'
  ];
  const result = {};
  for (const v of vars) result[v] = !!process.env[v];
  res.json({ ok: true, env: result });
});

// Debug: attempt a simple Supabase REST call to verify headers and connectivity
app.get('/api/test-supabase', async (req, res) => {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
  if (!SUPABASE_URL) return res.status(400).json({ ok: false, error: 'SUPABASE_URL missing on server' });
  try {
    const fetchRes = await fetch((SUPABASE_URL.endsWith('/') ? SUPABASE_URL.slice(0, -1) : SUPABASE_URL) + '/rest/v1/', {
      method: 'GET',
      headers: { apikey: SUPABASE_ANON_KEY || '', 'Content-Type': 'application/json' },
    });
    const text = await fetchRes.text().catch(() => '');
    return res.json({ ok: true, status: fetchRes.status, statusText: fetchRes.statusText, snippet: text.slice(0, 200) });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e && e.message ? e.message : e) });
  }
});

// Fallback to index.html for client-side routing
app.get('*', (req, res) => {
  const indexPath = path.join(distDir, 'index.html');
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  console.error('[server] index.html not found:', indexPath);
  res.status(500).send('Build not found. Run "npm run build" to generate the dist/ directory.');
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
  console.log(`[server] serving from ${distDir}`);
});
