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

// Fallback to index.html for client-side routing
app.get('*', (req, res) => {
  const indexPath = path.join(distDir, 'index.html');
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  // Helpful error when build is missing
  console.error('[server] index.html not found:', indexPath);
  res.status(500).send('Build not found. Run "npm run build" to generate the dist/ directory.');
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
  console.log(`[server] serving from ${distDir}`);
});
