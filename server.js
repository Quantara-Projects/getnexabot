import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
const port = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve static assets from the Vite build (dist)
app.use(express.static(path.join(__dirname, 'dist'), { maxAge: '1d' }));

// Basic health check
app.get('/health', (req, res) => {
  res.json({ ok: true, uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// Fallback to index.html for client-side routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'), (err) => {
    if (err) {
      console.error('Error sending index.html', err);
      res.status(500).send('Server error');
    }
  });
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
