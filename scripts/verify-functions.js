#!/usr/bin/env node
// Simple verifier script for local functions server
// Usage: node scripts/verify-functions.js

import 'dotenv/config';
import fetch from 'node-fetch';

const base = process.env.FUNCTIONS_URL || 'http://localhost:8888';

async function call(path, body) {
  try {
    const res = await fetch(base + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || { message: 'ping from verifier' }),
      timeout: 10000,
    });
    const text = await res.text();
    console.log(`-> ${path} [${res.status}]`);
    console.log(text.slice(0, 2000));
  } catch (e) {
    console.error(`-> ${path} failed:`, e && e.message ? e.message : e);
  }
}

(async () => {
  console.log('Verifying local functions at', base);
  await call('/api/chat', { message: 'hello from verifier' });
  await call('/.netlify/functions/chat', { message: 'hello from verifier' });
})();
