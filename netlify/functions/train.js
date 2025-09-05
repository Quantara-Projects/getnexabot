const crypto = require('crypto');
const fetch = global.fetch || require('node-fetch');

function makeBotId(seed) {
  return 'bot_' + crypto.createHash('sha256').update(seed).digest('base64url').slice(0, 22);
}

exports.handler = async function(event) {
  try {
    if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
    const body = JSON.parse(event.body || '{}');
    const url = typeof body.url === 'string' ? body.url.trim() : '';
    const files = Array.isArray(body.files) ? body.files : [];
    if (!url && files.length === 0) return { statusCode: 400, body: JSON.stringify({ error: 'Provide url or files' }) };

    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
    if (!SUPABASE_URL || !SERVICE_KEY) return { statusCode: 500, body: JSON.stringify({ error: 'Server misconfigured' }) };

    const botSeed = (url || files.join(',')) + Date.now();
    const botId = makeBotId(botSeed);

    // Insert a training job record
    const payload = { bot_id: botId, source_url: url || null, files: files, status: 'queued', created_at: new Date().toISOString() };
    const resp = await fetch(`${SUPABASE_URL.replace(/\/+$/,'')}/rest/v1/training_jobs`, {
      method: 'POST',
      headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify(payload)
    }).catch((e) => { console.error('supabase insert error', e); return null; });

    if (!resp || !resp.ok) {
      console.error('failed to create training job');
      return { statusCode: 500, body: JSON.stringify({ error: 'Failed to create job' }) };
    }

    const j = await resp.json().catch(() => null);
    return { statusCode: 202, body: JSON.stringify({ jobId: botId, status: 'queued', raw: j }) };
  } catch (e) {
    console.error(e);
    return { statusCode: 500, body: JSON.stringify({ error: 'Server error' }) };
  }
};
