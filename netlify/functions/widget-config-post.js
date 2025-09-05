const crypto = require('crypto');
const fetch = global.fetch || require('node-fetch');

function verifyWidgetToken(token) {
  try {
    const widgetSecret = process.env.WIDGET_TOKEN_SECRET || 'local-widget-secret';
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const unsigned = parts[0] + '.' + parts[1];
    const sig = parts[2];
    const expected = crypto.createHmac('sha256', widgetSecret).update(unsigned).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return payload;
  } catch (e) { return null; }
}

exports.handler = async function(event) {
  try {
    if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
    const body = JSON.parse(event.body || '{}');
    const botId = String(body.botId || '').trim();
    const token = String(body.token || '').trim();
    if (!botId) return { statusCode: 400, body: JSON.stringify({ error: 'Missing botId' }) };

    const payload = verifyWidgetToken(token);
    if (!payload || payload.botId !== botId) return { statusCode: 401, body: JSON.stringify({ error: 'Invalid token' }) };

    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
    if (!SUPABASE_URL || !SERVICE_KEY) return { statusCode: 500, body: JSON.stringify({ error: 'Server misconfigured' }) };

    // Fetch chatbot config using service role key
    const q = `${SUPABASE_URL.replace(/\/+$/,'')}/rest/v1/chatbot_configs?bot_id=eq.${encodeURIComponent(botId)}&select=*`;
    const res = await fetch(q, { headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, 'Content-Type': 'application/json' } }).catch(() => null);
    if (!res || !res.ok) return { statusCode: 404, body: JSON.stringify({ error: 'Not found' }) };
    const data = await res.json().catch(() => []);
    const cfg = Array.isArray(data) && data.length > 0 ? data[0] : { settings: {} };
    return { statusCode: 200, body: JSON.stringify({ settings: cfg }) };
  } catch (e) {
    console.error(e);
    return { statusCode: 500, body: JSON.stringify({ error: 'Server error' }) };
  }
};
