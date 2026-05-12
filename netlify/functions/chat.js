const fetch = global.fetch || require('node-fetch');

// Load local .env for development when available
try { require('dotenv').config(); } catch (e) {}

// Minimal rate limiter (process-limited; on serverless each instance is fresh)
const rateMap = new Map();
function rateLimit(key, limit = 60, windowMs = 60_000) {
  const now = Date.now();
  const rec = rateMap.get(key);
  if (!rec || now - rec.ts > windowMs) {
    rateMap.set(key, { count: 1, ts: now });
    return true;
  }
  if (rec.count < limit) {
    rec.count += 1;
    return true;
  }
  return false;
}

exports.handler = async function(event) {
  try {
    if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
    const body = JSON.parse(event.body || '{}');
    const message = String(body.message || '').slice(0, 3000);
    const memory = String(body.memory || '').slice(0, 20000);
    const botId = String(body.botId || '').trim();
    if (!message) return { statusCode: 400, body: JSON.stringify({ error: 'Empty message' }) };

    const ip = (event.headers['x-forwarded-for'] || event.headers['X-Forwarded-For'] || 'ip').split(',')[0];
    if (!rateLimit('chat:' + ip, 60, 60_000)) return { statusCode: 429, body: JSON.stringify({ error: 'Too Many Requests' }) };

    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
    // best-effort: log the chat attempt to security_logs (if configured)
    if (SUPABASE_URL && SERVICE_KEY) {
      try {
        const q = `${SUPABASE_URL.replace(/\/+$/,'')}/rest/v1/security_logs`;
        fetch(q, { method: 'POST', headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'CHAT', details: { len: message.length, hasMemory: !!memory } }) }).catch(() => null);
      } catch (e) {}
    }

    const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY;
    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    if (!OPENROUTER_KEY && !OPENAI_KEY) {
      return { statusCode: 200, body: JSON.stringify({ reply: "AI not configured on server. Please set OPENROUTER_API_KEY in your environment." }) };
    }

    const systemPrompt = `You are a technical assistant specialized in analyzing websites and diagnosing issues, bugs, and configuration problems. ONLY answer questions related to the website, its content, code, deployment, or configuration. If the user's question is not about the website or its issues, respond exactly: ":Sorry I can't answer that question since i am design to answer your questions about the issue/bugs or reports on the website."`;
    const userPrompt = `Memory:\n${memory}\n\nUser question:\n${message}\n\nIf an image was provided, note that: none\n\nProvide a concise, actionable diagnostic and suggested fixes. If you need to ask for more details, ask clearly. Limit the answer to 800 words.`;

    const useOpenRouter = !!OPENROUTER_KEY;
    const url = useOpenRouter
      ? 'https://openrouter.ai/api/v1/chat/completions'
      : 'https://api.openai.com/v1/chat/completions';

    const headers = useOpenRouter
      ? {
          'Authorization': `Bearer ${OPENROUTER_KEY}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': process.env.APP_URL || 'http://localhost:8080',
          'X-Title': 'NexaBot',
        }
      : { 'Authorization': `Bearer ${OPENAI_KEY}`, 'Content-Type': 'application/json' };

    const resp = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: useOpenRouter ? 'openai/gpt-4o-mini' : 'gpt-4o-mini',
        messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userPrompt }],
        max_tokens: 800
      }),
    });

    if (!resp.ok) return { statusCode: 200, body: JSON.stringify({ reply: 'AI request failed' }) };
    const j = await resp.json().catch(() => null);
    const reply = j?.choices?.[0]?.message?.content || '';
    return { statusCode: 200, body: JSON.stringify({ reply }) };
  } catch (e) {
    console.error(e);
    return { statusCode: 500, body: JSON.stringify({ error: 'Server error' }) };
  }
};
