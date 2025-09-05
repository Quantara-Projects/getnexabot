const fetch = global.fetch || require('node-fetch');

exports.handler = async function(event) {
  try {
    // Allow in development or when ALLOW_DEBUG=true
    if (process.env.NODE_ENV !== 'development' && process.env.ALLOW_DEBUG !== 'true') {
      return { statusCode: 404, body: JSON.stringify({ error: 'Not found' }) };
    }
    if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
    const body = JSON.parse(event.body || '{}');
    const url = String(body.url || '').trim();
    if (!url) return { statusCode: 400, body: JSON.stringify({ error: 'Missing url' }) };
    try {
      const u = new URL(url);
      if (!(u.protocol === 'http:' || u.protocol === 'https:')) return { statusCode: 400, body: JSON.stringify({ error: 'Invalid protocol' }) };
    } catch (e) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Invalid url' }) };
    }
    try {
      const r = await fetch(url, { headers: { 'User-Agent': 'NexaBotVerifier/1.0' } });
      if (!r || !r.ok) return { statusCode: 400, body: JSON.stringify({ error: 'Fetch failed', status: r ? r.status : 0 }) };
      const text = await r.text();
      return { statusCode: 200, body: JSON.stringify({ ok: true, url, snippet: text.slice(0, 20000) }) };
    } catch (e) {
      return { statusCode: 500, body: JSON.stringify({ error: 'Fetch error', message: String(e?.message || e) }) };
    }
  } catch (e) {
    console.error(e);
    return { statusCode: 500, body: JSON.stringify({ error: 'Server error' }) };
  }
};
