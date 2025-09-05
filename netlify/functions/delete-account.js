const fetch = global.fetch || require('node-fetch');

exports.handler = async function(event) {
  try {
    if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
    const body = JSON.parse(event.body || '{}');
    const userId = String(body.userId || '').trim();
    if (!userId) return { statusCode: 400, body: JSON.stringify({ error: 'Missing userId' }) };

    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
    if (!SUPABASE_URL || !SERVICE_KEY) return { statusCode: 500, body: JSON.stringify({ error: 'Server misconfigured' }) };

    const tables = ['training_documents','chatbot_configs','domain_verifications','email_verifications','security_logs','user_settings','profiles','training_jobs'];
    let deleted = {};
    for (const t of tables) {
      try {
        const qurl = `${SUPABASE_URL.replace(/\/+$/,'')}/rest/v1/${t}?user_id=eq.${encodeURIComponent(userId)}`;
        const res = await fetch(qurl, { method: 'DELETE', headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` } }).catch(() => null);
        deleted[t] = res && res.ok ? true : false;
      } catch (e) { deleted[t] = false; }
    }

    // Attempt to delete auth user using admin endpoint
    try {
      const adminRes = await fetch(`${SUPABASE_URL.replace(/\/+$/,'')}/auth/v1/admin/users/${encodeURIComponent(userId)}`, { method: 'DELETE', headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` } }).catch(() => null);
      const deletedAuth = adminRes && adminRes.ok;
      return { statusCode: 200, body: JSON.stringify({ ok: true, deletedAuth, deleted }) };
    } catch (e) {
      return { statusCode: 200, body: JSON.stringify({ ok: true, deletedAuth: false, deleted }) };
    }
  } catch (e) {
    console.error(e);
    return { statusCode: 500, body: JSON.stringify({ error: 'Server error' }) };
  }
};
