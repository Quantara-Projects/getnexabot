const crypto = require('crypto');
const fetch = global.fetch || require('node-fetch');
const nodemailer = require('nodemailer');

exports.handler = async function(event) {
  try {
    if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
    const body = JSON.parse(event.body || '{}');
    const email = (body.email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { statusCode: 400, body: JSON.stringify({ error: 'Invalid email' }) };

    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
    const EMAIL_TOKEN_SECRET = process.env.EMAIL_TOKEN_SECRET || 'local-secret';

    if (!SUPABASE_URL || !SERVICE_KEY) {
      console.error('Supabase service key or URL not set');
      return { statusCode: 500, body: JSON.stringify({ error: 'Server misconfiguration' }) };
    }

    const token = crypto.randomBytes(32).toString('base64url');
    const tokenHash = crypto.createHash('sha256').update(token + EMAIL_TOKEN_SECRET).digest('base64');
    const expires = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();

    // Store token hash in Supabase
    const insertBody = [{ user_id: null, email, token_hash: tokenHash, expires_at: expires, used_at: null }];

    const resp = await fetch(`${SUPABASE_URL.replace(/\/+$/,'')}/rest/v1/email_verifications`, {
      method: 'POST',
      headers: {
        apikey: SERVICE_KEY,
        Authorization: `Bearer ${SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates'
      },
      body: JSON.stringify(insertBody)
    }).catch((e) => { console.error('supabase insert error', e); return null; });

    if (!resp || !resp.ok) {
      console.error('Failed inserting token into Supabase', resp && resp.status);
      // proceed — still return success to avoid leaking existence
    }

    // Send verification email via SMTP if configured
    const SMTP_HOST = process.env.SMTP_HOST;
    const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
    const SMTP_USER = process.env.SMTP_USER;
    const SMTP_PASS = process.env.SMTP_PASS;
    const EMAIL_FROM = process.env.EMAIL_FROM || 'NexaBot <no-reply@nexabot.ai>';
    const APP_URL = process.env.APP_URL || '';
    const verifyUrl = APP_URL ? `${APP_URL.replace(/\/+$/,'')}/api/verify-email?token=${encodeURIComponent(token)}` : `/api/verify-email?token=${encodeURIComponent(token)}`;

    if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
      try {
        const transporter = nodemailer.createTransport({ host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_PORT === 465, auth: { user: SMTP_USER, pass: SMTP_PASS } });
        const html = `<p>Click to verify: <a href="${verifyUrl}">${verifyUrl}</a></p>`;
        await transporter.sendMail({ to: email, from: EMAIL_FROM, subject: 'Verify your email', html });
      } catch (e) {
        console.error('sendMail error', e);
      }
    } else {
      console.warn('SMTP not configured; verification URL:', verifyUrl);
    }

    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (e) {
    console.error(e);
    return { statusCode: 500, body: JSON.stringify({ error: 'Server error' }) };
  }
};
