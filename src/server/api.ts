import type { Plugin } from 'vite';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

// Small JSON body parser with size limit
async function parseJson(req: any, limit = 1024 * 100) {
  return new Promise<any>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > limit) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        const json = raw ? JSON.parse(raw) : {};
        resolve(json);
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function json(res: any, status: number, data: any, headers: Record<string, string> = {}) {
  const body = JSON.stringify(data);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.end(body);
}

const isHttps = (req: any) => {
  const proto = (req.headers['x-forwarded-proto'] as string) || '';
  return proto === 'https' || (req.socket && (req.socket as any).encrypted);
};

function requireEnv(name: string) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} not set`);
  return v;
}

async function supabaseFetch(path: string, options: any, req: any) {
  const base = requireEnv('SUPABASE_URL');
  const anon = requireEnv('SUPABASE_ANON_KEY');
  const token = (req.headers['authorization'] as string) || '';
  const headers: Record<string, string> = {
    apikey: anon,
    'Content-Type': 'application/json',
  };
  if (token) headers['Authorization'] = token;
  return fetch(`${base}${path}`, { ...options, headers: { ...headers, ...(options?.headers || {}) } });
}

function makeBotId(seed: string) {
  return 'bot_' + crypto.createHash('sha256').update(seed).digest('base64url').slice(0, 22);
}

// Extract visible text from HTML (naive)
function extractTextFromHtml(html: string) {
  // remove scripts/styles
  const withoutScripts = html.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, ' ');
  const withoutStyles = withoutScripts.replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, ' ');
  // remove tags
  const text = withoutStyles.replace(/<[^>]+>/g, ' ');
  // decode HTML entities (basic)
  return text.replace(/&nbsp;|&amp;|&lt;|&gt;|&quot;|&#39;/g, (s) => {
    switch (s) {
      case '&nbsp;': return ' ';
      case '&amp;': return '&';
      case '&lt;': return '<';
      case '&gt;': return '>';
      case '&quot;': return '"';
      case '&#39;': return '\'';
      default: return s;
    }
  }).replace(/\s+/g, ' ').trim();
}

async function tryFetchUrlText(u: string) {
  try {
    const res = await fetch(u, { headers: { 'User-Agent': 'NexaBotCrawler/1.0' } });
    if (!res.ok) return '';
    const html = await res.text();
    return extractTextFromHtml(html);
  } catch (e) {
    return '';
  }
}

function chunkText(text: string, maxChars = 1500) {
  const paragraphs = text.split(/\n|\r|\.|\!|\?/).map(p => p.trim()).filter(Boolean);
  const chunks: string[] = [];
  let cur = '';
  for (const p of paragraphs) {
    if ((cur + ' ' + p).length > maxChars) {
      if (cur) { chunks.push(cur.trim()); cur = p; }
      else { chunks.push(p.slice(0, maxChars)); cur = p.slice(maxChars); }
    } else {
      cur = (cur + ' ' + p).trim();
    }
  }
  if (cur) chunks.push(cur.trim());
  return chunks;
}

async function embedChunks(chunks: string[]): Promise<number[][] | null> {
  const key = process.env.OPENAI_API_KEY;
  if (!key) return null;
  try {
    const resp = await fetch('https://api.openai.com/v1/embeddings', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: chunks, model: 'text-embedding-3-small' }),
    });
    if (!resp.ok) return null;
    const j = await resp.json();
    if (!j.data) return null;
    return j.data.map((d: any) => d.embedding as number[]);
  } catch (e) {
    return null;
  }
}

async function processTrainJob(jobId: string, body: any, req: any) {
  const url = body.url || '';
  const files: string[] = Array.isArray(body.files) ? body.files : [];
  const botSeed = (url || files.join(',')) + Date.now();
  const botId = makeBotId(botSeed);

  // gather texts
  const docs: { source: string; content: string }[] = [];

  if (url) {
    const text = await tryFetchUrlText(url);
    if (text) docs.push({ source: url, content: text });
  }

  // files are storage paths in bucket/training/...
  for (const path of files) {
    try {
      const SUPABASE_URL = process.env.SUPABASE_URL;
      const bucketPublicUrl = SUPABASE_URL + `/storage/v1/object/public/training/${encodeURIComponent(path)}`;
      const res = await fetch(bucketPublicUrl);
      if (!res.ok) continue;
      const buf = await res.arrayBuffer();
      // crude text extraction: if it's pdf or text
      const header = String.fromCharCode.apply(null, new Uint8Array(buf.slice(0, 8)) as any);
      if (header.includes('%PDF')) {
        // cannot parse PDF here; store placeholder
        docs.push({ source: path, content: '(PDF content -- processed externally)' });
      } else {
        const text = new TextDecoder().decode(buf);
        const cleaned = extractTextFromHtml(text);
        docs.push({ source: path, content: cleaned || '(binary file)' });
      }
    } catch (e) { continue; }
  }

  // chunk and embed
  for (const doc of docs) {
    const chunks = chunkText(doc.content);
    const embeddings = await embedChunks(chunks);

    // store documents and embeddings in Supabase
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      const emb = embeddings ? embeddings[i] : null;
      try {
        await supabaseFetch('/rest/v1/training_documents', {
          method: 'POST',
          body: JSON.stringify({ bot_id: botId, source: doc.source, content: chunk, embedding: emb }),
          headers: { Prefer: 'return=representation', 'Content-Type': 'application/json' },
        }, req).catch(() => null);
      } catch {}
    }
  }

  // mark job in logs
  try {
    await supabaseFetch('/rest/v1/security_logs', {
      method: 'POST',
      body: JSON.stringify({ action: 'TRAIN_JOB_COMPLETE', details: { jobId, botId, docs: docs.length } }),
    }, req).catch(() => null);
  } catch {}
}

async function ensureDomainVerification(domain: string, req: any) {
  // check domains table for verified
  try {
    const res = await supabaseFetch(`/rest/v1/domains?domain=eq.${encodeURIComponent(domain)}`, { method: 'GET' }, req);
    if (res && (res as any).ok) {
      const j = await (res as Response).json().catch(() => []);
      if (Array.isArray(j) && j.length > 0 && j[0].verified) return { verified: true };
    }
  } catch {}
  // create verification token entry
  const token = crypto.randomBytes(16).toString('base64url');
  const secret = process.env.DOMAIN_VERIFICATION_SECRET || 'local-dom-secret';
  const tokenHash = crypto.createHash('sha256').update(token + secret).digest('base64');
  const expires = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();
  try {
    await supabaseFetch('/rest/v1/domain_verifications', {
      method: 'POST',
      body: JSON.stringify({ domain, token_hash: tokenHash, expires_at: expires }),
      headers: { Prefer: 'resolution=merge-duplicates', 'Content-Type': 'application/json' },
    }, req).catch(() => null);
  } catch {}
  return { verified: false, token };
}

function verifyWidgetToken(token: string) {
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

// Simple in-memory rate limiter
const rateMap = new Map<string, { count: number; ts: number }>();
function rateLimit(key: string, limit: number, windowMs: number) {
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

export function serverApiPlugin(): Plugin {
  return {
    name: 'server-api-plugin',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url || !req.url.startsWith('/api/')) return next();

        // Basic security headers for all API responses
        const corsOrigin = req.headers.origin || '*';
        res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
        res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

        // In dev allow http; in prod (behind proxy), require https
        if (process.env.NODE_ENV === 'production' && !isHttps(req)) {
          return json(res, 400, { error: 'HTTPS required' }, { 'Access-Control-Allow-Origin': String(corsOrigin) });
        }

        // CORS preflight
        if (req.method === 'OPTIONS') {
          res.setHeader('Access-Control-Allow-Origin', String(corsOrigin));
          res.setHeader('Access-Control-Allow-Methods', 'POST,GET,OPTIONS');
          res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          res.statusCode = 204;
          return res.end();
        }

        const endJson = (status: number, data: any) => json(res, status, data, { 'Access-Control-Allow-Origin': String(corsOrigin) });

        try {
          if (req.url === '/api/train' && req.method === 'POST') {
            const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'ip';
            if (!rateLimit('train:' + ip, 20, 60_000)) return endJson(429, { error: 'Too Many Requests' });
            const body = await parseJson(req).catch(() => ({}));
            const url = typeof body?.url === 'string' ? body.url.trim() : '';
            if (!url && !Array.isArray(body?.files)) {
              return endJson(400, { error: 'Provide url or files' });
            }
            if (url) {
              try {
                const u = new URL(url);
                if (!(u.protocol === 'http:' || u.protocol === 'https:')) throw new Error('invalid');
              } catch {
                return endJson(400, { error: 'Invalid url' });
              }
            }

            // Log event
            await supabaseFetch('/rest/v1/security_logs', {
              method: 'POST',
              body: JSON.stringify({ action: 'TRAIN_REQUEST', details: { hasUrl: !!url, fileCount: (body?.files?.length) || 0 } }),
            }, req).catch(() => null);

            const jobId = makeBotId((url || '') + Date.now());

            // Start background processing (non-blocking)
            (async () => {
              try {
                await processTrainJob(jobId, { url, files: Array.isArray(body?.files) ? body.files : [] }, req);
              } catch (e) {
                try {
                  await supabaseFetch('/rest/v1/security_logs', {
                    method: 'POST',
                    body: JSON.stringify({ action: 'TRAIN_JOB_ERROR', details: { jobId, error: String(e?.message || e) } }),
                  }, req);
                } catch {}
              }
            })();

            return endJson(202, { jobId, status: 'queued' });
          }

          if (req.url === '/api/connect' && req.method === 'POST') {
            const body = await parseJson(req);
            if (body?.channel !== 'website') return endJson(400, { error: 'Unsupported channel' });
            const rawUrl = (body?.url || '').trim();
            const domain = (() => {
              try { return rawUrl ? new URL(rawUrl).host : 'local'; } catch { return 'local'; }
            })();

            // Ensure domain verification
            const vres = await ensureDomainVerification(domain, req);
            if (!vres.verified) {
              // return verification required and instructions
              return endJson(202, { status: 'verification_required', instructions: `Add a DNS TXT record or a meta tag with token: ${vres.token}`, token: vres.token });
            }

            const seed = domain + '|' + (req.headers['authorization'] || '');
            const botId = makeBotId(seed);

            // Upsert chatbot_configs (if RLS allows with user token)
            await supabaseFetch('/rest/v1/chatbot_configs', {
              method: 'POST',
              body: JSON.stringify({ bot_id: botId, channel: 'website', domain, settings: {} }),
              headers: { Prefer: 'resolution=merge-duplicates' },
            }, req).catch(() => null);

            // Create widget token (HMAC signed)
            const widgetPayload = { botId, domain, iat: Math.floor(Date.now()/1000) };
            const widgetSecret = process.env.WIDGET_TOKEN_SECRET || 'local-widget-secret';
            const header = { alg: 'HS256', typ: 'JWT' };
            const b64 = (s: string) => Buffer.from(s).toString('base64url');
            const unsigned = b64(JSON.stringify(header)) + '.' + b64(JSON.stringify(widgetPayload));
            const sig = crypto.createHmac('sha256', widgetSecret).update(unsigned).digest('base64url');
            const widgetToken = unsigned + '.' + sig;

            return endJson(200, { botId, widgetToken });
          }

          // Widget config endpoint: returns bot settings for widget consumers (requires token)
          if (req.url?.startsWith('/api/widget-config') && req.method === 'GET') {
            const urlObj = new URL(req.url, 'http://local');
            const botId = urlObj.searchParams.get('botId') || '';
            const token = urlObj.searchParams.get('token') || '';
            if (!botId) return endJson(400, { error: 'Missing botId' });
            const payload = verifyWidgetToken(token);
            if (!payload || payload.botId !== botId) return endJson(401, { error: 'Invalid token' });
            try {
              const r = await supabaseFetch('/rest/v1/chatbot_configs?bot_id=eq.' + encodeURIComponent(botId) + '&select=*', { method: 'GET' }, req).catch(() => null);
              if (!r || !(r as any).ok) return endJson(404, { error: 'Not found' });
              const data = await (r as Response).json().catch(() => []);
              const cfg = Array.isArray(data) && data.length > 0 ? data[0] : { settings: {} };
              return endJson(200, { settings: cfg });
            } catch (e) { return endJson(500, { error: 'Server error' }); }
          }

          if (req.url === '/api/verify-domain' && req.method === 'POST') {
            const body = await parseJson(req).catch(() => ({}));
            const domain = String(body?.domain || '').trim();
            const token = String(body?.token || '').trim();
            if (!domain || !token) return endJson(400, { error: 'Missing domain or token' });

            // Try multiple candidate URLs for verification (root, index.html, well-known)
            const candidates = [
              `https://${domain}`,
              `http://${domain}`,
              `https://${domain}/index.html`,
              `http://${domain}/index.html`,
              `https://${domain}/.well-known/nexabot-domain-verification`,
              `http://${domain}/.well-known/nexabot-domain-verification`,
            ];

            // Build robust regex to match meta tag in any attribute order
            const esc = (s: string) => s.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
            const tEsc = esc(token);
            const metaRe = new RegExp(`<meta[^>]*(?:name\s*=\s*['\"]nexabot-domain-verification['\"][^>]*content\s*=\s*['\"]${tEsc}['\"]|content\s*=\s*['\"]${tEsc}['\"][^>]*name\s*=\s*['\"]nexabot-domain-verification['\"])`, 'i');
            const plainRe = new RegExp(`nexabot-domain-verification[:=]\s*${tEsc}`, 'i');

            let found = false;
            for (const url of candidates) {
              try {
                const r = await fetch(url, { headers: { 'User-Agent': 'NexaBotVerifier/1.0' } });
                if (!r || !r.ok) continue;
                const text = await r.text();
                if (metaRe.test(text) || plainRe.test(text)) {
                  found = true;
                  break;
                }
              } catch (e) {
                // ignore and try next candidate
              }
            }

            if (!found) return endJson(400, { error: 'Verification token not found on site' });

            try {
              await supabaseFetch('/rest/v1/domains', {
                method: 'POST',
                body: JSON.stringify({ domain, verified: true, verified_at: new Date().toISOString() }),
                headers: { Prefer: 'resolution=merge-duplicates', 'Content-Type': 'application/json' },
              }, req).catch(() => null);
            } catch {}

            return endJson(200, { ok: true, domain });
          }

          if (req.url === '/api/launch' && req.method === 'POST') {
            const body = await parseJson(req);
            const botId = String(body?.botId || '').trim();
            if (!botId) return endJson(400, { error: 'Missing botId' });
            const customization = body?.customization || {};

            await supabaseFetch('/rest/v1/chatbot_configs?bot_id=eq.' + encodeURIComponent(botId), {
              method: 'PATCH',
              body: JSON.stringify({ settings: customization }),
              headers: { 'Content-Type': 'application/json', Prefer: 'return=representation' },
            }, req).catch(() => null);

            return endJson(200, { botId });
          }

          if (req.url === '/api/chat' && req.method === 'POST') {
            const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'ip';
            if (!rateLimit('chat:' + ip, 60, 60_000)) return endJson(429, { error: 'Too Many Requests' });
            const body = await parseJson(req).catch(() => ({}));
            const message = String(body?.message || '').slice(0, 2000);
            if (!message) return endJson(400, { error: 'Empty message' });

            await supabaseFetch('/rest/v1/security_logs', {
              method: 'POST',
              body: JSON.stringify({ action: 'CHAT', details: { len: message.length } }),
            }, req).catch(() => null);

            const reply = "I'm still learning, but our team will get back to you soon.";
            return endJson(200, { reply });
          }

          // Custom email verification: send email
          if (req.url === '/api/send-verify' && req.method === 'POST') {
            const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'ip';
            if (!rateLimit('verify:' + ip, 5, 60*60_000)) return endJson(429, { error: 'Too Many Requests' });
            const body = await parseJson(req).catch(() => ({}));
            const email = String(body?.email || '').trim().toLowerCase();
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return endJson(400, { error: 'Invalid email' });

            // Verify authenticated user matches email
            const ures = await supabaseFetch('/auth/v1/user', { method: 'GET' }, req).catch(() => null);
            if (!ures || !(ures as any).ok) return endJson(401, { error: 'Unauthorized' });
            const user = await (ures as Response).json().catch(() => null);
            if (!user || user.email?.toLowerCase() !== email) return endJson(403, { error: 'Email mismatch' });

            const token = crypto.randomBytes(32).toString('base64url');
            const secret = process.env.EMAIL_TOKEN_SECRET || 'local-secret';
            const tokenHash = crypto.createHash('sha256').update(token + secret).digest('base64');
            const expires = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();

            // Store token hash (not raw token)
            await supabaseFetch('/rest/v1/email_verifications', {
              method: 'POST',
              headers: { Prefer: 'resolution=merge-duplicates' },
              body: JSON.stringify({ user_id: user.id, email, token_hash: tokenHash, expires_at: expires, used_at: null }),
            }, req).catch(() => null);

            // Send email via SMTP
            const host = process.env.SMTP_HOST;
            const port = Number(process.env.SMTP_PORT || 587);
            const userSmtp = process.env.SMTP_USER;
            const passSmtp = process.env.SMTP_PASS;
            const from = process.env.EMAIL_FROM || 'NexaBot <no-reply@nexabot.ai>';
            const appUrl = process.env.APP_URL || 'http://localhost:3000';
            const verifyUrl = `${appUrl}/api/verify-email?token=${token}`;

            if (host && userSmtp && passSmtp) {
              const transporter = nodemailer.createTransport({ host, port, secure: port === 465, auth: { user: userSmtp, pass: passSmtp } });
              const html = `
                <table style="width:100%;background:#f6f8fb;padding:24px;font-family:Inter,Segoe UI,Arial,sans-serif;color:#0f172a">
                  <tr><td align="center">
                    <table style="max-width:560px;width:100%;background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden">
                      <tr>
                        <td style="background:linear-gradient(90deg,#6366f1,#8b5cf6);padding:20px;color:#fff;font-size:18px;font-weight:700">
                          NexaBot
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:24px">
                          <h1 style="margin:0 0 8px 0;font-size:20px;color:#111827">Confirm your email</h1>
                          <p style="margin:0 0 16px 0;color:#374151;line-height:1.5">Hi, please confirm your email address to secure your NexaBot account and complete setup.</p>
                          <p style="margin:0 0 16px 0;color:#374151;line-height:1.5">This link expires in 24 hours.</p>
                          <a href="${verifyUrl}" style="display:inline-block;background:#6366f1;color:#fff;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:600">Verify Email</a>
                          <p style="margin:16px 0 0 0;color:#6b7280;font-size:12px">If the button doesn’t work, copy and paste this link into your browser:<br>${verifyUrl}</p>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:16px 24px;color:#6b7280;font-size:12px;border-top:1px solid #e5e7eb">© ${new Date().getFullYear()} NexaBot. All rights reserved.</td>
                      </tr>
                    </table>
                  </td></tr>
                </table>`;
              await transporter.sendMail({ to: email, from, subject: 'Verify your email for NexaBot', html });
            } else {
              if (process.env.NODE_ENV !== 'production') {
                console.warn('[email] SMTP not configured; verification URL:', verifyUrl);
              }
            }

            return endJson(200, { ok: true });
          }

          // Verify link endpoint
          if (req.url?.startsWith('/api/verify-email') && req.method === 'GET') {
            const urlObj = new URL(req.url, 'http://local');
            const token = urlObj.searchParams.get('token') || '';
            if (!token) {
              res.statusCode = 400;
              res.setHeader('Content-Type', 'text/html');
              return res.end('<p>Invalid token</p>');
            }
            const secret = process.env.EMAIL_TOKEN_SECRET || 'local-secret';
            const tokenHash = crypto.createHash('sha256').update(token + secret).digest('base64');

            // Prefer RPC (security definer) on DB: verify_email_hash(p_hash text)
            let ok = false;
            try {
              const rpc = await supabaseFetch('/rest/v1/rpc/verify_email_hash', {
                method: 'POST',
                body: JSON.stringify({ p_hash: tokenHash }),
              }, req);
              if (rpc && (rpc as any).ok) ok = true;
            } catch {}

            if (!ok) {
              const nowIso = new Date().toISOString();
              await supabaseFetch('/rest/v1/email_verifications?token_hash=eq.' + encodeURIComponent(tokenHash) + '&used_at=is.null&expires_at=gt.' + encodeURIComponent(nowIso), {
                method: 'PATCH',
                body: JSON.stringify({ used_at: nowIso }),
                headers: { Prefer: 'return=representation' },
              }, req).catch(() => null);
            }

            res.statusCode = 200;
            res.setHeader('Content-Type', 'text/html');
            return res.end(`<!doctype html><meta http-equiv="refresh" content="2;url=/"><style>body{font-family:Inter,Segoe UI,Arial,sans-serif;background:#f6f8fb;color:#111827;display:grid;place-items:center;height:100vh}</style><div><h1>✅ Email verified</h1><p>You can close this tab.</p></div>`);
          }

          return endJson(404, { error: 'Not Found' });
        } catch (e: any) {
          return endJson(500, { error: 'Server Error' });
        }
      });
    },
  };
}
