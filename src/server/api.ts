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

async function supabaseFetch(path: string, options: any, req: any) {
  const base = process.env.SUPABASE_URL || 'https://fzygxynereijjfbcvwoh.supabase.co';
  const anon = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZ6eWd4eW5lcmVpampmYmN2d29oIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTY5NTYxMzMsImV4cCI6MjA3MjUzMjEzM30.-JnUwaXflcWmvL8_fu08uEzeBnIhxvAkd6_hqVeSYlI';
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

export function serverApiPlugin(): Plugin {
  return {
    name: 'server-api-plugin',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url || !req.url.startsWith('/api/')) return next();

        // Basic security headers for all API responses
        const corsOrigin = req.headers.origin || '*';

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
            return endJson(202, { jobId, status: 'queued' });
          }

          if (req.url === '/api/connect' && req.method === 'POST') {
            const body = await parseJson(req);
            if (body?.channel !== 'website') return endJson(400, { error: 'Unsupported channel' });
            const rawUrl = (body?.url || '').trim();
            const domain = (() => {
              try { return rawUrl ? new URL(rawUrl).host : 'local'; } catch { return 'local'; }
            })();
            const seed = domain + '|' + (req.headers['authorization'] || '');
            const botId = makeBotId(seed);

            // Upsert chatbot_configs (if RLS allows with user token)
            await supabaseFetch('/rest/v1/chatbot_configs', {
              method: 'POST',
              body: JSON.stringify({ bot_id: botId, channel: 'website', domain, settings: {} }),
              headers: { Prefer: 'resolution=merge-duplicates' },
            }, req).catch(() => null);

            return endJson(200, { botId });
          }

          if (req.url === '/api/launch' && req.method === 'POST') {
            const body = await parseJson(req);
            const botId = String(body?.botId || '').trim();
            if (!botId) return endJson(400, { error: 'Missing botId' });
            const customization = body?.customization || {};

            await supabaseFetch('/rest/v1/chatbot_configs', {
              method: 'PATCH',
              body: JSON.stringify({ settings: customization }),
              headers: { 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates' },
            }, req).catch(() => null);

            return endJson(200, { botId });
          }

          if (req.url === '/api/chat' && req.method === 'POST') {
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

          return endJson(404, { error: 'Not Found' });
        } catch (e: any) {
          return endJson(500, { error: 'Server Error' });
        }
      });
    },
  };
}
