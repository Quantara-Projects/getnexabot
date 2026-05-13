import { createRequire } from 'module';
import path from 'path';

const require = createRequire(import.meta.url);

export function createNetlifyAdapter(funcPath) {
  // funcPath is relative to project root, e.g. 'netlify/functions/chat.js'
  const full = path.join(process.cwd(), funcPath);
  return async function handler(req, res) {
    let mod;
    try {
      mod = require(full);
    } catch (e) {
      console.error('[adapter] failed to require', full, e && e.message);
      return res.status(500).json({ error: 'Function load error' });
    }

    const fn = mod && (mod.handler || mod.default || mod);
    if (!fn) return res.status(500).json({ error: 'Function handler missing' });

    const event = {
      httpMethod: req.method,
      headers: req.headers,
      queryStringParameters: req.query,
      body: typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {}),
      path: req.path,
    };

    try {
      const result = await fn(event, {});
      if (!result) return res.status(500).json({ error: 'No response from function' });
      const status = result.statusCode || 200;
      if (result.headers) {
        for (const k of Object.keys(result.headers)) res.setHeader(k, result.headers[k]);
      }
      const body = result.body == null ? '' : result.body;
      if (typeof body === 'string') {
        const trimmed = body.trim();
        if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
          try { return res.status(status).json(JSON.parse(trimmed)); } catch (e) {}
        }
        return res.status(status).send(body);
      }
      return res.status(status).send(body);
    } catch (e) {
      console.error('[adapter] function execution error for', funcPath, e && e.stack || e);
      return res.status(500).json({ error: 'Function execution error' });
    }
  };
}
