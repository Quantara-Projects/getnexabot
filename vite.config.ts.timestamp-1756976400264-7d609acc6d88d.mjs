// vite.config.ts
import { defineConfig } from "file:///app/code/node_modules/vite/dist/node/index.js";
import react from "file:///app/code/node_modules/@vitejs/plugin-react-swc/index.js";
import path from "path";
import { componentTagger } from "file:///app/code/node_modules/lovable-tagger/dist/index.js";

// src/server/api.ts
import crypto from "crypto";
import nodemailer from "file:///app/code/node_modules/nodemailer/lib/nodemailer.js";
async function parseJson(req, limit = 1024 * 100) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error("Payload too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        const json2 = raw ? JSON.parse(raw) : {};
        resolve(json2);
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}
function json(res, status, data, headers = {}) {
  const body = JSON.stringify(data);
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.end(body);
}
var isHttps = (req) => {
  const proto = req.headers["x-forwarded-proto"] || "";
  return proto === "https" || req.socket && req.socket.encrypted;
};
function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} not set`);
  return v;
}
async function supabaseFetch(path2, options, req) {
  const base = requireEnv("SUPABASE_URL");
  const anon = requireEnv("SUPABASE_ANON_KEY");
  const token = req.headers["authorization"] || "";
  const headers = {
    apikey: anon,
    "Content-Type": "application/json"
  };
  if (token) headers["Authorization"] = token;
  return fetch(`${base}${path2}`, { ...options, headers: { ...headers, ...options?.headers || {} } });
}
function makeBotId(seed) {
  return "bot_" + crypto.createHash("sha256").update(seed).digest("base64url").slice(0, 22);
}
function extractTextFromHtml(html) {
  const withoutScripts = html.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, " ");
  const withoutStyles = withoutScripts.replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, " ");
  const text = withoutStyles.replace(/<[^>]+>/g, " ");
  return text.replace(/&nbsp;|&amp;|&lt;|&gt;|&quot;|&#39;/g, (s) => {
    switch (s) {
      case "&nbsp;":
        return " ";
      case "&amp;":
        return "&";
      case "&lt;":
        return "<";
      case "&gt;":
        return ">";
      case "&quot;":
        return '"';
      case "&#39;":
        return "'";
      default:
        return s;
    }
  }).replace(/\s+/g, " ").trim();
}
async function tryFetchUrlText(u) {
  try {
    const res = await fetch(u, { headers: { "User-Agent": "NexaBotCrawler/1.0" } });
    if (!res.ok) return "";
    const html = await res.text();
    return extractTextFromHtml(html);
  } catch (e) {
    return "";
  }
}
function chunkText(text, maxChars = 1500) {
  const paragraphs = text.split(/\n|\r|\.|\!|\?/).map((p) => p.trim()).filter(Boolean);
  const chunks = [];
  let cur = "";
  for (const p of paragraphs) {
    if ((cur + " " + p).length > maxChars) {
      if (cur) {
        chunks.push(cur.trim());
        cur = p;
      } else {
        chunks.push(p.slice(0, maxChars));
        cur = p.slice(maxChars);
      }
    } else {
      cur = (cur + " " + p).trim();
    }
  }
  if (cur) chunks.push(cur.trim());
  return chunks;
}
async function embedChunks(chunks) {
  const key = process.env.OPENAI_API_KEY;
  if (!key) return null;
  try {
    const resp = await fetch("https://api.openai.com/v1/embeddings", {
      method: "POST",
      headers: { "Authorization": `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({ input: chunks, model: "text-embedding-3-small" })
    });
    if (!resp.ok) return null;
    const j = await resp.json();
    if (!j.data) return null;
    return j.data.map((d) => d.embedding);
  } catch (e) {
    return null;
  }
}
async function processTrainJob(jobId, body, req) {
  const url = body.url || "";
  const files = Array.isArray(body.files) ? body.files : [];
  const botSeed = (url || files.join(",")) + Date.now();
  const botId = makeBotId(botSeed);
  const docs = [];
  if (url) {
    const text = await tryFetchUrlText(url);
    if (text) docs.push({ source: url, content: text });
  }
  for (const path2 of files) {
    try {
      const SUPABASE_URL = process.env.SUPABASE_URL;
      const bucketPublicUrl = SUPABASE_URL + `/storage/v1/object/public/training/${encodeURIComponent(path2)}`;
      const res = await fetch(bucketPublicUrl);
      if (!res.ok) continue;
      const buf = await res.arrayBuffer();
      const header = String.fromCharCode.apply(null, new Uint8Array(buf.slice(0, 8)));
      if (header.includes("%PDF")) {
        docs.push({ source: path2, content: "(PDF content -- processed externally)" });
      } else {
        const text = new TextDecoder().decode(buf);
        const cleaned = extractTextFromHtml(text);
        docs.push({ source: path2, content: cleaned || "(binary file)" });
      }
    } catch (e) {
      continue;
    }
  }
  for (const doc of docs) {
    const chunks = chunkText(doc.content);
    const embeddings = await embedChunks(chunks);
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      const emb = embeddings ? embeddings[i] : null;
      try {
        await supabaseFetch("/rest/v1/training_documents", {
          method: "POST",
          body: JSON.stringify({ bot_id: botId, source: doc.source, content: chunk, embedding: emb }),
          headers: { Prefer: "return=representation", "Content-Type": "application/json" }
        }, req).catch(() => null);
      } catch {
      }
    }
  }
  try {
    await supabaseFetch("/rest/v1/security_logs", {
      method: "POST",
      body: JSON.stringify({ action: "TRAIN_JOB_COMPLETE", details: { jobId, botId, docs: docs.length } })
    }, req).catch(() => null);
  } catch {
  }
}
async function ensureDomainVerification(domain, req) {
  try {
    const res = await supabaseFetch(`/rest/v1/domains?domain=eq.${encodeURIComponent(domain)}`, { method: "GET" }, req);
    if (res && res.ok) {
      const j = await res.json().catch(() => []);
      if (Array.isArray(j) && j.length > 0 && j[0].verified) return { verified: true };
    }
  } catch {
  }
  try {
    const nowIso = (/* @__PURE__ */ new Date()).toISOString();
    const q = `/rest/v1/domain_verifications?domain=eq.${encodeURIComponent(domain)}&expires_at=gt.${encodeURIComponent(nowIso)}&used_at=is.null`;
    const r = await supabaseFetch(q, { method: "GET" }, req).catch(() => null);
    if (r && r.ok) {
      const arr = await r.json().catch(() => []);
      if (Array.isArray(arr) && arr.length > 0) {
        const existing = arr[0];
        if (existing.token) return { verified: false, token: existing.token };
      }
    }
  } catch {
  }
  const token = crypto.randomBytes(16).toString("base64url");
  const secret = process.env.DOMAIN_VERIFICATION_SECRET || "local-dom-secret";
  const tokenHash = crypto.createHash("sha256").update(token + secret).digest("base64");
  const expires = new Date(Date.now() + 1e3 * 60 * 60 * 24).toISOString();
  try {
    await supabaseFetch("/rest/v1/domain_verifications", {
      method: "POST",
      body: JSON.stringify({ domain, token, token_hash: tokenHash, expires_at: expires, used_at: null }),
      headers: { Prefer: "resolution=merge-duplicates", "Content-Type": "application/json" }
    }, req).catch(() => null);
  } catch {
  }
  return { verified: false, token };
}
function verifyWidgetToken(token) {
  try {
    const widgetSecret = process.env.WIDGET_TOKEN_SECRET || "local-widget-secret";
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const unsigned = parts[0] + "." + parts[1];
    const sig = parts[2];
    const expected = crypto.createHmac("sha256", widgetSecret).update(unsigned).digest("base64url");
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return payload;
  } catch (e) {
    return null;
  }
}
var rateMap = /* @__PURE__ */ new Map();
function rateLimit(key, limit, windowMs) {
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
function serverApiPlugin() {
  return {
    name: "server-api-plugin",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url || !req.url.startsWith("/api/")) return next();
        const corsOrigin = req.headers.origin || "*";
        res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
        res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
        if (process.env.NODE_ENV === "production" && !isHttps(req)) {
          return json(res, 400, { error: "HTTPS required" }, { "Access-Control-Allow-Origin": String(corsOrigin) });
        }
        if (req.method === "OPTIONS") {
          res.setHeader("Access-Control-Allow-Origin", String(corsOrigin));
          res.setHeader("Access-Control-Allow-Methods", "POST,GET,OPTIONS");
          res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
          res.statusCode = 204;
          return res.end();
        }
        const endJson = (status, data) => json(res, status, data, { "Access-Control-Allow-Origin": String(corsOrigin) });
        try {
          if (req.url === "/api/train" && req.method === "POST") {
            const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "ip";
            if (!rateLimit("train:" + ip, 20, 6e4)) return endJson(429, { error: "Too Many Requests" });
            const body = await parseJson(req).catch(() => ({}));
            const url = typeof body?.url === "string" ? body.url.trim() : "";
            if (!url && !Array.isArray(body?.files)) {
              return endJson(400, { error: "Provide url or files" });
            }
            if (url) {
              try {
                const u = new URL(url);
                if (!(u.protocol === "http:" || u.protocol === "https:")) throw new Error("invalid");
              } catch {
                return endJson(400, { error: "Invalid url" });
              }
            }
            await supabaseFetch("/rest/v1/security_logs", {
              method: "POST",
              body: JSON.stringify({ action: "TRAIN_REQUEST", details: { hasUrl: !!url, fileCount: body?.files?.length || 0 } })
            }, req).catch(() => null);
            const jobId = makeBotId((url || "") + Date.now());
            (async () => {
              try {
                await processTrainJob(jobId, { url, files: Array.isArray(body?.files) ? body.files : [] }, req);
              } catch (e) {
                try {
                  await supabaseFetch("/rest/v1/security_logs", {
                    method: "POST",
                    body: JSON.stringify({ action: "TRAIN_JOB_ERROR", details: { jobId, error: String(e?.message || e) } })
                  }, req);
                } catch {
                }
              }
            })();
            return endJson(202, { jobId, status: "queued" });
          }
          if (req.url === "/api/connect" && req.method === "POST") {
            const body = await parseJson(req);
            if (body?.channel !== "website") return endJson(400, { error: "Unsupported channel" });
            const rawUrl = (body?.url || "").trim();
            const domain = (() => {
              try {
                return rawUrl ? new URL(rawUrl).host : "local";
              } catch {
                return "local";
              }
            })();
            const vres = await ensureDomainVerification(domain, req);
            if (!vres.verified) {
              return endJson(202, { status: "verification_required", instructions: `Add a DNS TXT record or a meta tag with token: ${vres.token}`, token: vres.token });
            }
            const seed = domain + "|" + (req.headers["authorization"] || "");
            const botId = makeBotId(seed);
            await supabaseFetch("/rest/v1/chatbot_configs", {
              method: "POST",
              body: JSON.stringify({ bot_id: botId, channel: "website", domain, settings: {} }),
              headers: { Prefer: "resolution=merge-duplicates" }
            }, req).catch(() => null);
            const widgetPayload = { botId, domain, iat: Math.floor(Date.now() / 1e3) };
            const widgetSecret = process.env.WIDGET_TOKEN_SECRET || "local-widget-secret";
            const header = { alg: "HS256", typ: "JWT" };
            const b64 = (s) => Buffer.from(s).toString("base64url");
            const unsigned = b64(JSON.stringify(header)) + "." + b64(JSON.stringify(widgetPayload));
            const sig = crypto.createHmac("sha256", widgetSecret).update(unsigned).digest("base64url");
            const widgetToken = unsigned + "." + sig;
            return endJson(200, { botId, widgetToken });
          }
          if (req.url?.startsWith("/api/widget-config") && req.method === "GET") {
            const urlObj = new URL(req.url, "http://local");
            const botId = urlObj.searchParams.get("botId") || "";
            const token = urlObj.searchParams.get("token") || "";
            if (!botId) return endJson(400, { error: "Missing botId" });
            const payload = verifyWidgetToken(token);
            if (!payload || payload.botId !== botId) return endJson(401, { error: "Invalid token" });
            try {
              const r = await supabaseFetch("/rest/v1/chatbot_configs?bot_id=eq." + encodeURIComponent(botId) + "&select=*", { method: "GET" }, req).catch(() => null);
              if (!r || !r.ok) return endJson(404, { error: "Not found" });
              const data = await r.json().catch(() => []);
              const cfg = Array.isArray(data) && data.length > 0 ? data[0] : { settings: {} };
              return endJson(200, { settings: cfg });
            } catch (e) {
              return endJson(500, { error: "Server error" });
            }
          }
          if (req.url === "/api/debug-fetch" && req.method === "POST") {
            const body = await parseJson(req).catch(() => ({}));
            const urlStr = String(body?.url || "").trim();
            if (!urlStr) return endJson(400, { error: "Missing url" });
            try {
              const u = new URL(urlStr);
              if (!(u.protocol === "http:" || u.protocol === "https:")) return endJson(400, { error: "Invalid protocol" });
            } catch (e) {
              return endJson(400, { error: "Invalid url" });
            }
            try {
              const r = await fetch(urlStr, { headers: { "User-Agent": "NexaBotVerifier/1.0" } });
              if (!r || !r.ok) return endJson(400, { error: "Fetch failed", status: r ? r.status : 0 });
              const text = await r.text();
              return endJson(200, { ok: true, url: urlStr, snippet: text.slice(0, 2e4) });
            } catch (e) {
              return endJson(500, { error: "Fetch error", message: String(e?.message || e) });
            }
          }
          if (req.url === "/api/verify-domain" && req.method === "POST") {
            const body = await parseJson(req).catch(() => ({}));
            const domain = String(body?.domain || "").trim();
            const token = String(body?.token || "").trim();
            if (!domain || !token) return endJson(400, { error: "Missing domain or token" });
            const candidates = [
              `https://${domain}`,
              `http://${domain}`,
              `https://${domain}/index.html`,
              `http://${domain}/index.html`,
              `https://${domain}/.well-known/nexabot-domain-verification`,
              `http://${domain}/.well-known/nexabot-domain-verification`
            ];
            const esc = (s) => s.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
            const tEsc = esc(token);
            const metaRe = new RegExp(`<meta[^>]*(?:names*=s*['"]nexabot-domain-verification['"][^>]*contents*=s*['"]${tEsc}['"]|contents*=s*['"]${tEsc}['"][^>]*names*=s*['"]nexabot-domain-verification['"])`, "i");
            const plainRe = new RegExp(`nexabot-domain-verification[:=]s*${tEsc}`, "i");
            let found = false;
            for (const url of candidates) {
              try {
                const r = await fetch(url, { headers: { "User-Agent": "NexaBotVerifier/1.0" } });
                if (!r || !r.ok) continue;
                const text = await r.text();
                if (metaRe.test(text) || plainRe.test(text)) {
                  found = true;
                  break;
                }
              } catch (e) {
              }
            }
            if (!found) return endJson(400, { error: "Verification token not found on site" });
            try {
              await supabaseFetch("/rest/v1/domains", {
                method: "POST",
                body: JSON.stringify({ domain, verified: true, verified_at: (/* @__PURE__ */ new Date()).toISOString() }),
                headers: { Prefer: "resolution=merge-duplicates", "Content-Type": "application/json" }
              }, req).catch(() => null);
            } catch {
            }
            return endJson(200, { ok: true, domain });
          }
          if (req.url === "/api/launch" && req.method === "POST") {
            const body = await parseJson(req);
            const botId = String(body?.botId || "").trim();
            if (!botId) return endJson(400, { error: "Missing botId" });
            const customization = body?.customization || {};
            await supabaseFetch("/rest/v1/chatbot_configs?bot_id=eq." + encodeURIComponent(botId), {
              method: "PATCH",
              body: JSON.stringify({ settings: customization }),
              headers: { "Content-Type": "application/json", Prefer: "return=representation" }
            }, req).catch(() => null);
            return endJson(200, { botId });
          }
          if (req.url === "/api/chat" && req.method === "POST") {
            const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "ip";
            if (!rateLimit("chat:" + ip, 60, 6e4)) return endJson(429, { error: "Too Many Requests" });
            const body = await parseJson(req).catch(() => ({}));
            const message = String(body?.message || "").slice(0, 2e3);
            if (!message) return endJson(400, { error: "Empty message" });
            await supabaseFetch("/rest/v1/security_logs", {
              method: "POST",
              body: JSON.stringify({ action: "CHAT", details: { len: message.length } })
            }, req).catch(() => null);
            const reply = "I'm still learning, but our team will get back to you soon.";
            return endJson(200, { reply });
          }
          if (req.url === "/api/send-verify" && req.method === "POST") {
            const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "ip";
            if (!rateLimit("verify:" + ip, 5, 60 * 6e4)) return endJson(429, { error: "Too Many Requests" });
            const body = await parseJson(req).catch(() => ({}));
            const email = String(body?.email || "").trim().toLowerCase();
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return endJson(400, { error: "Invalid email" });
            const ures = await supabaseFetch("/auth/v1/user", { method: "GET" }, req).catch(() => null);
            if (!ures || !ures.ok) return endJson(401, { error: "Unauthorized" });
            const user = await ures.json().catch(() => null);
            if (!user || user.email?.toLowerCase() !== email) return endJson(403, { error: "Email mismatch" });
            const token = crypto.randomBytes(32).toString("base64url");
            const secret = process.env.EMAIL_TOKEN_SECRET || "local-secret";
            const tokenHash = crypto.createHash("sha256").update(token + secret).digest("base64");
            const expires = new Date(Date.now() + 1e3 * 60 * 60 * 24).toISOString();
            await supabaseFetch("/rest/v1/email_verifications", {
              method: "POST",
              headers: { Prefer: "resolution=merge-duplicates" },
              body: JSON.stringify({ user_id: user.id, email, token_hash: tokenHash, expires_at: expires, used_at: null })
            }, req).catch(() => null);
            const host = process.env.SMTP_HOST;
            const port = Number(process.env.SMTP_PORT || 587);
            const userSmtp = process.env.SMTP_USER;
            const passSmtp = process.env.SMTP_PASS;
            const from = process.env.EMAIL_FROM || "NexaBot <no-reply@nexabot.ai>";
            const appUrl = process.env.APP_URL || "http://localhost:3000";
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
                          <p style="margin:16px 0 0 0;color:#6b7280;font-size:12px">If the button doesn\u2019t work, copy and paste this link into your browser:<br>${verifyUrl}</p>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:16px 24px;color:#6b7280;font-size:12px;border-top:1px solid #e5e7eb">\xA9 ${(/* @__PURE__ */ new Date()).getFullYear()} NexaBot. All rights reserved.</td>
                      </tr>
                    </table>
                  </td></tr>
                </table>`;
              await transporter.sendMail({ to: email, from, subject: "Verify your email for NexaBot", html });
            } else {
              if (process.env.NODE_ENV !== "production") {
                console.warn("[email] SMTP not configured; verification URL:", verifyUrl);
              }
            }
            return endJson(200, { ok: true });
          }
          if (req.url?.startsWith("/api/verify-email") && req.method === "GET") {
            const urlObj = new URL(req.url, "http://local");
            const token = urlObj.searchParams.get("token") || "";
            if (!token) {
              res.statusCode = 400;
              res.setHeader("Content-Type", "text/html");
              return res.end("<p>Invalid token</p>");
            }
            const secret = process.env.EMAIL_TOKEN_SECRET || "local-secret";
            const tokenHash = crypto.createHash("sha256").update(token + secret).digest("base64");
            let ok = false;
            try {
              const rpc = await supabaseFetch("/rest/v1/rpc/verify_email_hash", {
                method: "POST",
                body: JSON.stringify({ p_hash: tokenHash })
              }, req);
              if (rpc && rpc.ok) ok = true;
            } catch {
            }
            if (!ok) {
              const nowIso = (/* @__PURE__ */ new Date()).toISOString();
              await supabaseFetch("/rest/v1/email_verifications?token_hash=eq." + encodeURIComponent(tokenHash) + "&used_at=is.null&expires_at=gt." + encodeURIComponent(nowIso), {
                method: "PATCH",
                body: JSON.stringify({ used_at: nowIso }),
                headers: { Prefer: "return=representation" }
              }, req).catch(() => null);
            }
            res.statusCode = 200;
            res.setHeader("Content-Type", "text/html");
            return res.end(`<!doctype html><meta http-equiv="refresh" content="2;url=/"><style>body{font-family:Inter,Segoe UI,Arial,sans-serif;background:#f6f8fb;color:#111827;display:grid;place-items:center;height:100vh}</style><div><h1>\u2705 Email verified</h1><p>You can close this tab.</p></div>`);
          }
          return endJson(404, { error: "Not Found" });
        } catch (e) {
          return endJson(500, { error: "Server Error" });
        }
      });
    }
  };
}

// vite.config.ts
var __vite_injected_original_dirname = "/app/code";
var vite_config_default = defineConfig(({ mode }) => ({
  server: {
    host: "::",
    port: 8080
  },
  plugins: [
    react(),
    mode === "development" && componentTagger(),
    serverApiPlugin()
  ].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__vite_injected_original_dirname, "./src")
    }
  }
}));
export {
  vite_config_default as default
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL3NlcnZlci9hcGkudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGVcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9hcHAvY29kZS92aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vYXBwL2NvZGUvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tIFwidml0ZVwiO1xuaW1wb3J0IHJlYWN0IGZyb20gXCJAdml0ZWpzL3BsdWdpbi1yZWFjdC1zd2NcIjtcbmltcG9ydCBwYXRoIGZyb20gXCJwYXRoXCI7XG5pbXBvcnQgeyBjb21wb25lbnRUYWdnZXIgfSBmcm9tIFwibG92YWJsZS10YWdnZXJcIjtcbmltcG9ydCB7IHNlcnZlckFwaVBsdWdpbiB9IGZyb20gXCIuL3NyYy9zZXJ2ZXIvYXBpXCI7XG5cbi8vIGh0dHBzOi8vdml0ZWpzLmRldi9jb25maWcvXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiAoe1xuICBzZXJ2ZXI6IHtcbiAgICBob3N0OiBcIjo6XCIsXG4gICAgcG9ydDogODA4MCxcbiAgfSxcbiAgcGx1Z2luczogW1xuICAgIHJlYWN0KCksXG4gICAgbW9kZSA9PT0gJ2RldmVsb3BtZW50JyAmJlxuICAgIGNvbXBvbmVudFRhZ2dlcigpLFxuICAgIHNlcnZlckFwaVBsdWdpbigpLFxuICBdLmZpbHRlcihCb29sZWFuKSxcbiAgcmVzb2x2ZToge1xuICAgIGFsaWFzOiB7XG4gICAgICBcIkBcIjogcGF0aC5yZXNvbHZlKF9fZGlybmFtZSwgXCIuL3NyY1wiKSxcbiAgICB9LFxuICB9LFxufSkpO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGUvc3JjL3NlcnZlclwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2FwcC9jb2RlL3NyYy9zZXJ2ZXIvYXBpLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9hcHAvY29kZS9zcmMvc2VydmVyL2FwaS50c1wiO2ltcG9ydCB0eXBlIHsgUGx1Z2luIH0gZnJvbSAndml0ZSc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5pbXBvcnQgbm9kZW1haWxlciBmcm9tICdub2RlbWFpbGVyJztcblxuLy8gU21hbGwgSlNPTiBib2R5IHBhcnNlciB3aXRoIHNpemUgbGltaXRcbmFzeW5jIGZ1bmN0aW9uIHBhcnNlSnNvbihyZXE6IGFueSwgbGltaXQgPSAxMDI0ICogMTAwKSB7XG4gIHJldHVybiBuZXcgUHJvbWlzZTxhbnk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICBjb25zdCBjaHVua3M6IEJ1ZmZlcltdID0gW107XG4gICAgbGV0IHNpemUgPSAwO1xuICAgIHJlcS5vbignZGF0YScsIChjOiBCdWZmZXIpID0+IHtcbiAgICAgIHNpemUgKz0gYy5sZW5ndGg7XG4gICAgICBpZiAoc2l6ZSA+IGxpbWl0KSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1BheWxvYWQgdG9vIGxhcmdlJykpO1xuICAgICAgICByZXEuZGVzdHJveSgpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjaHVua3MucHVzaChjKTtcbiAgICB9KTtcbiAgICByZXEub24oJ2VuZCcsICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJhdyA9IEJ1ZmZlci5jb25jYXQoY2h1bmtzKS50b1N0cmluZygndXRmOCcpO1xuICAgICAgICBjb25zdCBqc29uID0gcmF3ID8gSlNPTi5wYXJzZShyYXcpIDoge307XG4gICAgICAgIHJlc29sdmUoanNvbik7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHJlamVjdChlKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICByZXEub24oJ2Vycm9yJywgcmVqZWN0KTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIGpzb24ocmVzOiBhbnksIHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnksIGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7fSkge1xuICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7XG4gIHJlcy5zdGF0dXNDb2RlID0gc3RhdHVzO1xuICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCcpO1xuICByZXMuc2V0SGVhZGVyKCdYLUNvbnRlbnQtVHlwZS1PcHRpb25zJywgJ25vc25pZmYnKTtcbiAgcmVzLnNldEhlYWRlcignUmVmZXJyZXItUG9saWN5JywgJ25vLXJlZmVycmVyJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtRnJhbWUtT3B0aW9ucycsICdERU5ZJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtWFNTLVByb3RlY3Rpb24nLCAnMTsgbW9kZT1ibG9jaycpO1xuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhoZWFkZXJzKSkgcmVzLnNldEhlYWRlcihrLCB2KTtcbiAgcmVzLmVuZChib2R5KTtcbn1cblxuY29uc3QgaXNIdHRwcyA9IChyZXE6IGFueSkgPT4ge1xuICBjb25zdCBwcm90byA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtcHJvdG8nXSBhcyBzdHJpbmcpIHx8ICcnO1xuICByZXR1cm4gcHJvdG8gPT09ICdodHRwcycgfHwgKHJlcS5zb2NrZXQgJiYgKHJlcS5zb2NrZXQgYXMgYW55KS5lbmNyeXB0ZWQpO1xufTtcblxuZnVuY3Rpb24gcmVxdWlyZUVudihuYW1lOiBzdHJpbmcpIHtcbiAgY29uc3QgdiA9IHByb2Nlc3MuZW52W25hbWVdO1xuICBpZiAoIXYpIHRocm93IG5ldyBFcnJvcihgJHtuYW1lfSBub3Qgc2V0YCk7XG4gIHJldHVybiB2O1xufVxuXG5hc3luYyBmdW5jdGlvbiBzdXBhYmFzZUZldGNoKHBhdGg6IHN0cmluZywgb3B0aW9uczogYW55LCByZXE6IGFueSkge1xuICBjb25zdCBiYXNlID0gcmVxdWlyZUVudignU1VQQUJBU0VfVVJMJyk7XG4gIGNvbnN0IGFub24gPSByZXF1aXJlRW52KCdTVVBBQkFTRV9BTk9OX0tFWScpO1xuICBjb25zdCB0b2tlbiA9IChyZXEuaGVhZGVyc1snYXV0aG9yaXphdGlvbiddIGFzIHN0cmluZykgfHwgJyc7XG4gIGNvbnN0IGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7XG4gICAgYXBpa2V5OiBhbm9uLFxuICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsXG4gIH07XG4gIGlmICh0b2tlbikgaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gdG9rZW47XG4gIHJldHVybiBmZXRjaChgJHtiYXNlfSR7cGF0aH1gLCB7IC4uLm9wdGlvbnMsIGhlYWRlcnM6IHsgLi4uaGVhZGVycywgLi4uKG9wdGlvbnM/LmhlYWRlcnMgfHwge30pIH0gfSk7XG59XG5cbmZ1bmN0aW9uIG1ha2VCb3RJZChzZWVkOiBzdHJpbmcpIHtcbiAgcmV0dXJuICdib3RfJyArIGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUoc2VlZCkuZGlnZXN0KCdiYXNlNjR1cmwnKS5zbGljZSgwLCAyMik7XG59XG5cbi8vIEV4dHJhY3QgdmlzaWJsZSB0ZXh0IGZyb20gSFRNTCAobmFpdmUpXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21IdG1sKGh0bWw6IHN0cmluZykge1xuICAvLyByZW1vdmUgc2NyaXB0cy9zdHlsZXNcbiAgY29uc3Qgd2l0aG91dFNjcmlwdHMgPSBodG1sLnJlcGxhY2UoLzxzY3JpcHRbXFxzXFxTXSo/PltcXHNcXFNdKj88XFwvc2NyaXB0Pi9naSwgJyAnKTtcbiAgY29uc3Qgd2l0aG91dFN0eWxlcyA9IHdpdGhvdXRTY3JpcHRzLnJlcGxhY2UoLzxzdHlsZVtcXHNcXFNdKj8+W1xcc1xcU10qPzxcXC9zdHlsZT4vZ2ksICcgJyk7XG4gIC8vIHJlbW92ZSB0YWdzXG4gIGNvbnN0IHRleHQgPSB3aXRob3V0U3R5bGVzLnJlcGxhY2UoLzxbXj5dKz4vZywgJyAnKTtcbiAgLy8gZGVjb2RlIEhUTUwgZW50aXRpZXMgKGJhc2ljKVxuICByZXR1cm4gdGV4dC5yZXBsYWNlKC8mbmJzcDt8JmFtcDt8Jmx0O3wmZ3Q7fCZxdW90O3wmIzM5Oy9nLCAocykgPT4ge1xuICAgIHN3aXRjaCAocykge1xuICAgICAgY2FzZSAnJm5ic3A7JzogcmV0dXJuICcgJztcbiAgICAgIGNhc2UgJyZhbXA7JzogcmV0dXJuICcmJztcbiAgICAgIGNhc2UgJyZsdDsnOiByZXR1cm4gJzwnO1xuICAgICAgY2FzZSAnJmd0Oyc6IHJldHVybiAnPic7XG4gICAgICBjYXNlICcmcXVvdDsnOiByZXR1cm4gJ1wiJztcbiAgICAgIGNhc2UgJyYjMzk7JzogcmV0dXJuICdcXCcnO1xuICAgICAgZGVmYXVsdDogcmV0dXJuIHM7XG4gICAgfVxuICB9KS5yZXBsYWNlKC9cXHMrL2csICcgJykudHJpbSgpO1xufVxuXG5hc3luYyBmdW5jdGlvbiB0cnlGZXRjaFVybFRleHQodTogc3RyaW5nKSB7XG4gIHRyeSB7XG4gICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2godSwgeyBoZWFkZXJzOiB7ICdVc2VyLUFnZW50JzogJ05leGFCb3RDcmF3bGVyLzEuMCcgfSB9KTtcbiAgICBpZiAoIXJlcy5vaykgcmV0dXJuICcnO1xuICAgIGNvbnN0IGh0bWwgPSBhd2FpdCByZXMudGV4dCgpO1xuICAgIHJldHVybiBleHRyYWN0VGV4dEZyb21IdG1sKGh0bWwpO1xuICB9IGNhdGNoIChlKSB7XG4gICAgcmV0dXJuICcnO1xuICB9XG59XG5cbmZ1bmN0aW9uIGNodW5rVGV4dCh0ZXh0OiBzdHJpbmcsIG1heENoYXJzID0gMTUwMCkge1xuICBjb25zdCBwYXJhZ3JhcGhzID0gdGV4dC5zcGxpdCgvXFxufFxccnxcXC58XFwhfFxcPy8pLm1hcChwID0+IHAudHJpbSgpKS5maWx0ZXIoQm9vbGVhbik7XG4gIGNvbnN0IGNodW5rczogc3RyaW5nW10gPSBbXTtcbiAgbGV0IGN1ciA9ICcnO1xuICBmb3IgKGNvbnN0IHAgb2YgcGFyYWdyYXBocykge1xuICAgIGlmICgoY3VyICsgJyAnICsgcCkubGVuZ3RoID4gbWF4Q2hhcnMpIHtcbiAgICAgIGlmIChjdXIpIHsgY2h1bmtzLnB1c2goY3VyLnRyaW0oKSk7IGN1ciA9IHA7IH1cbiAgICAgIGVsc2UgeyBjaHVua3MucHVzaChwLnNsaWNlKDAsIG1heENoYXJzKSk7IGN1ciA9IHAuc2xpY2UobWF4Q2hhcnMpOyB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGN1ciA9IChjdXIgKyAnICcgKyBwKS50cmltKCk7XG4gICAgfVxuICB9XG4gIGlmIChjdXIpIGNodW5rcy5wdXNoKGN1ci50cmltKCkpO1xuICByZXR1cm4gY2h1bmtzO1xufVxuXG5hc3luYyBmdW5jdGlvbiBlbWJlZENodW5rcyhjaHVua3M6IHN0cmluZ1tdKTogUHJvbWlzZTxudW1iZXJbXVtdIHwgbnVsbD4ge1xuICBjb25zdCBrZXkgPSBwcm9jZXNzLmVudi5PUEVOQUlfQVBJX0tFWTtcbiAgaWYgKCFrZXkpIHJldHVybiBudWxsO1xuICB0cnkge1xuICAgIGNvbnN0IHJlc3AgPSBhd2FpdCBmZXRjaCgnaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS92MS9lbWJlZGRpbmdzJywge1xuICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICBoZWFkZXJzOiB7ICdBdXRob3JpemF0aW9uJzogYEJlYXJlciAke2tleX1gLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGlucHV0OiBjaHVua3MsIG1vZGVsOiAndGV4dC1lbWJlZGRpbmctMy1zbWFsbCcgfSksXG4gICAgfSk7XG4gICAgaWYgKCFyZXNwLm9rKSByZXR1cm4gbnVsbDtcbiAgICBjb25zdCBqID0gYXdhaXQgcmVzcC5qc29uKCk7XG4gICAgaWYgKCFqLmRhdGEpIHJldHVybiBudWxsO1xuICAgIHJldHVybiBqLmRhdGEubWFwKChkOiBhbnkpID0+IGQuZW1iZWRkaW5nIGFzIG51bWJlcltdKTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHByb2Nlc3NUcmFpbkpvYihqb2JJZDogc3RyaW5nLCBib2R5OiBhbnksIHJlcTogYW55KSB7XG4gIGNvbnN0IHVybCA9IGJvZHkudXJsIHx8ICcnO1xuICBjb25zdCBmaWxlczogc3RyaW5nW10gPSBBcnJheS5pc0FycmF5KGJvZHkuZmlsZXMpID8gYm9keS5maWxlcyA6IFtdO1xuICBjb25zdCBib3RTZWVkID0gKHVybCB8fCBmaWxlcy5qb2luKCcsJykpICsgRGF0ZS5ub3coKTtcbiAgY29uc3QgYm90SWQgPSBtYWtlQm90SWQoYm90U2VlZCk7XG5cbiAgLy8gZ2F0aGVyIHRleHRzXG4gIGNvbnN0IGRvY3M6IHsgc291cmNlOiBzdHJpbmc7IGNvbnRlbnQ6IHN0cmluZyB9W10gPSBbXTtcblxuICBpZiAodXJsKSB7XG4gICAgY29uc3QgdGV4dCA9IGF3YWl0IHRyeUZldGNoVXJsVGV4dCh1cmwpO1xuICAgIGlmICh0ZXh0KSBkb2NzLnB1c2goeyBzb3VyY2U6IHVybCwgY29udGVudDogdGV4dCB9KTtcbiAgfVxuXG4gIC8vIGZpbGVzIGFyZSBzdG9yYWdlIHBhdGhzIGluIGJ1Y2tldC90cmFpbmluZy8uLi5cbiAgZm9yIChjb25zdCBwYXRoIG9mIGZpbGVzKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IFNVUEFCQVNFX1VSTCA9IHByb2Nlc3MuZW52LlNVUEFCQVNFX1VSTDtcbiAgICAgIGNvbnN0IGJ1Y2tldFB1YmxpY1VybCA9IFNVUEFCQVNFX1VSTCArIGAvc3RvcmFnZS92MS9vYmplY3QvcHVibGljL3RyYWluaW5nLyR7ZW5jb2RlVVJJQ29tcG9uZW50KHBhdGgpfWA7XG4gICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChidWNrZXRQdWJsaWNVcmwpO1xuICAgICAgaWYgKCFyZXMub2spIGNvbnRpbnVlO1xuICAgICAgY29uc3QgYnVmID0gYXdhaXQgcmVzLmFycmF5QnVmZmVyKCk7XG4gICAgICAvLyBjcnVkZSB0ZXh0IGV4dHJhY3Rpb246IGlmIGl0J3MgcGRmIG9yIHRleHRcbiAgICAgIGNvbnN0IGhlYWRlciA9IFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCwgbmV3IFVpbnQ4QXJyYXkoYnVmLnNsaWNlKDAsIDgpKSBhcyBhbnkpO1xuICAgICAgaWYgKGhlYWRlci5pbmNsdWRlcygnJVBERicpKSB7XG4gICAgICAgIC8vIGNhbm5vdCBwYXJzZSBQREYgaGVyZTsgc3RvcmUgcGxhY2Vob2xkZXJcbiAgICAgICAgZG9jcy5wdXNoKHsgc291cmNlOiBwYXRoLCBjb250ZW50OiAnKFBERiBjb250ZW50IC0tIHByb2Nlc3NlZCBleHRlcm5hbGx5KScgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjb25zdCB0ZXh0ID0gbmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKGJ1Zik7XG4gICAgICAgIGNvbnN0IGNsZWFuZWQgPSBleHRyYWN0VGV4dEZyb21IdG1sKHRleHQpO1xuICAgICAgICBkb2NzLnB1c2goeyBzb3VyY2U6IHBhdGgsIGNvbnRlbnQ6IGNsZWFuZWQgfHwgJyhiaW5hcnkgZmlsZSknIH0pO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGUpIHsgY29udGludWU7IH1cbiAgfVxuXG4gIC8vIGNodW5rIGFuZCBlbWJlZFxuICBmb3IgKGNvbnN0IGRvYyBvZiBkb2NzKSB7XG4gICAgY29uc3QgY2h1bmtzID0gY2h1bmtUZXh0KGRvYy5jb250ZW50KTtcbiAgICBjb25zdCBlbWJlZGRpbmdzID0gYXdhaXQgZW1iZWRDaHVua3MoY2h1bmtzKTtcblxuICAgIC8vIHN0b3JlIGRvY3VtZW50cyBhbmQgZW1iZWRkaW5ncyBpbiBTdXBhYmFzZVxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgY2h1bmtzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBjb25zdCBjaHVuayA9IGNodW5rc1tpXTtcbiAgICAgIGNvbnN0IGVtYiA9IGVtYmVkZGluZ3MgPyBlbWJlZGRpbmdzW2ldIDogbnVsbDtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3RyYWluaW5nX2RvY3VtZW50cycsIHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGJvdF9pZDogYm90SWQsIHNvdXJjZTogZG9jLnNvdXJjZSwgY29udGVudDogY2h1bmssIGVtYmVkZGluZzogZW1iIH0pLFxuICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmV0dXJuPXJlcHJlc2VudGF0aW9uJywgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9LFxuICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgfSBjYXRjaCB7fVxuICAgIH1cbiAgfVxuXG4gIC8vIG1hcmsgam9iIGluIGxvZ3NcbiAgdHJ5IHtcbiAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFjdGlvbjogJ1RSQUlOX0pPQl9DT01QTEVURScsIGRldGFpbHM6IHsgam9iSWQsIGJvdElkLCBkb2NzOiBkb2NzLmxlbmd0aCB9IH0pLFxuICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gIH0gY2F0Y2gge31cbn1cblxuYXN5bmMgZnVuY3Rpb24gZW5zdXJlRG9tYWluVmVyaWZpY2F0aW9uKGRvbWFpbjogc3RyaW5nLCByZXE6IGFueSkge1xuICAvLyBjaGVjayBkb21haW5zIHRhYmxlIGZvciB2ZXJpZmllZFxuICB0cnkge1xuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goYC9yZXN0L3YxL2RvbWFpbnM/ZG9tYWluPWVxLiR7ZW5jb2RlVVJJQ29tcG9uZW50KGRvbWFpbil9YCwgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSk7XG4gICAgaWYgKHJlcyAmJiAocmVzIGFzIGFueSkub2spIHtcbiAgICAgIGNvbnN0IGogPSBhd2FpdCAocmVzIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gW10pO1xuICAgICAgaWYgKEFycmF5LmlzQXJyYXkoaikgJiYgai5sZW5ndGggPiAwICYmIGpbMF0udmVyaWZpZWQpIHJldHVybiB7IHZlcmlmaWVkOiB0cnVlIH07XG4gICAgfVxuICB9IGNhdGNoIHt9XG5cbiAgLy8gQ2hlY2sgZm9yIGV4aXN0aW5nIG5vbi1leHBpcmVkIHZlcmlmaWNhdGlvbiB0b2tlblxuICB0cnkge1xuICAgIGNvbnN0IG5vd0lzbyA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgICBjb25zdCBxID0gYC9yZXN0L3YxL2RvbWFpbl92ZXJpZmljYXRpb25zP2RvbWFpbj1lcS4ke2VuY29kZVVSSUNvbXBvbmVudChkb21haW4pfSZleHBpcmVzX2F0PWd0LiR7ZW5jb2RlVVJJQ29tcG9uZW50KG5vd0lzbyl9JnVzZWRfYXQ9aXMubnVsbGA7XG4gICAgY29uc3QgciA9IGF3YWl0IHN1cGFiYXNlRmV0Y2gocSwgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgaWYgKHIgJiYgKHIgYXMgYW55KS5vaykge1xuICAgICAgY29uc3QgYXJyID0gYXdhaXQgKHIgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBbXSk7XG4gICAgICBpZiAoQXJyYXkuaXNBcnJheShhcnIpICYmIGFyci5sZW5ndGggPiAwKSB7XG4gICAgICAgIGNvbnN0IGV4aXN0aW5nID0gYXJyWzBdO1xuICAgICAgICBpZiAoZXhpc3RpbmcudG9rZW4pIHJldHVybiB7IHZlcmlmaWVkOiBmYWxzZSwgdG9rZW46IGV4aXN0aW5nLnRva2VuIH07XG4gICAgICB9XG4gICAgfVxuICB9IGNhdGNoIHt9XG5cbiAgLy8gY3JlYXRlIHZlcmlmaWNhdGlvbiB0b2tlbiBlbnRyeSAocGVyc2lzdCB0b2tlbiBzbyB1c2VyIGNhbiByZXVzZSlcbiAgY29uc3QgdG9rZW4gPSBjcnlwdG8ucmFuZG9tQnl0ZXMoMTYpLnRvU3RyaW5nKCdiYXNlNjR1cmwnKTtcbiAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRE9NQUlOX1ZFUklGSUNBVElPTl9TRUNSRVQgfHwgJ2xvY2FsLWRvbS1zZWNyZXQnO1xuICBjb25zdCB0b2tlbkhhc2ggPSBjcnlwdG8uY3JlYXRlSGFzaCgnc2hhMjU2JykudXBkYXRlKHRva2VuICsgc2VjcmV0KS5kaWdlc3QoJ2Jhc2U2NCcpO1xuICBjb25zdCBleHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIDEwMDAgKiA2MCAqIDYwICogMjQpLnRvSVNPU3RyaW5nKCk7XG4gIHRyeSB7XG4gICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZG9tYWluX3ZlcmlmaWNhdGlvbnMnLCB7XG4gICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgZG9tYWluLCB0b2tlbiwgdG9rZW5faGFzaDogdG9rZW5IYXNoLCBleHBpcmVzX2F0OiBleHBpcmVzLCB1c2VkX2F0OiBudWxsIH0pLFxuICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXNvbHV0aW9uPW1lcmdlLWR1cGxpY2F0ZXMnLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgfSBjYXRjaCB7fVxuICByZXR1cm4geyB2ZXJpZmllZDogZmFsc2UsIHRva2VuIH07XG59XG5cbmZ1bmN0aW9uIHZlcmlmeVdpZGdldFRva2VuKHRva2VuOiBzdHJpbmcpIHtcbiAgdHJ5IHtcbiAgICBjb25zdCB3aWRnZXRTZWNyZXQgPSBwcm9jZXNzLmVudi5XSURHRVRfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC13aWRnZXQtc2VjcmV0JztcbiAgICBjb25zdCBwYXJ0cyA9IHRva2VuLnNwbGl0KCcuJyk7XG4gICAgaWYgKHBhcnRzLmxlbmd0aCAhPT0gMykgcmV0dXJuIG51bGw7XG4gICAgY29uc3QgdW5zaWduZWQgPSBwYXJ0c1swXSArICcuJyArIHBhcnRzWzFdO1xuICAgIGNvbnN0IHNpZyA9IHBhcnRzWzJdO1xuICAgIGNvbnN0IGV4cGVjdGVkID0gY3J5cHRvLmNyZWF0ZUhtYWMoJ3NoYTI1NicsIHdpZGdldFNlY3JldCkudXBkYXRlKHVuc2lnbmVkKS5kaWdlc3QoJ2Jhc2U2NHVybCcpO1xuICAgIGlmIChzaWcgIT09IGV4cGVjdGVkKSByZXR1cm4gbnVsbDtcbiAgICBjb25zdCBwYXlsb2FkID0gSlNPTi5wYXJzZShCdWZmZXIuZnJvbShwYXJ0c1sxXSwgJ2Jhc2U2NHVybCcpLnRvU3RyaW5nKCd1dGY4JykpO1xuICAgIHJldHVybiBwYXlsb2FkO1xuICB9IGNhdGNoIChlKSB7IHJldHVybiBudWxsOyB9XG59XG5cbi8vIFNpbXBsZSBpbi1tZW1vcnkgcmF0ZSBsaW1pdGVyXG5jb25zdCByYXRlTWFwID0gbmV3IE1hcDxzdHJpbmcsIHsgY291bnQ6IG51bWJlcjsgdHM6IG51bWJlciB9PigpO1xuZnVuY3Rpb24gcmF0ZUxpbWl0KGtleTogc3RyaW5nLCBsaW1pdDogbnVtYmVyLCB3aW5kb3dNczogbnVtYmVyKSB7XG4gIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gIGNvbnN0IHJlYyA9IHJhdGVNYXAuZ2V0KGtleSk7XG4gIGlmICghcmVjIHx8IG5vdyAtIHJlYy50cyA+IHdpbmRvd01zKSB7XG4gICAgcmF0ZU1hcC5zZXQoa2V5LCB7IGNvdW50OiAxLCB0czogbm93IH0pO1xuICAgIHJldHVybiB0cnVlO1xuICB9XG4gIGlmIChyZWMuY291bnQgPCBsaW1pdCkge1xuICAgIHJlYy5jb3VudCArPSAxO1xuICAgIHJldHVybiB0cnVlO1xuICB9XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHNlcnZlckFwaVBsdWdpbigpOiBQbHVnaW4ge1xuICByZXR1cm4ge1xuICAgIG5hbWU6ICdzZXJ2ZXItYXBpLXBsdWdpbicsXG4gICAgY29uZmlndXJlU2VydmVyKHNlcnZlcikge1xuICAgICAgc2VydmVyLm1pZGRsZXdhcmVzLnVzZShhc3luYyAocmVxLCByZXMsIG5leHQpID0+IHtcbiAgICAgICAgaWYgKCFyZXEudXJsIHx8ICFyZXEudXJsLnN0YXJ0c1dpdGgoJy9hcGkvJykpIHJldHVybiBuZXh0KCk7XG5cbiAgICAgICAgLy8gQmFzaWMgc2VjdXJpdHkgaGVhZGVycyBmb3IgYWxsIEFQSSByZXNwb25zZXNcbiAgICAgICAgY29uc3QgY29yc09yaWdpbiA9IHJlcS5oZWFkZXJzLm9yaWdpbiB8fCAnKic7XG4gICAgICAgIHJlcy5zZXRIZWFkZXIoJ1Blcm1pc3Npb25zLVBvbGljeScsICdnZW9sb2NhdGlvbj0oKSwgbWljcm9waG9uZT0oKSwgY2FtZXJhPSgpJyk7XG4gICAgICAgIHJlcy5zZXRIZWFkZXIoJ0Nyb3NzLU9yaWdpbi1SZXNvdXJjZS1Qb2xpY3knLCAnc2FtZS1vcmlnaW4nKTtcblxuICAgICAgICAvLyBJbiBkZXYgYWxsb3cgaHR0cDsgaW4gcHJvZCAoYmVoaW5kIHByb3h5KSwgcmVxdWlyZSBodHRwc1xuICAgICAgICBpZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgPT09ICdwcm9kdWN0aW9uJyAmJiAhaXNIdHRwcyhyZXEpKSB7XG4gICAgICAgICAgcmV0dXJuIGpzb24ocmVzLCA0MDAsIHsgZXJyb3I6ICdIVFRQUyByZXF1aXJlZCcgfSwgeyAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJzogU3RyaW5nKGNvcnNPcmlnaW4pIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQ09SUyBwcmVmbGlnaHRcbiAgICAgICAgaWYgKHJlcS5tZXRob2QgPT09ICdPUFRJT05TJykge1xuICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbicsIFN0cmluZyhjb3JzT3JpZ2luKSk7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctTWV0aG9kcycsICdQT1NULEdFVCxPUFRJT05TJyk7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycycsICdDb250ZW50LVR5cGUsIEF1dGhvcml6YXRpb24nKTtcbiAgICAgICAgICByZXMuc3RhdHVzQ29kZSA9IDIwNDtcbiAgICAgICAgICByZXR1cm4gcmVzLmVuZCgpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZW5kSnNvbiA9IChzdGF0dXM6IG51bWJlciwgZGF0YTogYW55KSA9PiBqc29uKHJlcywgc3RhdHVzLCBkYXRhLCB7ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nOiBTdHJpbmcoY29yc09yaWdpbikgfSk7XG5cbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvdHJhaW4nICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgaXAgPSAocmVxLmhlYWRlcnNbJ3gtZm9yd2FyZGVkLWZvciddIGFzIHN0cmluZykgfHwgcmVxLnNvY2tldC5yZW1vdGVBZGRyZXNzIHx8ICdpcCc7XG4gICAgICAgICAgICBpZiAoIXJhdGVMaW1pdCgndHJhaW46JyArIGlwLCAyMCwgNjBfMDAwKSkgcmV0dXJuIGVuZEpzb24oNDI5LCB7IGVycm9yOiAnVG9vIE1hbnkgUmVxdWVzdHMnIH0pO1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpLmNhdGNoKCgpID0+ICh7fSkpO1xuICAgICAgICAgICAgY29uc3QgdXJsID0gdHlwZW9mIGJvZHk/LnVybCA9PT0gJ3N0cmluZycgPyBib2R5LnVybC50cmltKCkgOiAnJztcbiAgICAgICAgICAgIGlmICghdXJsICYmICFBcnJheS5pc0FycmF5KGJvZHk/LmZpbGVzKSkge1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdQcm92aWRlIHVybCBvciBmaWxlcycgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAodXJsKSB7XG4gICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgY29uc3QgdSA9IG5ldyBVUkwodXJsKTtcbiAgICAgICAgICAgICAgICBpZiAoISh1LnByb3RvY29sID09PSAnaHR0cDonIHx8IHUucHJvdG9jb2wgPT09ICdodHRwczonKSkgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkJyk7XG4gICAgICAgICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgdXJsJyB9KTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBMb2cgZXZlbnRcbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3NlY3VyaXR5X2xvZ3MnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFjdGlvbjogJ1RSQUlOX1JFUVVFU1QnLCBkZXRhaWxzOiB7IGhhc1VybDogISF1cmwsIGZpbGVDb3VudDogKGJvZHk/LmZpbGVzPy5sZW5ndGgpIHx8IDAgfSB9KSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIGNvbnN0IGpvYklkID0gbWFrZUJvdElkKCh1cmwgfHwgJycpICsgRGF0ZS5ub3coKSk7XG5cbiAgICAgICAgICAgIC8vIFN0YXJ0IGJhY2tncm91bmQgcHJvY2Vzc2luZyAobm9uLWJsb2NraW5nKVxuICAgICAgICAgICAgKGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBhd2FpdCBwcm9jZXNzVHJhaW5Kb2Ioam9iSWQsIHsgdXJsLCBmaWxlczogQXJyYXkuaXNBcnJheShib2R5Py5maWxlcykgPyBib2R5LmZpbGVzIDogW10gfSwgcmVxKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBhY3Rpb246ICdUUkFJTl9KT0JfRVJST1InLCBkZXRhaWxzOiB7IGpvYklkLCBlcnJvcjogU3RyaW5nKGU/Lm1lc3NhZ2UgfHwgZSkgfSB9KSxcbiAgICAgICAgICAgICAgICAgIH0sIHJlcSk7XG4gICAgICAgICAgICAgICAgfSBjYXRjaCB7fVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KSgpO1xuXG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDIsIHsgam9iSWQsIHN0YXR1czogJ3F1ZXVlZCcgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2Nvbm5lY3QnICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpO1xuICAgICAgICAgICAgaWYgKGJvZHk/LmNoYW5uZWwgIT09ICd3ZWJzaXRlJykgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnVW5zdXBwb3J0ZWQgY2hhbm5lbCcgfSk7XG4gICAgICAgICAgICBjb25zdCByYXdVcmwgPSAoYm9keT8udXJsIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBjb25zdCBkb21haW4gPSAoKCkgPT4ge1xuICAgICAgICAgICAgICB0cnkgeyByZXR1cm4gcmF3VXJsID8gbmV3IFVSTChyYXdVcmwpLmhvc3QgOiAnbG9jYWwnOyB9IGNhdGNoIHsgcmV0dXJuICdsb2NhbCc7IH1cbiAgICAgICAgICAgIH0pKCk7XG5cbiAgICAgICAgICAgIC8vIEVuc3VyZSBkb21haW4gdmVyaWZpY2F0aW9uXG4gICAgICAgICAgICBjb25zdCB2cmVzID0gYXdhaXQgZW5zdXJlRG9tYWluVmVyaWZpY2F0aW9uKGRvbWFpbiwgcmVxKTtcbiAgICAgICAgICAgIGlmICghdnJlcy52ZXJpZmllZCkge1xuICAgICAgICAgICAgICAvLyByZXR1cm4gdmVyaWZpY2F0aW9uIHJlcXVpcmVkIGFuZCBpbnN0cnVjdGlvbnNcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAyLCB7IHN0YXR1czogJ3ZlcmlmaWNhdGlvbl9yZXF1aXJlZCcsIGluc3RydWN0aW9uczogYEFkZCBhIEROUyBUWFQgcmVjb3JkIG9yIGEgbWV0YSB0YWcgd2l0aCB0b2tlbjogJHt2cmVzLnRva2VufWAsIHRva2VuOiB2cmVzLnRva2VuIH0pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBjb25zdCBzZWVkID0gZG9tYWluICsgJ3wnICsgKHJlcS5oZWFkZXJzWydhdXRob3JpemF0aW9uJ10gfHwgJycpO1xuICAgICAgICAgICAgY29uc3QgYm90SWQgPSBtYWtlQm90SWQoc2VlZCk7XG5cbiAgICAgICAgICAgIC8vIFVwc2VydCBjaGF0Ym90X2NvbmZpZ3MgKGlmIFJMUyBhbGxvd3Mgd2l0aCB1c2VyIHRva2VuKVxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvY2hhdGJvdF9jb25maWdzJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBib3RfaWQ6IGJvdElkLCBjaGFubmVsOiAnd2Vic2l0ZScsIGRvbWFpbiwgc2V0dGluZ3M6IHt9IH0pLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycgfSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIC8vIENyZWF0ZSB3aWRnZXQgdG9rZW4gKEhNQUMgc2lnbmVkKVxuICAgICAgICAgICAgY29uc3Qgd2lkZ2V0UGF5bG9hZCA9IHsgYm90SWQsIGRvbWFpbiwgaWF0OiBNYXRoLmZsb29yKERhdGUubm93KCkvMTAwMCkgfTtcbiAgICAgICAgICAgIGNvbnN0IHdpZGdldFNlY3JldCA9IHByb2Nlc3MuZW52LldJREdFVF9UT0tFTl9TRUNSRVQgfHwgJ2xvY2FsLXdpZGdldC1zZWNyZXQnO1xuICAgICAgICAgICAgY29uc3QgaGVhZGVyID0geyBhbGc6ICdIUzI1NicsIHR5cDogJ0pXVCcgfTtcbiAgICAgICAgICAgIGNvbnN0IGI2NCA9IChzOiBzdHJpbmcpID0+IEJ1ZmZlci5mcm9tKHMpLnRvU3RyaW5nKCdiYXNlNjR1cmwnKTtcbiAgICAgICAgICAgIGNvbnN0IHVuc2lnbmVkID0gYjY0KEpTT04uc3RyaW5naWZ5KGhlYWRlcikpICsgJy4nICsgYjY0KEpTT04uc3RyaW5naWZ5KHdpZGdldFBheWxvYWQpKTtcbiAgICAgICAgICAgIGNvbnN0IHNpZyA9IGNyeXB0by5jcmVhdGVIbWFjKCdzaGEyNTYnLCB3aWRnZXRTZWNyZXQpLnVwZGF0ZSh1bnNpZ25lZCkuZGlnZXN0KCdiYXNlNjR1cmwnKTtcbiAgICAgICAgICAgIGNvbnN0IHdpZGdldFRva2VuID0gdW5zaWduZWQgKyAnLicgKyBzaWc7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBib3RJZCwgd2lkZ2V0VG9rZW4gfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gV2lkZ2V0IGNvbmZpZyBlbmRwb2ludDogcmV0dXJucyBib3Qgc2V0dGluZ3MgZm9yIHdpZGdldCBjb25zdW1lcnMgKHJlcXVpcmVzIHRva2VuKVxuICAgICAgICAgIGlmIChyZXEudXJsPy5zdGFydHNXaXRoKCcvYXBpL3dpZGdldC1jb25maWcnKSAmJiByZXEubWV0aG9kID09PSAnR0VUJykge1xuICAgICAgICAgICAgY29uc3QgdXJsT2JqID0gbmV3IFVSTChyZXEudXJsLCAnaHR0cDovL2xvY2FsJyk7XG4gICAgICAgICAgICBjb25zdCBib3RJZCA9IHVybE9iai5zZWFyY2hQYXJhbXMuZ2V0KCdib3RJZCcpIHx8ICcnO1xuICAgICAgICAgICAgY29uc3QgdG9rZW4gPSB1cmxPYmouc2VhcmNoUGFyYW1zLmdldCgndG9rZW4nKSB8fCAnJztcbiAgICAgICAgICAgIGlmICghYm90SWQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgYm90SWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgcGF5bG9hZCA9IHZlcmlmeVdpZGdldFRva2VuKHRva2VuKTtcbiAgICAgICAgICAgIGlmICghcGF5bG9hZCB8fCBwYXlsb2FkLmJvdElkICE9PSBib3RJZCkgcmV0dXJuIGVuZEpzb24oNDAxLCB7IGVycm9yOiAnSW52YWxpZCB0b2tlbicgfSk7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvY2hhdGJvdF9jb25maWdzP2JvdF9pZD1lcS4nICsgZW5jb2RlVVJJQ29tcG9uZW50KGJvdElkKSArICcmc2VsZWN0PSonLCB7IG1ldGhvZDogJ0dFVCcgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKCFyIHx8ICEociBhcyBhbnkpLm9rKSByZXR1cm4gZW5kSnNvbig0MDQsIHsgZXJyb3I6ICdOb3QgZm91bmQnIH0pO1xuICAgICAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgKHIgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBbXSk7XG4gICAgICAgICAgICAgIGNvbnN0IGNmZyA9IEFycmF5LmlzQXJyYXkoZGF0YSkgJiYgZGF0YS5sZW5ndGggPiAwID8gZGF0YVswXSA6IHsgc2V0dGluZ3M6IHt9IH07XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBzZXR0aW5nczogY2ZnIH0pO1xuICAgICAgICAgICAgfSBjYXRjaCAoZSkgeyByZXR1cm4gZW5kSnNvbig1MDAsIHsgZXJyb3I6ICdTZXJ2ZXIgZXJyb3InIH0pOyB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2RlYnVnLWZldGNoJyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IHVybFN0ciA9IFN0cmluZyhib2R5Py51cmwgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghdXJsU3RyKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIHVybCcgfSk7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmxTdHIpO1xuICAgICAgICAgICAgICBpZiAoISh1LnByb3RvY29sID09PSAnaHR0cDonIHx8IHUucHJvdG9jb2wgPT09ICdodHRwczonKSkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCBwcm90b2NvbCcgfSk7XG4gICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgdXJsJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHIgPSBhd2FpdCBmZXRjaCh1cmxTdHIsIHsgaGVhZGVyczogeyAnVXNlci1BZ2VudCc6ICdOZXhhQm90VmVyaWZpZXIvMS4wJyB9IH0pO1xuICAgICAgICAgICAgICBpZiAoIXIgfHwgIXIub2spIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ZldGNoIGZhaWxlZCcsIHN0YXR1czogciA/IHIuc3RhdHVzIDogMCB9KTtcbiAgICAgICAgICAgICAgY29uc3QgdGV4dCA9IGF3YWl0IHIudGV4dCgpO1xuICAgICAgICAgICAgICAvLyByZXR1cm4gYSBzbmlwcGV0IHRvIGF2b2lkIGh1Z2UgcGF5bG9hZHNcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IG9rOiB0cnVlLCB1cmw6IHVybFN0ciwgc25pcHBldDogdGV4dC5zbGljZSgwLCAyMDAwMCkgfSk7XG4gICAgICAgICAgICB9IGNhdGNoIChlOiBhbnkpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNTAwLCB7IGVycm9yOiAnRmV0Y2ggZXJyb3InLCBtZXNzYWdlOiBTdHJpbmcoZT8ubWVzc2FnZSB8fCBlKSB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvdmVyaWZ5LWRvbWFpbicgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCBkb21haW4gPSBTdHJpbmcoYm9keT8uZG9tYWluIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IFN0cmluZyhib2R5Py50b2tlbiB8fCAnJykudHJpbSgpO1xuICAgICAgICAgICAgaWYgKCFkb21haW4gfHwgIXRva2VuKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIGRvbWFpbiBvciB0b2tlbicgfSk7XG5cbiAgICAgICAgICAgIC8vIFRyeSBtdWx0aXBsZSBjYW5kaWRhdGUgVVJMcyBmb3IgdmVyaWZpY2F0aW9uIChyb290LCBpbmRleC5odG1sLCB3ZWxsLWtub3duKVxuICAgICAgICAgICAgY29uc3QgY2FuZGlkYXRlcyA9IFtcbiAgICAgICAgICAgICAgYGh0dHBzOi8vJHtkb21haW59YCxcbiAgICAgICAgICAgICAgYGh0dHA6Ly8ke2RvbWFpbn1gLFxuICAgICAgICAgICAgICBgaHR0cHM6Ly8ke2RvbWFpbn0vaW5kZXguaHRtbGAsXG4gICAgICAgICAgICAgIGBodHRwOi8vJHtkb21haW59L2luZGV4Lmh0bWxgLFxuICAgICAgICAgICAgICBgaHR0cHM6Ly8ke2RvbWFpbn0vLndlbGwta25vd24vbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uYCxcbiAgICAgICAgICAgICAgYGh0dHA6Ly8ke2RvbWFpbn0vLndlbGwta25vd24vbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uYCxcbiAgICAgICAgICAgIF07XG5cbiAgICAgICAgICAgIC8vIEJ1aWxkIHJvYnVzdCByZWdleCB0byBtYXRjaCBtZXRhIHRhZyBpbiBhbnkgYXR0cmlidXRlIG9yZGVyXG4gICAgICAgICAgICBjb25zdCBlc2MgPSAoczogc3RyaW5nKSA9PiBzLnJlcGxhY2UoL1stL1xcXFxeJCorPy4oKXxbXFxde31dL2csICdcXFxcJCYnKTtcbiAgICAgICAgICAgIGNvbnN0IHRFc2MgPSBlc2ModG9rZW4pO1xuICAgICAgICAgICAgY29uc3QgbWV0YVJlID0gbmV3IFJlZ0V4cChgPG1ldGFbXj5dKig/Om5hbWVcXHMqPVxccypbJ1xcXCJdbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uWydcXFwiXVtePl0qY29udGVudFxccyo9XFxzKlsnXFxcIl0ke3RFc2N9WydcXFwiXXxjb250ZW50XFxzKj1cXHMqWydcXFwiXSR7dEVzY31bJ1xcXCJdW14+XSpuYW1lXFxzKj1cXHMqWydcXFwiXW5leGFib3QtZG9tYWluLXZlcmlmaWNhdGlvblsnXFxcIl0pYCwgJ2knKTtcbiAgICAgICAgICAgIGNvbnN0IHBsYWluUmUgPSBuZXcgUmVnRXhwKGBuZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25bOj1dXFxzKiR7dEVzY31gLCAnaScpO1xuXG4gICAgICAgICAgICBsZXQgZm91bmQgPSBmYWxzZTtcbiAgICAgICAgICAgIGZvciAoY29uc3QgdXJsIG9mIGNhbmRpZGF0ZXMpIHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgZmV0Y2godXJsLCB7IGhlYWRlcnM6IHsgJ1VzZXItQWdlbnQnOiAnTmV4YUJvdFZlcmlmaWVyLzEuMCcgfSB9KTtcbiAgICAgICAgICAgICAgICBpZiAoIXIgfHwgIXIub2spIGNvbnRpbnVlO1xuICAgICAgICAgICAgICAgIGNvbnN0IHRleHQgPSBhd2FpdCByLnRleHQoKTtcbiAgICAgICAgICAgICAgICBpZiAobWV0YVJlLnRlc3QodGV4dCkgfHwgcGxhaW5SZS50ZXN0KHRleHQpKSB7XG4gICAgICAgICAgICAgICAgICBmb3VuZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICAvLyBpZ25vcmUgYW5kIHRyeSBuZXh0IGNhbmRpZGF0ZVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghZm91bmQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ1ZlcmlmaWNhdGlvbiB0b2tlbiBub3QgZm91bmQgb24gc2l0ZScgfSk7XG5cbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2RvbWFpbnMnLCB7XG4gICAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBkb21haW4sIHZlcmlmaWVkOiB0cnVlLCB2ZXJpZmllZF9hdDogbmV3IERhdGUoKS50b0lTT1N0cmluZygpIH0pLFxuICAgICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmVzb2x1dGlvbj1tZXJnZS1kdXBsaWNhdGVzJywgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9LFxuICAgICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgfSBjYXRjaCB7fVxuXG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgb2s6IHRydWUsIGRvbWFpbiB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvbGF1bmNoJyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKTtcbiAgICAgICAgICAgIGNvbnN0IGJvdElkID0gU3RyaW5nKGJvZHk/LmJvdElkIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBpZiAoIWJvdElkKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIGJvdElkJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGN1c3RvbWl6YXRpb24gPSBib2R5Py5jdXN0b21pemF0aW9uIHx8IHt9O1xuXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9jaGF0Ym90X2NvbmZpZ3M/Ym90X2lkPWVxLicgKyBlbmNvZGVVUklDb21wb25lbnQoYm90SWQpLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BBVENIJyxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBzZXR0aW5nczogY3VzdG9taXphdGlvbiB9KSxcbiAgICAgICAgICAgICAgaGVhZGVyczogeyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLCBQcmVmZXI6ICdyZXR1cm49cmVwcmVzZW50YXRpb24nIH0sXG4gICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuXG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgYm90SWQgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2NoYXQnICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgaXAgPSAocmVxLmhlYWRlcnNbJ3gtZm9yd2FyZGVkLWZvciddIGFzIHN0cmluZykgfHwgcmVxLnNvY2tldC5yZW1vdGVBZGRyZXNzIHx8ICdpcCc7XG4gICAgICAgICAgICBpZiAoIXJhdGVMaW1pdCgnY2hhdDonICsgaXAsIDYwLCA2MF8wMDApKSByZXR1cm4gZW5kSnNvbig0MjksIHsgZXJyb3I6ICdUb28gTWFueSBSZXF1ZXN0cycgfSk7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCBtZXNzYWdlID0gU3RyaW5nKGJvZHk/Lm1lc3NhZ2UgfHwgJycpLnNsaWNlKDAsIDIwMDApO1xuICAgICAgICAgICAgaWYgKCFtZXNzYWdlKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdFbXB0eSBtZXNzYWdlJyB9KTtcblxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnQ0hBVCcsIGRldGFpbHM6IHsgbGVuOiBtZXNzYWdlLmxlbmd0aCB9IH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgY29uc3QgcmVwbHkgPSBcIkknbSBzdGlsbCBsZWFybmluZywgYnV0IG91ciB0ZWFtIHdpbGwgZ2V0IGJhY2sgdG8geW91IHNvb24uXCI7XG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgcmVwbHkgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gQ3VzdG9tIGVtYWlsIHZlcmlmaWNhdGlvbjogc2VuZCBlbWFpbFxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9zZW5kLXZlcmlmeScgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBpcCA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtZm9yJ10gYXMgc3RyaW5nKSB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJ2lwJztcbiAgICAgICAgICAgIGlmICghcmF0ZUxpbWl0KCd2ZXJpZnk6JyArIGlwLCA1LCA2MCo2MF8wMDApKSByZXR1cm4gZW5kSnNvbig0MjksIHsgZXJyb3I6ICdUb28gTWFueSBSZXF1ZXN0cycgfSk7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCBlbWFpbCA9IFN0cmluZyhib2R5Py5lbWFpbCB8fCAnJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgICBpZiAoIS9eW15cXHNAXStAW15cXHNAXStcXC5bXlxcc0BdKyQvLnRlc3QoZW1haWwpKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdJbnZhbGlkIGVtYWlsJyB9KTtcblxuICAgICAgICAgICAgLy8gVmVyaWZ5IGF1dGhlbnRpY2F0ZWQgdXNlciBtYXRjaGVzIGVtYWlsXG4gICAgICAgICAgICBjb25zdCB1cmVzID0gYXdhaXQgc3VwYWJhc2VGZXRjaCgnL2F1dGgvdjEvdXNlcicsIHsgbWV0aG9kOiAnR0VUJyB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgaWYgKCF1cmVzIHx8ICEodXJlcyBhcyBhbnkpLm9rKSByZXR1cm4gZW5kSnNvbig0MDEsIHsgZXJyb3I6ICdVbmF1dGhvcml6ZWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgdXNlciA9IGF3YWl0ICh1cmVzIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICBpZiAoIXVzZXIgfHwgdXNlci5lbWFpbD8udG9Mb3dlckNhc2UoKSAhPT0gZW1haWwpIHJldHVybiBlbmRKc29uKDQwMywgeyBlcnJvcjogJ0VtYWlsIG1pc21hdGNoJyB9KTtcblxuICAgICAgICAgICAgY29uc3QgdG9rZW4gPSBjcnlwdG8ucmFuZG9tQnl0ZXMoMzIpLnRvU3RyaW5nKCdiYXNlNjR1cmwnKTtcbiAgICAgICAgICAgIGNvbnN0IHNlY3JldCA9IHByb2Nlc3MuZW52LkVNQUlMX1RPS0VOX1NFQ1JFVCB8fCAnbG9jYWwtc2VjcmV0JztcbiAgICAgICAgICAgIGNvbnN0IHRva2VuSGFzaCA9IGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUodG9rZW4gKyBzZWNyZXQpLmRpZ2VzdCgnYmFzZTY0Jyk7XG4gICAgICAgICAgICBjb25zdCBleHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIDEwMDAgKiA2MCAqIDYwICogMjQpLnRvSVNPU3RyaW5nKCk7XG5cbiAgICAgICAgICAgIC8vIFN0b3JlIHRva2VuIGhhc2ggKG5vdCByYXcgdG9rZW4pXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9lbWFpbF92ZXJpZmljYXRpb25zJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXNvbHV0aW9uPW1lcmdlLWR1cGxpY2F0ZXMnIH0sXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdXNlcl9pZDogdXNlci5pZCwgZW1haWwsIHRva2VuX2hhc2g6IHRva2VuSGFzaCwgZXhwaXJlc19hdDogZXhwaXJlcywgdXNlZF9hdDogbnVsbCB9KSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIC8vIFNlbmQgZW1haWwgdmlhIFNNVFBcbiAgICAgICAgICAgIGNvbnN0IGhvc3QgPSBwcm9jZXNzLmVudi5TTVRQX0hPU1Q7XG4gICAgICAgICAgICBjb25zdCBwb3J0ID0gTnVtYmVyKHByb2Nlc3MuZW52LlNNVFBfUE9SVCB8fCA1ODcpO1xuICAgICAgICAgICAgY29uc3QgdXNlclNtdHAgPSBwcm9jZXNzLmVudi5TTVRQX1VTRVI7XG4gICAgICAgICAgICBjb25zdCBwYXNzU210cCA9IHByb2Nlc3MuZW52LlNNVFBfUEFTUztcbiAgICAgICAgICAgIGNvbnN0IGZyb20gPSBwcm9jZXNzLmVudi5FTUFJTF9GUk9NIHx8ICdOZXhhQm90IDxuby1yZXBseUBuZXhhYm90LmFpPic7XG4gICAgICAgICAgICBjb25zdCBhcHBVcmwgPSBwcm9jZXNzLmVudi5BUFBfVVJMIHx8ICdodHRwOi8vbG9jYWxob3N0OjMwMDAnO1xuICAgICAgICAgICAgY29uc3QgdmVyaWZ5VXJsID0gYCR7YXBwVXJsfS9hcGkvdmVyaWZ5LWVtYWlsP3Rva2VuPSR7dG9rZW59YDtcblxuICAgICAgICAgICAgaWYgKGhvc3QgJiYgdXNlclNtdHAgJiYgcGFzc1NtdHApIHtcbiAgICAgICAgICAgICAgY29uc3QgdHJhbnNwb3J0ZXIgPSBub2RlbWFpbGVyLmNyZWF0ZVRyYW5zcG9ydCh7IGhvc3QsIHBvcnQsIHNlY3VyZTogcG9ydCA9PT0gNDY1LCBhdXRoOiB7IHVzZXI6IHVzZXJTbXRwLCBwYXNzOiBwYXNzU210cCB9IH0pO1xuICAgICAgICAgICAgICBjb25zdCBodG1sID0gYFxuICAgICAgICAgICAgICAgIDx0YWJsZSBzdHlsZT1cIndpZHRoOjEwMCU7YmFja2dyb3VuZDojZjZmOGZiO3BhZGRpbmc6MjRweDtmb250LWZhbWlseTpJbnRlcixTZWdvZSBVSSxBcmlhbCxzYW5zLXNlcmlmO2NvbG9yOiMwZjE3MmFcIj5cbiAgICAgICAgICAgICAgICAgIDx0cj48dGQgYWxpZ249XCJjZW50ZXJcIj5cbiAgICAgICAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPVwibWF4LXdpZHRoOjU2MHB4O3dpZHRoOjEwMCU7YmFja2dyb3VuZDojZmZmZmZmO2JvcmRlcjoxcHggc29saWQgI2U1ZTdlYjtib3JkZXItcmFkaXVzOjEycHg7b3ZlcmZsb3c6aGlkZGVuXCI+XG4gICAgICAgICAgICAgICAgICAgICAgPHRyPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPVwiYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsIzYzNjZmMSwjOGI1Y2Y2KTtwYWRkaW5nOjIwcHg7Y29sb3I6I2ZmZjtmb250LXNpemU6MThweDtmb250LXdlaWdodDo3MDBcIj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgTmV4YUJvdFxuICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICAgIDx0cj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT1cInBhZGRpbmc6MjRweFwiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8aDEgc3R5bGU9XCJtYXJnaW46MCAwIDhweCAwO2ZvbnQtc2l6ZToyMHB4O2NvbG9yOiMxMTE4MjdcIj5Db25maXJtIHlvdXIgZW1haWw8L2gxPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8cCBzdHlsZT1cIm1hcmdpbjowIDAgMTZweCAwO2NvbG9yOiMzNzQxNTE7bGluZS1oZWlnaHQ6MS41XCI+SGksIHBsZWFzZSBjb25maXJtIHlvdXIgZW1haWwgYWRkcmVzcyB0byBzZWN1cmUgeW91ciBOZXhhQm90IGFjY291bnQgYW5kIGNvbXBsZXRlIHNldHVwLjwvcD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgPHAgc3R5bGU9XCJtYXJnaW46MCAwIDE2cHggMDtjb2xvcjojMzc0MTUxO2xpbmUtaGVpZ2h0OjEuNVwiPlRoaXMgbGluayBleHBpcmVzIGluIDI0IGhvdXJzLjwvcD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgPGEgaHJlZj1cIiR7dmVyaWZ5VXJsfVwiIHN0eWxlPVwiZGlzcGxheTppbmxpbmUtYmxvY2s7YmFja2dyb3VuZDojNjM2NmYxO2NvbG9yOiNmZmY7dGV4dC1kZWNvcmF0aW9uOm5vbmU7cGFkZGluZzoxMHB4IDE2cHg7Ym9yZGVyLXJhZGl1czo4cHg7Zm9udC13ZWlnaHQ6NjAwXCI+VmVyaWZ5IEVtYWlsPC9hPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8cCBzdHlsZT1cIm1hcmdpbjoxNnB4IDAgMCAwO2NvbG9yOiM2YjcyODA7Zm9udC1zaXplOjEycHhcIj5JZiB0aGUgYnV0dG9uIGRvZXNuXHUyMDE5dCB3b3JrLCBjb3B5IGFuZCBwYXN0ZSB0aGlzIGxpbmsgaW50byB5b3VyIGJyb3dzZXI6PGJyPiR7dmVyaWZ5VXJsfTwvcD5cbiAgICAgICAgICAgICAgICAgICAgICAgIDwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICAgICAgICA8dHI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9XCJwYWRkaW5nOjE2cHggMjRweDtjb2xvcjojNmI3MjgwO2ZvbnQtc2l6ZToxMnB4O2JvcmRlci10b3A6MXB4IHNvbGlkICNlNWU3ZWJcIj5cdTAwQTkgJHtuZXcgRGF0ZSgpLmdldEZ1bGxZZWFyKCl9IE5leGFCb3QuIEFsbCByaWdodHMgcmVzZXJ2ZWQuPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICA8L3RhYmxlPlxuICAgICAgICAgICAgICAgICAgPC90ZD48L3RyPlxuICAgICAgICAgICAgICAgIDwvdGFibGU+YDtcbiAgICAgICAgICAgICAgYXdhaXQgdHJhbnNwb3J0ZXIuc2VuZE1haWwoeyB0bzogZW1haWwsIGZyb20sIHN1YmplY3Q6ICdWZXJpZnkgeW91ciBlbWFpbCBmb3IgTmV4YUJvdCcsIGh0bWwgfSk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBpZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgIT09ICdwcm9kdWN0aW9uJykge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUud2FybignW2VtYWlsXSBTTVRQIG5vdCBjb25maWd1cmVkOyB2ZXJpZmljYXRpb24gVVJMOicsIHZlcmlmeVVybCk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IG9rOiB0cnVlIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIC8vIFZlcmlmeSBsaW5rIGVuZHBvaW50XG4gICAgICAgICAgaWYgKHJlcS51cmw/LnN0YXJ0c1dpdGgoJy9hcGkvdmVyaWZ5LWVtYWlsJykgJiYgcmVxLm1ldGhvZCA9PT0gJ0dFVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IHVybE9iaiA9IG5ldyBVUkwocmVxLnVybCwgJ2h0dHA6Ly9sb2NhbCcpO1xuICAgICAgICAgICAgY29uc3QgdG9rZW4gPSB1cmxPYmouc2VhcmNoUGFyYW1zLmdldCgndG9rZW4nKSB8fCAnJztcbiAgICAgICAgICAgIGlmICghdG9rZW4pIHtcbiAgICAgICAgICAgICAgcmVzLnN0YXR1c0NvZGUgPSA0MDA7XG4gICAgICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0NvbnRlbnQtVHlwZScsICd0ZXh0L2h0bWwnKTtcbiAgICAgICAgICAgICAgcmV0dXJuIHJlcy5lbmQoJzxwPkludmFsaWQgdG9rZW48L3A+Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCBzZWNyZXQgPSBwcm9jZXNzLmVudi5FTUFJTF9UT0tFTl9TRUNSRVQgfHwgJ2xvY2FsLXNlY3JldCc7XG4gICAgICAgICAgICBjb25zdCB0b2tlbkhhc2ggPSBjcnlwdG8uY3JlYXRlSGFzaCgnc2hhMjU2JykudXBkYXRlKHRva2VuICsgc2VjcmV0KS5kaWdlc3QoJ2Jhc2U2NCcpO1xuXG4gICAgICAgICAgICAvLyBQcmVmZXIgUlBDIChzZWN1cml0eSBkZWZpbmVyKSBvbiBEQjogdmVyaWZ5X2VtYWlsX2hhc2gocF9oYXNoIHRleHQpXG4gICAgICAgICAgICBsZXQgb2sgPSBmYWxzZTtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHJwYyA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3JwYy92ZXJpZnlfZW1haWxfaGFzaCcsIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHBfaGFzaDogdG9rZW5IYXNoIH0pLFxuICAgICAgICAgICAgICB9LCByZXEpO1xuICAgICAgICAgICAgICBpZiAocnBjICYmIChycGMgYXMgYW55KS5vaykgb2sgPSB0cnVlO1xuICAgICAgICAgICAgfSBjYXRjaCB7fVxuXG4gICAgICAgICAgICBpZiAoIW9rKSB7XG4gICAgICAgICAgICAgIGNvbnN0IG5vd0lzbyA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZW1haWxfdmVyaWZpY2F0aW9ucz90b2tlbl9oYXNoPWVxLicgKyBlbmNvZGVVUklDb21wb25lbnQodG9rZW5IYXNoKSArICcmdXNlZF9hdD1pcy5udWxsJmV4cGlyZXNfYXQ9Z3QuJyArIGVuY29kZVVSSUNvbXBvbmVudChub3dJc28pLCB7XG4gICAgICAgICAgICAgICAgbWV0aG9kOiAnUEFUQ0gnLFxuICAgICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdXNlZF9hdDogbm93SXNvIH0pLFxuICAgICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmV0dXJuPXJlcHJlc2VudGF0aW9uJyB9LFxuICAgICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXMuc3RhdHVzQ29kZSA9IDIwMDtcbiAgICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0NvbnRlbnQtVHlwZScsICd0ZXh0L2h0bWwnKTtcbiAgICAgICAgICAgIHJldHVybiByZXMuZW5kKGA8IWRvY3R5cGUgaHRtbD48bWV0YSBodHRwLWVxdWl2PVwicmVmcmVzaFwiIGNvbnRlbnQ9XCIyO3VybD0vXCI+PHN0eWxlPmJvZHl7Zm9udC1mYW1pbHk6SW50ZXIsU2Vnb2UgVUksQXJpYWwsc2Fucy1zZXJpZjtiYWNrZ3JvdW5kOiNmNmY4ZmI7Y29sb3I6IzExMTgyNztkaXNwbGF5OmdyaWQ7cGxhY2UtaXRlbXM6Y2VudGVyO2hlaWdodDoxMDB2aH08L3N0eWxlPjxkaXY+PGgxPlx1MjcwNSBFbWFpbCB2ZXJpZmllZDwvaDE+PHA+WW91IGNhbiBjbG9zZSB0aGlzIHRhYi48L3A+PC9kaXY+YCk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDA0LCB7IGVycm9yOiAnTm90IEZvdW5kJyB9KTtcbiAgICAgICAgfSBjYXRjaCAoZTogYW55KSB7XG4gICAgICAgICAgcmV0dXJuIGVuZEpzb24oNTAwLCB7IGVycm9yOiAnU2VydmVyIEVycm9yJyB9KTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSxcbiAgfTtcbn1cbiJdLAogICJtYXBwaW5ncyI6ICI7QUFBNk0sU0FBUyxvQkFBb0I7QUFDMU8sT0FBTyxXQUFXO0FBQ2xCLE9BQU8sVUFBVTtBQUNqQixTQUFTLHVCQUF1Qjs7O0FDRmhDLE9BQU8sWUFBWTtBQUNuQixPQUFPLGdCQUFnQjtBQUd2QixlQUFlLFVBQVUsS0FBVSxRQUFRLE9BQU8sS0FBSztBQUNyRCxTQUFPLElBQUksUUFBYSxDQUFDLFNBQVMsV0FBVztBQUMzQyxVQUFNLFNBQW1CLENBQUM7QUFDMUIsUUFBSSxPQUFPO0FBQ1gsUUFBSSxHQUFHLFFBQVEsQ0FBQyxNQUFjO0FBQzVCLGNBQVEsRUFBRTtBQUNW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
