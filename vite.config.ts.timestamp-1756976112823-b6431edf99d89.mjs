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
  const token = crypto.randomBytes(16).toString("base64url");
  const secret = process.env.DOMAIN_VERIFICATION_SECRET || "local-dom-secret";
  const tokenHash = crypto.createHash("sha256").update(token + secret).digest("base64");
  const expires = new Date(Date.now() + 1e3 * 60 * 60 * 24).toISOString();
  try {
    await supabaseFetch("/rest/v1/domain_verifications", {
      method: "POST",
      body: JSON.stringify({ domain, token_hash: tokenHash, expires_at: expires }),
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL3NlcnZlci9hcGkudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGVcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9hcHAvY29kZS92aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vYXBwL2NvZGUvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tIFwidml0ZVwiO1xuaW1wb3J0IHJlYWN0IGZyb20gXCJAdml0ZWpzL3BsdWdpbi1yZWFjdC1zd2NcIjtcbmltcG9ydCBwYXRoIGZyb20gXCJwYXRoXCI7XG5pbXBvcnQgeyBjb21wb25lbnRUYWdnZXIgfSBmcm9tIFwibG92YWJsZS10YWdnZXJcIjtcbmltcG9ydCB7IHNlcnZlckFwaVBsdWdpbiB9IGZyb20gXCIuL3NyYy9zZXJ2ZXIvYXBpXCI7XG5cbi8vIGh0dHBzOi8vdml0ZWpzLmRldi9jb25maWcvXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiAoe1xuICBzZXJ2ZXI6IHtcbiAgICBob3N0OiBcIjo6XCIsXG4gICAgcG9ydDogODA4MCxcbiAgfSxcbiAgcGx1Z2luczogW1xuICAgIHJlYWN0KCksXG4gICAgbW9kZSA9PT0gJ2RldmVsb3BtZW50JyAmJlxuICAgIGNvbXBvbmVudFRhZ2dlcigpLFxuICAgIHNlcnZlckFwaVBsdWdpbigpLFxuICBdLmZpbHRlcihCb29sZWFuKSxcbiAgcmVzb2x2ZToge1xuICAgIGFsaWFzOiB7XG4gICAgICBcIkBcIjogcGF0aC5yZXNvbHZlKF9fZGlybmFtZSwgXCIuL3NyY1wiKSxcbiAgICB9LFxuICB9LFxufSkpO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGUvc3JjL3NlcnZlclwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2FwcC9jb2RlL3NyYy9zZXJ2ZXIvYXBpLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9hcHAvY29kZS9zcmMvc2VydmVyL2FwaS50c1wiO2ltcG9ydCB0eXBlIHsgUGx1Z2luIH0gZnJvbSAndml0ZSc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5pbXBvcnQgbm9kZW1haWxlciBmcm9tICdub2RlbWFpbGVyJztcblxuLy8gU21hbGwgSlNPTiBib2R5IHBhcnNlciB3aXRoIHNpemUgbGltaXRcbmFzeW5jIGZ1bmN0aW9uIHBhcnNlSnNvbihyZXE6IGFueSwgbGltaXQgPSAxMDI0ICogMTAwKSB7XG4gIHJldHVybiBuZXcgUHJvbWlzZTxhbnk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICBjb25zdCBjaHVua3M6IEJ1ZmZlcltdID0gW107XG4gICAgbGV0IHNpemUgPSAwO1xuICAgIHJlcS5vbignZGF0YScsIChjOiBCdWZmZXIpID0+IHtcbiAgICAgIHNpemUgKz0gYy5sZW5ndGg7XG4gICAgICBpZiAoc2l6ZSA+IGxpbWl0KSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1BheWxvYWQgdG9vIGxhcmdlJykpO1xuICAgICAgICByZXEuZGVzdHJveSgpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjaHVua3MucHVzaChjKTtcbiAgICB9KTtcbiAgICByZXEub24oJ2VuZCcsICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJhdyA9IEJ1ZmZlci5jb25jYXQoY2h1bmtzKS50b1N0cmluZygndXRmOCcpO1xuICAgICAgICBjb25zdCBqc29uID0gcmF3ID8gSlNPTi5wYXJzZShyYXcpIDoge307XG4gICAgICAgIHJlc29sdmUoanNvbik7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHJlamVjdChlKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICByZXEub24oJ2Vycm9yJywgcmVqZWN0KTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIGpzb24ocmVzOiBhbnksIHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnksIGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7fSkge1xuICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7XG4gIHJlcy5zdGF0dXNDb2RlID0gc3RhdHVzO1xuICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCcpO1xuICByZXMuc2V0SGVhZGVyKCdYLUNvbnRlbnQtVHlwZS1PcHRpb25zJywgJ25vc25pZmYnKTtcbiAgcmVzLnNldEhlYWRlcignUmVmZXJyZXItUG9saWN5JywgJ25vLXJlZmVycmVyJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtRnJhbWUtT3B0aW9ucycsICdERU5ZJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtWFNTLVByb3RlY3Rpb24nLCAnMTsgbW9kZT1ibG9jaycpO1xuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhoZWFkZXJzKSkgcmVzLnNldEhlYWRlcihrLCB2KTtcbiAgcmVzLmVuZChib2R5KTtcbn1cblxuY29uc3QgaXNIdHRwcyA9IChyZXE6IGFueSkgPT4ge1xuICBjb25zdCBwcm90byA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtcHJvdG8nXSBhcyBzdHJpbmcpIHx8ICcnO1xuICByZXR1cm4gcHJvdG8gPT09ICdodHRwcycgfHwgKHJlcS5zb2NrZXQgJiYgKHJlcS5zb2NrZXQgYXMgYW55KS5lbmNyeXB0ZWQpO1xufTtcblxuZnVuY3Rpb24gcmVxdWlyZUVudihuYW1lOiBzdHJpbmcpIHtcbiAgY29uc3QgdiA9IHByb2Nlc3MuZW52W25hbWVdO1xuICBpZiAoIXYpIHRocm93IG5ldyBFcnJvcihgJHtuYW1lfSBub3Qgc2V0YCk7XG4gIHJldHVybiB2O1xufVxuXG5hc3luYyBmdW5jdGlvbiBzdXBhYmFzZUZldGNoKHBhdGg6IHN0cmluZywgb3B0aW9uczogYW55LCByZXE6IGFueSkge1xuICBjb25zdCBiYXNlID0gcmVxdWlyZUVudignU1VQQUJBU0VfVVJMJyk7XG4gIGNvbnN0IGFub24gPSByZXF1aXJlRW52KCdTVVBBQkFTRV9BTk9OX0tFWScpO1xuICBjb25zdCB0b2tlbiA9IChyZXEuaGVhZGVyc1snYXV0aG9yaXphdGlvbiddIGFzIHN0cmluZykgfHwgJyc7XG4gIGNvbnN0IGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7XG4gICAgYXBpa2V5OiBhbm9uLFxuICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsXG4gIH07XG4gIGlmICh0b2tlbikgaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gdG9rZW47XG4gIHJldHVybiBmZXRjaChgJHtiYXNlfSR7cGF0aH1gLCB7IC4uLm9wdGlvbnMsIGhlYWRlcnM6IHsgLi4uaGVhZGVycywgLi4uKG9wdGlvbnM/LmhlYWRlcnMgfHwge30pIH0gfSk7XG59XG5cbmZ1bmN0aW9uIG1ha2VCb3RJZChzZWVkOiBzdHJpbmcpIHtcbiAgcmV0dXJuICdib3RfJyArIGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUoc2VlZCkuZGlnZXN0KCdiYXNlNjR1cmwnKS5zbGljZSgwLCAyMik7XG59XG5cbi8vIEV4dHJhY3QgdmlzaWJsZSB0ZXh0IGZyb20gSFRNTCAobmFpdmUpXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21IdG1sKGh0bWw6IHN0cmluZykge1xuICAvLyByZW1vdmUgc2NyaXB0cy9zdHlsZXNcbiAgY29uc3Qgd2l0aG91dFNjcmlwdHMgPSBodG1sLnJlcGxhY2UoLzxzY3JpcHRbXFxzXFxTXSo/PltcXHNcXFNdKj88XFwvc2NyaXB0Pi9naSwgJyAnKTtcbiAgY29uc3Qgd2l0aG91dFN0eWxlcyA9IHdpdGhvdXRTY3JpcHRzLnJlcGxhY2UoLzxzdHlsZVtcXHNcXFNdKj8+W1xcc1xcU10qPzxcXC9zdHlsZT4vZ2ksICcgJyk7XG4gIC8vIHJlbW92ZSB0YWdzXG4gIGNvbnN0IHRleHQgPSB3aXRob3V0U3R5bGVzLnJlcGxhY2UoLzxbXj5dKz4vZywgJyAnKTtcbiAgLy8gZGVjb2RlIEhUTUwgZW50aXRpZXMgKGJhc2ljKVxuICByZXR1cm4gdGV4dC5yZXBsYWNlKC8mbmJzcDt8JmFtcDt8Jmx0O3wmZ3Q7fCZxdW90O3wmIzM5Oy9nLCAocykgPT4ge1xuICAgIHN3aXRjaCAocykge1xuICAgICAgY2FzZSAnJm5ic3A7JzogcmV0dXJuICcgJztcbiAgICAgIGNhc2UgJyZhbXA7JzogcmV0dXJuICcmJztcbiAgICAgIGNhc2UgJyZsdDsnOiByZXR1cm4gJzwnO1xuICAgICAgY2FzZSAnJmd0Oyc6IHJldHVybiAnPic7XG4gICAgICBjYXNlICcmcXVvdDsnOiByZXR1cm4gJ1wiJztcbiAgICAgIGNhc2UgJyYjMzk7JzogcmV0dXJuICdcXCcnO1xuICAgICAgZGVmYXVsdDogcmV0dXJuIHM7XG4gICAgfVxuICB9KS5yZXBsYWNlKC9cXHMrL2csICcgJykudHJpbSgpO1xufVxuXG5hc3luYyBmdW5jdGlvbiB0cnlGZXRjaFVybFRleHQodTogc3RyaW5nKSB7XG4gIHRyeSB7XG4gICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2godSwgeyBoZWFkZXJzOiB7ICdVc2VyLUFnZW50JzogJ05leGFCb3RDcmF3bGVyLzEuMCcgfSB9KTtcbiAgICBpZiAoIXJlcy5vaykgcmV0dXJuICcnO1xuICAgIGNvbnN0IGh0bWwgPSBhd2FpdCByZXMudGV4dCgpO1xuICAgIHJldHVybiBleHRyYWN0VGV4dEZyb21IdG1sKGh0bWwpO1xuICB9IGNhdGNoIChlKSB7XG4gICAgcmV0dXJuICcnO1xuICB9XG59XG5cbmZ1bmN0aW9uIGNodW5rVGV4dCh0ZXh0OiBzdHJpbmcsIG1heENoYXJzID0gMTUwMCkge1xuICBjb25zdCBwYXJhZ3JhcGhzID0gdGV4dC5zcGxpdCgvXFxufFxccnxcXC58XFwhfFxcPy8pLm1hcChwID0+IHAudHJpbSgpKS5maWx0ZXIoQm9vbGVhbik7XG4gIGNvbnN0IGNodW5rczogc3RyaW5nW10gPSBbXTtcbiAgbGV0IGN1ciA9ICcnO1xuICBmb3IgKGNvbnN0IHAgb2YgcGFyYWdyYXBocykge1xuICAgIGlmICgoY3VyICsgJyAnICsgcCkubGVuZ3RoID4gbWF4Q2hhcnMpIHtcbiAgICAgIGlmIChjdXIpIHsgY2h1bmtzLnB1c2goY3VyLnRyaW0oKSk7IGN1ciA9IHA7IH1cbiAgICAgIGVsc2UgeyBjaHVua3MucHVzaChwLnNsaWNlKDAsIG1heENoYXJzKSk7IGN1ciA9IHAuc2xpY2UobWF4Q2hhcnMpOyB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGN1ciA9IChjdXIgKyAnICcgKyBwKS50cmltKCk7XG4gICAgfVxuICB9XG4gIGlmIChjdXIpIGNodW5rcy5wdXNoKGN1ci50cmltKCkpO1xuICByZXR1cm4gY2h1bmtzO1xufVxuXG5hc3luYyBmdW5jdGlvbiBlbWJlZENodW5rcyhjaHVua3M6IHN0cmluZ1tdKTogUHJvbWlzZTxudW1iZXJbXVtdIHwgbnVsbD4ge1xuICBjb25zdCBrZXkgPSBwcm9jZXNzLmVudi5PUEVOQUlfQVBJX0tFWTtcbiAgaWYgKCFrZXkpIHJldHVybiBudWxsO1xuICB0cnkge1xuICAgIGNvbnN0IHJlc3AgPSBhd2FpdCBmZXRjaCgnaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS92MS9lbWJlZGRpbmdzJywge1xuICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICBoZWFkZXJzOiB7ICdBdXRob3JpemF0aW9uJzogYEJlYXJlciAke2tleX1gLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGlucHV0OiBjaHVua3MsIG1vZGVsOiAndGV4dC1lbWJlZGRpbmctMy1zbWFsbCcgfSksXG4gICAgfSk7XG4gICAgaWYgKCFyZXNwLm9rKSByZXR1cm4gbnVsbDtcbiAgICBjb25zdCBqID0gYXdhaXQgcmVzcC5qc29uKCk7XG4gICAgaWYgKCFqLmRhdGEpIHJldHVybiBudWxsO1xuICAgIHJldHVybiBqLmRhdGEubWFwKChkOiBhbnkpID0+IGQuZW1iZWRkaW5nIGFzIG51bWJlcltdKTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHByb2Nlc3NUcmFpbkpvYihqb2JJZDogc3RyaW5nLCBib2R5OiBhbnksIHJlcTogYW55KSB7XG4gIGNvbnN0IHVybCA9IGJvZHkudXJsIHx8ICcnO1xuICBjb25zdCBmaWxlczogc3RyaW5nW10gPSBBcnJheS5pc0FycmF5KGJvZHkuZmlsZXMpID8gYm9keS5maWxlcyA6IFtdO1xuICBjb25zdCBib3RTZWVkID0gKHVybCB8fCBmaWxlcy5qb2luKCcsJykpICsgRGF0ZS5ub3coKTtcbiAgY29uc3QgYm90SWQgPSBtYWtlQm90SWQoYm90U2VlZCk7XG5cbiAgLy8gZ2F0aGVyIHRleHRzXG4gIGNvbnN0IGRvY3M6IHsgc291cmNlOiBzdHJpbmc7IGNvbnRlbnQ6IHN0cmluZyB9W10gPSBbXTtcblxuICBpZiAodXJsKSB7XG4gICAgY29uc3QgdGV4dCA9IGF3YWl0IHRyeUZldGNoVXJsVGV4dCh1cmwpO1xuICAgIGlmICh0ZXh0KSBkb2NzLnB1c2goeyBzb3VyY2U6IHVybCwgY29udGVudDogdGV4dCB9KTtcbiAgfVxuXG4gIC8vIGZpbGVzIGFyZSBzdG9yYWdlIHBhdGhzIGluIGJ1Y2tldC90cmFpbmluZy8uLi5cbiAgZm9yIChjb25zdCBwYXRoIG9mIGZpbGVzKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IFNVUEFCQVNFX1VSTCA9IHByb2Nlc3MuZW52LlNVUEFCQVNFX1VSTDtcbiAgICAgIGNvbnN0IGJ1Y2tldFB1YmxpY1VybCA9IFNVUEFCQVNFX1VSTCArIGAvc3RvcmFnZS92MS9vYmplY3QvcHVibGljL3RyYWluaW5nLyR7ZW5jb2RlVVJJQ29tcG9uZW50KHBhdGgpfWA7XG4gICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChidWNrZXRQdWJsaWNVcmwpO1xuICAgICAgaWYgKCFyZXMub2spIGNvbnRpbnVlO1xuICAgICAgY29uc3QgYnVmID0gYXdhaXQgcmVzLmFycmF5QnVmZmVyKCk7XG4gICAgICAvLyBjcnVkZSB0ZXh0IGV4dHJhY3Rpb246IGlmIGl0J3MgcGRmIG9yIHRleHRcbiAgICAgIGNvbnN0IGhlYWRlciA9IFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCwgbmV3IFVpbnQ4QXJyYXkoYnVmLnNsaWNlKDAsIDgpKSBhcyBhbnkpO1xuICAgICAgaWYgKGhlYWRlci5pbmNsdWRlcygnJVBERicpKSB7XG4gICAgICAgIC8vIGNhbm5vdCBwYXJzZSBQREYgaGVyZTsgc3RvcmUgcGxhY2Vob2xkZXJcbiAgICAgICAgZG9jcy5wdXNoKHsgc291cmNlOiBwYXRoLCBjb250ZW50OiAnKFBERiBjb250ZW50IC0tIHByb2Nlc3NlZCBleHRlcm5hbGx5KScgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjb25zdCB0ZXh0ID0gbmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKGJ1Zik7XG4gICAgICAgIGNvbnN0IGNsZWFuZWQgPSBleHRyYWN0VGV4dEZyb21IdG1sKHRleHQpO1xuICAgICAgICBkb2NzLnB1c2goeyBzb3VyY2U6IHBhdGgsIGNvbnRlbnQ6IGNsZWFuZWQgfHwgJyhiaW5hcnkgZmlsZSknIH0pO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGUpIHsgY29udGludWU7IH1cbiAgfVxuXG4gIC8vIGNodW5rIGFuZCBlbWJlZFxuICBmb3IgKGNvbnN0IGRvYyBvZiBkb2NzKSB7XG4gICAgY29uc3QgY2h1bmtzID0gY2h1bmtUZXh0KGRvYy5jb250ZW50KTtcbiAgICBjb25zdCBlbWJlZGRpbmdzID0gYXdhaXQgZW1iZWRDaHVua3MoY2h1bmtzKTtcblxuICAgIC8vIHN0b3JlIGRvY3VtZW50cyBhbmQgZW1iZWRkaW5ncyBpbiBTdXBhYmFzZVxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgY2h1bmtzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBjb25zdCBjaHVuayA9IGNodW5rc1tpXTtcbiAgICAgIGNvbnN0IGVtYiA9IGVtYmVkZGluZ3MgPyBlbWJlZGRpbmdzW2ldIDogbnVsbDtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3RyYWluaW5nX2RvY3VtZW50cycsIHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGJvdF9pZDogYm90SWQsIHNvdXJjZTogZG9jLnNvdXJjZSwgY29udGVudDogY2h1bmssIGVtYmVkZGluZzogZW1iIH0pLFxuICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmV0dXJuPXJlcHJlc2VudGF0aW9uJywgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9LFxuICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgfSBjYXRjaCB7fVxuICAgIH1cbiAgfVxuXG4gIC8vIG1hcmsgam9iIGluIGxvZ3NcbiAgdHJ5IHtcbiAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFjdGlvbjogJ1RSQUlOX0pPQl9DT01QTEVURScsIGRldGFpbHM6IHsgam9iSWQsIGJvdElkLCBkb2NzOiBkb2NzLmxlbmd0aCB9IH0pLFxuICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gIH0gY2F0Y2gge31cbn1cblxuYXN5bmMgZnVuY3Rpb24gZW5zdXJlRG9tYWluVmVyaWZpY2F0aW9uKGRvbWFpbjogc3RyaW5nLCByZXE6IGFueSkge1xuICAvLyBjaGVjayBkb21haW5zIHRhYmxlIGZvciB2ZXJpZmllZFxuICB0cnkge1xuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goYC9yZXN0L3YxL2RvbWFpbnM/ZG9tYWluPWVxLiR7ZW5jb2RlVVJJQ29tcG9uZW50KGRvbWFpbil9YCwgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSk7XG4gICAgaWYgKHJlcyAmJiAocmVzIGFzIGFueSkub2spIHtcbiAgICAgIGNvbnN0IGogPSBhd2FpdCAocmVzIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gW10pO1xuICAgICAgaWYgKEFycmF5LmlzQXJyYXkoaikgJiYgai5sZW5ndGggPiAwICYmIGpbMF0udmVyaWZpZWQpIHJldHVybiB7IHZlcmlmaWVkOiB0cnVlIH07XG4gICAgfVxuICB9IGNhdGNoIHt9XG4gIC8vIGNyZWF0ZSB2ZXJpZmljYXRpb24gdG9rZW4gZW50cnlcbiAgY29uc3QgdG9rZW4gPSBjcnlwdG8ucmFuZG9tQnl0ZXMoMTYpLnRvU3RyaW5nKCdiYXNlNjR1cmwnKTtcbiAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRE9NQUlOX1ZFUklGSUNBVElPTl9TRUNSRVQgfHwgJ2xvY2FsLWRvbS1zZWNyZXQnO1xuICBjb25zdCB0b2tlbkhhc2ggPSBjcnlwdG8uY3JlYXRlSGFzaCgnc2hhMjU2JykudXBkYXRlKHRva2VuICsgc2VjcmV0KS5kaWdlc3QoJ2Jhc2U2NCcpO1xuICBjb25zdCBleHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIDEwMDAgKiA2MCAqIDYwICogMjQpLnRvSVNPU3RyaW5nKCk7XG4gIHRyeSB7XG4gICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZG9tYWluX3ZlcmlmaWNhdGlvbnMnLCB7XG4gICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgZG9tYWluLCB0b2tlbl9oYXNoOiB0b2tlbkhhc2gsIGV4cGlyZXNfYXQ6IGV4cGlyZXMgfSksXG4gICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycsICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicgfSxcbiAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICB9IGNhdGNoIHt9XG4gIHJldHVybiB7IHZlcmlmaWVkOiBmYWxzZSwgdG9rZW4gfTtcbn1cblxuZnVuY3Rpb24gdmVyaWZ5V2lkZ2V0VG9rZW4odG9rZW46IHN0cmluZykge1xuICB0cnkge1xuICAgIGNvbnN0IHdpZGdldFNlY3JldCA9IHByb2Nlc3MuZW52LldJREdFVF9UT0tFTl9TRUNSRVQgfHwgJ2xvY2FsLXdpZGdldC1zZWNyZXQnO1xuICAgIGNvbnN0IHBhcnRzID0gdG9rZW4uc3BsaXQoJy4nKTtcbiAgICBpZiAocGFydHMubGVuZ3RoICE9PSAzKSByZXR1cm4gbnVsbDtcbiAgICBjb25zdCB1bnNpZ25lZCA9IHBhcnRzWzBdICsgJy4nICsgcGFydHNbMV07XG4gICAgY29uc3Qgc2lnID0gcGFydHNbMl07XG4gICAgY29uc3QgZXhwZWN0ZWQgPSBjcnlwdG8uY3JlYXRlSG1hYygnc2hhMjU2Jywgd2lkZ2V0U2VjcmV0KS51cGRhdGUodW5zaWduZWQpLmRpZ2VzdCgnYmFzZTY0dXJsJyk7XG4gICAgaWYgKHNpZyAhPT0gZXhwZWN0ZWQpIHJldHVybiBudWxsO1xuICAgIGNvbnN0IHBheWxvYWQgPSBKU09OLnBhcnNlKEJ1ZmZlci5mcm9tKHBhcnRzWzFdLCAnYmFzZTY0dXJsJykudG9TdHJpbmcoJ3V0ZjgnKSk7XG4gICAgcmV0dXJuIHBheWxvYWQ7XG4gIH0gY2F0Y2ggKGUpIHsgcmV0dXJuIG51bGw7IH1cbn1cblxuLy8gU2ltcGxlIGluLW1lbW9yeSByYXRlIGxpbWl0ZXJcbmNvbnN0IHJhdGVNYXAgPSBuZXcgTWFwPHN0cmluZywgeyBjb3VudDogbnVtYmVyOyB0czogbnVtYmVyIH0+KCk7XG5mdW5jdGlvbiByYXRlTGltaXQoa2V5OiBzdHJpbmcsIGxpbWl0OiBudW1iZXIsIHdpbmRvd01zOiBudW1iZXIpIHtcbiAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgY29uc3QgcmVjID0gcmF0ZU1hcC5nZXQoa2V5KTtcbiAgaWYgKCFyZWMgfHwgbm93IC0gcmVjLnRzID4gd2luZG93TXMpIHtcbiAgICByYXRlTWFwLnNldChrZXksIHsgY291bnQ6IDEsIHRzOiBub3cgfSk7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cbiAgaWYgKHJlYy5jb3VudCA8IGxpbWl0KSB7XG4gICAgcmVjLmNvdW50ICs9IDE7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cbiAgcmV0dXJuIGZhbHNlO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gc2VydmVyQXBpUGx1Z2luKCk6IFBsdWdpbiB7XG4gIHJldHVybiB7XG4gICAgbmFtZTogJ3NlcnZlci1hcGktcGx1Z2luJyxcbiAgICBjb25maWd1cmVTZXJ2ZXIoc2VydmVyKSB7XG4gICAgICBzZXJ2ZXIubWlkZGxld2FyZXMudXNlKGFzeW5jIChyZXEsIHJlcywgbmV4dCkgPT4ge1xuICAgICAgICBpZiAoIXJlcS51cmwgfHwgIXJlcS51cmwuc3RhcnRzV2l0aCgnL2FwaS8nKSkgcmV0dXJuIG5leHQoKTtcblxuICAgICAgICAvLyBCYXNpYyBzZWN1cml0eSBoZWFkZXJzIGZvciBhbGwgQVBJIHJlc3BvbnNlc1xuICAgICAgICBjb25zdCBjb3JzT3JpZ2luID0gcmVxLmhlYWRlcnMub3JpZ2luIHx8ICcqJztcbiAgICAgICAgcmVzLnNldEhlYWRlcignUGVybWlzc2lvbnMtUG9saWN5JywgJ2dlb2xvY2F0aW9uPSgpLCBtaWNyb3Bob25lPSgpLCBjYW1lcmE9KCknKTtcbiAgICAgICAgcmVzLnNldEhlYWRlcignQ3Jvc3MtT3JpZ2luLVJlc291cmNlLVBvbGljeScsICdzYW1lLW9yaWdpbicpO1xuXG4gICAgICAgIC8vIEluIGRldiBhbGxvdyBodHRwOyBpbiBwcm9kIChiZWhpbmQgcHJveHkpLCByZXF1aXJlIGh0dHBzXG4gICAgICAgIGlmIChwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ3Byb2R1Y3Rpb24nICYmICFpc0h0dHBzKHJlcSkpIHtcbiAgICAgICAgICByZXR1cm4ganNvbihyZXMsIDQwMCwgeyBlcnJvcjogJ0hUVFBTIHJlcXVpcmVkJyB9LCB7ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nOiBTdHJpbmcoY29yc09yaWdpbikgfSk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDT1JTIHByZWZsaWdodFxuICAgICAgICBpZiAocmVxLm1ldGhvZCA9PT0gJ09QVElPTlMnKSB7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJywgU3RyaW5nKGNvcnNPcmlnaW4pKTtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1NZXRob2RzJywgJ1BPU1QsR0VULE9QVElPTlMnKTtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzJywgJ0NvbnRlbnQtVHlwZSwgQXV0aG9yaXphdGlvbicpO1xuICAgICAgICAgIHJlcy5zdGF0dXNDb2RlID0gMjA0O1xuICAgICAgICAgIHJldHVybiByZXMuZW5kKCk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBlbmRKc29uID0gKHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnkpID0+IGpzb24ocmVzLCBzdGF0dXMsIGRhdGEsIHsgJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbic6IFN0cmluZyhjb3JzT3JpZ2luKSB9KTtcblxuICAgICAgICB0cnkge1xuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS90cmFpbicgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBpcCA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtZm9yJ10gYXMgc3RyaW5nKSB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJ2lwJztcbiAgICAgICAgICAgIGlmICghcmF0ZUxpbWl0KCd0cmFpbjonICsgaXAsIDIwLCA2MF8wMDApKSByZXR1cm4gZW5kSnNvbig0MjksIHsgZXJyb3I6ICdUb28gTWFueSBSZXF1ZXN0cycgfSk7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCB1cmwgPSB0eXBlb2YgYm9keT8udXJsID09PSAnc3RyaW5nJyA/IGJvZHkudXJsLnRyaW0oKSA6ICcnO1xuICAgICAgICAgICAgaWYgKCF1cmwgJiYgIUFycmF5LmlzQXJyYXkoYm9keT8uZmlsZXMpKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ1Byb3ZpZGUgdXJsIG9yIGZpbGVzJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICh1cmwpIHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmwpO1xuICAgICAgICAgICAgICAgIGlmICghKHUucHJvdG9jb2wgPT09ICdodHRwOicgfHwgdS5wcm90b2NvbCA9PT0gJ2h0dHBzOicpKSB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQnKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCB1cmwnIH0pO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIExvZyBldmVudFxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnVFJBSU5fUkVRVUVTVCcsIGRldGFpbHM6IHsgaGFzVXJsOiAhIXVybCwgZmlsZUNvdW50OiAoYm9keT8uZmlsZXM/Lmxlbmd0aCkgfHwgMCB9IH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgY29uc3Qgam9iSWQgPSBtYWtlQm90SWQoKHVybCB8fCAnJykgKyBEYXRlLm5vdygpKTtcblxuICAgICAgICAgICAgLy8gU3RhcnQgYmFja2dyb3VuZCBwcm9jZXNzaW5nIChub24tYmxvY2tpbmcpXG4gICAgICAgICAgICAoYXN5bmMgKCkgPT4ge1xuICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGF3YWl0IHByb2Nlc3NUcmFpbkpvYihqb2JJZCwgeyB1cmwsIGZpbGVzOiBBcnJheS5pc0FycmF5KGJvZHk/LmZpbGVzKSA/IGJvZHkuZmlsZXMgOiBbXSB9LCByZXEpO1xuICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3NlY3VyaXR5X2xvZ3MnLCB7XG4gICAgICAgICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFjdGlvbjogJ1RSQUlOX0pPQl9FUlJPUicsIGRldGFpbHM6IHsgam9iSWQsIGVycm9yOiBTdHJpbmcoZT8ubWVzc2FnZSB8fCBlKSB9IH0pLFxuICAgICAgICAgICAgICAgICAgfSwgcmVxKTtcbiAgICAgICAgICAgICAgICB9IGNhdGNoIHt9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pKCk7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMiwgeyBqb2JJZCwgc3RhdHVzOiAncXVldWVkJyB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY29ubmVjdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSk7XG4gICAgICAgICAgICBpZiAoYm9keT8uY2hhbm5lbCAhPT0gJ3dlYnNpdGUnKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdVbnN1cHBvcnRlZCBjaGFubmVsJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IHJhd1VybCA9IChib2R5Py51cmwgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGNvbnN0IGRvbWFpbiA9ICgoKSA9PiB7XG4gICAgICAgICAgICAgIHRyeSB7IHJldHVybiByYXdVcmwgPyBuZXcgVVJMKHJhd1VybCkuaG9zdCA6ICdsb2NhbCc7IH0gY2F0Y2ggeyByZXR1cm4gJ2xvY2FsJzsgfVxuICAgICAgICAgICAgfSkoKTtcblxuICAgICAgICAgICAgLy8gRW5zdXJlIGRvbWFpbiB2ZXJpZmljYXRpb25cbiAgICAgICAgICAgIGNvbnN0IHZyZXMgPSBhd2FpdCBlbnN1cmVEb21haW5WZXJpZmljYXRpb24oZG9tYWluLCByZXEpO1xuICAgICAgICAgICAgaWYgKCF2cmVzLnZlcmlmaWVkKSB7XG4gICAgICAgICAgICAgIC8vIHJldHVybiB2ZXJpZmljYXRpb24gcmVxdWlyZWQgYW5kIGluc3RydWN0aW9uc1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDIsIHsgc3RhdHVzOiAndmVyaWZpY2F0aW9uX3JlcXVpcmVkJywgaW5zdHJ1Y3Rpb25zOiBgQWRkIGEgRE5TIFRYVCByZWNvcmQgb3IgYSBtZXRhIHRhZyB3aXRoIHRva2VuOiAke3ZyZXMudG9rZW59YCwgdG9rZW46IHZyZXMudG9rZW4gfSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGNvbnN0IHNlZWQgPSBkb21haW4gKyAnfCcgKyAocmVxLmhlYWRlcnNbJ2F1dGhvcml6YXRpb24nXSB8fCAnJyk7XG4gICAgICAgICAgICBjb25zdCBib3RJZCA9IG1ha2VCb3RJZChzZWVkKTtcblxuICAgICAgICAgICAgLy8gVXBzZXJ0IGNoYXRib3RfY29uZmlncyAoaWYgUkxTIGFsbG93cyB3aXRoIHVzZXIgdG9rZW4pXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9jaGF0Ym90X2NvbmZpZ3MnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGJvdF9pZDogYm90SWQsIGNoYW5uZWw6ICd3ZWJzaXRlJywgZG9tYWluLCBzZXR0aW5nczoge30gfSksXG4gICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmVzb2x1dGlvbj1tZXJnZS1kdXBsaWNhdGVzJyB9LFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgLy8gQ3JlYXRlIHdpZGdldCB0b2tlbiAoSE1BQyBzaWduZWQpXG4gICAgICAgICAgICBjb25zdCB3aWRnZXRQYXlsb2FkID0geyBib3RJZCwgZG9tYWluLCBpYXQ6IE1hdGguZmxvb3IoRGF0ZS5ub3coKS8xMDAwKSB9O1xuICAgICAgICAgICAgY29uc3Qgd2lkZ2V0U2VjcmV0ID0gcHJvY2Vzcy5lbnYuV0lER0VUX1RPS0VOX1NFQ1JFVCB8fCAnbG9jYWwtd2lkZ2V0LXNlY3JldCc7XG4gICAgICAgICAgICBjb25zdCBoZWFkZXIgPSB7IGFsZzogJ0hTMjU2JywgdHlwOiAnSldUJyB9O1xuICAgICAgICAgICAgY29uc3QgYjY0ID0gKHM6IHN0cmluZykgPT4gQnVmZmVyLmZyb20ocykudG9TdHJpbmcoJ2Jhc2U2NHVybCcpO1xuICAgICAgICAgICAgY29uc3QgdW5zaWduZWQgPSBiNjQoSlNPTi5zdHJpbmdpZnkoaGVhZGVyKSkgKyAnLicgKyBiNjQoSlNPTi5zdHJpbmdpZnkod2lkZ2V0UGF5bG9hZCkpO1xuICAgICAgICAgICAgY29uc3Qgc2lnID0gY3J5cHRvLmNyZWF0ZUhtYWMoJ3NoYTI1NicsIHdpZGdldFNlY3JldCkudXBkYXRlKHVuc2lnbmVkKS5kaWdlc3QoJ2Jhc2U2NHVybCcpO1xuICAgICAgICAgICAgY29uc3Qgd2lkZ2V0VG9rZW4gPSB1bnNpZ25lZCArICcuJyArIHNpZztcblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IGJvdElkLCB3aWRnZXRUb2tlbiB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBXaWRnZXQgY29uZmlnIGVuZHBvaW50OiByZXR1cm5zIGJvdCBzZXR0aW5ncyBmb3Igd2lkZ2V0IGNvbnN1bWVycyAocmVxdWlyZXMgdG9rZW4pXG4gICAgICAgICAgaWYgKHJlcS51cmw/LnN0YXJ0c1dpdGgoJy9hcGkvd2lkZ2V0LWNvbmZpZycpICYmIHJlcS5tZXRob2QgPT09ICdHRVQnKSB7XG4gICAgICAgICAgICBjb25zdCB1cmxPYmogPSBuZXcgVVJMKHJlcS51cmwsICdodHRwOi8vbG9jYWwnKTtcbiAgICAgICAgICAgIGNvbnN0IGJvdElkID0gdXJsT2JqLnNlYXJjaFBhcmFtcy5nZXQoJ2JvdElkJykgfHwgJyc7XG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IHVybE9iai5zZWFyY2hQYXJhbXMuZ2V0KCd0b2tlbicpIHx8ICcnO1xuICAgICAgICAgICAgaWYgKCFib3RJZCkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnTWlzc2luZyBib3RJZCcgfSk7XG4gICAgICAgICAgICBjb25zdCBwYXlsb2FkID0gdmVyaWZ5V2lkZ2V0VG9rZW4odG9rZW4pO1xuICAgICAgICAgICAgaWYgKCFwYXlsb2FkIHx8IHBheWxvYWQuYm90SWQgIT09IGJvdElkKSByZXR1cm4gZW5kSnNvbig0MDEsIHsgZXJyb3I6ICdJbnZhbGlkIHRva2VuJyB9KTtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHIgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9jaGF0Ym90X2NvbmZpZ3M/Ym90X2lkPWVxLicgKyBlbmNvZGVVUklDb21wb25lbnQoYm90SWQpICsgJyZzZWxlY3Q9KicsIHsgbWV0aG9kOiAnR0VUJyB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgICBpZiAoIXIgfHwgIShyIGFzIGFueSkub2spIHJldHVybiBlbmRKc29uKDQwNCwgeyBlcnJvcjogJ05vdCBmb3VuZCcgfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCAociBhcyBSZXNwb25zZSkuanNvbigpLmNhdGNoKCgpID0+IFtdKTtcbiAgICAgICAgICAgICAgY29uc3QgY2ZnID0gQXJyYXkuaXNBcnJheShkYXRhKSAmJiBkYXRhLmxlbmd0aCA+IDAgPyBkYXRhWzBdIDogeyBzZXR0aW5nczoge30gfTtcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IHNldHRpbmdzOiBjZmcgfSk7XG4gICAgICAgICAgICB9IGNhdGNoIChlKSB7IHJldHVybiBlbmRKc29uKDUwMCwgeyBlcnJvcjogJ1NlcnZlciBlcnJvcicgfSk7IH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvZGVidWctZmV0Y2gnICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpLmNhdGNoKCgpID0+ICh7fSkpO1xuICAgICAgICAgICAgY29uc3QgdXJsU3RyID0gU3RyaW5nKGJvZHk/LnVybCB8fCAnJykudHJpbSgpO1xuICAgICAgICAgICAgaWYgKCF1cmxTdHIpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgdXJsJyB9KTtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHUgPSBuZXcgVVJMKHVybFN0cik7XG4gICAgICAgICAgICAgIGlmICghKHUucHJvdG9jb2wgPT09ICdodHRwOicgfHwgdS5wcm90b2NvbCA9PT0gJ2h0dHBzOicpKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdJbnZhbGlkIHByb3RvY29sJyB9KTtcbiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCB1cmwnIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgY29uc3QgciA9IGF3YWl0IGZldGNoKHVybFN0ciwgeyBoZWFkZXJzOiB7ICdVc2VyLUFnZW50JzogJ05leGFCb3RWZXJpZmllci8xLjAnIH0gfSk7XG4gICAgICAgICAgICAgIGlmICghciB8fCAhci5vaykgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnRmV0Y2ggZmFpbGVkJywgc3RhdHVzOiByID8gci5zdGF0dXMgOiAwIH0pO1xuICAgICAgICAgICAgICBjb25zdCB0ZXh0ID0gYXdhaXQgci50ZXh0KCk7XG4gICAgICAgICAgICAgIC8vIHJldHVybiBhIHNuaXBwZXQgdG8gYXZvaWQgaHVnZSBwYXlsb2Fkc1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgb2s6IHRydWUsIHVybDogdXJsU3RyLCBzbmlwcGV0OiB0ZXh0LnNsaWNlKDAsIDIwMDAwKSB9KTtcbiAgICAgICAgICAgIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbig1MDAsIHsgZXJyb3I6ICdGZXRjaCBlcnJvcicsIG1lc3NhZ2U6IFN0cmluZyhlPy5tZXNzYWdlIHx8IGUpIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS92ZXJpZnktZG9tYWluJyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IGRvbWFpbiA9IFN0cmluZyhib2R5Py5kb21haW4gfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGNvbnN0IHRva2VuID0gU3RyaW5nKGJvZHk/LnRva2VuIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBpZiAoIWRvbWFpbiB8fCAhdG9rZW4pIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgZG9tYWluIG9yIHRva2VuJyB9KTtcblxuICAgICAgICAgICAgLy8gVHJ5IG11bHRpcGxlIGNhbmRpZGF0ZSBVUkxzIGZvciB2ZXJpZmljYXRpb24gKHJvb3QsIGluZGV4Lmh0bWwsIHdlbGwta25vd24pXG4gICAgICAgICAgICBjb25zdCBjYW5kaWRhdGVzID0gW1xuICAgICAgICAgICAgICBgaHR0cHM6Ly8ke2RvbWFpbn1gLFxuICAgICAgICAgICAgICBgaHR0cDovLyR7ZG9tYWlufWAsXG4gICAgICAgICAgICAgIGBodHRwczovLyR7ZG9tYWlufS9pbmRleC5odG1sYCxcbiAgICAgICAgICAgICAgYGh0dHA6Ly8ke2RvbWFpbn0vaW5kZXguaHRtbGAsXG4gICAgICAgICAgICAgIGBodHRwczovLyR7ZG9tYWlufS8ud2VsbC1rbm93bi9uZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25gLFxuICAgICAgICAgICAgICBgaHR0cDovLyR7ZG9tYWlufS8ud2VsbC1rbm93bi9uZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25gLFxuICAgICAgICAgICAgXTtcblxuICAgICAgICAgICAgLy8gQnVpbGQgcm9idXN0IHJlZ2V4IHRvIG1hdGNoIG1ldGEgdGFnIGluIGFueSBhdHRyaWJ1dGUgb3JkZXJcbiAgICAgICAgICAgIGNvbnN0IGVzYyA9IChzOiBzdHJpbmcpID0+IHMucmVwbGFjZSgvWy0vXFxcXF4kKis/LigpfFtcXF17fV0vZywgJ1xcXFwkJicpO1xuICAgICAgICAgICAgY29uc3QgdEVzYyA9IGVzYyh0b2tlbik7XG4gICAgICAgICAgICBjb25zdCBtZXRhUmUgPSBuZXcgUmVnRXhwKGA8bWV0YVtePl0qKD86bmFtZVxccyo9XFxzKlsnXFxcIl1uZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25bJ1xcXCJdW14+XSpjb250ZW50XFxzKj1cXHMqWydcXFwiXSR7dEVzY31bJ1xcXCJdfGNvbnRlbnRcXHMqPVxccypbJ1xcXCJdJHt0RXNjfVsnXFxcIl1bXj5dKm5hbWVcXHMqPVxccypbJ1xcXCJdbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uWydcXFwiXSlgLCAnaScpO1xuICAgICAgICAgICAgY29uc3QgcGxhaW5SZSA9IG5ldyBSZWdFeHAoYG5leGFib3QtZG9tYWluLXZlcmlmaWNhdGlvbls6PV1cXHMqJHt0RXNjfWAsICdpJyk7XG5cbiAgICAgICAgICAgIGxldCBmb3VuZCA9IGZhbHNlO1xuICAgICAgICAgICAgZm9yIChjb25zdCB1cmwgb2YgY2FuZGlkYXRlcykge1xuICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGNvbnN0IHIgPSBhd2FpdCBmZXRjaCh1cmwsIHsgaGVhZGVyczogeyAnVXNlci1BZ2VudCc6ICdOZXhhQm90VmVyaWZpZXIvMS4wJyB9IH0pO1xuICAgICAgICAgICAgICAgIGlmICghciB8fCAhci5vaykgY29udGludWU7XG4gICAgICAgICAgICAgICAgY29uc3QgdGV4dCA9IGF3YWl0IHIudGV4dCgpO1xuICAgICAgICAgICAgICAgIGlmIChtZXRhUmUudGVzdCh0ZXh0KSB8fCBwbGFpblJlLnRlc3QodGV4dCkpIHtcbiAgICAgICAgICAgICAgICAgIGZvdW5kID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgIC8vIGlnbm9yZSBhbmQgdHJ5IG5leHQgY2FuZGlkYXRlXG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKCFmb3VuZCkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnVmVyaWZpY2F0aW9uIHRva2VuIG5vdCBmb3VuZCBvbiBzaXRlJyB9KTtcblxuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZG9tYWlucycsIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGRvbWFpbiwgdmVyaWZpZWQ6IHRydWUsIHZlcmlmaWVkX2F0OiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkgfSksXG4gICAgICAgICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXNvbHV0aW9uPW1lcmdlLWR1cGxpY2F0ZXMnLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICB9IGNhdGNoIHt9XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogdHJ1ZSwgZG9tYWluIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9sYXVuY2gnICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpO1xuICAgICAgICAgICAgY29uc3QgYm90SWQgPSBTdHJpbmcoYm9keT8uYm90SWQgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghYm90SWQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgYm90SWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgY3VzdG9taXphdGlvbiA9IGJvZHk/LmN1c3RvbWl6YXRpb24gfHwge307XG5cbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2NoYXRib3RfY29uZmlncz9ib3RfaWQ9ZXEuJyArIGVuY29kZVVSSUNvbXBvbmVudChib3RJZCksIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUEFUQ0gnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHNldHRpbmdzOiBjdXN0b21pemF0aW9uIH0pLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsIFByZWZlcjogJ3JldHVybj1yZXByZXNlbnRhdGlvbicgfSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBib3RJZCB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY2hhdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBpcCA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtZm9yJ10gYXMgc3RyaW5nKSB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJ2lwJztcbiAgICAgICAgICAgIGlmICghcmF0ZUxpbWl0KCdjaGF0OicgKyBpcCwgNjAsIDYwXzAwMCkpIHJldHVybiBlbmRKc29uKDQyOSwgeyBlcnJvcjogJ1RvbyBNYW55IFJlcXVlc3RzJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IG1lc3NhZ2UgPSBTdHJpbmcoYm9keT8ubWVzc2FnZSB8fCAnJykuc2xpY2UoMCwgMjAwMCk7XG4gICAgICAgICAgICBpZiAoIW1lc3NhZ2UpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0VtcHR5IG1lc3NhZ2UnIH0pO1xuXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBhY3Rpb246ICdDSEFUJywgZGV0YWlsczogeyBsZW46IG1lc3NhZ2UubGVuZ3RoIH0gfSksXG4gICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuXG4gICAgICAgICAgICBjb25zdCByZXBseSA9IFwiSSdtIHN0aWxsIGxlYXJuaW5nLCBidXQgb3VyIHRlYW0gd2lsbCBnZXQgYmFjayB0byB5b3Ugc29vbi5cIjtcbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyByZXBseSB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBDdXN0b20gZW1haWwgdmVyaWZpY2F0aW9uOiBzZW5kIGVtYWlsXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL3NlbmQtdmVyaWZ5JyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGlwID0gKHJlcS5oZWFkZXJzWyd4LWZvcndhcmRlZC1mb3InXSBhcyBzdHJpbmcpIHx8IHJlcS5zb2NrZXQucmVtb3RlQWRkcmVzcyB8fCAnaXAnO1xuICAgICAgICAgICAgaWYgKCFyYXRlTGltaXQoJ3ZlcmlmeTonICsgaXAsIDUsIDYwKjYwXzAwMCkpIHJldHVybiBlbmRKc29uKDQyOSwgeyBlcnJvcjogJ1RvbyBNYW55IFJlcXVlc3RzJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IGVtYWlsID0gU3RyaW5nKGJvZHk/LmVtYWlsIHx8ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIGlmICghL15bXlxcc0BdK0BbXlxcc0BdK1xcLlteXFxzQF0rJC8udGVzdChlbWFpbCkpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgZW1haWwnIH0pO1xuXG4gICAgICAgICAgICAvLyBWZXJpZnkgYXV0aGVudGljYXRlZCB1c2VyIG1hdGNoZXMgZW1haWxcbiAgICAgICAgICAgIGNvbnN0IHVyZXMgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvYXV0aC92MS91c2VyJywgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICBpZiAoIXVyZXMgfHwgISh1cmVzIGFzIGFueSkub2spIHJldHVybiBlbmRKc29uKDQwMSwgeyBlcnJvcjogJ1VuYXV0aG9yaXplZCcgfSk7XG4gICAgICAgICAgICBjb25zdCB1c2VyID0gYXdhaXQgKHVyZXMgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgIGlmICghdXNlciB8fCB1c2VyLmVtYWlsPy50b0xvd2VyQ2FzZSgpICE9PSBlbWFpbCkgcmV0dXJuIGVuZEpzb24oNDAzLCB7IGVycm9yOiAnRW1haWwgbWlzbWF0Y2gnIH0pO1xuXG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IGNyeXB0by5yYW5kb21CeXRlcygzMikudG9TdHJpbmcoJ2Jhc2U2NHVybCcpO1xuICAgICAgICAgICAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRU1BSUxfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC1zZWNyZXQnO1xuICAgICAgICAgICAgY29uc3QgdG9rZW5IYXNoID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZSh0b2tlbiArIHNlY3JldCkuZGlnZXN0KCdiYXNlNjQnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXMgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgMTAwMCAqIDYwICogNjAgKiAyNCkudG9JU09TdHJpbmcoKTtcblxuICAgICAgICAgICAgLy8gU3RvcmUgdG9rZW4gaGFzaCAobm90IHJhdyB0b2tlbilcbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2VtYWlsX3ZlcmlmaWNhdGlvbnMnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycgfSxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VyX2lkOiB1c2VyLmlkLCBlbWFpbCwgdG9rZW5faGFzaDogdG9rZW5IYXNoLCBleHBpcmVzX2F0OiBleHBpcmVzLCB1c2VkX2F0OiBudWxsIH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgLy8gU2VuZCBlbWFpbCB2aWEgU01UUFxuICAgICAgICAgICAgY29uc3QgaG9zdCA9IHByb2Nlc3MuZW52LlNNVFBfSE9TVDtcbiAgICAgICAgICAgIGNvbnN0IHBvcnQgPSBOdW1iZXIocHJvY2Vzcy5lbnYuU01UUF9QT1JUIHx8IDU4Nyk7XG4gICAgICAgICAgICBjb25zdCB1c2VyU210cCA9IHByb2Nlc3MuZW52LlNNVFBfVVNFUjtcbiAgICAgICAgICAgIGNvbnN0IHBhc3NTbXRwID0gcHJvY2Vzcy5lbnYuU01UUF9QQVNTO1xuICAgICAgICAgICAgY29uc3QgZnJvbSA9IHByb2Nlc3MuZW52LkVNQUlMX0ZST00gfHwgJ05leGFCb3QgPG5vLXJlcGx5QG5leGFib3QuYWk+JztcbiAgICAgICAgICAgIGNvbnN0IGFwcFVybCA9IHByb2Nlc3MuZW52LkFQUF9VUkwgfHwgJ2h0dHA6Ly9sb2NhbGhvc3Q6MzAwMCc7XG4gICAgICAgICAgICBjb25zdCB2ZXJpZnlVcmwgPSBgJHthcHBVcmx9L2FwaS92ZXJpZnktZW1haWw/dG9rZW49JHt0b2tlbn1gO1xuXG4gICAgICAgICAgICBpZiAoaG9zdCAmJiB1c2VyU210cCAmJiBwYXNzU210cCkge1xuICAgICAgICAgICAgICBjb25zdCB0cmFuc3BvcnRlciA9IG5vZGVtYWlsZXIuY3JlYXRlVHJhbnNwb3J0KHsgaG9zdCwgcG9ydCwgc2VjdXJlOiBwb3J0ID09PSA0NjUsIGF1dGg6IHsgdXNlcjogdXNlclNtdHAsIHBhc3M6IHBhc3NTbXRwIH0gfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGh0bWwgPSBgXG4gICAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPVwid2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiNmNmY4ZmI7cGFkZGluZzoyNHB4O2ZvbnQtZmFtaWx5OkludGVyLFNlZ29lIFVJLEFyaWFsLHNhbnMtc2VyaWY7Y29sb3I6IzBmMTcyYVwiPlxuICAgICAgICAgICAgICAgICAgPHRyPjx0ZCBhbGlnbj1cImNlbnRlclwiPlxuICAgICAgICAgICAgICAgICAgICA8dGFibGUgc3R5bGU9XCJtYXgtd2lkdGg6NTYwcHg7d2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiNmZmZmZmY7Ym9yZGVyOjFweCBzb2xpZCAjZTVlN2ViO2JvcmRlci1yYWRpdXM6MTJweDtvdmVyZmxvdzpoaWRkZW5cIj5cbiAgICAgICAgICAgICAgICAgICAgICA8dHI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9XCJiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZywjNjM2NmYxLCM4YjVjZjYpO3BhZGRpbmc6MjBweDtjb2xvcjojZmZmO2ZvbnQtc2l6ZToxOHB4O2ZvbnQtd2VpZ2h0OjcwMFwiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICBOZXhhQm90XG4gICAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICAgICAgPHRyPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPVwicGFkZGluZzoyNHB4XCI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxoMSBzdHlsZT1cIm1hcmdpbjowIDAgOHB4IDA7Zm9udC1zaXplOjIwcHg7Y29sb3I6IzExMTgyN1wiPkNvbmZpcm0geW91ciBlbWFpbDwvaDE+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjAgMCAxNnB4IDA7Y29sb3I6IzM3NDE1MTtsaW5lLWhlaWdodDoxLjVcIj5IaSwgcGxlYXNlIGNvbmZpcm0geW91ciBlbWFpbCBhZGRyZXNzIHRvIHNlY3VyZSB5b3VyIE5leGFCb3QgYWNjb3VudCBhbmQgY29tcGxldGUgc2V0dXAuPC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8cCBzdHlsZT1cIm1hcmdpbjowIDAgMTZweCAwO2NvbG9yOiMzNzQxNTE7bGluZS1oZWlnaHQ6MS41XCI+VGhpcyBsaW5rIGV4cGlyZXMgaW4gMjQgaG91cnMuPC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8YSBocmVmPVwiJHt2ZXJpZnlVcmx9XCIgc3R5bGU9XCJkaXNwbGF5OmlubGluZS1ibG9jaztiYWNrZ3JvdW5kOiM2MzY2ZjE7Y29sb3I6I2ZmZjt0ZXh0LWRlY29yYXRpb246bm9uZTtwYWRkaW5nOjEwcHggMTZweDtib3JkZXItcmFkaXVzOjhweDtmb250LXdlaWdodDo2MDBcIj5WZXJpZnkgRW1haWw8L2E+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjE2cHggMCAwIDA7Y29sb3I6IzZiNzI4MDtmb250LXNpemU6MTJweFwiPklmIHRoZSBidXR0b24gZG9lc25cdTIwMTl0IHdvcmssIGNvcHkgYW5kIHBhc3RlIHRoaXMgbGluayBpbnRvIHlvdXIgYnJvd3Nlcjo8YnI+JHt2ZXJpZnlVcmx9PC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICAgIDx0cj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT1cInBhZGRpbmc6MTZweCAyNHB4O2NvbG9yOiM2YjcyODA7Zm9udC1zaXplOjEycHg7Ym9yZGVyLXRvcDoxcHggc29saWQgI2U1ZTdlYlwiPlx1MDBBOSAke25ldyBEYXRlKCkuZ2V0RnVsbFllYXIoKX0gTmV4YUJvdC4gQWxsIHJpZ2h0cyByZXNlcnZlZC48L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICAgIDwvdGFibGU+XG4gICAgICAgICAgICAgICAgICA8L3RkPjwvdHI+XG4gICAgICAgICAgICAgICAgPC90YWJsZT5gO1xuICAgICAgICAgICAgICBhd2FpdCB0cmFuc3BvcnRlci5zZW5kTWFpbCh7IHRvOiBlbWFpbCwgZnJvbSwgc3ViamVjdDogJ1ZlcmlmeSB5b3VyIGVtYWlsIGZvciBOZXhhQm90JywgaHRtbCB9KTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIGlmIChwcm9jZXNzLmVudi5OT0RFX0VOViAhPT0gJ3Byb2R1Y3Rpb24nKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS53YXJuKCdbZW1haWxdIFNNVFAgbm90IGNvbmZpZ3VyZWQ7IHZlcmlmaWNhdGlvbiBVUkw6JywgdmVyaWZ5VXJsKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgb2s6IHRydWUgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gVmVyaWZ5IGxpbmsgZW5kcG9pbnRcbiAgICAgICAgICBpZiAocmVxLnVybD8uc3RhcnRzV2l0aCgnL2FwaS92ZXJpZnktZW1haWwnKSAmJiByZXEubWV0aG9kID09PSAnR0VUJykge1xuICAgICAgICAgICAgY29uc3QgdXJsT2JqID0gbmV3IFVSTChyZXEudXJsLCAnaHR0cDovL2xvY2FsJyk7XG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IHVybE9iai5zZWFyY2hQYXJhbXMuZ2V0KCd0b2tlbicpIHx8ICcnO1xuICAgICAgICAgICAgaWYgKCF0b2tlbikge1xuICAgICAgICAgICAgICByZXMuc3RhdHVzQ29kZSA9IDQwMDtcbiAgICAgICAgICAgICAgcmVzLnNldEhlYWRlcignQ29udGVudC1UeXBlJywgJ3RleHQvaHRtbCcpO1xuICAgICAgICAgICAgICByZXR1cm4gcmVzLmVuZCgnPHA+SW52YWxpZCB0b2tlbjwvcD4nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHNlY3JldCA9IHByb2Nlc3MuZW52LkVNQUlMX1RPS0VOX1NFQ1JFVCB8fCAnbG9jYWwtc2VjcmV0JztcbiAgICAgICAgICAgIGNvbnN0IHRva2VuSGFzaCA9IGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUodG9rZW4gKyBzZWNyZXQpLmRpZ2VzdCgnYmFzZTY0Jyk7XG5cbiAgICAgICAgICAgIC8vIFByZWZlciBSUEMgKHNlY3VyaXR5IGRlZmluZXIpIG9uIERCOiB2ZXJpZnlfZW1haWxfaGFzaChwX2hhc2ggdGV4dClcbiAgICAgICAgICAgIGxldCBvayA9IGZhbHNlO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgY29uc3QgcnBjID0gYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvcnBjL3ZlcmlmeV9lbWFpbF9oYXNoJywge1xuICAgICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgcF9oYXNoOiB0b2tlbkhhc2ggfSksXG4gICAgICAgICAgICAgIH0sIHJlcSk7XG4gICAgICAgICAgICAgIGlmIChycGMgJiYgKHJwYyBhcyBhbnkpLm9rKSBvayA9IHRydWU7XG4gICAgICAgICAgICB9IGNhdGNoIHt9XG5cbiAgICAgICAgICAgIGlmICghb2spIHtcbiAgICAgICAgICAgICAgY29uc3Qgbm93SXNvID0gbmV3IERhdGUoKS50b0lTT1N0cmluZygpO1xuICAgICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9lbWFpbF92ZXJpZmljYXRpb25zP3Rva2VuX2hhc2g9ZXEuJyArIGVuY29kZVVSSUNvbXBvbmVudCh0b2tlbkhhc2gpICsgJyZ1c2VkX2F0PWlzLm51bGwmZXhwaXJlc19hdD1ndC4nICsgZW5jb2RlVVJJQ29tcG9uZW50KG5vd0lzbyksIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQQVRDSCcsXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VkX2F0OiBub3dJc28gfSksXG4gICAgICAgICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXR1cm49cmVwcmVzZW50YXRpb24nIH0sXG4gICAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJlcy5zdGF0dXNDb2RlID0gMjAwO1xuICAgICAgICAgICAgcmVzLnNldEhlYWRlcignQ29udGVudC1UeXBlJywgJ3RleHQvaHRtbCcpO1xuICAgICAgICAgICAgcmV0dXJuIHJlcy5lbmQoYDwhZG9jdHlwZSBodG1sPjxtZXRhIGh0dHAtZXF1aXY9XCJyZWZyZXNoXCIgY29udGVudD1cIjI7dXJsPS9cIj48c3R5bGU+Ym9keXtmb250LWZhbWlseTpJbnRlcixTZWdvZSBVSSxBcmlhbCxzYW5zLXNlcmlmO2JhY2tncm91bmQ6I2Y2ZjhmYjtjb2xvcjojMTExODI3O2Rpc3BsYXk6Z3JpZDtwbGFjZS1pdGVtczpjZW50ZXI7aGVpZ2h0OjEwMHZofTwvc3R5bGU+PGRpdj48aDE+XHUyNzA1IEVtYWlsIHZlcmlmaWVkPC9oMT48cD5Zb3UgY2FuIGNsb3NlIHRoaXMgdGFiLjwvcD48L2Rpdj5gKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gZW5kSnNvbig0MDQsIHsgZXJyb3I6ICdOb3QgRm91bmQnIH0pO1xuICAgICAgICB9IGNhdGNoIChlOiBhbnkpIHtcbiAgICAgICAgICByZXR1cm4gZW5kSnNvbig1MDAsIHsgZXJyb3I6ICdTZXJ2ZXIgRXJyb3InIH0pO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9LFxuICB9O1xufVxuIl0sCiAgIm1hcHBpbmdzIjogIjtBQUE2TSxTQUFTLG9CQUFvQjtBQUMxTyxPQUFPLFdBQVc7QUFDbEIsT0FBTyxVQUFVO0FBQ2pCLFNBQVMsdUJBQXVCOzs7QUNGaEMsT0FBTyxZQUFZO0FBQ25CLE9BQU8sZ0JBQWdCO0FBR3ZCLGVBQWUsVUFBVSxLQUFVLFFBQVEsT0FBTyxLQUFLO0FBQ3JELFNBQU8sSUFBSSxRQUFhLENBQUMsU0FBUyxXQUFXO0FBQzNDLFVBQU0sU0FBbUIsQ0FBQztBQUMxQixRQUFJLE9BQU87QUFDWCxRQUFJLEdBQUcsUUFBUSxDQUFDLE1BQWM7QUFDNUIsY0FBUSxFQUFFO0FBQ1YsVUFBSSxPQUFPLE9BQU87QUFDaEIsZUFBTyxJQUFJLE1BQU0sbUJBQW1CLENBQUM7QUFDckMsWUFBSSxRQUFRO0FBQ1o7QUFBQSxNQUNGO0FBQ0EsYUFBTyxLQUFLLENBQUM7QUFBQSxJQUNmLENBQUM7QUFDRCxRQUFJLEdBQUcsT0FBTyxNQUFNO0FBQ2xCLFVBQUk7QUFDRixjQUFNLE1BQU0sT0FBTyxPQUFPLE1BQU0sRUFBRSxTQUFTLE1BQU07QUFDakQsY0FBTUEsUUFBTyxNQUFNLEtBQUssTUFBTSxHQUFHLElBQUksQ0FBQztBQUN0QyxnQkFBUUEsS0FBSTtBQUFBLE1BQ2QsU0FBUyxHQUFHO0FBQ1YsZUFBTyxDQUFDO0FBQUEsTUFDVjtBQUFBLElBQ0YsQ0FBQztBQUNELFFBQUksR0FBRyxTQUFTLE1BQU07QUFBQSxFQUN4QixDQUFDO0FBQ0g7QUFFQSxTQUFTLEtBQUssS0FBVSxRQUFnQixNQUFXLFVBQWtDLENBQUMsR0FBRztBQUN2RixRQUFNLE9BQU8sS0FBSyxVQUFVLElBQUk7QUFDaEMsTUFBSSxhQUFhO0FBQ2pCLE1BQUksVUFBVSxnQkFBZ0IsaUNBQWlDO0FBQy9ELE1BQUksVUFBVSwwQkFBMEIsU0FBUztBQUNqRCxNQUFJLFVBQVUsbUJBQW1CLGFBQWE7QUFDOUMsTUFBSSxVQUFVLG1CQUFtQixNQUFNO0FBQ3ZDLE1BQUksVUFBVSxvQkFBb0IsZUFBZTtBQUNqRCxhQUFXLENBQUMsR0FBRyxDQUFDLEtBQUssT0FBTyxRQUFRLE9BQU8sRUFBRyxLQUFJLFVBQVUsR0FBRyxDQUFDO0FBQ2hFLE1BQUksSUFBSSxJQUFJO0FBQ2Q7QUFFQSxJQUFNLFVBQVUsQ0FBQyxRQUFhO0FBQzVCLFFBQU0sUUFBUyxJQUFJLFFBQVEsbUJBQW1CLEtBQWdCO0FBQzlELFNBQU8sVUFBVSxXQUFZLElBQUksVUFBVyxJQUFJLE9BQWU7QUFDakU7QUFFQSxTQUFTLFdBQVcsTUFBYztBQUNoQyxRQUFNLElBQUksUUFBUSxJQUFJLElBQUk7QUFDMUIsTUFBSSxDQUFDLEVBQUcsT0FBTSxJQUFJLE1BQU0sR0FBRyxJQUFJLFVBQVU7QUFDekMsU0FBTztBQUNUO0FBRUEsZUFBZSxjQUFjQyxPQUFjLFNBQWMsS0FBVTtBQUNqRSxRQUFNLE9BQU8sV0FBVyxjQUFjO0FBQ3RDLFFBQU0sT0FBTyxXQUFXLG1CQUFtQjtBQUMzQyxRQUFNLFFBQVMsSUFBSSxRQUFRLGVBQWUsS0FBZ0I7QUFDMUQsUUFBTSxVQUFrQztBQUFBLElBQ3RDLFFBQVE7QUFBQSxJQUNSLGdCQUFnQjtBQUFBLEVBQ2xCO0FBQ0EsTUFBSSxNQUFPLFNBQVEsZUFBZSxJQUFJO0FBQ3RDLFNBQU8sTUFBTSxHQUFHLElBQUksR0FBR0EsS0FBSSxJQUFJLEVBQUUsR0FBRyxTQUFTLFNBQVMsRUFBRSxHQUFHLFNBQVMsR0FBSSxTQUFTLFdBQVcsQ0FBQyxFQUFHLEVBQUUsQ0FBQztBQUNyRztBQUVBLFNBQVMsVUFBVSxNQUFjO0FBQy9CLFNBQU8sU0FBUyxPQUFPLFdBQVcsUUFBUSxFQUFFLE9BQU8sSUFBSSxFQUFFLE9BQU8sV0FBVyxFQUFFLE1BQU0sR0FBRyxFQUFFO0FBQzFGO0FBR0EsU0FBUyxvQkFBb0IsTUFBYztBQUV6QyxRQUFNLGlCQUFpQixLQUFLLFFBQVEsd0NBQXdDLEdBQUc7QUFDL0UsUUFBTSxnQkFBZ0IsZUFBZSxRQUFRLHNDQUFzQyxHQUFHO0FBRXRGLFFBQU0sT0FBTyxjQUFjLFFBQVEsWUFBWSxHQUFHO0FBRWxELFNBQU8sS0FBSyxRQUFRLHdDQUF3QyxDQUFDLE1BQU07QUFDakUsWUFBUSxHQUFHO0FBQUEsTUFDVCxLQUFLO0FBQVUsZUFBTztBQUFBLE1BQ3RCLEtBQUs7QUFBUyxlQUFPO0FBQUEsTUFDckIsS0FBSztBQUFRLGVBQU87QUFBQSxNQUNwQixLQUFLO0FBQVEsZUFBTztBQUFBLE1BQ3BCLEtBQUs7QUFBVSxlQUFPO0FBQUEsTUFDdEIsS0FBSztBQUFTLGVBQU87QUFBQSxNQUNyQjtBQUFTLGVBQU87QUFBQSxJQUNsQjtBQUFBLEVBQ0YsQ0FBQyxFQUFFLFFBQVEsUUFBUSxHQUFHLEVBQUUsS0FBSztBQUMvQjtBQUVBLGVBQWUsZ0JBQWdCLEdBQVc7QUFDeEMsTUFBSTtBQUNGLFVBQU0sTUFBTSxNQUFNLE1BQU0sR0FBRyxFQUFFLFNBQVMsRUFBRSxjQUFjLHFCQUFxQixFQUFFLENBQUM7QUFDOUUsUUFBSSxDQUFDLElBQUksR0FBSSxRQUFPO0FBQ3BCLFVBQU0sT0FBTyxNQUFNLElBQUksS0FBSztBQUM1QixXQUFPLG9CQUFvQixJQUFJO0FBQUEsRUFDakMsU0FBUyxHQUFHO0FBQ1YsV0FBTztBQUFBLEVBQ1Q7QUFDRjtBQUVBLFNBQVMsVUFBVSxNQUFjLFdBQVcsTUFBTTtBQUNoRCxRQUFNLGFBQWEsS0FBSyxNQUFNLGdCQUFnQixFQUFFLElBQUksT0FBSyxFQUFFLEtBQUssQ0FBQyxFQUFFLE9BQU8sT0FBTztBQUNqRixRQUFNLFNBQW1CLENBQUM7QUFDMUIsTUFBSSxNQUFNO0FBQ1YsYUFBVyxLQUFLLFlBQVk7QUFDMUIsU0FBSyxNQUFNLE1BQU0sR0FBRyxTQUFTLFVBQVU7QUFDckMsVUFBSSxLQUFLO0FBQUUsZUFBTyxLQUFLLElBQUksS0FBSyxDQUFDO0FBQUcsY0FBTTtBQUFBLE1BQUcsT0FDeEM7QUFBRSxlQUFPLEtBQUssRUFBRSxNQUFNLEdBQUcsUUFBUSxDQUFDO0FBQUcsY0FBTSxFQUFFLE1BQU0sUUFBUTtBQUFBLE1BQUc7QUFBQSxJQUNyRSxPQUFPO0FBQ0wsYUFBTyxNQUFNLE1BQU0sR0FBRyxLQUFLO0FBQUEsSUFDN0I7QUFBQSxFQUNGO0FBQ0EsTUFBSSxJQUFLLFFBQU8sS0FBSyxJQUFJLEtBQUssQ0FBQztBQUMvQixTQUFPO0FBQ1Q7QUFFQSxlQUFlLFlBQVksUUFBOEM7QUFDdkUsUUFBTSxNQUFNLFFBQVEsSUFBSTtBQUN4QixNQUFJLENBQUMsSUFBSyxRQUFPO0FBQ2pCLE1BQUk7QUFDRixVQUFNLE9BQU8sTUFBTSxNQUFNLHdDQUF3QztBQUFBLE1BQy9ELFFBQVE7QUFBQSxNQUNSLFNBQVMsRUFBRSxpQkFBaUIsVUFBVSxHQUFHLElBQUksZ0JBQWdCLG1CQUFtQjtBQUFBLE1BQ2hGLE1BQU0sS0FBSyxVQUFVLEVBQUUsT0FBTyxRQUFRLE9BQU8seUJBQXlCLENBQUM7QUFBQSxJQUN6RSxDQUFDO0FBQ0QsUUFBSSxDQUFDLEtBQUssR0FBSSxRQUFPO0FBQ3JCLFVBQU0sSUFBSSxNQUFNLEtBQUssS0FBSztBQUMxQixRQUFJLENBQUMsRUFBRSxLQUFNLFFBQU87QUFDcEIsV0FBTyxFQUFFLEtBQUssSUFBSSxDQUFDLE1BQVcsRUFBRSxTQUFxQjtBQUFBLEVBQ3ZELFNBQVMsR0FBRztBQUNWLFdBQU87QUFBQSxFQUNUO0FBQ0Y7QUFFQSxlQUFlLGdCQUFnQixPQUFlLE1BQVcsS0FBVTtBQUNqRSxRQUFNLE1BQU0sS0FBSyxPQUFPO0FBQ3hCLFFBQU0sUUFBa0IsTUFBTSxRQUFRLEtBQUssS0FBSyxJQUFJLEtBQUssUUFBUSxDQUFDO0FBQ2xFLFFBQU0sV0FBVyxPQUFPLE1BQU0sS0FBSyxHQUFHLEtBQUssS0FBSyxJQUFJO0FBQ3BELFFBQU0sUUFBUSxVQUFVLE9BQU87QUFHL0IsUUFBTSxPQUE4QyxDQUFDO0FBRXJELE1BQUksS0FBSztBQUNQLFVBQU0sT0FBTyxNQUFNLGdCQUFnQixHQUFHO0FBQ3RDLFFBQUksS0FBTSxNQUFLLEtBQUssRUFBRSxRQUFRLEtBQUssU0FBUyxLQUFLLENBQUM7QUFBQSxFQUNwRDtBQUdBLGFBQVdBLFNBQVEsT0FBTztBQUN4QixRQUFJO0FBQ0YsWUFBTSxlQUFlLFFBQVEsSUFBSTtBQUNqQyxZQUFNLGtCQUFrQixlQUFlLHNDQUFzQyxtQkFBbUJBLEtBQUksQ0FBQztBQUNyRyxZQUFNLE1BQU0sTUFBTSxNQUFNLGVBQWU7QUFDdkMsVUFBSSxDQUFDLElBQUksR0FBSTtBQUNiLFlBQU0sTUFBTSxNQUFNLElBQUksWUFBWTtBQUVsQyxZQUFNLFNBQVMsT0FBTyxhQUFhLE1BQU0sTUFBTSxJQUFJLFdBQVcsSUFBSSxNQUFNLEdBQUcsQ0FBQyxDQUFDLENBQVE7QUFDckYsVUFBSSxPQUFPLFNBQVMsTUFBTSxHQUFHO0FBRTNCLGFBQUssS0FBSyxFQUFFLFFBQVFBLE9BQU0sU0FBUyx3Q0FBd0MsQ0FBQztBQUFBLE1BQzlFLE9BQU87QUFDTCxjQUFNLE9BQU8sSUFBSSxZQUFZLEVBQUUsT0FBTyxHQUFHO0FBQ3pDLGNBQU0sVUFBVSxvQkFBb0IsSUFBSTtBQUN4QyxhQUFLLEtBQUssRUFBRSxRQUFRQSxPQUFNLFNBQVMsV0FBVyxnQkFBZ0IsQ0FBQztBQUFBLE1BQ2pFO0FBQUEsSUFDRixTQUFTLEdBQUc7QUFBRTtBQUFBLElBQVU7QUFBQSxFQUMxQjtBQUdBLGFBQVcsT0FBTyxNQUFNO0FBQ3RCLFVBQU0sU0FBUyxVQUFVLElBQUksT0FBTztBQUNwQyxVQUFNLGFBQWEsTUFBTSxZQUFZLE1BQU07QUFHM0MsYUFBUyxJQUFJLEdBQUcsSUFBSSxPQUFPLFFBQVEsS0FBSztBQUN0QyxZQUFNLFFBQVEsT0FBTyxDQUFDO0FBQ3RCLFlBQU0sTUFBTSxhQUFhLFdBQVcsQ0FBQyxJQUFJO0FBQ3pDLFVBQUk7QUFDRixjQUFNLGNBQWMsK0JBQStCO0FBQUEsVUFDakQsUUFBUTtBQUFBLFVBQ1IsTUFBTSxLQUFLLFVBQVUsRUFBRSxRQUFRLE9BQU8sUUFBUSxJQUFJLFFBQVEsU0FBUyxPQUFPLFdBQVcsSUFBSSxDQUFDO0FBQUEsVUFDMUYsU0FBUyxFQUFFLFFBQVEseUJBQXlCLGdCQUFnQixtQkFBbUI7QUFBQSxRQUNqRixHQUFHLEdBQUcsRUFBRSxNQUFNLE1BQU0sSUFBSTtBQUFBLE1BQzFCLFFBQVE7QUFBQSxNQUFDO0FBQUEsSUFDWDtBQUFBLEVBQ0Y7QUFHQSxNQUFJO0FBQ0YsVUFBTSxjQUFjLDBCQUEwQjtBQUFBLE1BQzVDLFFBQVE7QUFBQSxNQUNSLE1BQU0sS0FBSyxVQUFVLEVBQUUsUUFBUSxzQkFBc0IsU0FBUyxFQUFFLE9BQU8sT0FBTyxNQUFNLEtBQUssT0FBTyxFQUFFLENBQUM7QUFBQSxJQUNyRyxHQUFHLEdBQUcsRUFBRSxNQUFNLE1BQU0sSUFBSTtBQUFBLEVBQzFCLFFBQVE7QUFBQSxFQUFDO0FBQ1g7QUFFQSxlQUFlLHlCQUF5QixRQUFnQixLQUFVO0FBRWhFLE1BQUk7QUFDRixVQUFNLE1BQU0sTUFBTSxjQUFjLDhCQUE4QixtQkFBbUIsTUFBTSxDQUFDLElBQUksRUFBRSxRQUFRLE1BQU0sR0FBRyxHQUFHO0FBQ2xILFFBQUksT0FBUSxJQUFZLElBQUk7QUFDMUIsWUFBTSxJQUFJLE1BQU8sSUFBaUIsS0FBSyxFQUFFLE1BQU0sTUFBTSxDQUFDLENBQUM7QUFDdkQsVUFBSSxNQUFNLFFBQVEsQ0FBQyxLQUFLLEVBQUUsU0FBUyxLQUFLLEVBQUUsQ0FBQyxFQUFFLFNBQVUsUUFBTyxFQUFFLFVBQVUsS0FBSztBQUFBLElBQ2pGO0FBQUEsRUFDRixRQUFRO0FBQUEsRUFBQztBQUVULFFBQU0sUUFBUSxPQUFPLFlBQVksRUFBRSxFQUFFLFNBQVMsV0FBVztBQUN6RCxRQUFNLFNBQVMsUUFBUSxJQUFJLDhCQUE4QjtBQUN6RCxRQUFNLFlBQVksT0FBTyxXQUFXLFFBQVEsRUFBRSxPQUFPLFFBQVEsTUFBTSxFQUFFLE9BQU8sUUFBUTtBQUNwRixRQUFNLFVBQVUsSUFBSSxLQUFLLEtBQUssSUFBSSxJQUFJLE1BQU8sS0FBSyxLQUFLLEVBQUUsRUFBRSxZQUFZO0FBQ3ZFLE1BQUk7QUFDRixVQUFNLGNBQWMsaUNBQWlDO0FBQUEsTUFDbkQsUUFBUTtBQUFBLE1BQ1IsTUFBTSxLQUFLLFVBQVUsRUFBRSxRQUFRLFlBQVksV0FBVyxZQUFZLFFBQVEsQ0FBQztBQUFBLE1BQzNFLFNBQVMsRUFBRSxRQUFRLCtCQUErQixnQkFBZ0IsbUJBQW1CO0FBQUEsSUFDdkYsR0FBRyxHQUFHLEVBQUUsTUFBTSxNQUFNLElBQUk7QUFBQSxFQUMxQixRQUFRO0FBQUEsRUFBQztBQUNULFNBQU8sRUFBRSxVQUFVLE9BQU8sTUFBTTtBQUNsQztBQUVBLFNBQVMsa0JBQWtCLE9BQWU7QUFDeEMsTUFBSTtBQUNGLFVBQU0sZUFBZSxRQUFRLElBQUksdUJBQXVCO0FBQ3hELFVBQU0sUUFBUSxNQUFNLE1BQU0sR0FBRztBQUM3QixRQUFJLE1BQU0sV0FBVyxFQUFHLFFBQU87QUFDL0IsVUFBTSxXQUFXLE1BQU0sQ0FBQyxJQUFJLE1BQU0sTUFBTSxDQUFDO0FBQ3pDLFVBQU0sTUFBTSxNQUFNLENBQUM7QUFDbkIsVUFBTSxXQUFXLE9BQU8sV0FBVyxVQUFVLFlBQVksRUFBRSxPQUFPLFFBQVEsRUFBRSxPQUFPLFdBQVc7QUFDOUYsUUFBSSxRQUFRLFNBQVUsUUFBTztBQUM3QixVQUFNLFVBQVUsS0FBSyxNQUFNLE9BQU8sS0FBSyxNQUFNLENBQUMsR0FBRyxXQUFXLEVBQUUsU0FBUyxNQUFNLENBQUM7QUFDOUUsV0FBTztBQUFBLEVBQ1QsU0FBUyxHQUFHO0FBQUUsV0FBTztBQUFBLEVBQU07QUFDN0I7QUFHQSxJQUFNLFVBQVUsb0JBQUksSUFBMkM7QUFDL0QsU0FBUyxVQUFVLEtBQWEsT0FBZSxVQUFrQjtBQUMvRCxRQUFNLE1BQU0sS0FBSyxJQUFJO0FBQ3JCLFFBQU0sTUFBTSxRQUFRLElBQUksR0FBRztBQUMzQixNQUFJLENBQUMsT0FBTyxNQUFNLElBQUksS0FBSyxVQUFVO0FBQ25DLFlBQVEsSUFBSSxLQUFLLEVBQUUsT0FBTyxHQUFHLElBQUksSUFBSSxDQUFDO0FBQ3RDLFdBQU87QUFBQSxFQUNUO0FBQ0EsTUFBSSxJQUFJLFFBQVEsT0FBTztBQUNyQixRQUFJLFNBQVM7QUFDYixXQUFPO0FBQUEsRUFDVDtBQUNBLFNBQU87QUFDVDtBQUVPLFNBQVMsa0JBQTBCO0FBQ3hDLFNBQU87QUFBQSxJQUNMLE1BQU07QUFBQSxJQUNOLGdCQUFnQixRQUFRO0FBQ3RCLGFBQU8sWUFBWSxJQUFJLE9BQU8sS0FBSyxLQUFLLFNBQVM7QUFDL0MsWUFBSSxDQUFDLElBQUksT0FBTyxDQUFDLElBQUksSUFBSSxXQUFXLE9BQU8sRUFBRyxRQUFPLEtBQUs7QUFHMUQsY0FBTSxhQUFhLElBQUksUUFBUSxVQUFVO0FBQ3pDLFlBQUksVUFBVSxzQkFBc0IsMENBQTBDO0FBQzlFLFlBQUksVUFBVSxnQ0FBZ0MsYUFBYTtBQUczRCxZQUFJLFFBQVEsSUFBSSxhQUFhLGdCQUFnQixDQUFDLFFBQVEsR0FBRyxHQUFHO0FBQzFELGlCQUFPLEtBQUssS0FBSyxLQUFLLEVBQUUsT0FBTyxpQkFBaUIsR0FBRyxFQUFFLCtCQUErQixPQUFPLFVBQVUsRUFBRSxDQUFDO0FBQUEsUUFDMUc7QUFHQSxZQUFJLElBQUksV0FBVyxXQUFXO0FBQzVCLGNBQUksVUFBVSwrQkFBK0IsT0FBTyxVQUFVLENBQUM7QUFDL0QsY0FBSSxVQUFVLGdDQUFnQyxrQkFBa0I7QUFDaEUsY0FBSSxVQUFVLGdDQUFnQyw2QkFBNkI7QUFDM0UsY0FBSSxhQUFhO0FBQ2pCLGlCQUFPLElBQUksSUFBSTtBQUFBLFFBQ2pCO0FBRUEsY0FBTSxVQUFVLENBQUMsUUFBZ0IsU0FBYyxLQUFLLEtBQUssUUFBUSxNQUFNLEVBQUUsK0JBQStCLE9BQU8sVUFBVSxFQUFFLENBQUM7QUFFNUgsWUFBSTtBQUNGLGNBQUksSUFBSSxRQUFRLGdCQUFnQixJQUFJLFdBQVcsUUFBUTtBQUNyRCxrQkFBTSxLQUFNLElBQUksUUFBUSxpQkFBaUIsS0FBZ0IsSUFBSSxPQUFPLGlCQUFpQjtBQUNyRixnQkFBSSxDQUFDLFVBQVUsV0FBVyxJQUFJLElBQUksR0FBTSxFQUFHLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxvQkFBb0IsQ0FBQztBQUM3RixrQkFBTSxPQUFPLE1BQU0sVUFBVSxHQUFHLEVBQUUsTUFBTSxPQUFPLENBQUMsRUFBRTtBQUNsRCxrQkFBTSxNQUFNLE9BQU8sTUFBTSxRQUFRLFdBQVcsS0FBSyxJQUFJLEtBQUssSUFBSTtBQUM5RCxnQkFBSSxDQUFDLE9BQU8sQ0FBQyxNQUFNLFFBQVEsTUFBTSxLQUFLLEdBQUc7QUFDdkMscUJBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyx1QkFBdUIsQ0FBQztBQUFBLFlBQ3ZEO0FBQ0EsZ0JBQUksS0FBSztBQUNQLGtCQUFJO0FBQ0Ysc0JBQU0sSUFBSSxJQUFJLElBQUksR0FBRztBQUNyQixvQkFBSSxFQUFFLEVBQUUsYUFBYSxXQUFXLEVBQUUsYUFBYSxVQUFXLE9BQU0sSUFBSSxNQUFNLFNBQVM7QUFBQSxjQUNyRixRQUFRO0FBQ04sdUJBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxjQUFjLENBQUM7QUFBQSxjQUM5QztBQUFBLFlBQ0Y7QUFHQSxrQkFBTSxjQUFjLDBCQUEwQjtBQUFBLGNBQzVDLFFBQVE7QUFBQSxjQUNSLE1BQU0sS0FBSyxVQUFVLEVBQUUsUUFBUSxpQkFBaUIsU0FBUyxFQUFFLFFBQVEsQ0FBQyxDQUFDLEtBQUssV0FBWSxNQUFNLE9BQU8sVUFBVyxFQUFFLEVBQUUsQ0FBQztBQUFBLFlBQ3JILEdBQUcsR0FBRyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBRXhCLGtCQUFNLFFBQVEsV0FBVyxPQUFPLE1BQU0sS0FBSyxJQUFJLENBQUM7QUFHaEQsYUFBQyxZQUFZO0FBQ1gsa0JBQUk7QUFDRixzQkFBTSxnQkFBZ0IsT0FBTyxFQUFFLEtBQUssT0FBTyxNQUFNLFFBQVEsTUFBTSxLQUFLLElBQUksS0FBSyxRQUFRLENBQUMsRUFBRSxHQUFHLEdBQUc7QUFBQSxjQUNoRyxTQUFTLEdBQUc7QUFDVixvQkFBSTtBQUNGLHdCQUFNLGNBQWMsMEJBQTBCO0FBQUEsb0JBQzVDLFFBQVE7QUFBQSxvQkFDUixNQUFNLEtBQUssVUFBVSxFQUFFLFFBQVEsbUJBQW1CLFNBQVMsRUFBRSxPQUFPLE9BQU8sT0FBTyxHQUFHLFdBQVcsQ0FBQyxFQUFFLEVBQUUsQ0FBQztBQUFBLGtCQUN4RyxHQUFHLEdBQUc7QUFBQSxnQkFDUixRQUFRO0FBQUEsZ0JBQUM7QUFBQSxjQUNYO0FBQUEsWUFDRixHQUFHO0FBRUgsbUJBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxRQUFRLFNBQVMsQ0FBQztBQUFBLFVBQ2pEO0FBRUEsY0FBSSxJQUFJLFFBQVEsa0JBQWtCLElBQUksV0FBVyxRQUFRO0FBQ3ZELGtCQUFNLE9BQU8sTUFBTSxVQUFVLEdBQUc7QUFDaEMsZ0JBQUksTUFBTSxZQUFZLFVBQVcsUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLHNCQUFzQixDQUFDO0FBQ3JGLGtCQUFNLFVBQVUsTUFBTSxPQUFPLElBQUksS0FBSztBQUN0QyxrQkFBTSxVQUFVLE1BQU07QUFDcEIsa0JBQUk7QUFBRSx1QkFBTyxTQUFTLElBQUksSUFBSSxNQUFNLEVBQUUsT0FBTztBQUFBLGNBQVMsUUFBUTtBQUFFLHVCQUFPO0FBQUEsY0FBUztBQUFBLFlBQ2xGLEdBQUc7QUFHSCxrQkFBTSxPQUFPLE1BQU0seUJBQXlCLFFBQVEsR0FBRztBQUN2RCxnQkFBSSxDQUFDLEtBQUssVUFBVTtBQUVsQixxQkFBTyxRQUFRLEtBQUssRUFBRSxRQUFRLHlCQUF5QixjQUFjLGtEQUFrRCxLQUFLLEtBQUssSUFBSSxPQUFPLEtBQUssTUFBTSxDQUFDO0FBQUEsWUFDMUo7QUFFQSxrQkFBTSxPQUFPLFNBQVMsT0FBTyxJQUFJLFFBQVEsZUFBZSxLQUFLO0FBQzdELGtCQUFNLFFBQVEsVUFBVSxJQUFJO0FBRzVCLGtCQUFNLGNBQWMsNEJBQTRCO0FBQUEsY0FDOUMsUUFBUTtBQUFBLGNBQ1IsTUFBTSxLQUFLLFVBQVUsRUFBRSxRQUFRLE9BQU8sU0FBUyxXQUFXLFFBQVEsVUFBVSxDQUFDLEVBQUUsQ0FBQztBQUFBLGNBQ2hGLFNBQVMsRUFBRSxRQUFRLDhCQUE4QjtBQUFBLFlBQ25ELEdBQUcsR0FBRyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBR3hCLGtCQUFNLGdCQUFnQixFQUFFLE9BQU8sUUFBUSxLQUFLLEtBQUssTUFBTSxLQUFLLElBQUksSUFBRSxHQUFJLEVBQUU7QUFDeEUsa0JBQU0sZUFBZSxRQUFRLElBQUksdUJBQXVCO0FBQ3hELGtCQUFNLFNBQVMsRUFBRSxLQUFLLFNBQVMsS0FBSyxNQUFNO0FBQzFDLGtCQUFNLE1BQU0sQ0FBQyxNQUFjLE9BQU8sS0FBSyxDQUFDLEVBQUUsU0FBUyxXQUFXO0FBQzlELGtCQUFNLFdBQVcsSUFBSSxLQUFLLFVBQVUsTUFBTSxDQUFDLElBQUksTUFBTSxJQUFJLEtBQUssVUFBVSxhQUFhLENBQUM7QUFDdEYsa0JBQU0sTUFBTSxPQUFPLFdBQVcsVUFBVSxZQUFZLEVBQUUsT0FBTyxRQUFRLEVBQUUsT0FBTyxXQUFXO0FBQ3pGLGtCQUFNLGNBQWMsV0FBVyxNQUFNO0FBRXJDLG1CQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sWUFBWSxDQUFDO0FBQUEsVUFDNUM7QUFHQSxjQUFJLElBQUksS0FBSyxXQUFXLG9CQUFvQixLQUFLLElBQUksV0FBVyxPQUFPO0FBQ3JFLGtCQUFNLFNBQVMsSUFBSSxJQUFJLElBQUksS0FBSyxjQUFjO0FBQzlDLGtCQUFNLFFBQVEsT0FBTyxhQUFhLElBQUksT0FBTyxLQUFLO0FBQ2xELGtCQUFNLFFBQVEsT0FBTyxhQUFhLElBQUksT0FBTyxLQUFLO0FBQ2xELGdCQUFJLENBQUMsTUFBTyxRQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sZ0JBQWdCLENBQUM7QUFDMUQsa0JBQU0sVUFBVSxrQkFBa0IsS0FBSztBQUN2QyxnQkFBSSxDQUFDLFdBQVcsUUFBUSxVQUFVLE1BQU8sUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLGdCQUFnQixDQUFDO0FBQ3ZGLGdCQUFJO0FBQ0Ysb0JBQU0sSUFBSSxNQUFNLGNBQWMsd0NBQXdDLG1CQUFtQixLQUFLLElBQUksYUFBYSxFQUFFLFFBQVEsTUFBTSxHQUFHLEdBQUcsRUFBRSxNQUFNLE1BQU0sSUFBSTtBQUN2SixrQkFBSSxDQUFDLEtBQUssQ0FBRSxFQUFVLEdBQUksUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLFlBQVksQ0FBQztBQUNwRSxvQkFBTSxPQUFPLE1BQU8sRUFBZSxLQUFLLEVBQUUsTUFBTSxNQUFNLENBQUMsQ0FBQztBQUN4RCxvQkFBTSxNQUFNLE1BQU0sUUFBUSxJQUFJLEtBQUssS0FBSyxTQUFTLElBQUksS0FBSyxDQUFDLElBQUksRUFBRSxVQUFVLENBQUMsRUFBRTtBQUM5RSxxQkFBTyxRQUFRLEtBQUssRUFBRSxVQUFVLElBQUksQ0FBQztBQUFBLFlBQ3ZDLFNBQVMsR0FBRztBQUFFLHFCQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sZUFBZSxDQUFDO0FBQUEsWUFBRztBQUFBLFVBQ2hFO0FBRUEsY0FBSSxJQUFJLFFBQVEsc0JBQXNCLElBQUksV0FBVyxRQUFRO0FBQzNELGtCQUFNLE9BQU8sTUFBTSxVQUFVLEdBQUcsRUFBRSxNQUFNLE9BQU8sQ0FBQyxFQUFFO0FBQ2xELGtCQUFNLFNBQVMsT0FBTyxNQUFNLE9BQU8sRUFBRSxFQUFFLEtBQUs7QUFDNUMsZ0JBQUksQ0FBQyxPQUFRLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxjQUFjLENBQUM7QUFDekQsZ0JBQUk7QUFDRixvQkFBTSxJQUFJLElBQUksSUFBSSxNQUFNO0FBQ3hCLGtCQUFJLEVBQUUsRUFBRSxhQUFhLFdBQVcsRUFBRSxhQUFhLFVBQVcsUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLG1CQUFtQixDQUFDO0FBQUEsWUFDN0csU0FBUyxHQUFHO0FBQ1YscUJBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxjQUFjLENBQUM7QUFBQSxZQUM5QztBQUNBLGdCQUFJO0FBQ0Ysb0JBQU0sSUFBSSxNQUFNLE1BQU0sUUFBUSxFQUFFLFNBQVMsRUFBRSxjQUFjLHNCQUFzQixFQUFFLENBQUM7QUFDbEYsa0JBQUksQ0FBQyxLQUFLLENBQUMsRUFBRSxHQUFJLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxnQkFBZ0IsUUFBUSxJQUFJLEVBQUUsU0FBUyxFQUFFLENBQUM7QUFDeEYsb0JBQU0sT0FBTyxNQUFNLEVBQUUsS0FBSztBQUUxQixxQkFBTyxRQUFRLEtBQUssRUFBRSxJQUFJLE1BQU0sS0FBSyxRQUFRLFNBQVMsS0FBSyxNQUFNLEdBQUcsR0FBSyxFQUFFLENBQUM7QUFBQSxZQUM5RSxTQUFTLEdBQVE7QUFDZixxQkFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLGVBQWUsU0FBUyxPQUFPLEdBQUcsV0FBVyxDQUFDLEVBQUUsQ0FBQztBQUFBLFlBQ2hGO0FBQUEsVUFDRjtBQUVBLGNBQUksSUFBSSxRQUFRLHdCQUF3QixJQUFJLFdBQVcsUUFBUTtBQUM3RCxrQkFBTSxPQUFPLE1BQU0sVUFBVSxHQUFHLEVBQUUsTUFBTSxPQUFPLENBQUMsRUFBRTtBQUNsRCxrQkFBTSxTQUFTLE9BQU8sTUFBTSxVQUFVLEVBQUUsRUFBRSxLQUFLO0FBQy9DLGtCQUFNLFFBQVEsT0FBTyxNQUFNLFNBQVMsRUFBRSxFQUFFLEtBQUs7QUFDN0MsZ0JBQUksQ0FBQyxVQUFVLENBQUMsTUFBTyxRQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sMEJBQTBCLENBQUM7QUFHL0Usa0JBQU0sYUFBYTtBQUFBLGNBQ2pCLFdBQVcsTUFBTTtBQUFBLGNBQ2pCLFVBQVUsTUFBTTtBQUFBLGNBQ2hCLFdBQVcsTUFBTTtBQUFBLGNBQ2pCLFVBQVUsTUFBTTtBQUFBLGNBQ2hCLFdBQVcsTUFBTTtBQUFBLGNBQ2pCLFVBQVUsTUFBTTtBQUFBLFlBQ2xCO0FBR0Esa0JBQU0sTUFBTSxDQUFDLE1BQWMsRUFBRSxRQUFRLHlCQUF5QixNQUFNO0FBQ3BFLGtCQUFNLE9BQU8sSUFBSSxLQUFLO0FBQ3RCLGtCQUFNLFNBQVMsSUFBSSxPQUFPLGlGQUF3RixJQUFJLHdCQUE0QixJQUFJLDBEQUErRCxHQUFHO0FBQ3hOLGtCQUFNLFVBQVUsSUFBSSxPQUFPLG9DQUFxQyxJQUFJLElBQUksR0FBRztBQUUzRSxnQkFBSSxRQUFRO0FBQ1osdUJBQVcsT0FBTyxZQUFZO0FBQzVCLGtCQUFJO0FBQ0Ysc0JBQU0sSUFBSSxNQUFNLE1BQU0sS0FBSyxFQUFFLFNBQVMsRUFBRSxjQUFjLHNCQUFzQixFQUFFLENBQUM7QUFDL0Usb0JBQUksQ0FBQyxLQUFLLENBQUMsRUFBRSxHQUFJO0FBQ2pCLHNCQUFNLE9BQU8sTUFBTSxFQUFFLEtBQUs7QUFDMUIsb0JBQUksT0FBTyxLQUFLLElBQUksS0FBSyxRQUFRLEtBQUssSUFBSSxHQUFHO0FBQzNDLDBCQUFRO0FBQ1I7QUFBQSxnQkFDRjtBQUFBLGNBQ0YsU0FBUyxHQUFHO0FBQUEsY0FFWjtBQUFBLFlBQ0Y7QUFFQSxnQkFBSSxDQUFDLE1BQU8sUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLHVDQUF1QyxDQUFDO0FBRWpGLGdCQUFJO0FBQ0Ysb0JBQU0sY0FBYyxvQkFBb0I7QUFBQSxnQkFDdEMsUUFBUTtBQUFBLGdCQUNSLE1BQU0sS0FBSyxVQUFVLEVBQUUsUUFBUSxVQUFVLE1BQU0sY0FBYSxvQkFBSSxLQUFLLEdBQUUsWUFBWSxFQUFFLENBQUM7QUFBQSxnQkFDdEYsU0FBUyxFQUFFLFFBQVEsK0JBQStCLGdCQUFnQixtQkFBbUI7QUFBQSxjQUN2RixHQUFHLEdBQUcsRUFBRSxNQUFNLE1BQU0sSUFBSTtBQUFBLFlBQzFCLFFBQVE7QUFBQSxZQUFDO0FBRVQsbUJBQU8sUUFBUSxLQUFLLEVBQUUsSUFBSSxNQUFNLE9BQU8sQ0FBQztBQUFBLFVBQzFDO0FBRUEsY0FBSSxJQUFJLFFBQVEsaUJBQWlCLElBQUksV0FBVyxRQUFRO0FBQ3RELGtCQUFNLE9BQU8sTUFBTSxVQUFVLEdBQUc7QUFDaEMsa0JBQU0sUUFBUSxPQUFPLE1BQU0sU0FBUyxFQUFFLEVBQUUsS0FBSztBQUM3QyxnQkFBSSxDQUFDLE1BQU8sUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLGdCQUFnQixDQUFDO0FBQzFELGtCQUFNLGdCQUFnQixNQUFNLGlCQUFpQixDQUFDO0FBRTlDLGtCQUFNLGNBQWMsd0NBQXdDLG1CQUFtQixLQUFLLEdBQUc7QUFBQSxjQUNyRixRQUFRO0FBQUEsY0FDUixNQUFNLEtBQUssVUFBVSxFQUFFLFVBQVUsY0FBYyxDQUFDO0FBQUEsY0FDaEQsU0FBUyxFQUFFLGdCQUFnQixvQkFBb0IsUUFBUSx3QkFBd0I7QUFBQSxZQUNqRixHQUFHLEdBQUcsRUFBRSxNQUFNLE1BQU0sSUFBSTtBQUV4QixtQkFBTyxRQUFRLEtBQUssRUFBRSxNQUFNLENBQUM7QUFBQSxVQUMvQjtBQUVBLGNBQUksSUFBSSxRQUFRLGVBQWUsSUFBSSxXQUFXLFFBQVE7QUFDcEQsa0JBQU0sS0FBTSxJQUFJLFFBQVEsaUJBQWlCLEtBQWdCLElBQUksT0FBTyxpQkFBaUI7QUFDckYsZ0JBQUksQ0FBQyxVQUFVLFVBQVUsSUFBSSxJQUFJLEdBQU0sRUFBRyxRQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sb0JBQW9CLENBQUM7QUFDNUYsa0JBQU0sT0FBTyxNQUFNLFVBQVUsR0FBRyxFQUFFLE1BQU0sT0FBTyxDQUFDLEVBQUU7QUFDbEQsa0JBQU0sVUFBVSxPQUFPLE1BQU0sV0FBVyxFQUFFLEVBQUUsTUFBTSxHQUFHLEdBQUk7QUFDekQsZ0JBQUksQ0FBQyxRQUFTLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxnQkFBZ0IsQ0FBQztBQUU1RCxrQkFBTSxjQUFjLDBCQUEwQjtBQUFBLGNBQzVDLFFBQVE7QUFBQSxjQUNSLE1BQU0sS0FBSyxVQUFVLEVBQUUsUUFBUSxRQUFRLFNBQVMsRUFBRSxLQUFLLFFBQVEsT0FBTyxFQUFFLENBQUM7QUFBQSxZQUMzRSxHQUFHLEdBQUcsRUFBRSxNQUFNLE1BQU0sSUFBSTtBQUV4QixrQkFBTSxRQUFRO0FBQ2QsbUJBQU8sUUFBUSxLQUFLLEVBQUUsTUFBTSxDQUFDO0FBQUEsVUFDL0I7QUFHQSxjQUFJLElBQUksUUFBUSxzQkFBc0IsSUFBSSxXQUFXLFFBQVE7QUFDM0Qsa0JBQU0sS0FBTSxJQUFJLFFBQVEsaUJBQWlCLEtBQWdCLElBQUksT0FBTyxpQkFBaUI7QUFDckYsZ0JBQUksQ0FBQyxVQUFVLFlBQVksSUFBSSxHQUFHLEtBQUcsR0FBTSxFQUFHLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxvQkFBb0IsQ0FBQztBQUNoRyxrQkFBTSxPQUFPLE1BQU0sVUFBVSxHQUFHLEVBQUUsTUFBTSxPQUFPLENBQUMsRUFBRTtBQUNsRCxrQkFBTSxRQUFRLE9BQU8sTUFBTSxTQUFTLEVBQUUsRUFBRSxLQUFLLEVBQUUsWUFBWTtBQUMzRCxnQkFBSSxDQUFDLDZCQUE2QixLQUFLLEtBQUssRUFBRyxRQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sZ0JBQWdCLENBQUM7QUFHN0Ysa0JBQU0sT0FBTyxNQUFNLGNBQWMsaUJBQWlCLEVBQUUsUUFBUSxNQUFNLEdBQUcsR0FBRyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBQzFGLGdCQUFJLENBQUMsUUFBUSxDQUFFLEtBQWEsR0FBSSxRQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sZUFBZSxDQUFDO0FBQzdFLGtCQUFNLE9BQU8sTUFBTyxLQUFrQixLQUFLLEVBQUUsTUFBTSxNQUFNLElBQUk7QUFDN0QsZ0JBQUksQ0FBQyxRQUFRLEtBQUssT0FBTyxZQUFZLE1BQU0sTUFBTyxRQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8saUJBQWlCLENBQUM7QUFFakcsa0JBQU0sUUFBUSxPQUFPLFlBQVksRUFBRSxFQUFFLFNBQVMsV0FBVztBQUN6RCxrQkFBTSxTQUFTLFFBQVEsSUFBSSxzQkFBc0I7QUFDakQsa0JBQU0sWUFBWSxPQUFPLFdBQVcsUUFBUSxFQUFFLE9BQU8sUUFBUSxNQUFNLEVBQUUsT0FBTyxRQUFRO0FBQ3BGLGtCQUFNLFVBQVUsSUFBSSxLQUFLLEtBQUssSUFBSSxJQUFJLE1BQU8sS0FBSyxLQUFLLEVBQUUsRUFBRSxZQUFZO0FBR3ZFLGtCQUFNLGNBQWMsZ0NBQWdDO0FBQUEsY0FDbEQsUUFBUTtBQUFBLGNBQ1IsU0FBUyxFQUFFLFFBQVEsOEJBQThCO0FBQUEsY0FDakQsTUFBTSxLQUFLLFVBQVUsRUFBRSxTQUFTLEtBQUssSUFBSSxPQUFPLFlBQVksV0FBVyxZQUFZLFNBQVMsU0FBUyxLQUFLLENBQUM7QUFBQSxZQUM3RyxHQUFHLEdBQUcsRUFBRSxNQUFNLE1BQU0sSUFBSTtBQUd4QixrQkFBTSxPQUFPLFFBQVEsSUFBSTtBQUN6QixrQkFBTSxPQUFPLE9BQU8sUUFBUSxJQUFJLGFBQWEsR0FBRztBQUNoRCxrQkFBTSxXQUFXLFFBQVEsSUFBSTtBQUM3QixrQkFBTSxXQUFXLFFBQVEsSUFBSTtBQUM3QixrQkFBTSxPQUFPLFFBQVEsSUFBSSxjQUFjO0FBQ3ZDLGtCQUFNLFNBQVMsUUFBUSxJQUFJLFdBQVc7QUFDdEMsa0JBQU0sWUFBWSxHQUFHLE1BQU0sMkJBQTJCLEtBQUs7QUFFM0QsZ0JBQUksUUFBUSxZQUFZLFVBQVU7QUFDaEMsb0JBQU0sY0FBYyxXQUFXLGdCQUFnQixFQUFFLE1BQU0sTUFBTSxRQUFRLFNBQVMsS0FBSyxNQUFNLEVBQUUsTUFBTSxVQUFVLE1BQU0sU0FBUyxFQUFFLENBQUM7QUFDN0gsb0JBQU0sT0FBTztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUEscUNBY1UsU0FBUztBQUFBLHNLQUNtSCxTQUFTO0FBQUE7QUFBQTtBQUFBO0FBQUEsd0hBSXRELG9CQUFJLEtBQUssR0FBRSxZQUFZLENBQUM7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUs5SCxvQkFBTSxZQUFZLFNBQVMsRUFBRSxJQUFJLE9BQU8sTUFBTSxTQUFTLGlDQUFpQyxLQUFLLENBQUM7QUFBQSxZQUNoRyxPQUFPO0FBQ0wsa0JBQUksUUFBUSxJQUFJLGFBQWEsY0FBYztBQUN6Qyx3QkFBUSxLQUFLLGtEQUFrRCxTQUFTO0FBQUEsY0FDMUU7QUFBQSxZQUNGO0FBRUEsbUJBQU8sUUFBUSxLQUFLLEVBQUUsSUFBSSxLQUFLLENBQUM7QUFBQSxVQUNsQztBQUdBLGNBQUksSUFBSSxLQUFLLFdBQVcsbUJBQW1CLEtBQUssSUFBSSxXQUFXLE9BQU87QUFDcEUsa0JBQU0sU0FBUyxJQUFJLElBQUksSUFBSSxLQUFLLGNBQWM7QUFDOUMsa0JBQU0sUUFBUSxPQUFPLGFBQWEsSUFBSSxPQUFPLEtBQUs7QUFDbEQsZ0JBQUksQ0FBQyxPQUFPO0FBQ1Ysa0JBQUksYUFBYTtBQUNqQixrQkFBSSxVQUFVLGdCQUFnQixXQUFXO0FBQ3pDLHFCQUFPLElBQUksSUFBSSxzQkFBc0I7QUFBQSxZQUN2QztBQUNBLGtCQUFNLFNBQVMsUUFBUSxJQUFJLHNCQUFzQjtBQUNqRCxrQkFBTSxZQUFZLE9BQU8sV0FBVyxRQUFRLEVBQUUsT0FBTyxRQUFRLE1BQU0sRUFBRSxPQUFPLFFBQVE7QUFHcEYsZ0JBQUksS0FBSztBQUNULGdCQUFJO0FBQ0Ysb0JBQU0sTUFBTSxNQUFNLGNBQWMsa0NBQWtDO0FBQUEsZ0JBQ2hFLFFBQVE7QUFBQSxnQkFDUixNQUFNLEtBQUssVUFBVSxFQUFFLFFBQVEsVUFBVSxDQUFDO0FBQUEsY0FDNUMsR0FBRyxHQUFHO0FBQ04sa0JBQUksT0FBUSxJQUFZLEdBQUksTUFBSztBQUFBLFlBQ25DLFFBQVE7QUFBQSxZQUFDO0FBRVQsZ0JBQUksQ0FBQyxJQUFJO0FBQ1Asb0JBQU0sVUFBUyxvQkFBSSxLQUFLLEdBQUUsWUFBWTtBQUN0QyxvQkFBTSxjQUFjLGdEQUFnRCxtQkFBbUIsU0FBUyxJQUFJLG9DQUFvQyxtQkFBbUIsTUFBTSxHQUFHO0FBQUEsZ0JBQ2xLLFFBQVE7QUFBQSxnQkFDUixNQUFNLEtBQUssVUFBVSxFQUFFLFNBQVMsT0FBTyxDQUFDO0FBQUEsZ0JBQ3hDLFNBQVMsRUFBRSxRQUFRLHdCQUF3QjtBQUFBLGNBQzdDLEdBQUcsR0FBRyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBQUEsWUFDMUI7QUFFQSxnQkFBSSxhQUFhO0FBQ2pCLGdCQUFJLFVBQVUsZ0JBQWdCLFdBQVc7QUFDekMsbUJBQU8sSUFBSSxJQUFJLG1SQUE4UTtBQUFBLFVBQy9SO0FBRUEsaUJBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxZQUFZLENBQUM7QUFBQSxRQUM1QyxTQUFTLEdBQVE7QUFDZixpQkFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLGVBQWUsQ0FBQztBQUFBLFFBQy9DO0FBQUEsTUFDRixDQUFDO0FBQUEsSUFDSDtBQUFBLEVBQ0Y7QUFDRjs7O0FEbGxCQSxJQUFNLG1DQUFtQztBQU96QyxJQUFPLHNCQUFRLGFBQWEsQ0FBQyxFQUFFLEtBQUssT0FBTztBQUFBLEVBQ3pDLFFBQVE7QUFBQSxJQUNOLE1BQU07QUFBQSxJQUNOLE1BQU07QUFBQSxFQUNSO0FBQUEsRUFDQSxTQUFTO0FBQUEsSUFDUCxNQUFNO0FBQUEsSUFDTixTQUFTLGlCQUNULGdCQUFnQjtBQUFBLElBQ2hCLGdCQUFnQjtBQUFBLEVBQ2xCLEVBQUUsT0FBTyxPQUFPO0FBQUEsRUFDaEIsU0FBUztBQUFBLElBQ1AsT0FBTztBQUFBLE1BQ0wsS0FBSyxLQUFLLFFBQVEsa0NBQVcsT0FBTztBQUFBLElBQ3RDO0FBQUEsRUFDRjtBQUNGLEVBQUU7IiwKICAibmFtZXMiOiBbImpzb24iLCAicGF0aCJdCn0K
