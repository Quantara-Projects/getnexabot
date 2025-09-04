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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL3NlcnZlci9hcGkudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGVcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9hcHAvY29kZS92aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vYXBwL2NvZGUvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tIFwidml0ZVwiO1xuaW1wb3J0IHJlYWN0IGZyb20gXCJAdml0ZWpzL3BsdWdpbi1yZWFjdC1zd2NcIjtcbmltcG9ydCBwYXRoIGZyb20gXCJwYXRoXCI7XG5pbXBvcnQgeyBjb21wb25lbnRUYWdnZXIgfSBmcm9tIFwibG92YWJsZS10YWdnZXJcIjtcbmltcG9ydCB7IHNlcnZlckFwaVBsdWdpbiB9IGZyb20gXCIuL3NyYy9zZXJ2ZXIvYXBpXCI7XG5cbi8vIGh0dHBzOi8vdml0ZWpzLmRldi9jb25maWcvXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiAoe1xuICBzZXJ2ZXI6IHtcbiAgICBob3N0OiBcIjo6XCIsXG4gICAgcG9ydDogODA4MCxcbiAgfSxcbiAgcGx1Z2luczogW1xuICAgIHJlYWN0KCksXG4gICAgbW9kZSA9PT0gJ2RldmVsb3BtZW50JyAmJlxuICAgIGNvbXBvbmVudFRhZ2dlcigpLFxuICAgIHNlcnZlckFwaVBsdWdpbigpLFxuICBdLmZpbHRlcihCb29sZWFuKSxcbiAgcmVzb2x2ZToge1xuICAgIGFsaWFzOiB7XG4gICAgICBcIkBcIjogcGF0aC5yZXNvbHZlKF9fZGlybmFtZSwgXCIuL3NyY1wiKSxcbiAgICB9LFxuICB9LFxufSkpO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGUvc3JjL3NlcnZlclwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2FwcC9jb2RlL3NyYy9zZXJ2ZXIvYXBpLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9hcHAvY29kZS9zcmMvc2VydmVyL2FwaS50c1wiO2ltcG9ydCB0eXBlIHsgUGx1Z2luIH0gZnJvbSAndml0ZSc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5pbXBvcnQgbm9kZW1haWxlciBmcm9tICdub2RlbWFpbGVyJztcblxuLy8gU21hbGwgSlNPTiBib2R5IHBhcnNlciB3aXRoIHNpemUgbGltaXRcbmFzeW5jIGZ1bmN0aW9uIHBhcnNlSnNvbihyZXE6IGFueSwgbGltaXQgPSAxMDI0ICogMTAwKSB7XG4gIHJldHVybiBuZXcgUHJvbWlzZTxhbnk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICBjb25zdCBjaHVua3M6IEJ1ZmZlcltdID0gW107XG4gICAgbGV0IHNpemUgPSAwO1xuICAgIHJlcS5vbignZGF0YScsIChjOiBCdWZmZXIpID0+IHtcbiAgICAgIHNpemUgKz0gYy5sZW5ndGg7XG4gICAgICBpZiAoc2l6ZSA+IGxpbWl0KSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1BheWxvYWQgdG9vIGxhcmdlJykpO1xuICAgICAgICByZXEuZGVzdHJveSgpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjaHVua3MucHVzaChjKTtcbiAgICB9KTtcbiAgICByZXEub24oJ2VuZCcsICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJhdyA9IEJ1ZmZlci5jb25jYXQoY2h1bmtzKS50b1N0cmluZygndXRmOCcpO1xuICAgICAgICBjb25zdCBqc29uID0gcmF3ID8gSlNPTi5wYXJzZShyYXcpIDoge307XG4gICAgICAgIHJlc29sdmUoanNvbik7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHJlamVjdChlKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICByZXEub24oJ2Vycm9yJywgcmVqZWN0KTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIGpzb24ocmVzOiBhbnksIHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnksIGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7fSkge1xuICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7XG4gIHJlcy5zdGF0dXNDb2RlID0gc3RhdHVzO1xuICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCcpO1xuICByZXMuc2V0SGVhZGVyKCdYLUNvbnRlbnQtVHlwZS1PcHRpb25zJywgJ25vc25pZmYnKTtcbiAgcmVzLnNldEhlYWRlcignUmVmZXJyZXItUG9saWN5JywgJ25vLXJlZmVycmVyJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtRnJhbWUtT3B0aW9ucycsICdERU5ZJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtWFNTLVByb3RlY3Rpb24nLCAnMTsgbW9kZT1ibG9jaycpO1xuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhoZWFkZXJzKSkgcmVzLnNldEhlYWRlcihrLCB2KTtcbiAgcmVzLmVuZChib2R5KTtcbn1cblxuY29uc3QgaXNIdHRwcyA9IChyZXE6IGFueSkgPT4ge1xuICBjb25zdCBwcm90byA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtcHJvdG8nXSBhcyBzdHJpbmcpIHx8ICcnO1xuICByZXR1cm4gcHJvdG8gPT09ICdodHRwcycgfHwgKHJlcS5zb2NrZXQgJiYgKHJlcS5zb2NrZXQgYXMgYW55KS5lbmNyeXB0ZWQpO1xufTtcblxuZnVuY3Rpb24gcmVxdWlyZUVudihuYW1lOiBzdHJpbmcpIHtcbiAgY29uc3QgdiA9IHByb2Nlc3MuZW52W25hbWVdO1xuICBpZiAoIXYpIHRocm93IG5ldyBFcnJvcihgJHtuYW1lfSBub3Qgc2V0YCk7XG4gIHJldHVybiB2O1xufVxuXG5hc3luYyBmdW5jdGlvbiBzdXBhYmFzZUZldGNoKHBhdGg6IHN0cmluZywgb3B0aW9uczogYW55LCByZXE6IGFueSkge1xuICBjb25zdCBiYXNlID0gcmVxdWlyZUVudignU1VQQUJBU0VfVVJMJyk7XG4gIGNvbnN0IGFub24gPSByZXF1aXJlRW52KCdTVVBBQkFTRV9BTk9OX0tFWScpO1xuICBjb25zdCB0b2tlbiA9IChyZXEuaGVhZGVyc1snYXV0aG9yaXphdGlvbiddIGFzIHN0cmluZykgfHwgJyc7XG4gIGNvbnN0IGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7XG4gICAgYXBpa2V5OiBhbm9uLFxuICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsXG4gIH07XG4gIGlmICh0b2tlbikgaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gdG9rZW47XG4gIHJldHVybiBmZXRjaChgJHtiYXNlfSR7cGF0aH1gLCB7IC4uLm9wdGlvbnMsIGhlYWRlcnM6IHsgLi4uaGVhZGVycywgLi4uKG9wdGlvbnM/LmhlYWRlcnMgfHwge30pIH0gfSk7XG59XG5cbmZ1bmN0aW9uIG1ha2VCb3RJZChzZWVkOiBzdHJpbmcpIHtcbiAgcmV0dXJuICdib3RfJyArIGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUoc2VlZCkuZGlnZXN0KCdiYXNlNjR1cmwnKS5zbGljZSgwLCAyMik7XG59XG5cbi8vIEV4dHJhY3QgdmlzaWJsZSB0ZXh0IGZyb20gSFRNTCAobmFpdmUpXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21IdG1sKGh0bWw6IHN0cmluZykge1xuICAvLyByZW1vdmUgc2NyaXB0cy9zdHlsZXNcbiAgY29uc3Qgd2l0aG91dFNjcmlwdHMgPSBodG1sLnJlcGxhY2UoLzxzY3JpcHRbXFxzXFxTXSo/PltcXHNcXFNdKj88XFwvc2NyaXB0Pi9naSwgJyAnKTtcbiAgY29uc3Qgd2l0aG91dFN0eWxlcyA9IHdpdGhvdXRTY3JpcHRzLnJlcGxhY2UoLzxzdHlsZVtcXHNcXFNdKj8+W1xcc1xcU10qPzxcXC9zdHlsZT4vZ2ksICcgJyk7XG4gIC8vIHJlbW92ZSB0YWdzXG4gIGNvbnN0IHRleHQgPSB3aXRob3V0U3R5bGVzLnJlcGxhY2UoLzxbXj5dKz4vZywgJyAnKTtcbiAgLy8gZGVjb2RlIEhUTUwgZW50aXRpZXMgKGJhc2ljKVxuICByZXR1cm4gdGV4dC5yZXBsYWNlKC8mbmJzcDt8JmFtcDt8Jmx0O3wmZ3Q7fCZxdW90O3wmIzM5Oy9nLCAocykgPT4ge1xuICAgIHN3aXRjaCAocykge1xuICAgICAgY2FzZSAnJm5ic3A7JzogcmV0dXJuICcgJztcbiAgICAgIGNhc2UgJyZhbXA7JzogcmV0dXJuICcmJztcbiAgICAgIGNhc2UgJyZsdDsnOiByZXR1cm4gJzwnO1xuICAgICAgY2FzZSAnJmd0Oyc6IHJldHVybiAnPic7XG4gICAgICBjYXNlICcmcXVvdDsnOiByZXR1cm4gJ1wiJztcbiAgICAgIGNhc2UgJyYjMzk7JzogcmV0dXJuICdcXCcnO1xuICAgICAgZGVmYXVsdDogcmV0dXJuIHM7XG4gICAgfVxuICB9KS5yZXBsYWNlKC9cXHMrL2csICcgJykudHJpbSgpO1xufVxuXG5hc3luYyBmdW5jdGlvbiB0cnlGZXRjaFVybFRleHQodTogc3RyaW5nKSB7XG4gIHRyeSB7XG4gICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2godSwgeyBoZWFkZXJzOiB7ICdVc2VyLUFnZW50JzogJ05leGFCb3RDcmF3bGVyLzEuMCcgfSB9KTtcbiAgICBpZiAoIXJlcy5vaykgcmV0dXJuICcnO1xuICAgIGNvbnN0IGh0bWwgPSBhd2FpdCByZXMudGV4dCgpO1xuICAgIHJldHVybiBleHRyYWN0VGV4dEZyb21IdG1sKGh0bWwpO1xuICB9IGNhdGNoIChlKSB7XG4gICAgcmV0dXJuICcnO1xuICB9XG59XG5cbmZ1bmN0aW9uIGNodW5rVGV4dCh0ZXh0OiBzdHJpbmcsIG1heENoYXJzID0gMTUwMCkge1xuICBjb25zdCBwYXJhZ3JhcGhzID0gdGV4dC5zcGxpdCgvXFxufFxccnxcXC58XFwhfFxcPy8pLm1hcChwID0+IHAudHJpbSgpKS5maWx0ZXIoQm9vbGVhbik7XG4gIGNvbnN0IGNodW5rczogc3RyaW5nW10gPSBbXTtcbiAgbGV0IGN1ciA9ICcnO1xuICBmb3IgKGNvbnN0IHAgb2YgcGFyYWdyYXBocykge1xuICAgIGlmICgoY3VyICsgJyAnICsgcCkubGVuZ3RoID4gbWF4Q2hhcnMpIHtcbiAgICAgIGlmIChjdXIpIHsgY2h1bmtzLnB1c2goY3VyLnRyaW0oKSk7IGN1ciA9IHA7IH1cbiAgICAgIGVsc2UgeyBjaHVua3MucHVzaChwLnNsaWNlKDAsIG1heENoYXJzKSk7IGN1ciA9IHAuc2xpY2UobWF4Q2hhcnMpOyB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGN1ciA9IChjdXIgKyAnICcgKyBwKS50cmltKCk7XG4gICAgfVxuICB9XG4gIGlmIChjdXIpIGNodW5rcy5wdXNoKGN1ci50cmltKCkpO1xuICByZXR1cm4gY2h1bmtzO1xufVxuXG5hc3luYyBmdW5jdGlvbiBlbWJlZENodW5rcyhjaHVua3M6IHN0cmluZ1tdKTogUHJvbWlzZTxudW1iZXJbXVtdIHwgbnVsbD4ge1xuICBjb25zdCBrZXkgPSBwcm9jZXNzLmVudi5PUEVOQUlfQVBJX0tFWTtcbiAgaWYgKCFrZXkpIHJldHVybiBudWxsO1xuICB0cnkge1xuICAgIGNvbnN0IHJlc3AgPSBhd2FpdCBmZXRjaCgnaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS92MS9lbWJlZGRpbmdzJywge1xuICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICBoZWFkZXJzOiB7ICdBdXRob3JpemF0aW9uJzogYEJlYXJlciAke2tleX1gLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGlucHV0OiBjaHVua3MsIG1vZGVsOiAndGV4dC1lbWJlZGRpbmctMy1zbWFsbCcgfSksXG4gICAgfSk7XG4gICAgaWYgKCFyZXNwLm9rKSByZXR1cm4gbnVsbDtcbiAgICBjb25zdCBqID0gYXdhaXQgcmVzcC5qc29uKCk7XG4gICAgaWYgKCFqLmRhdGEpIHJldHVybiBudWxsO1xuICAgIHJldHVybiBqLmRhdGEubWFwKChkOiBhbnkpID0+IGQuZW1iZWRkaW5nIGFzIG51bWJlcltdKTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHByb2Nlc3NUcmFpbkpvYihqb2JJZDogc3RyaW5nLCBib2R5OiBhbnksIHJlcTogYW55KSB7XG4gIGNvbnN0IHVybCA9IGJvZHkudXJsIHx8ICcnO1xuICBjb25zdCBmaWxlczogc3RyaW5nW10gPSBBcnJheS5pc0FycmF5KGJvZHkuZmlsZXMpID8gYm9keS5maWxlcyA6IFtdO1xuICBjb25zdCBib3RTZWVkID0gKHVybCB8fCBmaWxlcy5qb2luKCcsJykpICsgRGF0ZS5ub3coKTtcbiAgY29uc3QgYm90SWQgPSBtYWtlQm90SWQoYm90U2VlZCk7XG5cbiAgLy8gZ2F0aGVyIHRleHRzXG4gIGNvbnN0IGRvY3M6IHsgc291cmNlOiBzdHJpbmc7IGNvbnRlbnQ6IHN0cmluZyB9W10gPSBbXTtcblxuICBpZiAodXJsKSB7XG4gICAgY29uc3QgdGV4dCA9IGF3YWl0IHRyeUZldGNoVXJsVGV4dCh1cmwpO1xuICAgIGlmICh0ZXh0KSBkb2NzLnB1c2goeyBzb3VyY2U6IHVybCwgY29udGVudDogdGV4dCB9KTtcbiAgfVxuXG4gIC8vIGZpbGVzIGFyZSBzdG9yYWdlIHBhdGhzIGluIGJ1Y2tldC90cmFpbmluZy8uLi5cbiAgZm9yIChjb25zdCBwYXRoIG9mIGZpbGVzKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IFNVUEFCQVNFX1VSTCA9IHByb2Nlc3MuZW52LlNVUEFCQVNFX1VSTDtcbiAgICAgIGNvbnN0IGJ1Y2tldFB1YmxpY1VybCA9IFNVUEFCQVNFX1VSTCArIGAvc3RvcmFnZS92MS9vYmplY3QvcHVibGljL3RyYWluaW5nLyR7ZW5jb2RlVVJJQ29tcG9uZW50KHBhdGgpfWA7XG4gICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChidWNrZXRQdWJsaWNVcmwpO1xuICAgICAgaWYgKCFyZXMub2spIGNvbnRpbnVlO1xuICAgICAgY29uc3QgYnVmID0gYXdhaXQgcmVzLmFycmF5QnVmZmVyKCk7XG4gICAgICAvLyBjcnVkZSB0ZXh0IGV4dHJhY3Rpb246IGlmIGl0J3MgcGRmIG9yIHRleHRcbiAgICAgIGNvbnN0IGhlYWRlciA9IFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCwgbmV3IFVpbnQ4QXJyYXkoYnVmLnNsaWNlKDAsIDgpKSBhcyBhbnkpO1xuICAgICAgaWYgKGhlYWRlci5pbmNsdWRlcygnJVBERicpKSB7XG4gICAgICAgIC8vIGNhbm5vdCBwYXJzZSBQREYgaGVyZTsgc3RvcmUgcGxhY2Vob2xkZXJcbiAgICAgICAgZG9jcy5wdXNoKHsgc291cmNlOiBwYXRoLCBjb250ZW50OiAnKFBERiBjb250ZW50IC0tIHByb2Nlc3NlZCBleHRlcm5hbGx5KScgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjb25zdCB0ZXh0ID0gbmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKGJ1Zik7XG4gICAgICAgIGNvbnN0IGNsZWFuZWQgPSBleHRyYWN0VGV4dEZyb21IdG1sKHRleHQpO1xuICAgICAgICBkb2NzLnB1c2goeyBzb3VyY2U6IHBhdGgsIGNvbnRlbnQ6IGNsZWFuZWQgfHwgJyhiaW5hcnkgZmlsZSknIH0pO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGUpIHsgY29udGludWU7IH1cbiAgfVxuXG4gIC8vIGNodW5rIGFuZCBlbWJlZFxuICBmb3IgKGNvbnN0IGRvYyBvZiBkb2NzKSB7XG4gICAgY29uc3QgY2h1bmtzID0gY2h1bmtUZXh0KGRvYy5jb250ZW50KTtcbiAgICBjb25zdCBlbWJlZGRpbmdzID0gYXdhaXQgZW1iZWRDaHVua3MoY2h1bmtzKTtcblxuICAgIC8vIHN0b3JlIGRvY3VtZW50cyBhbmQgZW1iZWRkaW5ncyBpbiBTdXBhYmFzZVxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgY2h1bmtzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBjb25zdCBjaHVuayA9IGNodW5rc1tpXTtcbiAgICAgIGNvbnN0IGVtYiA9IGVtYmVkZGluZ3MgPyBlbWJlZGRpbmdzW2ldIDogbnVsbDtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3RyYWluaW5nX2RvY3VtZW50cycsIHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGJvdF9pZDogYm90SWQsIHNvdXJjZTogZG9jLnNvdXJjZSwgY29udGVudDogY2h1bmssIGVtYmVkZGluZzogZW1iIH0pLFxuICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmV0dXJuPXJlcHJlc2VudGF0aW9uJywgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9LFxuICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgfSBjYXRjaCB7fVxuICAgIH1cbiAgfVxuXG4gIC8vIG1hcmsgam9iIGluIGxvZ3NcbiAgdHJ5IHtcbiAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFjdGlvbjogJ1RSQUlOX0pPQl9DT01QTEVURScsIGRldGFpbHM6IHsgam9iSWQsIGJvdElkLCBkb2NzOiBkb2NzLmxlbmd0aCB9IH0pLFxuICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gIH0gY2F0Y2gge31cbn1cblxuYXN5bmMgZnVuY3Rpb24gZW5zdXJlRG9tYWluVmVyaWZpY2F0aW9uKGRvbWFpbjogc3RyaW5nLCByZXE6IGFueSkge1xuICAvLyBjaGVjayBkb21haW5zIHRhYmxlIGZvciB2ZXJpZmllZFxuICB0cnkge1xuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goYC9yZXN0L3YxL2RvbWFpbnM/ZG9tYWluPWVxLiR7ZW5jb2RlVVJJQ29tcG9uZW50KGRvbWFpbil9YCwgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSk7XG4gICAgaWYgKHJlcyAmJiAocmVzIGFzIGFueSkub2spIHtcbiAgICAgIGNvbnN0IGogPSBhd2FpdCAocmVzIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gW10pO1xuICAgICAgaWYgKEFycmF5LmlzQXJyYXkoaikgJiYgai5sZW5ndGggPiAwICYmIGpbMF0udmVyaWZpZWQpIHJldHVybiB7IHZlcmlmaWVkOiB0cnVlIH07XG4gICAgfVxuICB9IGNhdGNoIHt9XG4gIC8vIGNyZWF0ZSB2ZXJpZmljYXRpb24gdG9rZW4gZW50cnlcbiAgY29uc3QgdG9rZW4gPSBjcnlwdG8ucmFuZG9tQnl0ZXMoMTYpLnRvU3RyaW5nKCdiYXNlNjR1cmwnKTtcbiAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRE9NQUlOX1ZFUklGSUNBVElPTl9TRUNSRVQgfHwgJ2xvY2FsLWRvbS1zZWNyZXQnO1xuICBjb25zdCB0b2tlbkhhc2ggPSBjcnlwdG8uY3JlYXRlSGFzaCgnc2hhMjU2JykudXBkYXRlKHRva2VuICsgc2VjcmV0KS5kaWdlc3QoJ2Jhc2U2NCcpO1xuICBjb25zdCBleHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIDEwMDAgKiA2MCAqIDYwICogMjQpLnRvSVNPU3RyaW5nKCk7XG4gIHRyeSB7XG4gICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZG9tYWluX3ZlcmlmaWNhdGlvbnMnLCB7XG4gICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgZG9tYWluLCB0b2tlbl9oYXNoOiB0b2tlbkhhc2gsIGV4cGlyZXNfYXQ6IGV4cGlyZXMgfSksXG4gICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycsICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicgfSxcbiAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICB9IGNhdGNoIHt9XG4gIHJldHVybiB7IHZlcmlmaWVkOiBmYWxzZSwgdG9rZW4gfTtcbn1cblxuZnVuY3Rpb24gdmVyaWZ5V2lkZ2V0VG9rZW4odG9rZW46IHN0cmluZykge1xuICB0cnkge1xuICAgIGNvbnN0IHdpZGdldFNlY3JldCA9IHByb2Nlc3MuZW52LldJREdFVF9UT0tFTl9TRUNSRVQgfHwgJ2xvY2FsLXdpZGdldC1zZWNyZXQnO1xuICAgIGNvbnN0IHBhcnRzID0gdG9rZW4uc3BsaXQoJy4nKTtcbiAgICBpZiAocGFydHMubGVuZ3RoICE9PSAzKSByZXR1cm4gbnVsbDtcbiAgICBjb25zdCB1bnNpZ25lZCA9IHBhcnRzWzBdICsgJy4nICsgcGFydHNbMV07XG4gICAgY29uc3Qgc2lnID0gcGFydHNbMl07XG4gICAgY29uc3QgZXhwZWN0ZWQgPSBjcnlwdG8uY3JlYXRlSG1hYygnc2hhMjU2Jywgd2lkZ2V0U2VjcmV0KS51cGRhdGUodW5zaWduZWQpLmRpZ2VzdCgnYmFzZTY0dXJsJyk7XG4gICAgaWYgKHNpZyAhPT0gZXhwZWN0ZWQpIHJldHVybiBudWxsO1xuICAgIGNvbnN0IHBheWxvYWQgPSBKU09OLnBhcnNlKEJ1ZmZlci5mcm9tKHBhcnRzWzFdLCAnYmFzZTY0dXJsJykudG9TdHJpbmcoJ3V0ZjgnKSk7XG4gICAgcmV0dXJuIHBheWxvYWQ7XG4gIH0gY2F0Y2ggKGUpIHsgcmV0dXJuIG51bGw7IH1cbn1cblxuLy8gU2ltcGxlIGluLW1lbW9yeSByYXRlIGxpbWl0ZXJcbmNvbnN0IHJhdGVNYXAgPSBuZXcgTWFwPHN0cmluZywgeyBjb3VudDogbnVtYmVyOyB0czogbnVtYmVyIH0+KCk7XG5mdW5jdGlvbiByYXRlTGltaXQoa2V5OiBzdHJpbmcsIGxpbWl0OiBudW1iZXIsIHdpbmRvd01zOiBudW1iZXIpIHtcbiAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgY29uc3QgcmVjID0gcmF0ZU1hcC5nZXQoa2V5KTtcbiAgaWYgKCFyZWMgfHwgbm93IC0gcmVjLnRzID4gd2luZG93TXMpIHtcbiAgICByYXRlTWFwLnNldChrZXksIHsgY291bnQ6IDEsIHRzOiBub3cgfSk7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cbiAgaWYgKHJlYy5jb3VudCA8IGxpbWl0KSB7XG4gICAgcmVjLmNvdW50ICs9IDE7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cbiAgcmV0dXJuIGZhbHNlO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gc2VydmVyQXBpUGx1Z2luKCk6IFBsdWdpbiB7XG4gIHJldHVybiB7XG4gICAgbmFtZTogJ3NlcnZlci1hcGktcGx1Z2luJyxcbiAgICBjb25maWd1cmVTZXJ2ZXIoc2VydmVyKSB7XG4gICAgICBzZXJ2ZXIubWlkZGxld2FyZXMudXNlKGFzeW5jIChyZXEsIHJlcywgbmV4dCkgPT4ge1xuICAgICAgICBpZiAoIXJlcS51cmwgfHwgIXJlcS51cmwuc3RhcnRzV2l0aCgnL2FwaS8nKSkgcmV0dXJuIG5leHQoKTtcblxuICAgICAgICAvLyBCYXNpYyBzZWN1cml0eSBoZWFkZXJzIGZvciBhbGwgQVBJIHJlc3BvbnNlc1xuICAgICAgICBjb25zdCBjb3JzT3JpZ2luID0gcmVxLmhlYWRlcnMub3JpZ2luIHx8ICcqJztcbiAgICAgICAgcmVzLnNldEhlYWRlcignUGVybWlzc2lvbnMtUG9saWN5JywgJ2dlb2xvY2F0aW9uPSgpLCBtaWNyb3Bob25lPSgpLCBjYW1lcmE9KCknKTtcbiAgICAgICAgcmVzLnNldEhlYWRlcignQ3Jvc3MtT3JpZ2luLVJlc291cmNlLVBvbGljeScsICdzYW1lLW9yaWdpbicpO1xuXG4gICAgICAgIC8vIEluIGRldiBhbGxvdyBodHRwOyBpbiBwcm9kIChiZWhpbmQgcHJveHkpLCByZXF1aXJlIGh0dHBzXG4gICAgICAgIGlmIChwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ3Byb2R1Y3Rpb24nICYmICFpc0h0dHBzKHJlcSkpIHtcbiAgICAgICAgICByZXR1cm4ganNvbihyZXMsIDQwMCwgeyBlcnJvcjogJ0hUVFBTIHJlcXVpcmVkJyB9LCB7ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nOiBTdHJpbmcoY29yc09yaWdpbikgfSk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDT1JTIHByZWZsaWdodFxuICAgICAgICBpZiAocmVxLm1ldGhvZCA9PT0gJ09QVElPTlMnKSB7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJywgU3RyaW5nKGNvcnNPcmlnaW4pKTtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1NZXRob2RzJywgJ1BPU1QsR0VULE9QVElPTlMnKTtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzJywgJ0NvbnRlbnQtVHlwZSwgQXV0aG9yaXphdGlvbicpO1xuICAgICAgICAgIHJlcy5zdGF0dXNDb2RlID0gMjA0O1xuICAgICAgICAgIHJldHVybiByZXMuZW5kKCk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBlbmRKc29uID0gKHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnkpID0+IGpzb24ocmVzLCBzdGF0dXMsIGRhdGEsIHsgJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbic6IFN0cmluZyhjb3JzT3JpZ2luKSB9KTtcblxuICAgICAgICB0cnkge1xuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS90cmFpbicgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBpcCA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtZm9yJ10gYXMgc3RyaW5nKSB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJ2lwJztcbiAgICAgICAgICAgIGlmICghcmF0ZUxpbWl0KCd0cmFpbjonICsgaXAsIDIwLCA2MF8wMDApKSByZXR1cm4gZW5kSnNvbig0MjksIHsgZXJyb3I6ICdUb28gTWFueSBSZXF1ZXN0cycgfSk7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCB1cmwgPSB0eXBlb2YgYm9keT8udXJsID09PSAnc3RyaW5nJyA/IGJvZHkudXJsLnRyaW0oKSA6ICcnO1xuICAgICAgICAgICAgaWYgKCF1cmwgJiYgIUFycmF5LmlzQXJyYXkoYm9keT8uZmlsZXMpKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ1Byb3ZpZGUgdXJsIG9yIGZpbGVzJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICh1cmwpIHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmwpO1xuICAgICAgICAgICAgICAgIGlmICghKHUucHJvdG9jb2wgPT09ICdodHRwOicgfHwgdS5wcm90b2NvbCA9PT0gJ2h0dHBzOicpKSB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQnKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCB1cmwnIH0pO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIExvZyBldmVudFxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnVFJBSU5fUkVRVUVTVCcsIGRldGFpbHM6IHsgaGFzVXJsOiAhIXVybCwgZmlsZUNvdW50OiAoYm9keT8uZmlsZXM/Lmxlbmd0aCkgfHwgMCB9IH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgY29uc3Qgam9iSWQgPSBtYWtlQm90SWQoKHVybCB8fCAnJykgKyBEYXRlLm5vdygpKTtcblxuICAgICAgICAgICAgLy8gU3RhcnQgYmFja2dyb3VuZCBwcm9jZXNzaW5nIChub24tYmxvY2tpbmcpXG4gICAgICAgICAgICAoYXN5bmMgKCkgPT4ge1xuICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGF3YWl0IHByb2Nlc3NUcmFpbkpvYihqb2JJZCwgeyB1cmwsIGZpbGVzOiBBcnJheS5pc0FycmF5KGJvZHk/LmZpbGVzKSA/IGJvZHkuZmlsZXMgOiBbXSB9LCByZXEpO1xuICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3NlY3VyaXR5X2xvZ3MnLCB7XG4gICAgICAgICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFjdGlvbjogJ1RSQUlOX0pPQl9FUlJPUicsIGRldGFpbHM6IHsgam9iSWQsIGVycm9yOiBTdHJpbmcoZT8ubWVzc2FnZSB8fCBlKSB9IH0pLFxuICAgICAgICAgICAgICAgICAgfSwgcmVxKTtcbiAgICAgICAgICAgICAgICB9IGNhdGNoIHt9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pKCk7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMiwgeyBqb2JJZCwgc3RhdHVzOiAncXVldWVkJyB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY29ubmVjdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSk7XG4gICAgICAgICAgICBpZiAoYm9keT8uY2hhbm5lbCAhPT0gJ3dlYnNpdGUnKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdVbnN1cHBvcnRlZCBjaGFubmVsJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IHJhd1VybCA9IChib2R5Py51cmwgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGNvbnN0IGRvbWFpbiA9ICgoKSA9PiB7XG4gICAgICAgICAgICAgIHRyeSB7IHJldHVybiByYXdVcmwgPyBuZXcgVVJMKHJhd1VybCkuaG9zdCA6ICdsb2NhbCc7IH0gY2F0Y2ggeyByZXR1cm4gJ2xvY2FsJzsgfVxuICAgICAgICAgICAgfSkoKTtcblxuICAgICAgICAgICAgLy8gRW5zdXJlIGRvbWFpbiB2ZXJpZmljYXRpb25cbiAgICAgICAgICAgIGNvbnN0IHZyZXMgPSBhd2FpdCBlbnN1cmVEb21haW5WZXJpZmljYXRpb24oZG9tYWluLCByZXEpO1xuICAgICAgICAgICAgaWYgKCF2cmVzLnZlcmlmaWVkKSB7XG4gICAgICAgICAgICAgIC8vIHJldHVybiB2ZXJpZmljYXRpb24gcmVxdWlyZWQgYW5kIGluc3RydWN0aW9uc1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDIsIHsgc3RhdHVzOiAndmVyaWZpY2F0aW9uX3JlcXVpcmVkJywgaW5zdHJ1Y3Rpb25zOiBgQWRkIGEgRE5TIFRYVCByZWNvcmQgb3IgYSBtZXRhIHRhZyB3aXRoIHRva2VuOiAke3ZyZXMudG9rZW59YCwgdG9rZW46IHZyZXMudG9rZW4gfSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGNvbnN0IHNlZWQgPSBkb21haW4gKyAnfCcgKyAocmVxLmhlYWRlcnNbJ2F1dGhvcml6YXRpb24nXSB8fCAnJyk7XG4gICAgICAgICAgICBjb25zdCBib3RJZCA9IG1ha2VCb3RJZChzZWVkKTtcblxuICAgICAgICAgICAgLy8gVXBzZXJ0IGNoYXRib3RfY29uZmlncyAoaWYgUkxTIGFsbG93cyB3aXRoIHVzZXIgdG9rZW4pXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9jaGF0Ym90X2NvbmZpZ3MnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGJvdF9pZDogYm90SWQsIGNoYW5uZWw6ICd3ZWJzaXRlJywgZG9tYWluLCBzZXR0aW5nczoge30gfSksXG4gICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmVzb2x1dGlvbj1tZXJnZS1kdXBsaWNhdGVzJyB9LFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgLy8gQ3JlYXRlIHdpZGdldCB0b2tlbiAoSE1BQyBzaWduZWQpXG4gICAgICAgICAgICBjb25zdCB3aWRnZXRQYXlsb2FkID0geyBib3RJZCwgZG9tYWluLCBpYXQ6IE1hdGguZmxvb3IoRGF0ZS5ub3coKS8xMDAwKSB9O1xuICAgICAgICAgICAgY29uc3Qgd2lkZ2V0U2VjcmV0ID0gcHJvY2Vzcy5lbnYuV0lER0VUX1RPS0VOX1NFQ1JFVCB8fCAnbG9jYWwtd2lkZ2V0LXNlY3JldCc7XG4gICAgICAgICAgICBjb25zdCBoZWFkZXIgPSB7IGFsZzogJ0hTMjU2JywgdHlwOiAnSldUJyB9O1xuICAgICAgICAgICAgY29uc3QgYjY0ID0gKHM6IHN0cmluZykgPT4gQnVmZmVyLmZyb20ocykudG9TdHJpbmcoJ2Jhc2U2NHVybCcpO1xuICAgICAgICAgICAgY29uc3QgdW5zaWduZWQgPSBiNjQoSlNPTi5zdHJpbmdpZnkoaGVhZGVyKSkgKyAnLicgKyBiNjQoSlNPTi5zdHJpbmdpZnkod2lkZ2V0UGF5bG9hZCkpO1xuICAgICAgICAgICAgY29uc3Qgc2lnID0gY3J5cHRvLmNyZWF0ZUhtYWMoJ3NoYTI1NicsIHdpZGdldFNlY3JldCkudXBkYXRlKHVuc2lnbmVkKS5kaWdlc3QoJ2Jhc2U2NHVybCcpO1xuICAgICAgICAgICAgY29uc3Qgd2lkZ2V0VG9rZW4gPSB1bnNpZ25lZCArICcuJyArIHNpZztcblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IGJvdElkLCB3aWRnZXRUb2tlbiB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBXaWRnZXQgY29uZmlnIGVuZHBvaW50OiByZXR1cm5zIGJvdCBzZXR0aW5ncyBmb3Igd2lkZ2V0IGNvbnN1bWVycyAocmVxdWlyZXMgdG9rZW4pXG4gICAgICAgICAgaWYgKHJlcS51cmw/LnN0YXJ0c1dpdGgoJy9hcGkvd2lkZ2V0LWNvbmZpZycpICYmIHJlcS5tZXRob2QgPT09ICdHRVQnKSB7XG4gICAgICAgICAgICBjb25zdCB1cmxPYmogPSBuZXcgVVJMKHJlcS51cmwsICdodHRwOi8vbG9jYWwnKTtcbiAgICAgICAgICAgIGNvbnN0IGJvdElkID0gdXJsT2JqLnNlYXJjaFBhcmFtcy5nZXQoJ2JvdElkJykgfHwgJyc7XG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IHVybE9iai5zZWFyY2hQYXJhbXMuZ2V0KCd0b2tlbicpIHx8ICcnO1xuICAgICAgICAgICAgaWYgKCFib3RJZCkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnTWlzc2luZyBib3RJZCcgfSk7XG4gICAgICAgICAgICBjb25zdCBwYXlsb2FkID0gdmVyaWZ5V2lkZ2V0VG9rZW4odG9rZW4pO1xuICAgICAgICAgICAgaWYgKCFwYXlsb2FkIHx8IHBheWxvYWQuYm90SWQgIT09IGJvdElkKSByZXR1cm4gZW5kSnNvbig0MDEsIHsgZXJyb3I6ICdJbnZhbGlkIHRva2VuJyB9KTtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHIgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9jaGF0Ym90X2NvbmZpZ3M/Ym90X2lkPWVxLicgKyBlbmNvZGVVUklDb21wb25lbnQoYm90SWQpICsgJyZzZWxlY3Q9KicsIHsgbWV0aG9kOiAnR0VUJyB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgICBpZiAoIXIgfHwgIShyIGFzIGFueSkub2spIHJldHVybiBlbmRKc29uKDQwNCwgeyBlcnJvcjogJ05vdCBmb3VuZCcgfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCAociBhcyBSZXNwb25zZSkuanNvbigpLmNhdGNoKCgpID0+IFtdKTtcbiAgICAgICAgICAgICAgY29uc3QgY2ZnID0gQXJyYXkuaXNBcnJheShkYXRhKSAmJiBkYXRhLmxlbmd0aCA+IDAgPyBkYXRhWzBdIDogeyBzZXR0aW5nczoge30gfTtcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IHNldHRpbmdzOiBjZmcgfSk7XG4gICAgICAgICAgICB9IGNhdGNoIChlKSB7IHJldHVybiBlbmRKc29uKDUwMCwgeyBlcnJvcjogJ1NlcnZlciBlcnJvcicgfSk7IH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvdmVyaWZ5LWRvbWFpbicgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCBkb21haW4gPSBTdHJpbmcoYm9keT8uZG9tYWluIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IFN0cmluZyhib2R5Py50b2tlbiB8fCAnJykudHJpbSgpO1xuICAgICAgICAgICAgaWYgKCFkb21haW4gfHwgIXRva2VuKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIGRvbWFpbiBvciB0b2tlbicgfSk7XG5cbiAgICAgICAgICAgIC8vIFRyeSBtdWx0aXBsZSBjYW5kaWRhdGUgVVJMcyBmb3IgdmVyaWZpY2F0aW9uIChyb290LCBpbmRleC5odG1sLCB3ZWxsLWtub3duKVxuICAgICAgICAgICAgY29uc3QgY2FuZGlkYXRlcyA9IFtcbiAgICAgICAgICAgICAgYGh0dHBzOi8vJHtkb21haW59YCxcbiAgICAgICAgICAgICAgYGh0dHA6Ly8ke2RvbWFpbn1gLFxuICAgICAgICAgICAgICBgaHR0cHM6Ly8ke2RvbWFpbn0vaW5kZXguaHRtbGAsXG4gICAgICAgICAgICAgIGBodHRwOi8vJHtkb21haW59L2luZGV4Lmh0bWxgLFxuICAgICAgICAgICAgICBgaHR0cHM6Ly8ke2RvbWFpbn0vLndlbGwta25vd24vbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uYCxcbiAgICAgICAgICAgICAgYGh0dHA6Ly8ke2RvbWFpbn0vLndlbGwta25vd24vbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uYCxcbiAgICAgICAgICAgIF07XG5cbiAgICAgICAgICAgIC8vIEJ1aWxkIHJvYnVzdCByZWdleCB0byBtYXRjaCBtZXRhIHRhZyBpbiBhbnkgYXR0cmlidXRlIG9yZGVyXG4gICAgICAgICAgICBjb25zdCBlc2MgPSAoczogc3RyaW5nKSA9PiBzLnJlcGxhY2UoL1stL1xcXFxeJCorPy4oKXxbXFxde31dL2csICdcXFxcJCYnKTtcbiAgICAgICAgICAgIGNvbnN0IHRFc2MgPSBlc2ModG9rZW4pO1xuICAgICAgICAgICAgY29uc3QgbWV0YVJlID0gbmV3IFJlZ0V4cChgPG1ldGFbXj5dKig/Om5hbWVcXHMqPVxccypbJ1xcXCJdbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uWydcXFwiXVtePl0qY29udGVudFxccyo9XFxzKlsnXFxcIl0ke3RFc2N9WydcXFwiXXxjb250ZW50XFxzKj1cXHMqWydcXFwiXSR7dEVzY31bJ1xcXCJdW14+XSpuYW1lXFxzKj1cXHMqWydcXFwiXW5leGFib3QtZG9tYWluLXZlcmlmaWNhdGlvblsnXFxcIl0pYCwgJ2knKTtcbiAgICAgICAgICAgIGNvbnN0IHBsYWluUmUgPSBuZXcgUmVnRXhwKGBuZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25bOj1dXFxzKiR7dEVzY31gLCAnaScpO1xuXG4gICAgICAgICAgICBsZXQgZm91bmQgPSBmYWxzZTtcbiAgICAgICAgICAgIGZvciAoY29uc3QgdXJsIG9mIGNhbmRpZGF0ZXMpIHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgZmV0Y2godXJsLCB7IGhlYWRlcnM6IHsgJ1VzZXItQWdlbnQnOiAnTmV4YUJvdFZlcmlmaWVyLzEuMCcgfSB9KTtcbiAgICAgICAgICAgICAgICBpZiAoIXIgfHwgIXIub2spIGNvbnRpbnVlO1xuICAgICAgICAgICAgICAgIGNvbnN0IHRleHQgPSBhd2FpdCByLnRleHQoKTtcbiAgICAgICAgICAgICAgICBpZiAobWV0YVJlLnRlc3QodGV4dCkgfHwgcGxhaW5SZS50ZXN0KHRleHQpKSB7XG4gICAgICAgICAgICAgICAgICBmb3VuZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICAvLyBpZ25vcmUgYW5kIHRyeSBuZXh0IGNhbmRpZGF0ZVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghZm91bmQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ1ZlcmlmaWNhdGlvbiB0b2tlbiBub3QgZm91bmQgb24gc2l0ZScgfSk7XG5cbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2RvbWFpbnMnLCB7XG4gICAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBkb21haW4sIHZlcmlmaWVkOiB0cnVlLCB2ZXJpZmllZF9hdDogbmV3IERhdGUoKS50b0lTT1N0cmluZygpIH0pLFxuICAgICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmVzb2x1dGlvbj1tZXJnZS1kdXBsaWNhdGVzJywgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9LFxuICAgICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgfSBjYXRjaCB7fVxuXG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgb2s6IHRydWUsIGRvbWFpbiB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvbGF1bmNoJyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKTtcbiAgICAgICAgICAgIGNvbnN0IGJvdElkID0gU3RyaW5nKGJvZHk/LmJvdElkIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBpZiAoIWJvdElkKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIGJvdElkJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGN1c3RvbWl6YXRpb24gPSBib2R5Py5jdXN0b21pemF0aW9uIHx8IHt9O1xuXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9jaGF0Ym90X2NvbmZpZ3M/Ym90X2lkPWVxLicgKyBlbmNvZGVVUklDb21wb25lbnQoYm90SWQpLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BBVENIJyxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBzZXR0aW5nczogY3VzdG9taXphdGlvbiB9KSxcbiAgICAgICAgICAgICAgaGVhZGVyczogeyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLCBQcmVmZXI6ICdyZXR1cm49cmVwcmVzZW50YXRpb24nIH0sXG4gICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuXG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgYm90SWQgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2NoYXQnICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgaXAgPSAocmVxLmhlYWRlcnNbJ3gtZm9yd2FyZGVkLWZvciddIGFzIHN0cmluZykgfHwgcmVxLnNvY2tldC5yZW1vdGVBZGRyZXNzIHx8ICdpcCc7XG4gICAgICAgICAgICBpZiAoIXJhdGVMaW1pdCgnY2hhdDonICsgaXAsIDYwLCA2MF8wMDApKSByZXR1cm4gZW5kSnNvbig0MjksIHsgZXJyb3I6ICdUb28gTWFueSBSZXF1ZXN0cycgfSk7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCBtZXNzYWdlID0gU3RyaW5nKGJvZHk/Lm1lc3NhZ2UgfHwgJycpLnNsaWNlKDAsIDIwMDApO1xuICAgICAgICAgICAgaWYgKCFtZXNzYWdlKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdFbXB0eSBtZXNzYWdlJyB9KTtcblxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnQ0hBVCcsIGRldGFpbHM6IHsgbGVuOiBtZXNzYWdlLmxlbmd0aCB9IH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgY29uc3QgcmVwbHkgPSBcIkknbSBzdGlsbCBsZWFybmluZywgYnV0IG91ciB0ZWFtIHdpbGwgZ2V0IGJhY2sgdG8geW91IHNvb24uXCI7XG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgcmVwbHkgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gQ3VzdG9tIGVtYWlsIHZlcmlmaWNhdGlvbjogc2VuZCBlbWFpbFxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9zZW5kLXZlcmlmeScgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBpcCA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtZm9yJ10gYXMgc3RyaW5nKSB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJ2lwJztcbiAgICAgICAgICAgIGlmICghcmF0ZUxpbWl0KCd2ZXJpZnk6JyArIGlwLCA1LCA2MCo2MF8wMDApKSByZXR1cm4gZW5kSnNvbig0MjksIHsgZXJyb3I6ICdUb28gTWFueSBSZXF1ZXN0cycgfSk7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCBlbWFpbCA9IFN0cmluZyhib2R5Py5lbWFpbCB8fCAnJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgICBpZiAoIS9eW15cXHNAXStAW15cXHNAXStcXC5bXlxcc0BdKyQvLnRlc3QoZW1haWwpKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdJbnZhbGlkIGVtYWlsJyB9KTtcblxuICAgICAgICAgICAgLy8gVmVyaWZ5IGF1dGhlbnRpY2F0ZWQgdXNlciBtYXRjaGVzIGVtYWlsXG4gICAgICAgICAgICBjb25zdCB1cmVzID0gYXdhaXQgc3VwYWJhc2VGZXRjaCgnL2F1dGgvdjEvdXNlcicsIHsgbWV0aG9kOiAnR0VUJyB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgaWYgKCF1cmVzIHx8ICEodXJlcyBhcyBhbnkpLm9rKSByZXR1cm4gZW5kSnNvbig0MDEsIHsgZXJyb3I6ICdVbmF1dGhvcml6ZWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgdXNlciA9IGF3YWl0ICh1cmVzIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICBpZiAoIXVzZXIgfHwgdXNlci5lbWFpbD8udG9Mb3dlckNhc2UoKSAhPT0gZW1haWwpIHJldHVybiBlbmRKc29uKDQwMywgeyBlcnJvcjogJ0VtYWlsIG1pc21hdGNoJyB9KTtcblxuICAgICAgICAgICAgY29uc3QgdG9rZW4gPSBjcnlwdG8ucmFuZG9tQnl0ZXMoMzIpLnRvU3RyaW5nKCdiYXNlNjR1cmwnKTtcbiAgICAgICAgICAgIGNvbnN0IHNlY3JldCA9IHByb2Nlc3MuZW52LkVNQUlMX1RPS0VOX1NFQ1JFVCB8fCAnbG9jYWwtc2VjcmV0JztcbiAgICAgICAgICAgIGNvbnN0IHRva2VuSGFzaCA9IGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUodG9rZW4gKyBzZWNyZXQpLmRpZ2VzdCgnYmFzZTY0Jyk7XG4gICAgICAgICAgICBjb25zdCBleHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIDEwMDAgKiA2MCAqIDYwICogMjQpLnRvSVNPU3RyaW5nKCk7XG5cbiAgICAgICAgICAgIC8vIFN0b3JlIHRva2VuIGhhc2ggKG5vdCByYXcgdG9rZW4pXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9lbWFpbF92ZXJpZmljYXRpb25zJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXNvbHV0aW9uPW1lcmdlLWR1cGxpY2F0ZXMnIH0sXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdXNlcl9pZDogdXNlci5pZCwgZW1haWwsIHRva2VuX2hhc2g6IHRva2VuSGFzaCwgZXhwaXJlc19hdDogZXhwaXJlcywgdXNlZF9hdDogbnVsbCB9KSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIC8vIFNlbmQgZW1haWwgdmlhIFNNVFBcbiAgICAgICAgICAgIGNvbnN0IGhvc3QgPSBwcm9jZXNzLmVudi5TTVRQX0hPU1Q7XG4gICAgICAgICAgICBjb25zdCBwb3J0ID0gTnVtYmVyKHByb2Nlc3MuZW52LlNNVFBfUE9SVCB8fCA1ODcpO1xuICAgICAgICAgICAgY29uc3QgdXNlclNtdHAgPSBwcm9jZXNzLmVudi5TTVRQX1VTRVI7XG4gICAgICAgICAgICBjb25zdCBwYXNzU210cCA9IHByb2Nlc3MuZW52LlNNVFBfUEFTUztcbiAgICAgICAgICAgIGNvbnN0IGZyb20gPSBwcm9jZXNzLmVudi5FTUFJTF9GUk9NIHx8ICdOZXhhQm90IDxuby1yZXBseUBuZXhhYm90LmFpPic7XG4gICAgICAgICAgICBjb25zdCBhcHBVcmwgPSBwcm9jZXNzLmVudi5BUFBfVVJMIHx8ICdodHRwOi8vbG9jYWxob3N0OjMwMDAnO1xuICAgICAgICAgICAgY29uc3QgdmVyaWZ5VXJsID0gYCR7YXBwVXJsfS9hcGkvdmVyaWZ5LWVtYWlsP3Rva2VuPSR7dG9rZW59YDtcblxuICAgICAgICAgICAgaWYgKGhvc3QgJiYgdXNlclNtdHAgJiYgcGFzc1NtdHApIHtcbiAgICAgICAgICAgICAgY29uc3QgdHJhbnNwb3J0ZXIgPSBub2RlbWFpbGVyLmNyZWF0ZVRyYW5zcG9ydCh7IGhvc3QsIHBvcnQsIHNlY3VyZTogcG9ydCA9PT0gNDY1LCBhdXRoOiB7IHVzZXI6IHVzZXJTbXRwLCBwYXNzOiBwYXNzU210cCB9IH0pO1xuICAgICAgICAgICAgICBjb25zdCBodG1sID0gYFxuICAgICAgICAgICAgICAgIDx0YWJsZSBzdHlsZT1cIndpZHRoOjEwMCU7YmFja2dyb3VuZDojZjZmOGZiO3BhZGRpbmc6MjRweDtmb250LWZhbWlseTpJbnRlcixTZWdvZSBVSSxBcmlhbCxzYW5zLXNlcmlmO2NvbG9yOiMwZjE3MmFcIj5cbiAgICAgICAgICAgICAgICAgIDx0cj48dGQgYWxpZ249XCJjZW50ZXJcIj5cbiAgICAgICAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPVwibWF4LXdpZHRoOjU2MHB4O3dpZHRoOjEwMCU7YmFja2dyb3VuZDojZmZmZmZmO2JvcmRlcjoxcHggc29saWQgI2U1ZTdlYjtib3JkZXItcmFkaXVzOjEycHg7b3ZlcmZsb3c6aGlkZGVuXCI+XG4gICAgICAgICAgICAgICAgICAgICAgPHRyPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPVwiYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsIzYzNjZmMSwjOGI1Y2Y2KTtwYWRkaW5nOjIwcHg7Y29sb3I6I2ZmZjtmb250LXNpemU6MThweDtmb250LXdlaWdodDo3MDBcIj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgTmV4YUJvdFxuICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICAgIDx0cj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT1cInBhZGRpbmc6MjRweFwiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8aDEgc3R5bGU9XCJtYXJnaW46MCAwIDhweCAwO2ZvbnQtc2l6ZToyMHB4O2NvbG9yOiMxMTE4MjdcIj5Db25maXJtIHlvdXIgZW1haWw8L2gxPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8cCBzdHlsZT1cIm1hcmdpbjowIDAgMTZweCAwO2NvbG9yOiMzNzQxNTE7bGluZS1oZWlnaHQ6MS41XCI+SGksIHBsZWFzZSBjb25maXJtIHlvdXIgZW1haWwgYWRkcmVzcyB0byBzZWN1cmUgeW91ciBOZXhhQm90IGFjY291bnQgYW5kIGNvbXBsZXRlIHNldHVwLjwvcD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgPHAgc3R5bGU9XCJtYXJnaW46MCAwIDE2cHggMDtjb2xvcjojMzc0MTUxO2xpbmUtaGVpZ2h0OjEuNVwiPlRoaXMgbGluayBleHBpcmVzIGluIDI0IGhvdXJzLjwvcD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgPGEgaHJlZj1cIiR7dmVyaWZ5VXJsfVwiIHN0eWxlPVwiZGlzcGxheTppbmxpbmUtYmxvY2s7YmFja2dyb3VuZDojNjM2NmYxO2NvbG9yOiNmZmY7dGV4dC1kZWNvcmF0aW9uOm5vbmU7cGFkZGluZzoxMHB4IDE2cHg7Ym9yZGVyLXJhZGl1czo4cHg7Zm9udC13ZWlnaHQ6NjAwXCI+VmVyaWZ5IEVtYWlsPC9hPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8cCBzdHlsZT1cIm1hcmdpbjoxNnB4IDAgMCAwO2NvbG9yOiM2YjcyODA7Zm9udC1zaXplOjEycHhcIj5JZiB0aGUgYnV0dG9uIGRvZXNuXHUyMDE5dCB3b3JrLCBjb3B5IGFuZCBwYXN0ZSB0aGlzIGxpbmsgaW50byB5b3VyIGJyb3dzZXI6PGJyPiR7dmVyaWZ5VXJsfTwvcD5cbiAgICAgICAgICAgICAgICAgICAgICAgIDwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICAgICAgICA8dHI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9XCJwYWRkaW5nOjE2cHggMjRweDtjb2xvcjojNmI3MjgwO2ZvbnQtc2l6ZToxMnB4O2JvcmRlci10b3A6MXB4IHNvbGlkICNlNWU3ZWJcIj5cdTAwQTkgJHtuZXcgRGF0ZSgpLmdldEZ1bGxZZWFyKCl9IE5leGFCb3QuIEFsbCByaWdodHMgcmVzZXJ2ZWQuPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICA8L3RhYmxlPlxuICAgICAgICAgICAgICAgICAgPC90ZD48L3RyPlxuICAgICAgICAgICAgICAgIDwvdGFibGU+YDtcbiAgICAgICAgICAgICAgYXdhaXQgdHJhbnNwb3J0ZXIuc2VuZE1haWwoeyB0bzogZW1haWwsIGZyb20sIHN1YmplY3Q6ICdWZXJpZnkgeW91ciBlbWFpbCBmb3IgTmV4YUJvdCcsIGh0bWwgfSk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBpZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgIT09ICdwcm9kdWN0aW9uJykge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUud2FybignW2VtYWlsXSBTTVRQIG5vdCBjb25maWd1cmVkOyB2ZXJpZmljYXRpb24gVVJMOicsIHZlcmlmeVVybCk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IG9rOiB0cnVlIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIC8vIFZlcmlmeSBsaW5rIGVuZHBvaW50XG4gICAgICAgICAgaWYgKHJlcS51cmw/LnN0YXJ0c1dpdGgoJy9hcGkvdmVyaWZ5LWVtYWlsJykgJiYgcmVxLm1ldGhvZCA9PT0gJ0dFVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IHVybE9iaiA9IG5ldyBVUkwocmVxLnVybCwgJ2h0dHA6Ly9sb2NhbCcpO1xuICAgICAgICAgICAgY29uc3QgdG9rZW4gPSB1cmxPYmouc2VhcmNoUGFyYW1zLmdldCgndG9rZW4nKSB8fCAnJztcbiAgICAgICAgICAgIGlmICghdG9rZW4pIHtcbiAgICAgICAgICAgICAgcmVzLnN0YXR1c0NvZGUgPSA0MDA7XG4gICAgICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0NvbnRlbnQtVHlwZScsICd0ZXh0L2h0bWwnKTtcbiAgICAgICAgICAgICAgcmV0dXJuIHJlcy5lbmQoJzxwPkludmFsaWQgdG9rZW48L3A+Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCBzZWNyZXQgPSBwcm9jZXNzLmVudi5FTUFJTF9UT0tFTl9TRUNSRVQgfHwgJ2xvY2FsLXNlY3JldCc7XG4gICAgICAgICAgICBjb25zdCB0b2tlbkhhc2ggPSBjcnlwdG8uY3JlYXRlSGFzaCgnc2hhMjU2JykudXBkYXRlKHRva2VuICsgc2VjcmV0KS5kaWdlc3QoJ2Jhc2U2NCcpO1xuXG4gICAgICAgICAgICAvLyBQcmVmZXIgUlBDIChzZWN1cml0eSBkZWZpbmVyKSBvbiBEQjogdmVyaWZ5X2VtYWlsX2hhc2gocF9oYXNoIHRleHQpXG4gICAgICAgICAgICBsZXQgb2sgPSBmYWxzZTtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHJwYyA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3JwYy92ZXJpZnlfZW1haWxfaGFzaCcsIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHBfaGFzaDogdG9rZW5IYXNoIH0pLFxuICAgICAgICAgICAgICB9LCByZXEpO1xuICAgICAgICAgICAgICBpZiAocnBjICYmIChycGMgYXMgYW55KS5vaykgb2sgPSB0cnVlO1xuICAgICAgICAgICAgfSBjYXRjaCB7fVxuXG4gICAgICAgICAgICBpZiAoIW9rKSB7XG4gICAgICAgICAgICAgIGNvbnN0IG5vd0lzbyA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZW1haWxfdmVyaWZpY2F0aW9ucz90b2tlbl9oYXNoPWVxLicgKyBlbmNvZGVVUklDb21wb25lbnQodG9rZW5IYXNoKSArICcmdXNlZF9hdD1pcy5udWxsJmV4cGlyZXNfYXQ9Z3QuJyArIGVuY29kZVVSSUNvbXBvbmVudChub3dJc28pLCB7XG4gICAgICAgICAgICAgICAgbWV0aG9kOiAnUEFUQ0gnLFxuICAgICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdXNlZF9hdDogbm93SXNvIH0pLFxuICAgICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmV0dXJuPXJlcHJlc2VudGF0aW9uJyB9LFxuICAgICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXMuc3RhdHVzQ29kZSA9IDIwMDtcbiAgICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0NvbnRlbnQtVHlwZScsICd0ZXh0L2h0bWwnKTtcbiAgICAgICAgICAgIHJldHVybiByZXMuZW5kKGA8IWRvY3R5cGUgaHRtbD48bWV0YSBodHRwLWVxdWl2PVwicmVmcmVzaFwiIGNvbnRlbnQ9XCIyO3VybD0vXCI+PHN0eWxlPmJvZHl7Zm9udC1mYW1pbHk6SW50ZXIsU2Vnb2UgVUksQXJpYWwsc2Fucy1zZXJpZjtiYWNrZ3JvdW5kOiNmNmY4ZmI7Y29sb3I6IzExMTgyNztkaXNwbGF5OmdyaWQ7cGxhY2UtaXRlbXM6Y2VudGVyO2hlaWdodDoxMDB2aH08L3N0eWxlPjxkaXY+PGgxPlx1MjcwNSBFbWFpbCB2ZXJpZmllZDwvaDE+PHA+WW91IGNhbiBjbG9zZSB0aGlzIHRhYi48L3A+PC9kaXY+YCk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDA0LCB7IGVycm9yOiAnTm90IEZvdW5kJyB9KTtcbiAgICAgICAgfSBjYXRjaCAoZTogYW55KSB7XG4gICAgICAgICAgcmV0dXJuIGVuZEpzb24oNTAwLCB7IGVycm9yOiAnU2VydmVyIEVycm9yJyB9KTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSxcbiAgfTtcbn1cbiJdLAogICJtYXBwaW5ncyI6ICI7QUFBNk0sU0FBUyxvQkFBb0I7QUFDMU8sT0FBTyxXQUFXO0FBQ2xCLE9BQU8sVUFBVTtBQUNqQixTQUFTLHVCQUF1Qjs7O0FDRmhDLE9BQU8sWUFBWTtBQUNuQixPQUFPLGdCQUFnQjtBQUd2QixlQUFlLFVBQVUsS0FBVSxRQUFRLE9BQU8sS0FBSztBQUNyRCxTQUFPLElBQUksUUFBYSxDQUFDLFNBQVMsV0FBVztBQUMzQyxVQUFNLFNBQW1CLENBQUM7QUFDMUIsUUFBSSxPQUFPO0FBQ1gsUUFBSSxHQUFHLFFBQVEsQ0FBQyxNQUFjO0FBQzVCLGNBQVEsRUFBRTtBQUNWLFVBQUksT0FBTyxPQUFPO0FBQ2hCLGVBQU8sSUFBSSxN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
