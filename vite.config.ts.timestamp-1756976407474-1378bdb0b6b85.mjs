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
              const nowIso = (/* @__PURE__ */ new Date()).toISOString();
              const q = `/rest/v1/domain_verifications?domain=eq.${encodeURIComponent(domain)}&token=eq.${encodeURIComponent(token)}&expires_at=gt.${encodeURIComponent(nowIso)}&used_at=is.null`;
              const vr = await supabaseFetch(q, { method: "GET" }, req).catch(() => null);
              if (!vr || !vr.ok) return endJson(400, { error: "Invalid or expired token" });
              const darr = await vr.json().catch(() => []);
              if (!Array.isArray(darr) || darr.length === 0) return endJson(400, { error: "Invalid or expired token" });
              const id = darr[0].id;
              await supabaseFetch("/rest/v1/domain_verifications?id=eq." + encodeURIComponent(id), {
                method: "PATCH",
                body: JSON.stringify({ used_at: (/* @__PURE__ */ new Date()).toISOString() }),
                headers: { "Content-Type": "application/json" }
              }, req).catch(() => null);
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL3NlcnZlci9hcGkudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGVcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9hcHAvY29kZS92aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vYXBwL2NvZGUvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tIFwidml0ZVwiO1xuaW1wb3J0IHJlYWN0IGZyb20gXCJAdml0ZWpzL3BsdWdpbi1yZWFjdC1zd2NcIjtcbmltcG9ydCBwYXRoIGZyb20gXCJwYXRoXCI7XG5pbXBvcnQgeyBjb21wb25lbnRUYWdnZXIgfSBmcm9tIFwibG92YWJsZS10YWdnZXJcIjtcbmltcG9ydCB7IHNlcnZlckFwaVBsdWdpbiB9IGZyb20gXCIuL3NyYy9zZXJ2ZXIvYXBpXCI7XG5cbi8vIGh0dHBzOi8vdml0ZWpzLmRldi9jb25maWcvXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiAoe1xuICBzZXJ2ZXI6IHtcbiAgICBob3N0OiBcIjo6XCIsXG4gICAgcG9ydDogODA4MCxcbiAgfSxcbiAgcGx1Z2luczogW1xuICAgIHJlYWN0KCksXG4gICAgbW9kZSA9PT0gJ2RldmVsb3BtZW50JyAmJlxuICAgIGNvbXBvbmVudFRhZ2dlcigpLFxuICAgIHNlcnZlckFwaVBsdWdpbigpLFxuICBdLmZpbHRlcihCb29sZWFuKSxcbiAgcmVzb2x2ZToge1xuICAgIGFsaWFzOiB7XG4gICAgICBcIkBcIjogcGF0aC5yZXNvbHZlKF9fZGlybmFtZSwgXCIuL3NyY1wiKSxcbiAgICB9LFxuICB9LFxufSkpO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGUvc3JjL3NlcnZlclwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2FwcC9jb2RlL3NyYy9zZXJ2ZXIvYXBpLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9hcHAvY29kZS9zcmMvc2VydmVyL2FwaS50c1wiO2ltcG9ydCB0eXBlIHsgUGx1Z2luIH0gZnJvbSAndml0ZSc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5pbXBvcnQgbm9kZW1haWxlciBmcm9tICdub2RlbWFpbGVyJztcblxuLy8gU21hbGwgSlNPTiBib2R5IHBhcnNlciB3aXRoIHNpemUgbGltaXRcbmFzeW5jIGZ1bmN0aW9uIHBhcnNlSnNvbihyZXE6IGFueSwgbGltaXQgPSAxMDI0ICogMTAwKSB7XG4gIHJldHVybiBuZXcgUHJvbWlzZTxhbnk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICBjb25zdCBjaHVua3M6IEJ1ZmZlcltdID0gW107XG4gICAgbGV0IHNpemUgPSAwO1xuICAgIHJlcS5vbignZGF0YScsIChjOiBCdWZmZXIpID0+IHtcbiAgICAgIHNpemUgKz0gYy5sZW5ndGg7XG4gICAgICBpZiAoc2l6ZSA+IGxpbWl0KSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1BheWxvYWQgdG9vIGxhcmdlJykpO1xuICAgICAgICByZXEuZGVzdHJveSgpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjaHVua3MucHVzaChjKTtcbiAgICB9KTtcbiAgICByZXEub24oJ2VuZCcsICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJhdyA9IEJ1ZmZlci5jb25jYXQoY2h1bmtzKS50b1N0cmluZygndXRmOCcpO1xuICAgICAgICBjb25zdCBqc29uID0gcmF3ID8gSlNPTi5wYXJzZShyYXcpIDoge307XG4gICAgICAgIHJlc29sdmUoanNvbik7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHJlamVjdChlKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICByZXEub24oJ2Vycm9yJywgcmVqZWN0KTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIGpzb24ocmVzOiBhbnksIHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnksIGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7fSkge1xuICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7XG4gIHJlcy5zdGF0dXNDb2RlID0gc3RhdHVzO1xuICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCcpO1xuICByZXMuc2V0SGVhZGVyKCdYLUNvbnRlbnQtVHlwZS1PcHRpb25zJywgJ25vc25pZmYnKTtcbiAgcmVzLnNldEhlYWRlcignUmVmZXJyZXItUG9saWN5JywgJ25vLXJlZmVycmVyJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtRnJhbWUtT3B0aW9ucycsICdERU5ZJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtWFNTLVByb3RlY3Rpb24nLCAnMTsgbW9kZT1ibG9jaycpO1xuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhoZWFkZXJzKSkgcmVzLnNldEhlYWRlcihrLCB2KTtcbiAgcmVzLmVuZChib2R5KTtcbn1cblxuY29uc3QgaXNIdHRwcyA9IChyZXE6IGFueSkgPT4ge1xuICBjb25zdCBwcm90byA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtcHJvdG8nXSBhcyBzdHJpbmcpIHx8ICcnO1xuICByZXR1cm4gcHJvdG8gPT09ICdodHRwcycgfHwgKHJlcS5zb2NrZXQgJiYgKHJlcS5zb2NrZXQgYXMgYW55KS5lbmNyeXB0ZWQpO1xufTtcblxuZnVuY3Rpb24gcmVxdWlyZUVudihuYW1lOiBzdHJpbmcpIHtcbiAgY29uc3QgdiA9IHByb2Nlc3MuZW52W25hbWVdO1xuICBpZiAoIXYpIHRocm93IG5ldyBFcnJvcihgJHtuYW1lfSBub3Qgc2V0YCk7XG4gIHJldHVybiB2O1xufVxuXG5hc3luYyBmdW5jdGlvbiBzdXBhYmFzZUZldGNoKHBhdGg6IHN0cmluZywgb3B0aW9uczogYW55LCByZXE6IGFueSkge1xuICBjb25zdCBiYXNlID0gcmVxdWlyZUVudignU1VQQUJBU0VfVVJMJyk7XG4gIGNvbnN0IGFub24gPSByZXF1aXJlRW52KCdTVVBBQkFTRV9BTk9OX0tFWScpO1xuICBjb25zdCB0b2tlbiA9IChyZXEuaGVhZGVyc1snYXV0aG9yaXphdGlvbiddIGFzIHN0cmluZykgfHwgJyc7XG4gIGNvbnN0IGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7XG4gICAgYXBpa2V5OiBhbm9uLFxuICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsXG4gIH07XG4gIGlmICh0b2tlbikgaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gdG9rZW47XG4gIHJldHVybiBmZXRjaChgJHtiYXNlfSR7cGF0aH1gLCB7IC4uLm9wdGlvbnMsIGhlYWRlcnM6IHsgLi4uaGVhZGVycywgLi4uKG9wdGlvbnM/LmhlYWRlcnMgfHwge30pIH0gfSk7XG59XG5cbmZ1bmN0aW9uIG1ha2VCb3RJZChzZWVkOiBzdHJpbmcpIHtcbiAgcmV0dXJuICdib3RfJyArIGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUoc2VlZCkuZGlnZXN0KCdiYXNlNjR1cmwnKS5zbGljZSgwLCAyMik7XG59XG5cbi8vIEV4dHJhY3QgdmlzaWJsZSB0ZXh0IGZyb20gSFRNTCAobmFpdmUpXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21IdG1sKGh0bWw6IHN0cmluZykge1xuICAvLyByZW1vdmUgc2NyaXB0cy9zdHlsZXNcbiAgY29uc3Qgd2l0aG91dFNjcmlwdHMgPSBodG1sLnJlcGxhY2UoLzxzY3JpcHRbXFxzXFxTXSo/PltcXHNcXFNdKj88XFwvc2NyaXB0Pi9naSwgJyAnKTtcbiAgY29uc3Qgd2l0aG91dFN0eWxlcyA9IHdpdGhvdXRTY3JpcHRzLnJlcGxhY2UoLzxzdHlsZVtcXHNcXFNdKj8+W1xcc1xcU10qPzxcXC9zdHlsZT4vZ2ksICcgJyk7XG4gIC8vIHJlbW92ZSB0YWdzXG4gIGNvbnN0IHRleHQgPSB3aXRob3V0U3R5bGVzLnJlcGxhY2UoLzxbXj5dKz4vZywgJyAnKTtcbiAgLy8gZGVjb2RlIEhUTUwgZW50aXRpZXMgKGJhc2ljKVxuICByZXR1cm4gdGV4dC5yZXBsYWNlKC8mbmJzcDt8JmFtcDt8Jmx0O3wmZ3Q7fCZxdW90O3wmIzM5Oy9nLCAocykgPT4ge1xuICAgIHN3aXRjaCAocykge1xuICAgICAgY2FzZSAnJm5ic3A7JzogcmV0dXJuICcgJztcbiAgICAgIGNhc2UgJyZhbXA7JzogcmV0dXJuICcmJztcbiAgICAgIGNhc2UgJyZsdDsnOiByZXR1cm4gJzwnO1xuICAgICAgY2FzZSAnJmd0Oyc6IHJldHVybiAnPic7XG4gICAgICBjYXNlICcmcXVvdDsnOiByZXR1cm4gJ1wiJztcbiAgICAgIGNhc2UgJyYjMzk7JzogcmV0dXJuICdcXCcnO1xuICAgICAgZGVmYXVsdDogcmV0dXJuIHM7XG4gICAgfVxuICB9KS5yZXBsYWNlKC9cXHMrL2csICcgJykudHJpbSgpO1xufVxuXG5hc3luYyBmdW5jdGlvbiB0cnlGZXRjaFVybFRleHQodTogc3RyaW5nKSB7XG4gIHRyeSB7XG4gICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2godSwgeyBoZWFkZXJzOiB7ICdVc2VyLUFnZW50JzogJ05leGFCb3RDcmF3bGVyLzEuMCcgfSB9KTtcbiAgICBpZiAoIXJlcy5vaykgcmV0dXJuICcnO1xuICAgIGNvbnN0IGh0bWwgPSBhd2FpdCByZXMudGV4dCgpO1xuICAgIHJldHVybiBleHRyYWN0VGV4dEZyb21IdG1sKGh0bWwpO1xuICB9IGNhdGNoIChlKSB7XG4gICAgcmV0dXJuICcnO1xuICB9XG59XG5cbmZ1bmN0aW9uIGNodW5rVGV4dCh0ZXh0OiBzdHJpbmcsIG1heENoYXJzID0gMTUwMCkge1xuICBjb25zdCBwYXJhZ3JhcGhzID0gdGV4dC5zcGxpdCgvXFxufFxccnxcXC58XFwhfFxcPy8pLm1hcChwID0+IHAudHJpbSgpKS5maWx0ZXIoQm9vbGVhbik7XG4gIGNvbnN0IGNodW5rczogc3RyaW5nW10gPSBbXTtcbiAgbGV0IGN1ciA9ICcnO1xuICBmb3IgKGNvbnN0IHAgb2YgcGFyYWdyYXBocykge1xuICAgIGlmICgoY3VyICsgJyAnICsgcCkubGVuZ3RoID4gbWF4Q2hhcnMpIHtcbiAgICAgIGlmIChjdXIpIHsgY2h1bmtzLnB1c2goY3VyLnRyaW0oKSk7IGN1ciA9IHA7IH1cbiAgICAgIGVsc2UgeyBjaHVua3MucHVzaChwLnNsaWNlKDAsIG1heENoYXJzKSk7IGN1ciA9IHAuc2xpY2UobWF4Q2hhcnMpOyB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGN1ciA9IChjdXIgKyAnICcgKyBwKS50cmltKCk7XG4gICAgfVxuICB9XG4gIGlmIChjdXIpIGNodW5rcy5wdXNoKGN1ci50cmltKCkpO1xuICByZXR1cm4gY2h1bmtzO1xufVxuXG5hc3luYyBmdW5jdGlvbiBlbWJlZENodW5rcyhjaHVua3M6IHN0cmluZ1tdKTogUHJvbWlzZTxudW1iZXJbXVtdIHwgbnVsbD4ge1xuICBjb25zdCBrZXkgPSBwcm9jZXNzLmVudi5PUEVOQUlfQVBJX0tFWTtcbiAgaWYgKCFrZXkpIHJldHVybiBudWxsO1xuICB0cnkge1xuICAgIGNvbnN0IHJlc3AgPSBhd2FpdCBmZXRjaCgnaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS92MS9lbWJlZGRpbmdzJywge1xuICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICBoZWFkZXJzOiB7ICdBdXRob3JpemF0aW9uJzogYEJlYXJlciAke2tleX1gLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGlucHV0OiBjaHVua3MsIG1vZGVsOiAndGV4dC1lbWJlZGRpbmctMy1zbWFsbCcgfSksXG4gICAgfSk7XG4gICAgaWYgKCFyZXNwLm9rKSByZXR1cm4gbnVsbDtcbiAgICBjb25zdCBqID0gYXdhaXQgcmVzcC5qc29uKCk7XG4gICAgaWYgKCFqLmRhdGEpIHJldHVybiBudWxsO1xuICAgIHJldHVybiBqLmRhdGEubWFwKChkOiBhbnkpID0+IGQuZW1iZWRkaW5nIGFzIG51bWJlcltdKTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHByb2Nlc3NUcmFpbkpvYihqb2JJZDogc3RyaW5nLCBib2R5OiBhbnksIHJlcTogYW55KSB7XG4gIGNvbnN0IHVybCA9IGJvZHkudXJsIHx8ICcnO1xuICBjb25zdCBmaWxlczogc3RyaW5nW10gPSBBcnJheS5pc0FycmF5KGJvZHkuZmlsZXMpID8gYm9keS5maWxlcyA6IFtdO1xuICBjb25zdCBib3RTZWVkID0gKHVybCB8fCBmaWxlcy5qb2luKCcsJykpICsgRGF0ZS5ub3coKTtcbiAgY29uc3QgYm90SWQgPSBtYWtlQm90SWQoYm90U2VlZCk7XG5cbiAgLy8gZ2F0aGVyIHRleHRzXG4gIGNvbnN0IGRvY3M6IHsgc291cmNlOiBzdHJpbmc7IGNvbnRlbnQ6IHN0cmluZyB9W10gPSBbXTtcblxuICBpZiAodXJsKSB7XG4gICAgY29uc3QgdGV4dCA9IGF3YWl0IHRyeUZldGNoVXJsVGV4dCh1cmwpO1xuICAgIGlmICh0ZXh0KSBkb2NzLnB1c2goeyBzb3VyY2U6IHVybCwgY29udGVudDogdGV4dCB9KTtcbiAgfVxuXG4gIC8vIGZpbGVzIGFyZSBzdG9yYWdlIHBhdGhzIGluIGJ1Y2tldC90cmFpbmluZy8uLi5cbiAgZm9yIChjb25zdCBwYXRoIG9mIGZpbGVzKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IFNVUEFCQVNFX1VSTCA9IHByb2Nlc3MuZW52LlNVUEFCQVNFX1VSTDtcbiAgICAgIGNvbnN0IGJ1Y2tldFB1YmxpY1VybCA9IFNVUEFCQVNFX1VSTCArIGAvc3RvcmFnZS92MS9vYmplY3QvcHVibGljL3RyYWluaW5nLyR7ZW5jb2RlVVJJQ29tcG9uZW50KHBhdGgpfWA7XG4gICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChidWNrZXRQdWJsaWNVcmwpO1xuICAgICAgaWYgKCFyZXMub2spIGNvbnRpbnVlO1xuICAgICAgY29uc3QgYnVmID0gYXdhaXQgcmVzLmFycmF5QnVmZmVyKCk7XG4gICAgICAvLyBjcnVkZSB0ZXh0IGV4dHJhY3Rpb246IGlmIGl0J3MgcGRmIG9yIHRleHRcbiAgICAgIGNvbnN0IGhlYWRlciA9IFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCwgbmV3IFVpbnQ4QXJyYXkoYnVmLnNsaWNlKDAsIDgpKSBhcyBhbnkpO1xuICAgICAgaWYgKGhlYWRlci5pbmNsdWRlcygnJVBERicpKSB7XG4gICAgICAgIC8vIGNhbm5vdCBwYXJzZSBQREYgaGVyZTsgc3RvcmUgcGxhY2Vob2xkZXJcbiAgICAgICAgZG9jcy5wdXNoKHsgc291cmNlOiBwYXRoLCBjb250ZW50OiAnKFBERiBjb250ZW50IC0tIHByb2Nlc3NlZCBleHRlcm5hbGx5KScgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjb25zdCB0ZXh0ID0gbmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKGJ1Zik7XG4gICAgICAgIGNvbnN0IGNsZWFuZWQgPSBleHRyYWN0VGV4dEZyb21IdG1sKHRleHQpO1xuICAgICAgICBkb2NzLnB1c2goeyBzb3VyY2U6IHBhdGgsIGNvbnRlbnQ6IGNsZWFuZWQgfHwgJyhiaW5hcnkgZmlsZSknIH0pO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGUpIHsgY29udGludWU7IH1cbiAgfVxuXG4gIC8vIGNodW5rIGFuZCBlbWJlZFxuICBmb3IgKGNvbnN0IGRvYyBvZiBkb2NzKSB7XG4gICAgY29uc3QgY2h1bmtzID0gY2h1bmtUZXh0KGRvYy5jb250ZW50KTtcbiAgICBjb25zdCBlbWJlZGRpbmdzID0gYXdhaXQgZW1iZWRDaHVua3MoY2h1bmtzKTtcblxuICAgIC8vIHN0b3JlIGRvY3VtZW50cyBhbmQgZW1iZWRkaW5ncyBpbiBTdXBhYmFzZVxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgY2h1bmtzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBjb25zdCBjaHVuayA9IGNodW5rc1tpXTtcbiAgICAgIGNvbnN0IGVtYiA9IGVtYmVkZGluZ3MgPyBlbWJlZGRpbmdzW2ldIDogbnVsbDtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3RyYWluaW5nX2RvY3VtZW50cycsIHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGJvdF9pZDogYm90SWQsIHNvdXJjZTogZG9jLnNvdXJjZSwgY29udGVudDogY2h1bmssIGVtYmVkZGluZzogZW1iIH0pLFxuICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmV0dXJuPXJlcHJlc2VudGF0aW9uJywgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9LFxuICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgfSBjYXRjaCB7fVxuICAgIH1cbiAgfVxuXG4gIC8vIG1hcmsgam9iIGluIGxvZ3NcbiAgdHJ5IHtcbiAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFjdGlvbjogJ1RSQUlOX0pPQl9DT01QTEVURScsIGRldGFpbHM6IHsgam9iSWQsIGJvdElkLCBkb2NzOiBkb2NzLmxlbmd0aCB9IH0pLFxuICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gIH0gY2F0Y2gge31cbn1cblxuYXN5bmMgZnVuY3Rpb24gZW5zdXJlRG9tYWluVmVyaWZpY2F0aW9uKGRvbWFpbjogc3RyaW5nLCByZXE6IGFueSkge1xuICAvLyBjaGVjayBkb21haW5zIHRhYmxlIGZvciB2ZXJpZmllZFxuICB0cnkge1xuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goYC9yZXN0L3YxL2RvbWFpbnM/ZG9tYWluPWVxLiR7ZW5jb2RlVVJJQ29tcG9uZW50KGRvbWFpbil9YCwgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSk7XG4gICAgaWYgKHJlcyAmJiAocmVzIGFzIGFueSkub2spIHtcbiAgICAgIGNvbnN0IGogPSBhd2FpdCAocmVzIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gW10pO1xuICAgICAgaWYgKEFycmF5LmlzQXJyYXkoaikgJiYgai5sZW5ndGggPiAwICYmIGpbMF0udmVyaWZpZWQpIHJldHVybiB7IHZlcmlmaWVkOiB0cnVlIH07XG4gICAgfVxuICB9IGNhdGNoIHt9XG5cbiAgLy8gQ2hlY2sgZm9yIGV4aXN0aW5nIG5vbi1leHBpcmVkIHZlcmlmaWNhdGlvbiB0b2tlblxuICB0cnkge1xuICAgIGNvbnN0IG5vd0lzbyA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgICBjb25zdCBxID0gYC9yZXN0L3YxL2RvbWFpbl92ZXJpZmljYXRpb25zP2RvbWFpbj1lcS4ke2VuY29kZVVSSUNvbXBvbmVudChkb21haW4pfSZleHBpcmVzX2F0PWd0LiR7ZW5jb2RlVVJJQ29tcG9uZW50KG5vd0lzbyl9JnVzZWRfYXQ9aXMubnVsbGA7XG4gICAgY29uc3QgciA9IGF3YWl0IHN1cGFiYXNlRmV0Y2gocSwgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgaWYgKHIgJiYgKHIgYXMgYW55KS5vaykge1xuICAgICAgY29uc3QgYXJyID0gYXdhaXQgKHIgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBbXSk7XG4gICAgICBpZiAoQXJyYXkuaXNBcnJheShhcnIpICYmIGFyci5sZW5ndGggPiAwKSB7XG4gICAgICAgIGNvbnN0IGV4aXN0aW5nID0gYXJyWzBdO1xuICAgICAgICBpZiAoZXhpc3RpbmcudG9rZW4pIHJldHVybiB7IHZlcmlmaWVkOiBmYWxzZSwgdG9rZW46IGV4aXN0aW5nLnRva2VuIH07XG4gICAgICB9XG4gICAgfVxuICB9IGNhdGNoIHt9XG5cbiAgLy8gY3JlYXRlIHZlcmlmaWNhdGlvbiB0b2tlbiBlbnRyeSAocGVyc2lzdCB0b2tlbiBzbyB1c2VyIGNhbiByZXVzZSlcbiAgY29uc3QgdG9rZW4gPSBjcnlwdG8ucmFuZG9tQnl0ZXMoMTYpLnRvU3RyaW5nKCdiYXNlNjR1cmwnKTtcbiAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRE9NQUlOX1ZFUklGSUNBVElPTl9TRUNSRVQgfHwgJ2xvY2FsLWRvbS1zZWNyZXQnO1xuICBjb25zdCB0b2tlbkhhc2ggPSBjcnlwdG8uY3JlYXRlSGFzaCgnc2hhMjU2JykudXBkYXRlKHRva2VuICsgc2VjcmV0KS5kaWdlc3QoJ2Jhc2U2NCcpO1xuICBjb25zdCBleHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIDEwMDAgKiA2MCAqIDYwICogMjQpLnRvSVNPU3RyaW5nKCk7XG4gIHRyeSB7XG4gICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZG9tYWluX3ZlcmlmaWNhdGlvbnMnLCB7XG4gICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgZG9tYWluLCB0b2tlbiwgdG9rZW5faGFzaDogdG9rZW5IYXNoLCBleHBpcmVzX2F0OiBleHBpcmVzLCB1c2VkX2F0OiBudWxsIH0pLFxuICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXNvbHV0aW9uPW1lcmdlLWR1cGxpY2F0ZXMnLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgfSBjYXRjaCB7fVxuICByZXR1cm4geyB2ZXJpZmllZDogZmFsc2UsIHRva2VuIH07XG59XG5cbmZ1bmN0aW9uIHZlcmlmeVdpZGdldFRva2VuKHRva2VuOiBzdHJpbmcpIHtcbiAgdHJ5IHtcbiAgICBjb25zdCB3aWRnZXRTZWNyZXQgPSBwcm9jZXNzLmVudi5XSURHRVRfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC13aWRnZXQtc2VjcmV0JztcbiAgICBjb25zdCBwYXJ0cyA9IHRva2VuLnNwbGl0KCcuJyk7XG4gICAgaWYgKHBhcnRzLmxlbmd0aCAhPT0gMykgcmV0dXJuIG51bGw7XG4gICAgY29uc3QgdW5zaWduZWQgPSBwYXJ0c1swXSArICcuJyArIHBhcnRzWzFdO1xuICAgIGNvbnN0IHNpZyA9IHBhcnRzWzJdO1xuICAgIGNvbnN0IGV4cGVjdGVkID0gY3J5cHRvLmNyZWF0ZUhtYWMoJ3NoYTI1NicsIHdpZGdldFNlY3JldCkudXBkYXRlKHVuc2lnbmVkKS5kaWdlc3QoJ2Jhc2U2NHVybCcpO1xuICAgIGlmIChzaWcgIT09IGV4cGVjdGVkKSByZXR1cm4gbnVsbDtcbiAgICBjb25zdCBwYXlsb2FkID0gSlNPTi5wYXJzZShCdWZmZXIuZnJvbShwYXJ0c1sxXSwgJ2Jhc2U2NHVybCcpLnRvU3RyaW5nKCd1dGY4JykpO1xuICAgIHJldHVybiBwYXlsb2FkO1xuICB9IGNhdGNoIChlKSB7IHJldHVybiBudWxsOyB9XG59XG5cbi8vIFNpbXBsZSBpbi1tZW1vcnkgcmF0ZSBsaW1pdGVyXG5jb25zdCByYXRlTWFwID0gbmV3IE1hcDxzdHJpbmcsIHsgY291bnQ6IG51bWJlcjsgdHM6IG51bWJlciB9PigpO1xuZnVuY3Rpb24gcmF0ZUxpbWl0KGtleTogc3RyaW5nLCBsaW1pdDogbnVtYmVyLCB3aW5kb3dNczogbnVtYmVyKSB7XG4gIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gIGNvbnN0IHJlYyA9IHJhdGVNYXAuZ2V0KGtleSk7XG4gIGlmICghcmVjIHx8IG5vdyAtIHJlYy50cyA+IHdpbmRvd01zKSB7XG4gICAgcmF0ZU1hcC5zZXQoa2V5LCB7IGNvdW50OiAxLCB0czogbm93IH0pO1xuICAgIHJldHVybiB0cnVlO1xuICB9XG4gIGlmIChyZWMuY291bnQgPCBsaW1pdCkge1xuICAgIHJlYy5jb3VudCArPSAxO1xuICAgIHJldHVybiB0cnVlO1xuICB9XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHNlcnZlckFwaVBsdWdpbigpOiBQbHVnaW4ge1xuICByZXR1cm4ge1xuICAgIG5hbWU6ICdzZXJ2ZXItYXBpLXBsdWdpbicsXG4gICAgY29uZmlndXJlU2VydmVyKHNlcnZlcikge1xuICAgICAgc2VydmVyLm1pZGRsZXdhcmVzLnVzZShhc3luYyAocmVxLCByZXMsIG5leHQpID0+IHtcbiAgICAgICAgaWYgKCFyZXEudXJsIHx8ICFyZXEudXJsLnN0YXJ0c1dpdGgoJy9hcGkvJykpIHJldHVybiBuZXh0KCk7XG5cbiAgICAgICAgLy8gQmFzaWMgc2VjdXJpdHkgaGVhZGVycyBmb3IgYWxsIEFQSSByZXNwb25zZXNcbiAgICAgICAgY29uc3QgY29yc09yaWdpbiA9IHJlcS5oZWFkZXJzLm9yaWdpbiB8fCAnKic7XG4gICAgICAgIHJlcy5zZXRIZWFkZXIoJ1Blcm1pc3Npb25zLVBvbGljeScsICdnZW9sb2NhdGlvbj0oKSwgbWljcm9waG9uZT0oKSwgY2FtZXJhPSgpJyk7XG4gICAgICAgIHJlcy5zZXRIZWFkZXIoJ0Nyb3NzLU9yaWdpbi1SZXNvdXJjZS1Qb2xpY3knLCAnc2FtZS1vcmlnaW4nKTtcblxuICAgICAgICAvLyBJbiBkZXYgYWxsb3cgaHR0cDsgaW4gcHJvZCAoYmVoaW5kIHByb3h5KSwgcmVxdWlyZSBodHRwc1xuICAgICAgICBpZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgPT09ICdwcm9kdWN0aW9uJyAmJiAhaXNIdHRwcyhyZXEpKSB7XG4gICAgICAgICAgcmV0dXJuIGpzb24ocmVzLCA0MDAsIHsgZXJyb3I6ICdIVFRQUyByZXF1aXJlZCcgfSwgeyAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJzogU3RyaW5nKGNvcnNPcmlnaW4pIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQ09SUyBwcmVmbGlnaHRcbiAgICAgICAgaWYgKHJlcS5tZXRob2QgPT09ICdPUFRJT05TJykge1xuICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbicsIFN0cmluZyhjb3JzT3JpZ2luKSk7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctTWV0aG9kcycsICdQT1NULEdFVCxPUFRJT05TJyk7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycycsICdDb250ZW50LVR5cGUsIEF1dGhvcml6YXRpb24nKTtcbiAgICAgICAgICByZXMuc3RhdHVzQ29kZSA9IDIwNDtcbiAgICAgICAgICByZXR1cm4gcmVzLmVuZCgpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZW5kSnNvbiA9IChzdGF0dXM6IG51bWJlciwgZGF0YTogYW55KSA9PiBqc29uKHJlcywgc3RhdHVzLCBkYXRhLCB7ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nOiBTdHJpbmcoY29yc09yaWdpbikgfSk7XG5cbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvdHJhaW4nICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgaXAgPSAocmVxLmhlYWRlcnNbJ3gtZm9yd2FyZGVkLWZvciddIGFzIHN0cmluZykgfHwgcmVxLnNvY2tldC5yZW1vdGVBZGRyZXNzIHx8ICdpcCc7XG4gICAgICAgICAgICBpZiAoIXJhdGVMaW1pdCgndHJhaW46JyArIGlwLCAyMCwgNjBfMDAwKSkgcmV0dXJuIGVuZEpzb24oNDI5LCB7IGVycm9yOiAnVG9vIE1hbnkgUmVxdWVzdHMnIH0pO1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpLmNhdGNoKCgpID0+ICh7fSkpO1xuICAgICAgICAgICAgY29uc3QgdXJsID0gdHlwZW9mIGJvZHk/LnVybCA9PT0gJ3N0cmluZycgPyBib2R5LnVybC50cmltKCkgOiAnJztcbiAgICAgICAgICAgIGlmICghdXJsICYmICFBcnJheS5pc0FycmF5KGJvZHk/LmZpbGVzKSkge1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdQcm92aWRlIHVybCBvciBmaWxlcycgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAodXJsKSB7XG4gICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgY29uc3QgdSA9IG5ldyBVUkwodXJsKTtcbiAgICAgICAgICAgICAgICBpZiAoISh1LnByb3RvY29sID09PSAnaHR0cDonIHx8IHUucHJvdG9jb2wgPT09ICdodHRwczonKSkgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkJyk7XG4gICAgICAgICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgdXJsJyB9KTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBMb2cgZXZlbnRcbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3NlY3VyaXR5X2xvZ3MnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFjdGlvbjogJ1RSQUlOX1JFUVVFU1QnLCBkZXRhaWxzOiB7IGhhc1VybDogISF1cmwsIGZpbGVDb3VudDogKGJvZHk/LmZpbGVzPy5sZW5ndGgpIHx8IDAgfSB9KSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIGNvbnN0IGpvYklkID0gbWFrZUJvdElkKCh1cmwgfHwgJycpICsgRGF0ZS5ub3coKSk7XG5cbiAgICAgICAgICAgIC8vIFN0YXJ0IGJhY2tncm91bmQgcHJvY2Vzc2luZyAobm9uLWJsb2NraW5nKVxuICAgICAgICAgICAgKGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBhd2FpdCBwcm9jZXNzVHJhaW5Kb2Ioam9iSWQsIHsgdXJsLCBmaWxlczogQXJyYXkuaXNBcnJheShib2R5Py5maWxlcykgPyBib2R5LmZpbGVzIDogW10gfSwgcmVxKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBhY3Rpb246ICdUUkFJTl9KT0JfRVJST1InLCBkZXRhaWxzOiB7IGpvYklkLCBlcnJvcjogU3RyaW5nKGU/Lm1lc3NhZ2UgfHwgZSkgfSB9KSxcbiAgICAgICAgICAgICAgICAgIH0sIHJlcSk7XG4gICAgICAgICAgICAgICAgfSBjYXRjaCB7fVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KSgpO1xuXG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDIsIHsgam9iSWQsIHN0YXR1czogJ3F1ZXVlZCcgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2Nvbm5lY3QnICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpO1xuICAgICAgICAgICAgaWYgKGJvZHk/LmNoYW5uZWwgIT09ICd3ZWJzaXRlJykgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnVW5zdXBwb3J0ZWQgY2hhbm5lbCcgfSk7XG4gICAgICAgICAgICBjb25zdCByYXdVcmwgPSAoYm9keT8udXJsIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBjb25zdCBkb21haW4gPSAoKCkgPT4ge1xuICAgICAgICAgICAgICB0cnkgeyByZXR1cm4gcmF3VXJsID8gbmV3IFVSTChyYXdVcmwpLmhvc3QgOiAnbG9jYWwnOyB9IGNhdGNoIHsgcmV0dXJuICdsb2NhbCc7IH1cbiAgICAgICAgICAgIH0pKCk7XG5cbiAgICAgICAgICAgIC8vIEVuc3VyZSBkb21haW4gdmVyaWZpY2F0aW9uXG4gICAgICAgICAgICBjb25zdCB2cmVzID0gYXdhaXQgZW5zdXJlRG9tYWluVmVyaWZpY2F0aW9uKGRvbWFpbiwgcmVxKTtcbiAgICAgICAgICAgIGlmICghdnJlcy52ZXJpZmllZCkge1xuICAgICAgICAgICAgICAvLyByZXR1cm4gdmVyaWZpY2F0aW9uIHJlcXVpcmVkIGFuZCBpbnN0cnVjdGlvbnNcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAyLCB7IHN0YXR1czogJ3ZlcmlmaWNhdGlvbl9yZXF1aXJlZCcsIGluc3RydWN0aW9uczogYEFkZCBhIEROUyBUWFQgcmVjb3JkIG9yIGEgbWV0YSB0YWcgd2l0aCB0b2tlbjogJHt2cmVzLnRva2VufWAsIHRva2VuOiB2cmVzLnRva2VuIH0pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBjb25zdCBzZWVkID0gZG9tYWluICsgJ3wnICsgKHJlcS5oZWFkZXJzWydhdXRob3JpemF0aW9uJ10gfHwgJycpO1xuICAgICAgICAgICAgY29uc3QgYm90SWQgPSBtYWtlQm90SWQoc2VlZCk7XG5cbiAgICAgICAgICAgIC8vIFVwc2VydCBjaGF0Ym90X2NvbmZpZ3MgKGlmIFJMUyBhbGxvd3Mgd2l0aCB1c2VyIHRva2VuKVxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvY2hhdGJvdF9jb25maWdzJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBib3RfaWQ6IGJvdElkLCBjaGFubmVsOiAnd2Vic2l0ZScsIGRvbWFpbiwgc2V0dGluZ3M6IHt9IH0pLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycgfSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIC8vIENyZWF0ZSB3aWRnZXQgdG9rZW4gKEhNQUMgc2lnbmVkKVxuICAgICAgICAgICAgY29uc3Qgd2lkZ2V0UGF5bG9hZCA9IHsgYm90SWQsIGRvbWFpbiwgaWF0OiBNYXRoLmZsb29yKERhdGUubm93KCkvMTAwMCkgfTtcbiAgICAgICAgICAgIGNvbnN0IHdpZGdldFNlY3JldCA9IHByb2Nlc3MuZW52LldJREdFVF9UT0tFTl9TRUNSRVQgfHwgJ2xvY2FsLXdpZGdldC1zZWNyZXQnO1xuICAgICAgICAgICAgY29uc3QgaGVhZGVyID0geyBhbGc6ICdIUzI1NicsIHR5cDogJ0pXVCcgfTtcbiAgICAgICAgICAgIGNvbnN0IGI2NCA9IChzOiBzdHJpbmcpID0+IEJ1ZmZlci5mcm9tKHMpLnRvU3RyaW5nKCdiYXNlNjR1cmwnKTtcbiAgICAgICAgICAgIGNvbnN0IHVuc2lnbmVkID0gYjY0KEpTT04uc3RyaW5naWZ5KGhlYWRlcikpICsgJy4nICsgYjY0KEpTT04uc3RyaW5naWZ5KHdpZGdldFBheWxvYWQpKTtcbiAgICAgICAgICAgIGNvbnN0IHNpZyA9IGNyeXB0by5jcmVhdGVIbWFjKCdzaGEyNTYnLCB3aWRnZXRTZWNyZXQpLnVwZGF0ZSh1bnNpZ25lZCkuZGlnZXN0KCdiYXNlNjR1cmwnKTtcbiAgICAgICAgICAgIGNvbnN0IHdpZGdldFRva2VuID0gdW5zaWduZWQgKyAnLicgKyBzaWc7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBib3RJZCwgd2lkZ2V0VG9rZW4gfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gV2lkZ2V0IGNvbmZpZyBlbmRwb2ludDogcmV0dXJucyBib3Qgc2V0dGluZ3MgZm9yIHdpZGdldCBjb25zdW1lcnMgKHJlcXVpcmVzIHRva2VuKVxuICAgICAgICAgIGlmIChyZXEudXJsPy5zdGFydHNXaXRoKCcvYXBpL3dpZGdldC1jb25maWcnKSAmJiByZXEubWV0aG9kID09PSAnR0VUJykge1xuICAgICAgICAgICAgY29uc3QgdXJsT2JqID0gbmV3IFVSTChyZXEudXJsLCAnaHR0cDovL2xvY2FsJyk7XG4gICAgICAgICAgICBjb25zdCBib3RJZCA9IHVybE9iai5zZWFyY2hQYXJhbXMuZ2V0KCdib3RJZCcpIHx8ICcnO1xuICAgICAgICAgICAgY29uc3QgdG9rZW4gPSB1cmxPYmouc2VhcmNoUGFyYW1zLmdldCgndG9rZW4nKSB8fCAnJztcbiAgICAgICAgICAgIGlmICghYm90SWQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgYm90SWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgcGF5bG9hZCA9IHZlcmlmeVdpZGdldFRva2VuKHRva2VuKTtcbiAgICAgICAgICAgIGlmICghcGF5bG9hZCB8fCBwYXlsb2FkLmJvdElkICE9PSBib3RJZCkgcmV0dXJuIGVuZEpzb24oNDAxLCB7IGVycm9yOiAnSW52YWxpZCB0b2tlbicgfSk7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvY2hhdGJvdF9jb25maWdzP2JvdF9pZD1lcS4nICsgZW5jb2RlVVJJQ29tcG9uZW50KGJvdElkKSArICcmc2VsZWN0PSonLCB7IG1ldGhvZDogJ0dFVCcgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKCFyIHx8ICEociBhcyBhbnkpLm9rKSByZXR1cm4gZW5kSnNvbig0MDQsIHsgZXJyb3I6ICdOb3QgZm91bmQnIH0pO1xuICAgICAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgKHIgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBbXSk7XG4gICAgICAgICAgICAgIGNvbnN0IGNmZyA9IEFycmF5LmlzQXJyYXkoZGF0YSkgJiYgZGF0YS5sZW5ndGggPiAwID8gZGF0YVswXSA6IHsgc2V0dGluZ3M6IHt9IH07XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBzZXR0aW5nczogY2ZnIH0pO1xuICAgICAgICAgICAgfSBjYXRjaCAoZSkgeyByZXR1cm4gZW5kSnNvbig1MDAsIHsgZXJyb3I6ICdTZXJ2ZXIgZXJyb3InIH0pOyB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2RlYnVnLWZldGNoJyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IHVybFN0ciA9IFN0cmluZyhib2R5Py51cmwgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghdXJsU3RyKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIHVybCcgfSk7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmxTdHIpO1xuICAgICAgICAgICAgICBpZiAoISh1LnByb3RvY29sID09PSAnaHR0cDonIHx8IHUucHJvdG9jb2wgPT09ICdodHRwczonKSkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCBwcm90b2NvbCcgfSk7XG4gICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgdXJsJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHIgPSBhd2FpdCBmZXRjaCh1cmxTdHIsIHsgaGVhZGVyczogeyAnVXNlci1BZ2VudCc6ICdOZXhhQm90VmVyaWZpZXIvMS4wJyB9IH0pO1xuICAgICAgICAgICAgICBpZiAoIXIgfHwgIXIub2spIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ZldGNoIGZhaWxlZCcsIHN0YXR1czogciA/IHIuc3RhdHVzIDogMCB9KTtcbiAgICAgICAgICAgICAgY29uc3QgdGV4dCA9IGF3YWl0IHIudGV4dCgpO1xuICAgICAgICAgICAgICAvLyByZXR1cm4gYSBzbmlwcGV0IHRvIGF2b2lkIGh1Z2UgcGF5bG9hZHNcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IG9rOiB0cnVlLCB1cmw6IHVybFN0ciwgc25pcHBldDogdGV4dC5zbGljZSgwLCAyMDAwMCkgfSk7XG4gICAgICAgICAgICB9IGNhdGNoIChlOiBhbnkpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNTAwLCB7IGVycm9yOiAnRmV0Y2ggZXJyb3InLCBtZXNzYWdlOiBTdHJpbmcoZT8ubWVzc2FnZSB8fCBlKSB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvdmVyaWZ5LWRvbWFpbicgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCBkb21haW4gPSBTdHJpbmcoYm9keT8uZG9tYWluIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IFN0cmluZyhib2R5Py50b2tlbiB8fCAnJykudHJpbSgpO1xuICAgICAgICAgICAgaWYgKCFkb21haW4gfHwgIXRva2VuKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIGRvbWFpbiBvciB0b2tlbicgfSk7XG5cbiAgICAgICAgICAgIC8vIFRyeSBtdWx0aXBsZSBjYW5kaWRhdGUgVVJMcyBmb3IgdmVyaWZpY2F0aW9uIChyb290LCBpbmRleC5odG1sLCB3ZWxsLWtub3duKVxuICAgICAgICAgICAgY29uc3QgY2FuZGlkYXRlcyA9IFtcbiAgICAgICAgICAgICAgYGh0dHBzOi8vJHtkb21haW59YCxcbiAgICAgICAgICAgICAgYGh0dHA6Ly8ke2RvbWFpbn1gLFxuICAgICAgICAgICAgICBgaHR0cHM6Ly8ke2RvbWFpbn0vaW5kZXguaHRtbGAsXG4gICAgICAgICAgICAgIGBodHRwOi8vJHtkb21haW59L2luZGV4Lmh0bWxgLFxuICAgICAgICAgICAgICBgaHR0cHM6Ly8ke2RvbWFpbn0vLndlbGwta25vd24vbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uYCxcbiAgICAgICAgICAgICAgYGh0dHA6Ly8ke2RvbWFpbn0vLndlbGwta25vd24vbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uYCxcbiAgICAgICAgICAgIF07XG5cbiAgICAgICAgICAgIC8vIEJ1aWxkIHJvYnVzdCByZWdleCB0byBtYXRjaCBtZXRhIHRhZyBpbiBhbnkgYXR0cmlidXRlIG9yZGVyXG4gICAgICAgICAgICBjb25zdCBlc2MgPSAoczogc3RyaW5nKSA9PiBzLnJlcGxhY2UoL1stL1xcXFxeJCorPy4oKXxbXFxde31dL2csICdcXFxcJCYnKTtcbiAgICAgICAgICAgIGNvbnN0IHRFc2MgPSBlc2ModG9rZW4pO1xuICAgICAgICAgICAgY29uc3QgbWV0YVJlID0gbmV3IFJlZ0V4cChgPG1ldGFbXj5dKig/Om5hbWVcXHMqPVxccypbJ1xcXCJdbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uWydcXFwiXVtePl0qY29udGVudFxccyo9XFxzKlsnXFxcIl0ke3RFc2N9WydcXFwiXXxjb250ZW50XFxzKj1cXHMqWydcXFwiXSR7dEVzY31bJ1xcXCJdW14+XSpuYW1lXFxzKj1cXHMqWydcXFwiXW5leGFib3QtZG9tYWluLXZlcmlmaWNhdGlvblsnXFxcIl0pYCwgJ2knKTtcbiAgICAgICAgICAgIGNvbnN0IHBsYWluUmUgPSBuZXcgUmVnRXhwKGBuZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25bOj1dXFxzKiR7dEVzY31gLCAnaScpO1xuXG4gICAgICAgICAgICBsZXQgZm91bmQgPSBmYWxzZTtcbiAgICAgICAgICAgIGZvciAoY29uc3QgdXJsIG9mIGNhbmRpZGF0ZXMpIHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgZmV0Y2godXJsLCB7IGhlYWRlcnM6IHsgJ1VzZXItQWdlbnQnOiAnTmV4YUJvdFZlcmlmaWVyLzEuMCcgfSB9KTtcbiAgICAgICAgICAgICAgICBpZiAoIXIgfHwgIXIub2spIGNvbnRpbnVlO1xuICAgICAgICAgICAgICAgIGNvbnN0IHRleHQgPSBhd2FpdCByLnRleHQoKTtcbiAgICAgICAgICAgICAgICBpZiAobWV0YVJlLnRlc3QodGV4dCkgfHwgcGxhaW5SZS50ZXN0KHRleHQpKSB7XG4gICAgICAgICAgICAgICAgICBmb3VuZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICAvLyBpZ25vcmUgYW5kIHRyeSBuZXh0IGNhbmRpZGF0ZVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghZm91bmQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ1ZlcmlmaWNhdGlvbiB0b2tlbiBub3QgZm91bmQgb24gc2l0ZScgfSk7XG5cbiAgICAgICAgICAgIC8vIEVuc3VyZSB0b2tlbiBtYXRjaGVzIGEgc3RvcmVkIHVuZXhwaXJlZCB2ZXJpZmljYXRpb24gZW50cnlcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IG5vd0lzbyA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgICAgICAgICAgICAgY29uc3QgcSA9IGAvcmVzdC92MS9kb21haW5fdmVyaWZpY2F0aW9ucz9kb21haW49ZXEuJHtlbmNvZGVVUklDb21wb25lbnQoZG9tYWluKX0mdG9rZW49ZXEuJHtlbmNvZGVVUklDb21wb25lbnQodG9rZW4pfSZleHBpcmVzX2F0PWd0LiR7ZW5jb2RlVVJJQ29tcG9uZW50KG5vd0lzbyl9JnVzZWRfYXQ9aXMubnVsbGA7XG4gICAgICAgICAgICAgIGNvbnN0IHZyID0gYXdhaXQgc3VwYWJhc2VGZXRjaChxLCB7IG1ldGhvZDogJ0dFVCcgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKCF2ciB8fCAhKHZyIGFzIGFueSkub2spIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgb3IgZXhwaXJlZCB0b2tlbicgfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGRhcnIgPSBhd2FpdCAodnIgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBbXSk7XG4gICAgICAgICAgICAgIGlmICghQXJyYXkuaXNBcnJheShkYXJyKSB8fCBkYXJyLmxlbmd0aCA9PT0gMCkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCBvciBleHBpcmVkIHRva2VuJyB9KTtcblxuICAgICAgICAgICAgICAvLyBtYXJrIHZlcmlmaWNhdGlvbiB1c2VkXG4gICAgICAgICAgICAgIGNvbnN0IGlkID0gZGFyclswXS5pZDtcbiAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZG9tYWluX3ZlcmlmaWNhdGlvbnM/aWQ9ZXEuJyArIGVuY29kZVVSSUNvbXBvbmVudChpZCksIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQQVRDSCcsXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VkX2F0OiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkgfSksXG4gICAgICAgICAgICAgICAgaGVhZGVyczogeyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZG9tYWlucycsIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGRvbWFpbiwgdmVyaWZpZWQ6IHRydWUsIHZlcmlmaWVkX2F0OiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkgfSksXG4gICAgICAgICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXNvbHV0aW9uPW1lcmdlLWR1cGxpY2F0ZXMnLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICB9IGNhdGNoIHt9XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogdHJ1ZSwgZG9tYWluIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9sYXVuY2gnICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpO1xuICAgICAgICAgICAgY29uc3QgYm90SWQgPSBTdHJpbmcoYm9keT8uYm90SWQgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghYm90SWQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgYm90SWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgY3VzdG9taXphdGlvbiA9IGJvZHk/LmN1c3RvbWl6YXRpb24gfHwge307XG5cbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2NoYXRib3RfY29uZmlncz9ib3RfaWQ9ZXEuJyArIGVuY29kZVVSSUNvbXBvbmVudChib3RJZCksIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUEFUQ0gnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHNldHRpbmdzOiBjdXN0b21pemF0aW9uIH0pLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsIFByZWZlcjogJ3JldHVybj1yZXByZXNlbnRhdGlvbicgfSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBib3RJZCB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY2hhdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBpcCA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtZm9yJ10gYXMgc3RyaW5nKSB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJ2lwJztcbiAgICAgICAgICAgIGlmICghcmF0ZUxpbWl0KCdjaGF0OicgKyBpcCwgNjAsIDYwXzAwMCkpIHJldHVybiBlbmRKc29uKDQyOSwgeyBlcnJvcjogJ1RvbyBNYW55IFJlcXVlc3RzJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IG1lc3NhZ2UgPSBTdHJpbmcoYm9keT8ubWVzc2FnZSB8fCAnJykuc2xpY2UoMCwgMjAwMCk7XG4gICAgICAgICAgICBpZiAoIW1lc3NhZ2UpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0VtcHR5IG1lc3NhZ2UnIH0pO1xuXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBhY3Rpb246ICdDSEFUJywgZGV0YWlsczogeyBsZW46IG1lc3NhZ2UubGVuZ3RoIH0gfSksXG4gICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuXG4gICAgICAgICAgICBjb25zdCByZXBseSA9IFwiSSdtIHN0aWxsIGxlYXJuaW5nLCBidXQgb3VyIHRlYW0gd2lsbCBnZXQgYmFjayB0byB5b3Ugc29vbi5cIjtcbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyByZXBseSB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBDdXN0b20gZW1haWwgdmVyaWZpY2F0aW9uOiBzZW5kIGVtYWlsXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL3NlbmQtdmVyaWZ5JyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGlwID0gKHJlcS5oZWFkZXJzWyd4LWZvcndhcmRlZC1mb3InXSBhcyBzdHJpbmcpIHx8IHJlcS5zb2NrZXQucmVtb3RlQWRkcmVzcyB8fCAnaXAnO1xuICAgICAgICAgICAgaWYgKCFyYXRlTGltaXQoJ3ZlcmlmeTonICsgaXAsIDUsIDYwKjYwXzAwMCkpIHJldHVybiBlbmRKc29uKDQyOSwgeyBlcnJvcjogJ1RvbyBNYW55IFJlcXVlc3RzJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IGVtYWlsID0gU3RyaW5nKGJvZHk/LmVtYWlsIHx8ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIGlmICghL15bXlxcc0BdK0BbXlxcc0BdK1xcLlteXFxzQF0rJC8udGVzdChlbWFpbCkpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgZW1haWwnIH0pO1xuXG4gICAgICAgICAgICAvLyBWZXJpZnkgYXV0aGVudGljYXRlZCB1c2VyIG1hdGNoZXMgZW1haWxcbiAgICAgICAgICAgIGNvbnN0IHVyZXMgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvYXV0aC92MS91c2VyJywgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICBpZiAoIXVyZXMgfHwgISh1cmVzIGFzIGFueSkub2spIHJldHVybiBlbmRKc29uKDQwMSwgeyBlcnJvcjogJ1VuYXV0aG9yaXplZCcgfSk7XG4gICAgICAgICAgICBjb25zdCB1c2VyID0gYXdhaXQgKHVyZXMgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgIGlmICghdXNlciB8fCB1c2VyLmVtYWlsPy50b0xvd2VyQ2FzZSgpICE9PSBlbWFpbCkgcmV0dXJuIGVuZEpzb24oNDAzLCB7IGVycm9yOiAnRW1haWwgbWlzbWF0Y2gnIH0pO1xuXG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IGNyeXB0by5yYW5kb21CeXRlcygzMikudG9TdHJpbmcoJ2Jhc2U2NHVybCcpO1xuICAgICAgICAgICAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRU1BSUxfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC1zZWNyZXQnO1xuICAgICAgICAgICAgY29uc3QgdG9rZW5IYXNoID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZSh0b2tlbiArIHNlY3JldCkuZGlnZXN0KCdiYXNlNjQnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXMgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgMTAwMCAqIDYwICogNjAgKiAyNCkudG9JU09TdHJpbmcoKTtcblxuICAgICAgICAgICAgLy8gU3RvcmUgdG9rZW4gaGFzaCAobm90IHJhdyB0b2tlbilcbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2VtYWlsX3ZlcmlmaWNhdGlvbnMnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycgfSxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VyX2lkOiB1c2VyLmlkLCBlbWFpbCwgdG9rZW5faGFzaDogdG9rZW5IYXNoLCBleHBpcmVzX2F0OiBleHBpcmVzLCB1c2VkX2F0OiBudWxsIH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgLy8gU2VuZCBlbWFpbCB2aWEgU01UUFxuICAgICAgICAgICAgY29uc3QgaG9zdCA9IHByb2Nlc3MuZW52LlNNVFBfSE9TVDtcbiAgICAgICAgICAgIGNvbnN0IHBvcnQgPSBOdW1iZXIocHJvY2Vzcy5lbnYuU01UUF9QT1JUIHx8IDU4Nyk7XG4gICAgICAgICAgICBjb25zdCB1c2VyU210cCA9IHByb2Nlc3MuZW52LlNNVFBfVVNFUjtcbiAgICAgICAgICAgIGNvbnN0IHBhc3NTbXRwID0gcHJvY2Vzcy5lbnYuU01UUF9QQVNTO1xuICAgICAgICAgICAgY29uc3QgZnJvbSA9IHByb2Nlc3MuZW52LkVNQUlMX0ZST00gfHwgJ05leGFCb3QgPG5vLXJlcGx5QG5leGFib3QuYWk+JztcbiAgICAgICAgICAgIGNvbnN0IGFwcFVybCA9IHByb2Nlc3MuZW52LkFQUF9VUkwgfHwgJ2h0dHA6Ly9sb2NhbGhvc3Q6MzAwMCc7XG4gICAgICAgICAgICBjb25zdCB2ZXJpZnlVcmwgPSBgJHthcHBVcmx9L2FwaS92ZXJpZnktZW1haWw/dG9rZW49JHt0b2tlbn1gO1xuXG4gICAgICAgICAgICBpZiAoaG9zdCAmJiB1c2VyU210cCAmJiBwYXNzU210cCkge1xuICAgICAgICAgICAgICBjb25zdCB0cmFuc3BvcnRlciA9IG5vZGVtYWlsZXIuY3JlYXRlVHJhbnNwb3J0KHsgaG9zdCwgcG9ydCwgc2VjdXJlOiBwb3J0ID09PSA0NjUsIGF1dGg6IHsgdXNlcjogdXNlclNtdHAsIHBhc3M6IHBhc3NTbXRwIH0gfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGh0bWwgPSBgXG4gICAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPVwid2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiNmNmY4ZmI7cGFkZGluZzoyNHB4O2ZvbnQtZmFtaWx5OkludGVyLFNlZ29lIFVJLEFyaWFsLHNhbnMtc2VyaWY7Y29sb3I6IzBmMTcyYVwiPlxuICAgICAgICAgICAgICAgICAgPHRyPjx0ZCBhbGlnbj1cImNlbnRlclwiPlxuICAgICAgICAgICAgICAgICAgICA8dGFibGUgc3R5bGU9XCJtYXgtd2lkdGg6NTYwcHg7d2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiNmZmZmZmY7Ym9yZGVyOjFweCBzb2xpZCAjZTVlN2ViO2JvcmRlci1yYWRpdXM6MTJweDtvdmVyZmxvdzpoaWRkZW5cIj5cbiAgICAgICAgICAgICAgICAgICAgICA8dHI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9XCJiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZywjNjM2NmYxLCM4YjVjZjYpO3BhZGRpbmc6MjBweDtjb2xvcjojZmZmO2ZvbnQtc2l6ZToxOHB4O2ZvbnQtd2VpZ2h0OjcwMFwiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICBOZXhhQm90XG4gICAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICAgICAgPHRyPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPVwicGFkZGluZzoyNHB4XCI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxoMSBzdHlsZT1cIm1hcmdpbjowIDAgOHB4IDA7Zm9udC1zaXplOjIwcHg7Y29sb3I6IzExMTgyN1wiPkNvbmZpcm0geW91ciBlbWFpbDwvaDE+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjAgMCAxNnB4IDA7Y29sb3I6IzM3NDE1MTtsaW5lLWhlaWdodDoxLjVcIj5IaSwgcGxlYXNlIGNvbmZpcm0geW91ciBlbWFpbCBhZGRyZXNzIHRvIHNlY3VyZSB5b3VyIE5leGFCb3QgYWNjb3VudCBhbmQgY29tcGxldGUgc2V0dXAuPC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8cCBzdHlsZT1cIm1hcmdpbjowIDAgMTZweCAwO2NvbG9yOiMzNzQxNTE7bGluZS1oZWlnaHQ6MS41XCI+VGhpcyBsaW5rIGV4cGlyZXMgaW4gMjQgaG91cnMuPC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8YSBocmVmPVwiJHt2ZXJpZnlVcmx9XCIgc3R5bGU9XCJkaXNwbGF5OmlubGluZS1ibG9jaztiYWNrZ3JvdW5kOiM2MzY2ZjE7Y29sb3I6I2ZmZjt0ZXh0LWRlY29yYXRpb246bm9uZTtwYWRkaW5nOjEwcHggMTZweDtib3JkZXItcmFkaXVzOjhweDtmb250LXdlaWdodDo2MDBcIj5WZXJpZnkgRW1haWw8L2E+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjE2cHggMCAwIDA7Y29sb3I6IzZiNzI4MDtmb250LXNpemU6MTJweFwiPklmIHRoZSBidXR0b24gZG9lc25cdTIwMTl0IHdvcmssIGNvcHkgYW5kIHBhc3RlIHRoaXMgbGluayBpbnRvIHlvdXIgYnJvd3Nlcjo8YnI+JHt2ZXJpZnlVcmx9PC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICAgIDx0cj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT1cInBhZGRpbmc6MTZweCAyNHB4O2NvbG9yOiM2YjcyODA7Zm9udC1zaXplOjEycHg7Ym9yZGVyLXRvcDoxcHggc29saWQgI2U1ZTdlYlwiPlx1MDBBOSAke25ldyBEYXRlKCkuZ2V0RnVsbFllYXIoKX0gTmV4YUJvdC4gQWxsIHJpZ2h0cyByZXNlcnZlZC48L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICAgIDwvdGFibGU+XG4gICAgICAgICAgICAgICAgICA8L3RkPjwvdHI+XG4gICAgICAgICAgICAgICAgPC90YWJsZT5gO1xuICAgICAgICAgICAgICBhd2FpdCB0cmFuc3BvcnRlci5zZW5kTWFpbCh7IHRvOiBlbWFpbCwgZnJvbSwgc3ViamVjdDogJ1ZlcmlmeSB5b3VyIGVtYWlsIGZvciBOZXhhQm90JywgaHRtbCB9KTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIGlmIChwcm9jZXNzLmVudi5OT0RFX0VOViAhPT0gJ3Byb2R1Y3Rpb24nKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS53YXJuKCdbZW1haWxdIFNNVFAgbm90IGNvbmZpZ3VyZWQ7IHZlcmlmaWNhdGlvbiBVUkw6JywgdmVyaWZ5VXJsKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgb2s6IHRydWUgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gVmVyaWZ5IGxpbmsgZW5kcG9pbnRcbiAgICAgICAgICBpZiAocmVxLnVybD8uc3RhcnRzV2l0aCgnL2FwaS92ZXJpZnktZW1haWwnKSAmJiByZXEubWV0aG9kID09PSAnR0VUJykge1xuICAgICAgICAgICAgY29uc3QgdXJsT2JqID0gbmV3IFVSTChyZXEudXJsLCAnaHR0cDovL2xvY2FsJyk7XG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IHVybE9iai5zZWFyY2hQYXJhbXMuZ2V0KCd0b2tlbicpIHx8ICcnO1xuICAgICAgICAgICAgaWYgKCF0b2tlbikge1xuICAgICAgICAgICAgICByZXMuc3RhdHVzQ29kZSA9IDQwMDtcbiAgICAgICAgICAgICAgcmVzLnNldEhlYWRlcignQ29udGVudC1UeXBlJywgJ3RleHQvaHRtbCcpO1xuICAgICAgICAgICAgICByZXR1cm4gcmVzLmVuZCgnPHA+SW52YWxpZCB0b2tlbjwvcD4nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHNlY3JldCA9IHByb2Nlc3MuZW52LkVNQUlMX1RPS0VOX1NFQ1JFVCB8fCAnbG9jYWwtc2VjcmV0JztcbiAgICAgICAgICAgIGNvbnN0IHRva2VuSGFzaCA9IGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUodG9rZW4gKyBzZWNyZXQpLmRpZ2VzdCgnYmFzZTY0Jyk7XG5cbiAgICAgICAgICAgIC8vIFByZWZlciBSUEMgKHNlY3VyaXR5IGRlZmluZXIpIG9uIERCOiB2ZXJpZnlfZW1haWxfaGFzaChwX2hhc2ggdGV4dClcbiAgICAgICAgICAgIGxldCBvayA9IGZhbHNlO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgY29uc3QgcnBjID0gYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvcnBjL3ZlcmlmeV9lbWFpbF9oYXNoJywge1xuICAgICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgcF9oYXNoOiB0b2tlbkhhc2ggfSksXG4gICAgICAgICAgICAgIH0sIHJlcSk7XG4gICAgICAgICAgICAgIGlmIChycGMgJiYgKHJwYyBhcyBhbnkpLm9rKSBvayA9IHRydWU7XG4gICAgICAgICAgICB9IGNhdGNoIHt9XG5cbiAgICAgICAgICAgIGlmICghb2spIHtcbiAgICAgICAgICAgICAgY29uc3Qgbm93SXNvID0gbmV3IERhdGUoKS50b0lTT1N0cmluZygpO1xuICAgICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9lbWFpbF92ZXJpZmljYXRpb25zP3Rva2VuX2hhc2g9ZXEuJyArIGVuY29kZVVSSUNvbXBvbmVudCh0b2tlbkhhc2gpICsgJyZ1c2VkX2F0PWlzLm51bGwmZXhwaXJlc19hdD1ndC4nICsgZW5jb2RlVVJJQ29tcG9uZW50KG5vd0lzbyksIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQQVRDSCcsXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VkX2F0OiBub3dJc28gfSksXG4gICAgICAgICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXR1cm49cmVwcmVzZW50YXRpb24nIH0sXG4gICAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJlcy5zdGF0dXNDb2RlID0gMjAwO1xuICAgICAgICAgICAgcmVzLnNldEhlYWRlcignQ29udGVudC1UeXBlJywgJ3RleHQvaHRtbCcpO1xuICAgICAgICAgICAgcmV0dXJuIHJlcy5lbmQoYDwhZG9jdHlwZSBodG1sPjxtZXRhIGh0dHAtZXF1aXY9XCJyZWZyZXNoXCIgY29udGVudD1cIjI7dXJsPS9cIj48c3R5bGU+Ym9keXtmb250LWZhbWlseTpJbnRlcixTZWdvZSBVSSxBcmlhbCxzYW5zLXNlcmlmO2JhY2tncm91bmQ6I2Y2ZjhmYjtjb2xvcjojMTExODI3O2Rpc3BsYXk6Z3JpZDtwbGFjZS1pdGVtczpjZW50ZXI7aGVpZ2h0OjEwMHZofTwvc3R5bGU+PGRpdj48aDE+XHUyNzA1IEVtYWlsIHZlcmlmaWVkPC9oMT48cD5Zb3UgY2FuIGNsb3NlIHRoaXMgdGFiLjwvcD48L2Rpdj5gKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gZW5kSnNvbig0MDQsIHsgZXJyb3I6ICdOb3QgRm91bmQnIH0pO1xuICAgICAgICB9IGNhdGNoIChlOiBhbnkpIHtcbiAgICAgICAgICByZXR1cm4gZW5kSnNvbig1MDAsIHsgZXJyb3I6ICdTZXJ2ZXIgRXJyb3InIH0pO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9LFxuICB9O1xufVxuIl0sCiAgIm1hcHBpbmdzIjogIjtBQUE2TSxTQUFTLG9CQUFvQjtBQUMxTyxPQUFPLFdBQVc7QUFDbEIs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
