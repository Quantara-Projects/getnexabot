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
  const expires = new Date(Date.now() + 1e3 * 60 * 60).toISOString();
  let createdId = null;
  try {
    const res = await supabaseFetch("/rest/v1/domain_verifications", {
      method: "POST",
      body: JSON.stringify({ domain, token_hash: tokenHash, expires_at: expires, used_at: null }),
      headers: { Prefer: "return=representation", "Content-Type": "application/json" }
    }, req).catch(() => null);
    if (res && res.ok) {
      const j = await res.json().catch(() => null);
      if (Array.isArray(j) && j.length > 0 && j[0].id) createdId = j[0].id;
      else if (j && j.id) createdId = j.id;
    }
  } catch {
  }
  return { verified: false, token, tokenId: createdId };
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
              return endJson(202, { status: "verification_required", instructions: `Add a DNS TXT record or a meta tag with token: ${vres.token}`, token: vres.token, tokenId: vres.tokenId || null });
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
          if (req.url?.startsWith("/api/debug-domain") && (req.method === "GET" || req.method === "POST")) {
            if (process.env.NODE_ENV !== "development") return endJson(404, { error: "Not found" });
            let domain = "";
            if (req.method === "GET") {
              try {
                const u = new URL(req.url, "http://local");
                domain = u.searchParams.get("domain") || "";
              } catch {
              }
            } else {
              const b = await parseJson(req).catch(() => ({}));
              domain = String(b?.domain || "");
            }
            if (!domain) return endJson(400, { error: "Missing domain" });
            try {
              const q = `/rest/v1/domain_verifications?domain=eq.${encodeURIComponent(domain)}&select=id,token_hash,expires_at,used_at`;
              const r = await supabaseFetch(q, { method: "GET" }, req).catch(() => null);
              if (!r || !r.ok) return endJson(200, { tokens: [] });
              const arr = await r.json().catch(() => []);
              return endJson(200, { tokens: Array.isArray(arr) ? arr : [] });
            } catch (e) {
              return endJson(500, { error: "Server error" });
            }
          }
          if (req.url === "/api/verify-domain" && req.method === "POST") {
            const body = await parseJson(req).catch(() => ({}));
            const domain = String(body?.domain || "").trim();
            const token = String(body?.token || "").trim();
            const tokenId = String(body?.tokenId || "").trim();
            if (!domain || !token || !tokenId) return endJson(400, { error: "Missing domain, token or tokenId" });
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
              const secret = process.env.DOMAIN_VERIFICATION_SECRET || "local-dom-secret";
              const tokenHash = crypto.createHash("sha256").update(token + secret).digest("base64");
              const q = `/rest/v1/domain_verifications?id=eq.${encodeURIComponent(tokenId)}&domain=eq.${encodeURIComponent(domain)}&token_hash=eq.${encodeURIComponent(tokenHash)}&expires_at=gt.${encodeURIComponent(nowIso)}&used_at=is.null`;
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL3NlcnZlci9hcGkudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGVcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9hcHAvY29kZS92aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vYXBwL2NvZGUvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tIFwidml0ZVwiO1xuaW1wb3J0IHJlYWN0IGZyb20gXCJAdml0ZWpzL3BsdWdpbi1yZWFjdC1zd2NcIjtcbmltcG9ydCBwYXRoIGZyb20gXCJwYXRoXCI7XG5pbXBvcnQgeyBjb21wb25lbnRUYWdnZXIgfSBmcm9tIFwibG92YWJsZS10YWdnZXJcIjtcbmltcG9ydCB7IHNlcnZlckFwaVBsdWdpbiB9IGZyb20gXCIuL3NyYy9zZXJ2ZXIvYXBpXCI7XG5cbi8vIGh0dHBzOi8vdml0ZWpzLmRldi9jb25maWcvXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiAoe1xuICBzZXJ2ZXI6IHtcbiAgICBob3N0OiBcIjo6XCIsXG4gICAgcG9ydDogODA4MCxcbiAgfSxcbiAgcGx1Z2luczogW1xuICAgIHJlYWN0KCksXG4gICAgbW9kZSA9PT0gJ2RldmVsb3BtZW50JyAmJlxuICAgIGNvbXBvbmVudFRhZ2dlcigpLFxuICAgIHNlcnZlckFwaVBsdWdpbigpLFxuICBdLmZpbHRlcihCb29sZWFuKSxcbiAgcmVzb2x2ZToge1xuICAgIGFsaWFzOiB7XG4gICAgICBcIkBcIjogcGF0aC5yZXNvbHZlKF9fZGlybmFtZSwgXCIuL3NyY1wiKSxcbiAgICB9LFxuICB9LFxufSkpO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGUvc3JjL3NlcnZlclwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2FwcC9jb2RlL3NyYy9zZXJ2ZXIvYXBpLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9hcHAvY29kZS9zcmMvc2VydmVyL2FwaS50c1wiO2ltcG9ydCB0eXBlIHsgUGx1Z2luIH0gZnJvbSAndml0ZSc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5pbXBvcnQgbm9kZW1haWxlciBmcm9tICdub2RlbWFpbGVyJztcblxuLy8gU21hbGwgSlNPTiBib2R5IHBhcnNlciB3aXRoIHNpemUgbGltaXRcbmFzeW5jIGZ1bmN0aW9uIHBhcnNlSnNvbihyZXE6IGFueSwgbGltaXQgPSAxMDI0ICogMTAwKSB7XG4gIHJldHVybiBuZXcgUHJvbWlzZTxhbnk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICBjb25zdCBjaHVua3M6IEJ1ZmZlcltdID0gW107XG4gICAgbGV0IHNpemUgPSAwO1xuICAgIHJlcS5vbignZGF0YScsIChjOiBCdWZmZXIpID0+IHtcbiAgICAgIHNpemUgKz0gYy5sZW5ndGg7XG4gICAgICBpZiAoc2l6ZSA+IGxpbWl0KSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1BheWxvYWQgdG9vIGxhcmdlJykpO1xuICAgICAgICByZXEuZGVzdHJveSgpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjaHVua3MucHVzaChjKTtcbiAgICB9KTtcbiAgICByZXEub24oJ2VuZCcsICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJhdyA9IEJ1ZmZlci5jb25jYXQoY2h1bmtzKS50b1N0cmluZygndXRmOCcpO1xuICAgICAgICBjb25zdCBqc29uID0gcmF3ID8gSlNPTi5wYXJzZShyYXcpIDoge307XG4gICAgICAgIHJlc29sdmUoanNvbik7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHJlamVjdChlKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICByZXEub24oJ2Vycm9yJywgcmVqZWN0KTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIGpzb24ocmVzOiBhbnksIHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnksIGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7fSkge1xuICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7XG4gIHJlcy5zdGF0dXNDb2RlID0gc3RhdHVzO1xuICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCcpO1xuICByZXMuc2V0SGVhZGVyKCdYLUNvbnRlbnQtVHlwZS1PcHRpb25zJywgJ25vc25pZmYnKTtcbiAgcmVzLnNldEhlYWRlcignUmVmZXJyZXItUG9saWN5JywgJ25vLXJlZmVycmVyJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtRnJhbWUtT3B0aW9ucycsICdERU5ZJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtWFNTLVByb3RlY3Rpb24nLCAnMTsgbW9kZT1ibG9jaycpO1xuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhoZWFkZXJzKSkgcmVzLnNldEhlYWRlcihrLCB2KTtcbiAgcmVzLmVuZChib2R5KTtcbn1cblxuY29uc3QgaXNIdHRwcyA9IChyZXE6IGFueSkgPT4ge1xuICBjb25zdCBwcm90byA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtcHJvdG8nXSBhcyBzdHJpbmcpIHx8ICcnO1xuICByZXR1cm4gcHJvdG8gPT09ICdodHRwcycgfHwgKHJlcS5zb2NrZXQgJiYgKHJlcS5zb2NrZXQgYXMgYW55KS5lbmNyeXB0ZWQpO1xufTtcblxuZnVuY3Rpb24gcmVxdWlyZUVudihuYW1lOiBzdHJpbmcpIHtcbiAgY29uc3QgdiA9IHByb2Nlc3MuZW52W25hbWVdO1xuICBpZiAoIXYpIHRocm93IG5ldyBFcnJvcihgJHtuYW1lfSBub3Qgc2V0YCk7XG4gIHJldHVybiB2O1xufVxuXG5hc3luYyBmdW5jdGlvbiBzdXBhYmFzZUZldGNoKHBhdGg6IHN0cmluZywgb3B0aW9uczogYW55LCByZXE6IGFueSkge1xuICBjb25zdCBiYXNlID0gcmVxdWlyZUVudignU1VQQUJBU0VfVVJMJyk7XG4gIGNvbnN0IGFub24gPSByZXF1aXJlRW52KCdTVVBBQkFTRV9BTk9OX0tFWScpO1xuICBjb25zdCB0b2tlbiA9IChyZXEuaGVhZGVyc1snYXV0aG9yaXphdGlvbiddIGFzIHN0cmluZykgfHwgJyc7XG4gIGNvbnN0IGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7XG4gICAgYXBpa2V5OiBhbm9uLFxuICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsXG4gIH07XG4gIGlmICh0b2tlbikgaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gdG9rZW47XG4gIHJldHVybiBmZXRjaChgJHtiYXNlfSR7cGF0aH1gLCB7IC4uLm9wdGlvbnMsIGhlYWRlcnM6IHsgLi4uaGVhZGVycywgLi4uKG9wdGlvbnM/LmhlYWRlcnMgfHwge30pIH0gfSk7XG59XG5cbmZ1bmN0aW9uIG1ha2VCb3RJZChzZWVkOiBzdHJpbmcpIHtcbiAgcmV0dXJuICdib3RfJyArIGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUoc2VlZCkuZGlnZXN0KCdiYXNlNjR1cmwnKS5zbGljZSgwLCAyMik7XG59XG5cbi8vIEV4dHJhY3QgdmlzaWJsZSB0ZXh0IGZyb20gSFRNTCAobmFpdmUpXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21IdG1sKGh0bWw6IHN0cmluZykge1xuICAvLyByZW1vdmUgc2NyaXB0cy9zdHlsZXNcbiAgY29uc3Qgd2l0aG91dFNjcmlwdHMgPSBodG1sLnJlcGxhY2UoLzxzY3JpcHRbXFxzXFxTXSo/PltcXHNcXFNdKj88XFwvc2NyaXB0Pi9naSwgJyAnKTtcbiAgY29uc3Qgd2l0aG91dFN0eWxlcyA9IHdpdGhvdXRTY3JpcHRzLnJlcGxhY2UoLzxzdHlsZVtcXHNcXFNdKj8+W1xcc1xcU10qPzxcXC9zdHlsZT4vZ2ksICcgJyk7XG4gIC8vIHJlbW92ZSB0YWdzXG4gIGNvbnN0IHRleHQgPSB3aXRob3V0U3R5bGVzLnJlcGxhY2UoLzxbXj5dKz4vZywgJyAnKTtcbiAgLy8gZGVjb2RlIEhUTUwgZW50aXRpZXMgKGJhc2ljKVxuICByZXR1cm4gdGV4dC5yZXBsYWNlKC8mbmJzcDt8JmFtcDt8Jmx0O3wmZ3Q7fCZxdW90O3wmIzM5Oy9nLCAocykgPT4ge1xuICAgIHN3aXRjaCAocykge1xuICAgICAgY2FzZSAnJm5ic3A7JzogcmV0dXJuICcgJztcbiAgICAgIGNhc2UgJyZhbXA7JzogcmV0dXJuICcmJztcbiAgICAgIGNhc2UgJyZsdDsnOiByZXR1cm4gJzwnO1xuICAgICAgY2FzZSAnJmd0Oyc6IHJldHVybiAnPic7XG4gICAgICBjYXNlICcmcXVvdDsnOiByZXR1cm4gJ1wiJztcbiAgICAgIGNhc2UgJyYjMzk7JzogcmV0dXJuICdcXCcnO1xuICAgICAgZGVmYXVsdDogcmV0dXJuIHM7XG4gICAgfVxuICB9KS5yZXBsYWNlKC9cXHMrL2csICcgJykudHJpbSgpO1xufVxuXG5hc3luYyBmdW5jdGlvbiB0cnlGZXRjaFVybFRleHQodTogc3RyaW5nKSB7XG4gIHRyeSB7XG4gICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2godSwgeyBoZWFkZXJzOiB7ICdVc2VyLUFnZW50JzogJ05leGFCb3RDcmF3bGVyLzEuMCcgfSB9KTtcbiAgICBpZiAoIXJlcy5vaykgcmV0dXJuICcnO1xuICAgIGNvbnN0IGh0bWwgPSBhd2FpdCByZXMudGV4dCgpO1xuICAgIHJldHVybiBleHRyYWN0VGV4dEZyb21IdG1sKGh0bWwpO1xuICB9IGNhdGNoIChlKSB7XG4gICAgcmV0dXJuICcnO1xuICB9XG59XG5cbmZ1bmN0aW9uIGNodW5rVGV4dCh0ZXh0OiBzdHJpbmcsIG1heENoYXJzID0gMTUwMCkge1xuICBjb25zdCBwYXJhZ3JhcGhzID0gdGV4dC5zcGxpdCgvXFxufFxccnxcXC58XFwhfFxcPy8pLm1hcChwID0+IHAudHJpbSgpKS5maWx0ZXIoQm9vbGVhbik7XG4gIGNvbnN0IGNodW5rczogc3RyaW5nW10gPSBbXTtcbiAgbGV0IGN1ciA9ICcnO1xuICBmb3IgKGNvbnN0IHAgb2YgcGFyYWdyYXBocykge1xuICAgIGlmICgoY3VyICsgJyAnICsgcCkubGVuZ3RoID4gbWF4Q2hhcnMpIHtcbiAgICAgIGlmIChjdXIpIHsgY2h1bmtzLnB1c2goY3VyLnRyaW0oKSk7IGN1ciA9IHA7IH1cbiAgICAgIGVsc2UgeyBjaHVua3MucHVzaChwLnNsaWNlKDAsIG1heENoYXJzKSk7IGN1ciA9IHAuc2xpY2UobWF4Q2hhcnMpOyB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGN1ciA9IChjdXIgKyAnICcgKyBwKS50cmltKCk7XG4gICAgfVxuICB9XG4gIGlmIChjdXIpIGNodW5rcy5wdXNoKGN1ci50cmltKCkpO1xuICByZXR1cm4gY2h1bmtzO1xufVxuXG5hc3luYyBmdW5jdGlvbiBlbWJlZENodW5rcyhjaHVua3M6IHN0cmluZ1tdKTogUHJvbWlzZTxudW1iZXJbXVtdIHwgbnVsbD4ge1xuICBjb25zdCBrZXkgPSBwcm9jZXNzLmVudi5PUEVOQUlfQVBJX0tFWTtcbiAgaWYgKCFrZXkpIHJldHVybiBudWxsO1xuICB0cnkge1xuICAgIGNvbnN0IHJlc3AgPSBhd2FpdCBmZXRjaCgnaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS92MS9lbWJlZGRpbmdzJywge1xuICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICBoZWFkZXJzOiB7ICdBdXRob3JpemF0aW9uJzogYEJlYXJlciAke2tleX1gLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGlucHV0OiBjaHVua3MsIG1vZGVsOiAndGV4dC1lbWJlZGRpbmctMy1zbWFsbCcgfSksXG4gICAgfSk7XG4gICAgaWYgKCFyZXNwLm9rKSByZXR1cm4gbnVsbDtcbiAgICBjb25zdCBqID0gYXdhaXQgcmVzcC5qc29uKCk7XG4gICAgaWYgKCFqLmRhdGEpIHJldHVybiBudWxsO1xuICAgIHJldHVybiBqLmRhdGEubWFwKChkOiBhbnkpID0+IGQuZW1iZWRkaW5nIGFzIG51bWJlcltdKTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHByb2Nlc3NUcmFpbkpvYihqb2JJZDogc3RyaW5nLCBib2R5OiBhbnksIHJlcTogYW55KSB7XG4gIGNvbnN0IHVybCA9IGJvZHkudXJsIHx8ICcnO1xuICBjb25zdCBmaWxlczogc3RyaW5nW10gPSBBcnJheS5pc0FycmF5KGJvZHkuZmlsZXMpID8gYm9keS5maWxlcyA6IFtdO1xuICBjb25zdCBib3RTZWVkID0gKHVybCB8fCBmaWxlcy5qb2luKCcsJykpICsgRGF0ZS5ub3coKTtcbiAgY29uc3QgYm90SWQgPSBtYWtlQm90SWQoYm90U2VlZCk7XG5cbiAgLy8gZ2F0aGVyIHRleHRzXG4gIGNvbnN0IGRvY3M6IHsgc291cmNlOiBzdHJpbmc7IGNvbnRlbnQ6IHN0cmluZyB9W10gPSBbXTtcblxuICBpZiAodXJsKSB7XG4gICAgY29uc3QgdGV4dCA9IGF3YWl0IHRyeUZldGNoVXJsVGV4dCh1cmwpO1xuICAgIGlmICh0ZXh0KSBkb2NzLnB1c2goeyBzb3VyY2U6IHVybCwgY29udGVudDogdGV4dCB9KTtcbiAgfVxuXG4gIC8vIGZpbGVzIGFyZSBzdG9yYWdlIHBhdGhzIGluIGJ1Y2tldC90cmFpbmluZy8uLi5cbiAgZm9yIChjb25zdCBwYXRoIG9mIGZpbGVzKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IFNVUEFCQVNFX1VSTCA9IHByb2Nlc3MuZW52LlNVUEFCQVNFX1VSTDtcbiAgICAgIGNvbnN0IGJ1Y2tldFB1YmxpY1VybCA9IFNVUEFCQVNFX1VSTCArIGAvc3RvcmFnZS92MS9vYmplY3QvcHVibGljL3RyYWluaW5nLyR7ZW5jb2RlVVJJQ29tcG9uZW50KHBhdGgpfWA7XG4gICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChidWNrZXRQdWJsaWNVcmwpO1xuICAgICAgaWYgKCFyZXMub2spIGNvbnRpbnVlO1xuICAgICAgY29uc3QgYnVmID0gYXdhaXQgcmVzLmFycmF5QnVmZmVyKCk7XG4gICAgICAvLyBjcnVkZSB0ZXh0IGV4dHJhY3Rpb246IGlmIGl0J3MgcGRmIG9yIHRleHRcbiAgICAgIGNvbnN0IGhlYWRlciA9IFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCwgbmV3IFVpbnQ4QXJyYXkoYnVmLnNsaWNlKDAsIDgpKSBhcyBhbnkpO1xuICAgICAgaWYgKGhlYWRlci5pbmNsdWRlcygnJVBERicpKSB7XG4gICAgICAgIC8vIGNhbm5vdCBwYXJzZSBQREYgaGVyZTsgc3RvcmUgcGxhY2Vob2xkZXJcbiAgICAgICAgZG9jcy5wdXNoKHsgc291cmNlOiBwYXRoLCBjb250ZW50OiAnKFBERiBjb250ZW50IC0tIHByb2Nlc3NlZCBleHRlcm5hbGx5KScgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjb25zdCB0ZXh0ID0gbmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKGJ1Zik7XG4gICAgICAgIGNvbnN0IGNsZWFuZWQgPSBleHRyYWN0VGV4dEZyb21IdG1sKHRleHQpO1xuICAgICAgICBkb2NzLnB1c2goeyBzb3VyY2U6IHBhdGgsIGNvbnRlbnQ6IGNsZWFuZWQgfHwgJyhiaW5hcnkgZmlsZSknIH0pO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGUpIHsgY29udGludWU7IH1cbiAgfVxuXG4gIC8vIGNodW5rIGFuZCBlbWJlZFxuICBmb3IgKGNvbnN0IGRvYyBvZiBkb2NzKSB7XG4gICAgY29uc3QgY2h1bmtzID0gY2h1bmtUZXh0KGRvYy5jb250ZW50KTtcbiAgICBjb25zdCBlbWJlZGRpbmdzID0gYXdhaXQgZW1iZWRDaHVua3MoY2h1bmtzKTtcblxuICAgIC8vIHN0b3JlIGRvY3VtZW50cyBhbmQgZW1iZWRkaW5ncyBpbiBTdXBhYmFzZVxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgY2h1bmtzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBjb25zdCBjaHVuayA9IGNodW5rc1tpXTtcbiAgICAgIGNvbnN0IGVtYiA9IGVtYmVkZGluZ3MgPyBlbWJlZGRpbmdzW2ldIDogbnVsbDtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3RyYWluaW5nX2RvY3VtZW50cycsIHtcbiAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGJvdF9pZDogYm90SWQsIHNvdXJjZTogZG9jLnNvdXJjZSwgY29udGVudDogY2h1bmssIGVtYmVkZGluZzogZW1iIH0pLFxuICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmV0dXJuPXJlcHJlc2VudGF0aW9uJywgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9LFxuICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgfSBjYXRjaCB7fVxuICAgIH1cbiAgfVxuXG4gIC8vIG1hcmsgam9iIGluIGxvZ3NcbiAgdHJ5IHtcbiAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFjdGlvbjogJ1RSQUlOX0pPQl9DT01QTEVURScsIGRldGFpbHM6IHsgam9iSWQsIGJvdElkLCBkb2NzOiBkb2NzLmxlbmd0aCB9IH0pLFxuICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gIH0gY2F0Y2gge31cbn1cblxuYXN5bmMgZnVuY3Rpb24gZW5zdXJlRG9tYWluVmVyaWZpY2F0aW9uKGRvbWFpbjogc3RyaW5nLCByZXE6IGFueSkge1xuICAvLyBjaGVjayBkb21haW5zIHRhYmxlIGZvciB2ZXJpZmllZFxuICB0cnkge1xuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goYC9yZXN0L3YxL2RvbWFpbnM/ZG9tYWluPWVxLiR7ZW5jb2RlVVJJQ29tcG9uZW50KGRvbWFpbil9YCwgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSk7XG4gICAgaWYgKHJlcyAmJiAocmVzIGFzIGFueSkub2spIHtcbiAgICAgIGNvbnN0IGogPSBhd2FpdCAocmVzIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gW10pO1xuICAgICAgaWYgKEFycmF5LmlzQXJyYXkoaikgJiYgai5sZW5ndGggPiAwICYmIGpbMF0udmVyaWZpZWQpIHJldHVybiB7IHZlcmlmaWVkOiB0cnVlIH07XG4gICAgfVxuICB9IGNhdGNoIHt9XG5cbiAgLy8gYWx3YXlzIGNyZWF0ZSBhIGZyZXNoIHNob3J0LWxpdmVkIHNpbmdsZS11c2UgdmVyaWZpY2F0aW9uIHRva2VuIChkbyBOT1QgcGVyc2lzdCBwbGFpbnRleHQpXG4gIGNvbnN0IHRva2VuID0gY3J5cHRvLnJhbmRvbUJ5dGVzKDE2KS50b1N0cmluZygnYmFzZTY0dXJsJyk7XG4gIGNvbnN0IHNlY3JldCA9IHByb2Nlc3MuZW52LkRPTUFJTl9WRVJJRklDQVRJT05fU0VDUkVUIHx8ICdsb2NhbC1kb20tc2VjcmV0JztcbiAgY29uc3QgdG9rZW5IYXNoID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZSh0b2tlbiArIHNlY3JldCkuZGlnZXN0KCdiYXNlNjQnKTtcbiAgY29uc3QgZXhwaXJlcyA9IG5ldyBEYXRlKERhdGUubm93KCkgKyAxMDAwICogNjAgKiA2MCkudG9JU09TdHJpbmcoKTtcbiAgbGV0IGNyZWF0ZWRJZDogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gIHRyeSB7XG4gICAgY29uc3QgcmVzID0gYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZG9tYWluX3ZlcmlmaWNhdGlvbnMnLCB7XG4gICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgZG9tYWluLCB0b2tlbl9oYXNoOiB0b2tlbkhhc2gsIGV4cGlyZXNfYXQ6IGV4cGlyZXMsIHVzZWRfYXQ6IG51bGwgfSksXG4gICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3JldHVybj1yZXByZXNlbnRhdGlvbicsICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicgfSxcbiAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgIGlmIChyZXMgJiYgKHJlcyBhcyBhbnkpLm9rKSB7XG4gICAgICBjb25zdCBqID0gYXdhaXQgKHJlcyBhcyBSZXNwb25zZSkuanNvbigpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgaWYgKEFycmF5LmlzQXJyYXkoaikgJiYgai5sZW5ndGggPiAwICYmIGpbMF0uaWQpIGNyZWF0ZWRJZCA9IGpbMF0uaWQ7XG4gICAgICBlbHNlIGlmIChqICYmIGouaWQpIGNyZWF0ZWRJZCA9IGouaWQ7XG4gICAgfVxuICB9IGNhdGNoIHt9XG4gIC8vIFJldHVybiB0aGUgcGxhaW50ZXh0IHRva2VuIGFuZCBpdHMgREIgaWQgdG8gdGhlIGNhbGxlciBzbyB0aGV5IGNhbiBwbGFjZSBpdCBpbiB0aGVpciBzaXRlLCBidXQgZG8gbm90IHBlcnNpc3QgcGxhaW50ZXh0XG4gIHJldHVybiB7IHZlcmlmaWVkOiBmYWxzZSwgdG9rZW4sIHRva2VuSWQ6IGNyZWF0ZWRJZCB9O1xufVxuXG5mdW5jdGlvbiB2ZXJpZnlXaWRnZXRUb2tlbih0b2tlbjogc3RyaW5nKSB7XG4gIHRyeSB7XG4gICAgY29uc3Qgd2lkZ2V0U2VjcmV0ID0gcHJvY2Vzcy5lbnYuV0lER0VUX1RPS0VOX1NFQ1JFVCB8fCAnbG9jYWwtd2lkZ2V0LXNlY3JldCc7XG4gICAgY29uc3QgcGFydHMgPSB0b2tlbi5zcGxpdCgnLicpO1xuICAgIGlmIChwYXJ0cy5sZW5ndGggIT09IDMpIHJldHVybiBudWxsO1xuICAgIGNvbnN0IHVuc2lnbmVkID0gcGFydHNbMF0gKyAnLicgKyBwYXJ0c1sxXTtcbiAgICBjb25zdCBzaWcgPSBwYXJ0c1syXTtcbiAgICBjb25zdCBleHBlY3RlZCA9IGNyeXB0by5jcmVhdGVIbWFjKCdzaGEyNTYnLCB3aWRnZXRTZWNyZXQpLnVwZGF0ZSh1bnNpZ25lZCkuZGlnZXN0KCdiYXNlNjR1cmwnKTtcbiAgICBpZiAoc2lnICE9PSBleHBlY3RlZCkgcmV0dXJuIG51bGw7XG4gICAgY29uc3QgcGF5bG9hZCA9IEpTT04ucGFyc2UoQnVmZmVyLmZyb20ocGFydHNbMV0sICdiYXNlNjR1cmwnKS50b1N0cmluZygndXRmOCcpKTtcbiAgICByZXR1cm4gcGF5bG9hZDtcbiAgfSBjYXRjaCAoZSkgeyByZXR1cm4gbnVsbDsgfVxufVxuXG4vLyBTaW1wbGUgaW4tbWVtb3J5IHJhdGUgbGltaXRlclxuY29uc3QgcmF0ZU1hcCA9IG5ldyBNYXA8c3RyaW5nLCB7IGNvdW50OiBudW1iZXI7IHRzOiBudW1iZXIgfT4oKTtcbmZ1bmN0aW9uIHJhdGVMaW1pdChrZXk6IHN0cmluZywgbGltaXQ6IG51bWJlciwgd2luZG93TXM6IG51bWJlcikge1xuICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICBjb25zdCByZWMgPSByYXRlTWFwLmdldChrZXkpO1xuICBpZiAoIXJlYyB8fCBub3cgLSByZWMudHMgPiB3aW5kb3dNcykge1xuICAgIHJhdGVNYXAuc2V0KGtleSwgeyBjb3VudDogMSwgdHM6IG5vdyB9KTtcbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuICBpZiAocmVjLmNvdW50IDwgbGltaXQpIHtcbiAgICByZWMuY291bnQgKz0gMTtcbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuICByZXR1cm4gZmFsc2U7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBzZXJ2ZXJBcGlQbHVnaW4oKTogUGx1Z2luIHtcbiAgcmV0dXJuIHtcbiAgICBuYW1lOiAnc2VydmVyLWFwaS1wbHVnaW4nLFxuICAgIGNvbmZpZ3VyZVNlcnZlcihzZXJ2ZXIpIHtcbiAgICAgIHNlcnZlci5taWRkbGV3YXJlcy51c2UoYXN5bmMgKHJlcSwgcmVzLCBuZXh0KSA9PiB7XG4gICAgICAgIGlmICghcmVxLnVybCB8fCAhcmVxLnVybC5zdGFydHNXaXRoKCcvYXBpLycpKSByZXR1cm4gbmV4dCgpO1xuXG4gICAgICAgIC8vIEJhc2ljIHNlY3VyaXR5IGhlYWRlcnMgZm9yIGFsbCBBUEkgcmVzcG9uc2VzXG4gICAgICAgIGNvbnN0IGNvcnNPcmlnaW4gPSByZXEuaGVhZGVycy5vcmlnaW4gfHwgJyonO1xuICAgICAgICByZXMuc2V0SGVhZGVyKCdQZXJtaXNzaW9ucy1Qb2xpY3knLCAnZ2VvbG9jYXRpb249KCksIG1pY3JvcGhvbmU9KCksIGNhbWVyYT0oKScpO1xuICAgICAgICByZXMuc2V0SGVhZGVyKCdDcm9zcy1PcmlnaW4tUmVzb3VyY2UtUG9saWN5JywgJ3NhbWUtb3JpZ2luJyk7XG5cbiAgICAgICAgLy8gSW4gZGV2IGFsbG93IGh0dHA7IGluIHByb2QgKGJlaGluZCBwcm94eSksIHJlcXVpcmUgaHR0cHNcbiAgICAgICAgaWYgKHByb2Nlc3MuZW52Lk5PREVfRU5WID09PSAncHJvZHVjdGlvbicgJiYgIWlzSHR0cHMocmVxKSkge1xuICAgICAgICAgIHJldHVybiBqc29uKHJlcywgNDAwLCB7IGVycm9yOiAnSFRUUFMgcmVxdWlyZWQnIH0sIHsgJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbic6IFN0cmluZyhjb3JzT3JpZ2luKSB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIENPUlMgcHJlZmxpZ2h0XG4gICAgICAgIGlmIChyZXEubWV0aG9kID09PSAnT1BUSU9OUycpIHtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nLCBTdHJpbmcoY29yc09yaWdpbikpO1xuICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0FjY2Vzcy1Db250cm9sLUFsbG93LU1ldGhvZHMnLCAnUE9TVCxHRVQsT1BUSU9OUycpO1xuICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0FjY2Vzcy1Db250cm9sLUFsbG93LUhlYWRlcnMnLCAnQ29udGVudC1UeXBlLCBBdXRob3JpemF0aW9uJyk7XG4gICAgICAgICAgcmVzLnN0YXR1c0NvZGUgPSAyMDQ7XG4gICAgICAgICAgcmV0dXJuIHJlcy5lbmQoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGVuZEpzb24gPSAoc3RhdHVzOiBudW1iZXIsIGRhdGE6IGFueSkgPT4ganNvbihyZXMsIHN0YXR1cywgZGF0YSwgeyAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJzogU3RyaW5nKGNvcnNPcmlnaW4pIH0pO1xuXG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL3RyYWluJyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGlwID0gKHJlcS5oZWFkZXJzWyd4LWZvcndhcmRlZC1mb3InXSBhcyBzdHJpbmcpIHx8IHJlcS5zb2NrZXQucmVtb3RlQWRkcmVzcyB8fCAnaXAnO1xuICAgICAgICAgICAgaWYgKCFyYXRlTGltaXQoJ3RyYWluOicgKyBpcCwgMjAsIDYwXzAwMCkpIHJldHVybiBlbmRKc29uKDQyOSwgeyBlcnJvcjogJ1RvbyBNYW55IFJlcXVlc3RzJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IHVybCA9IHR5cGVvZiBib2R5Py51cmwgPT09ICdzdHJpbmcnID8gYm9keS51cmwudHJpbSgpIDogJyc7XG4gICAgICAgICAgICBpZiAoIXVybCAmJiAhQXJyYXkuaXNBcnJheShib2R5Py5maWxlcykpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnUHJvdmlkZSB1cmwgb3IgZmlsZXMnIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKHVybCkge1xuICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGNvbnN0IHUgPSBuZXcgVVJMKHVybCk7XG4gICAgICAgICAgICAgICAgaWYgKCEodS5wcm90b2NvbCA9PT0gJ2h0dHA6JyB8fCB1LnByb3RvY29sID09PSAnaHR0cHM6JykpIHRocm93IG5ldyBFcnJvcignaW52YWxpZCcpO1xuICAgICAgICAgICAgICB9IGNhdGNoIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdJbnZhbGlkIHVybCcgfSk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gTG9nIGV2ZW50XG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBhY3Rpb246ICdUUkFJTl9SRVFVRVNUJywgZGV0YWlsczogeyBoYXNVcmw6ICEhdXJsLCBmaWxlQ291bnQ6IChib2R5Py5maWxlcz8ubGVuZ3RoKSB8fCAwIH0gfSksXG4gICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuXG4gICAgICAgICAgICBjb25zdCBqb2JJZCA9IG1ha2VCb3RJZCgodXJsIHx8ICcnKSArIERhdGUubm93KCkpO1xuXG4gICAgICAgICAgICAvLyBTdGFydCBiYWNrZ3JvdW5kIHByb2Nlc3NpbmcgKG5vbi1ibG9ja2luZylcbiAgICAgICAgICAgIChhc3luYyAoKSA9PiB7XG4gICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgYXdhaXQgcHJvY2Vzc1RyYWluSm9iKGpvYklkLCB7IHVybCwgZmlsZXM6IEFycmF5LmlzQXJyYXkoYm9keT8uZmlsZXMpID8gYm9keS5maWxlcyA6IFtdIH0sIHJlcSk7XG4gICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnVFJBSU5fSk9CX0VSUk9SJywgZGV0YWlsczogeyBqb2JJZCwgZXJyb3I6IFN0cmluZyhlPy5tZXNzYWdlIHx8IGUpIH0gfSksXG4gICAgICAgICAgICAgICAgICB9LCByZXEpO1xuICAgICAgICAgICAgICAgIH0gY2F0Y2gge31cbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSkoKTtcblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAyLCB7IGpvYklkLCBzdGF0dXM6ICdxdWV1ZWQnIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9jb25uZWN0JyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKTtcbiAgICAgICAgICAgIGlmIChib2R5Py5jaGFubmVsICE9PSAnd2Vic2l0ZScpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ1Vuc3VwcG9ydGVkIGNoYW5uZWwnIH0pO1xuICAgICAgICAgICAgY29uc3QgcmF3VXJsID0gKGJvZHk/LnVybCB8fCAnJykudHJpbSgpO1xuICAgICAgICAgICAgY29uc3QgZG9tYWluID0gKCgpID0+IHtcbiAgICAgICAgICAgICAgdHJ5IHsgcmV0dXJuIHJhd1VybCA/IG5ldyBVUkwocmF3VXJsKS5ob3N0IDogJ2xvY2FsJzsgfSBjYXRjaCB7IHJldHVybiAnbG9jYWwnOyB9XG4gICAgICAgICAgICB9KSgpO1xuXG4gICAgICAgICAgICAvLyBFbnN1cmUgZG9tYWluIHZlcmlmaWNhdGlvblxuICAgICAgICAgICAgY29uc3QgdnJlcyA9IGF3YWl0IGVuc3VyZURvbWFpblZlcmlmaWNhdGlvbihkb21haW4sIHJlcSk7XG4gICAgICAgICAgICBpZiAoIXZyZXMudmVyaWZpZWQpIHtcbiAgICAgICAgICAgICAgLy8gcmV0dXJuIHZlcmlmaWNhdGlvbiByZXF1aXJlZCBhbmQgaW5zdHJ1Y3Rpb25zIChpbmNsdWRlIHRva2VuIGlkKVxuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDIsIHsgc3RhdHVzOiAndmVyaWZpY2F0aW9uX3JlcXVpcmVkJywgaW5zdHJ1Y3Rpb25zOiBgQWRkIGEgRE5TIFRYVCByZWNvcmQgb3IgYSBtZXRhIHRhZyB3aXRoIHRva2VuOiAke3ZyZXMudG9rZW59YCwgdG9rZW46IHZyZXMudG9rZW4sIHRva2VuSWQ6IHZyZXMudG9rZW5JZCB8fCBudWxsIH0pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBjb25zdCBzZWVkID0gZG9tYWluICsgJ3wnICsgKHJlcS5oZWFkZXJzWydhdXRob3JpemF0aW9uJ10gfHwgJycpO1xuICAgICAgICAgICAgY29uc3QgYm90SWQgPSBtYWtlQm90SWQoc2VlZCk7XG5cbiAgICAgICAgICAgIC8vIFVwc2VydCBjaGF0Ym90X2NvbmZpZ3MgKGlmIFJMUyBhbGxvd3Mgd2l0aCB1c2VyIHRva2VuKVxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvY2hhdGJvdF9jb25maWdzJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBib3RfaWQ6IGJvdElkLCBjaGFubmVsOiAnd2Vic2l0ZScsIGRvbWFpbiwgc2V0dGluZ3M6IHt9IH0pLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycgfSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIC8vIENyZWF0ZSB3aWRnZXQgdG9rZW4gKEhNQUMgc2lnbmVkKVxuICAgICAgICAgICAgY29uc3Qgd2lkZ2V0UGF5bG9hZCA9IHsgYm90SWQsIGRvbWFpbiwgaWF0OiBNYXRoLmZsb29yKERhdGUubm93KCkvMTAwMCkgfTtcbiAgICAgICAgICAgIGNvbnN0IHdpZGdldFNlY3JldCA9IHByb2Nlc3MuZW52LldJREdFVF9UT0tFTl9TRUNSRVQgfHwgJ2xvY2FsLXdpZGdldC1zZWNyZXQnO1xuICAgICAgICAgICAgY29uc3QgaGVhZGVyID0geyBhbGc6ICdIUzI1NicsIHR5cDogJ0pXVCcgfTtcbiAgICAgICAgICAgIGNvbnN0IGI2NCA9IChzOiBzdHJpbmcpID0+IEJ1ZmZlci5mcm9tKHMpLnRvU3RyaW5nKCdiYXNlNjR1cmwnKTtcbiAgICAgICAgICAgIGNvbnN0IHVuc2lnbmVkID0gYjY0KEpTT04uc3RyaW5naWZ5KGhlYWRlcikpICsgJy4nICsgYjY0KEpTT04uc3RyaW5naWZ5KHdpZGdldFBheWxvYWQpKTtcbiAgICAgICAgICAgIGNvbnN0IHNpZyA9IGNyeXB0by5jcmVhdGVIbWFjKCdzaGEyNTYnLCB3aWRnZXRTZWNyZXQpLnVwZGF0ZSh1bnNpZ25lZCkuZGlnZXN0KCdiYXNlNjR1cmwnKTtcbiAgICAgICAgICAgIGNvbnN0IHdpZGdldFRva2VuID0gdW5zaWduZWQgKyAnLicgKyBzaWc7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBib3RJZCwgd2lkZ2V0VG9rZW4gfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gV2lkZ2V0IGNvbmZpZyBlbmRwb2ludDogcmV0dXJucyBib3Qgc2V0dGluZ3MgZm9yIHdpZGdldCBjb25zdW1lcnMgKHJlcXVpcmVzIHRva2VuKVxuICAgICAgICAgIGlmIChyZXEudXJsPy5zdGFydHNXaXRoKCcvYXBpL3dpZGdldC1jb25maWcnKSAmJiByZXEubWV0aG9kID09PSAnR0VUJykge1xuICAgICAgICAgICAgY29uc3QgdXJsT2JqID0gbmV3IFVSTChyZXEudXJsLCAnaHR0cDovL2xvY2FsJyk7XG4gICAgICAgICAgICBjb25zdCBib3RJZCA9IHVybE9iai5zZWFyY2hQYXJhbXMuZ2V0KCdib3RJZCcpIHx8ICcnO1xuICAgICAgICAgICAgY29uc3QgdG9rZW4gPSB1cmxPYmouc2VhcmNoUGFyYW1zLmdldCgndG9rZW4nKSB8fCAnJztcbiAgICAgICAgICAgIGlmICghYm90SWQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgYm90SWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgcGF5bG9hZCA9IHZlcmlmeVdpZGdldFRva2VuKHRva2VuKTtcbiAgICAgICAgICAgIGlmICghcGF5bG9hZCB8fCBwYXlsb2FkLmJvdElkICE9PSBib3RJZCkgcmV0dXJuIGVuZEpzb24oNDAxLCB7IGVycm9yOiAnSW52YWxpZCB0b2tlbicgfSk7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvY2hhdGJvdF9jb25maWdzP2JvdF9pZD1lcS4nICsgZW5jb2RlVVJJQ29tcG9uZW50KGJvdElkKSArICcmc2VsZWN0PSonLCB7IG1ldGhvZDogJ0dFVCcgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKCFyIHx8ICEociBhcyBhbnkpLm9rKSByZXR1cm4gZW5kSnNvbig0MDQsIHsgZXJyb3I6ICdOb3QgZm91bmQnIH0pO1xuICAgICAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgKHIgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBbXSk7XG4gICAgICAgICAgICAgIGNvbnN0IGNmZyA9IEFycmF5LmlzQXJyYXkoZGF0YSkgJiYgZGF0YS5sZW5ndGggPiAwID8gZGF0YVswXSA6IHsgc2V0dGluZ3M6IHt9IH07XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBzZXR0aW5nczogY2ZnIH0pO1xuICAgICAgICAgICAgfSBjYXRjaCAoZSkgeyByZXR1cm4gZW5kSnNvbig1MDAsIHsgZXJyb3I6ICdTZXJ2ZXIgZXJyb3InIH0pOyB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2RlYnVnLWZldGNoJyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IHVybFN0ciA9IFN0cmluZyhib2R5Py51cmwgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghdXJsU3RyKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIHVybCcgfSk7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmxTdHIpO1xuICAgICAgICAgICAgICBpZiAoISh1LnByb3RvY29sID09PSAnaHR0cDonIHx8IHUucHJvdG9jb2wgPT09ICdodHRwczonKSkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCBwcm90b2NvbCcgfSk7XG4gICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgdXJsJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHIgPSBhd2FpdCBmZXRjaCh1cmxTdHIsIHsgaGVhZGVyczogeyAnVXNlci1BZ2VudCc6ICdOZXhhQm90VmVyaWZpZXIvMS4wJyB9IH0pO1xuICAgICAgICAgICAgICBpZiAoIXIgfHwgIXIub2spIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ZldGNoIGZhaWxlZCcsIHN0YXR1czogciA/IHIuc3RhdHVzIDogMCB9KTtcbiAgICAgICAgICAgICAgY29uc3QgdGV4dCA9IGF3YWl0IHIudGV4dCgpO1xuICAgICAgICAgICAgICAvLyByZXR1cm4gYSBzbmlwcGV0IHRvIGF2b2lkIGh1Z2UgcGF5bG9hZHNcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IG9rOiB0cnVlLCB1cmw6IHVybFN0ciwgc25pcHBldDogdGV4dC5zbGljZSgwLCAyMDAwMCkgfSk7XG4gICAgICAgICAgICB9IGNhdGNoIChlOiBhbnkpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNTAwLCB7IGVycm9yOiAnRmV0Y2ggZXJyb3InLCBtZXNzYWdlOiBTdHJpbmcoZT8ubWVzc2FnZSB8fCBlKSB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBEZWJ1ZzogbGlzdCBzdG9yZWQgdmVyaWZpY2F0aW9uIHRva2VucyBmb3IgYSBkb21haW4gKERFViBPTkxZKSBcdTIwMTQgZG8gTk9UIGV4cG9zZSB0b2tlbiBwbGFpbnRleHQgaW4gcHJvZHVjdGlvblxuICAgICAgICAgIGlmIChyZXEudXJsPy5zdGFydHNXaXRoKCcvYXBpL2RlYnVnLWRvbWFpbicpICYmIChyZXEubWV0aG9kID09PSAnR0VUJyB8fCByZXEubWV0aG9kID09PSAnUE9TVCcpKSB7XG4gICAgICAgICAgICBpZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgIT09ICdkZXZlbG9wbWVudCcpIHJldHVybiBlbmRKc29uKDQwNCwgeyBlcnJvcjogJ05vdCBmb3VuZCcgfSk7XG4gICAgICAgICAgICAvLyBBY2NlcHQgYm90aCBxdWVyeSBwYXJhbSA/ZG9tYWluPSBvciBKU09OIGJvZHkgeyBkb21haW4gfVxuICAgICAgICAgICAgbGV0IGRvbWFpbiA9ICcnO1xuICAgICAgICAgICAgaWYgKHJlcS5tZXRob2QgPT09ICdHRVQnKSB7XG4gICAgICAgICAgICAgIHRyeSB7IGNvbnN0IHUgPSBuZXcgVVJMKHJlcS51cmwsICdodHRwOi8vbG9jYWwnKTsgZG9tYWluID0gdS5zZWFyY2hQYXJhbXMuZ2V0KCdkb21haW4nKSB8fCAnJzsgfSBjYXRjaCB7fVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgY29uc3QgYiA9IGF3YWl0IHBhcnNlSnNvbihyZXEpLmNhdGNoKCgpID0+ICh7fSkpOyBkb21haW4gPSBTdHJpbmcoYj8uZG9tYWluIHx8ICcnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICghZG9tYWluKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIGRvbWFpbicgfSk7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCBxID0gYC9yZXN0L3YxL2RvbWFpbl92ZXJpZmljYXRpb25zP2RvbWFpbj1lcS4ke2VuY29kZVVSSUNvbXBvbmVudChkb21haW4pfSZzZWxlY3Q9aWQsdG9rZW5faGFzaCxleHBpcmVzX2F0LHVzZWRfYXRgO1xuICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgc3VwYWJhc2VGZXRjaChxLCB7IG1ldGhvZDogJ0dFVCcgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKCFyIHx8ICEociBhcyBhbnkpLm9rKSByZXR1cm4gZW5kSnNvbigyMDAsIHsgdG9rZW5zOiBbXSB9KTtcbiAgICAgICAgICAgICAgY29uc3QgYXJyID0gYXdhaXQgKHIgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBbXSk7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyB0b2tlbnM6IEFycmF5LmlzQXJyYXkoYXJyKSA/IGFyciA6IFtdIH0pO1xuICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbig1MDAsIHsgZXJyb3I6ICdTZXJ2ZXIgZXJyb3InIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS92ZXJpZnktZG9tYWluJyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IGRvbWFpbiA9IFN0cmluZyhib2R5Py5kb21haW4gfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGNvbnN0IHRva2VuID0gU3RyaW5nKGJvZHk/LnRva2VuIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBjb25zdCB0b2tlbklkID0gU3RyaW5nKGJvZHk/LnRva2VuSWQgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghZG9tYWluIHx8ICF0b2tlbiB8fCAhdG9rZW5JZCkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnTWlzc2luZyBkb21haW4sIHRva2VuIG9yIHRva2VuSWQnIH0pO1xuXG4gICAgICAgICAgICAvLyBUcnkgbXVsdGlwbGUgY2FuZGlkYXRlIFVSTHMgZm9yIHZlcmlmaWNhdGlvbiAocm9vdCwgaW5kZXguaHRtbCwgd2VsbC1rbm93bilcbiAgICAgICAgICAgIGNvbnN0IGNhbmRpZGF0ZXMgPSBbXG4gICAgICAgICAgICAgIGBodHRwczovLyR7ZG9tYWlufWAsXG4gICAgICAgICAgICAgIGBodHRwOi8vJHtkb21haW59YCxcbiAgICAgICAgICAgICAgYGh0dHBzOi8vJHtkb21haW59L2luZGV4Lmh0bWxgLFxuICAgICAgICAgICAgICBgaHR0cDovLyR7ZG9tYWlufS9pbmRleC5odG1sYCxcbiAgICAgICAgICAgICAgYGh0dHBzOi8vJHtkb21haW59Ly53ZWxsLWtub3duL25leGFib3QtZG9tYWluLXZlcmlmaWNhdGlvbmAsXG4gICAgICAgICAgICAgIGBodHRwOi8vJHtkb21haW59Ly53ZWxsLWtub3duL25leGFib3QtZG9tYWluLXZlcmlmaWNhdGlvbmAsXG4gICAgICAgICAgICBdO1xuXG4gICAgICAgICAgICAvLyBCdWlsZCByb2J1c3QgcmVnZXggdG8gbWF0Y2ggbWV0YSB0YWcgaW4gYW55IGF0dHJpYnV0ZSBvcmRlclxuICAgICAgICAgICAgY29uc3QgZXNjID0gKHM6IHN0cmluZykgPT4gcy5yZXBsYWNlKC9bLS9cXFxcXiQqKz8uKCl8W1xcXXt9XS9nLCAnXFxcXCQmJyk7XG4gICAgICAgICAgICBjb25zdCB0RXNjID0gZXNjKHRva2VuKTtcbiAgICAgICAgICAgIGNvbnN0IG1ldGFSZSA9IG5ldyBSZWdFeHAoYDxtZXRhW14+XSooPzpuYW1lXFxzKj1cXHMqWydcXFwiXW5leGFib3QtZG9tYWluLXZlcmlmaWNhdGlvblsnXFxcIl1bXj5dKmNvbnRlbnRcXHMqPVxccypbJ1xcXCJdJHt0RXNjfVsnXFxcIl18Y29udGVudFxccyo9XFxzKlsnXFxcIl0ke3RFc2N9WydcXFwiXVtePl0qbmFtZVxccyo9XFxzKlsnXFxcIl1uZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25bJ1xcXCJdKWAsICdpJyk7XG4gICAgICAgICAgICBjb25zdCBwbGFpblJlID0gbmV3IFJlZ0V4cChgbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uWzo9XVxccyoke3RFc2N9YCwgJ2knKTtcblxuICAgICAgICAgICAgbGV0IGZvdW5kID0gZmFsc2U7XG4gICAgICAgICAgICBmb3IgKGNvbnN0IHVybCBvZiBjYW5kaWRhdGVzKSB7XG4gICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgY29uc3QgciA9IGF3YWl0IGZldGNoKHVybCwgeyBoZWFkZXJzOiB7ICdVc2VyLUFnZW50JzogJ05leGFCb3RWZXJpZmllci8xLjAnIH0gfSk7XG4gICAgICAgICAgICAgICAgaWYgKCFyIHx8ICFyLm9rKSBjb250aW51ZTtcbiAgICAgICAgICAgICAgICBjb25zdCB0ZXh0ID0gYXdhaXQgci50ZXh0KCk7XG4gICAgICAgICAgICAgICAgaWYgKG1ldGFSZS50ZXN0KHRleHQpIHx8IHBsYWluUmUudGVzdCh0ZXh0KSkge1xuICAgICAgICAgICAgICAgICAgZm91bmQgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgICAgLy8gaWdub3JlIGFuZCB0cnkgbmV4dCBjYW5kaWRhdGVcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAoIWZvdW5kKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdWZXJpZmljYXRpb24gdG9rZW4gbm90IGZvdW5kIG9uIHNpdGUnIH0pO1xuXG4gICAgICAgICAgICAvLyBFbnN1cmUgdG9rZW4gbWF0Y2hlcyBhIHN0b3JlZCB1bmV4cGlyZWQgdmVyaWZpY2F0aW9uIGVudHJ5XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCBub3dJc28gPSBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCk7XG4gICAgICAgICAgICAgIGNvbnN0IHNlY3JldCA9IHByb2Nlc3MuZW52LkRPTUFJTl9WRVJJRklDQVRJT05fU0VDUkVUIHx8ICdsb2NhbC1kb20tc2VjcmV0JztcbiAgICAgICAgICAgICAgY29uc3QgdG9rZW5IYXNoID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZSh0b2tlbiArIHNlY3JldCkuZGlnZXN0KCdiYXNlNjQnKTtcbiAgICAgICAgICAgICAgLy8gUXVlcnkgYnkgc3BlY2lmaWMgaWQgdG8gYXZvaWQgYW1iaWd1aXR5XG4gICAgICAgICAgICAgIGNvbnN0IHEgPSBgL3Jlc3QvdjEvZG9tYWluX3ZlcmlmaWNhdGlvbnM/aWQ9ZXEuJHtlbmNvZGVVUklDb21wb25lbnQodG9rZW5JZCl9JmRvbWFpbj1lcS4ke2VuY29kZVVSSUNvbXBvbmVudChkb21haW4pfSZ0b2tlbl9oYXNoPWVxLiR7ZW5jb2RlVVJJQ29tcG9uZW50KHRva2VuSGFzaCl9JmV4cGlyZXNfYXQ9Z3QuJHtlbmNvZGVVUklDb21wb25lbnQobm93SXNvKX0mdXNlZF9hdD1pcy5udWxsYDtcbiAgICAgICAgICAgICAgY29uc3QgdnIgPSBhd2FpdCBzdXBhYmFzZUZldGNoKHEsIHsgbWV0aG9kOiAnR0VUJyB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgICBpZiAoIXZyIHx8ICEodnIgYXMgYW55KS5vaykgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCBvciBleHBpcmVkIHRva2VuJyB9KTtcbiAgICAgICAgICAgICAgY29uc3QgZGFyciA9IGF3YWl0ICh2ciBhcyBSZXNwb25zZSkuanNvbigpLmNhdGNoKCgpID0+IFtdKTtcbiAgICAgICAgICAgICAgaWYgKCFBcnJheS5pc0FycmF5KGRhcnIpIHx8IGRhcnIubGVuZ3RoID09PSAwKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdJbnZhbGlkIG9yIGV4cGlyZWQgdG9rZW4nIH0pO1xuXG4gICAgICAgICAgICAgIC8vIG1hcmsgdmVyaWZpY2F0aW9uIHVzZWRcbiAgICAgICAgICAgICAgY29uc3QgaWQgPSBkYXJyWzBdLmlkO1xuICAgICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9kb21haW5fdmVyaWZpY2F0aW9ucz9pZD1lcS4nICsgZW5jb2RlVVJJQ29tcG9uZW50KGlkKSwge1xuICAgICAgICAgICAgICAgIG1ldGhvZDogJ1BBVENIJyxcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHVzZWRfYXQ6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSB9KSxcbiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicgfSxcbiAgICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9kb21haW5zJywge1xuICAgICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgZG9tYWluLCB2ZXJpZmllZDogdHJ1ZSwgdmVyaWZpZWRfYXQ6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSB9KSxcbiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycsICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicgfSxcbiAgICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgIH0gY2F0Y2gge31cblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IG9rOiB0cnVlLCBkb21haW4gfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2xhdW5jaCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSk7XG4gICAgICAgICAgICBjb25zdCBib3RJZCA9IFN0cmluZyhib2R5Py5ib3RJZCB8fCAnJykudHJpbSgpO1xuICAgICAgICAgICAgaWYgKCFib3RJZCkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnTWlzc2luZyBib3RJZCcgfSk7XG4gICAgICAgICAgICBjb25zdCBjdXN0b21pemF0aW9uID0gYm9keT8uY3VzdG9taXphdGlvbiB8fCB7fTtcblxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvY2hhdGJvdF9jb25maWdzP2JvdF9pZD1lcS4nICsgZW5jb2RlVVJJQ29tcG9uZW50KGJvdElkKSwge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQQVRDSCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgc2V0dGluZ3M6IGN1c3RvbWl6YXRpb24gfSksXG4gICAgICAgICAgICAgIGhlYWRlcnM6IHsgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJywgUHJlZmVyOiAncmV0dXJuPXJlcHJlc2VudGF0aW9uJyB9LFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IGJvdElkIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9jaGF0JyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGlwID0gKHJlcS5oZWFkZXJzWyd4LWZvcndhcmRlZC1mb3InXSBhcyBzdHJpbmcpIHx8IHJlcS5zb2NrZXQucmVtb3RlQWRkcmVzcyB8fCAnaXAnO1xuICAgICAgICAgICAgaWYgKCFyYXRlTGltaXQoJ2NoYXQ6JyArIGlwLCA2MCwgNjBfMDAwKSkgcmV0dXJuIGVuZEpzb24oNDI5LCB7IGVycm9yOiAnVG9vIE1hbnkgUmVxdWVzdHMnIH0pO1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpLmNhdGNoKCgpID0+ICh7fSkpO1xuICAgICAgICAgICAgY29uc3QgbWVzc2FnZSA9IFN0cmluZyhib2R5Py5tZXNzYWdlIHx8ICcnKS5zbGljZSgwLCAyMDAwKTtcbiAgICAgICAgICAgIGlmICghbWVzc2FnZSkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnRW1wdHkgbWVzc2FnZScgfSk7XG5cbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3NlY3VyaXR5X2xvZ3MnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFjdGlvbjogJ0NIQVQnLCBkZXRhaWxzOiB7IGxlbjogbWVzc2FnZS5sZW5ndGggfSB9KSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIGNvbnN0IHJlcGx5ID0gXCJJJ20gc3RpbGwgbGVhcm5pbmcsIGJ1dCBvdXIgdGVhbSB3aWxsIGdldCBiYWNrIHRvIHlvdSBzb29uLlwiO1xuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IHJlcGx5IH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIC8vIEN1c3RvbSBlbWFpbCB2ZXJpZmljYXRpb246IHNlbmQgZW1haWxcbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvc2VuZC12ZXJpZnknICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgaXAgPSAocmVxLmhlYWRlcnNbJ3gtZm9yd2FyZGVkLWZvciddIGFzIHN0cmluZykgfHwgcmVxLnNvY2tldC5yZW1vdGVBZGRyZXNzIHx8ICdpcCc7XG4gICAgICAgICAgICBpZiAoIXJhdGVMaW1pdCgndmVyaWZ5OicgKyBpcCwgNSwgNjAqNjBfMDAwKSkgcmV0dXJuIGVuZEpzb24oNDI5LCB7IGVycm9yOiAnVG9vIE1hbnkgUmVxdWVzdHMnIH0pO1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpLmNhdGNoKCgpID0+ICh7fSkpO1xuICAgICAgICAgICAgY29uc3QgZW1haWwgPSBTdHJpbmcoYm9keT8uZW1haWwgfHwgJycpLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgaWYgKCEvXlteXFxzQF0rQFteXFxzQF0rXFwuW15cXHNAXSskLy50ZXN0KGVtYWlsKSkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCBlbWFpbCcgfSk7XG5cbiAgICAgICAgICAgIC8vIFZlcmlmeSBhdXRoZW50aWNhdGVkIHVzZXIgbWF0Y2hlcyBlbWFpbFxuICAgICAgICAgICAgY29uc3QgdXJlcyA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9hdXRoL3YxL3VzZXInLCB7IG1ldGhvZDogJ0dFVCcgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgIGlmICghdXJlcyB8fCAhKHVyZXMgYXMgYW55KS5vaykgcmV0dXJuIGVuZEpzb24oNDAxLCB7IGVycm9yOiAnVW5hdXRob3JpemVkJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IHVzZXIgPSBhd2FpdCAodXJlcyBhcyBSZXNwb25zZSkuanNvbigpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgaWYgKCF1c2VyIHx8IHVzZXIuZW1haWw/LnRvTG93ZXJDYXNlKCkgIT09IGVtYWlsKSByZXR1cm4gZW5kSnNvbig0MDMsIHsgZXJyb3I6ICdFbWFpbCBtaXNtYXRjaCcgfSk7XG5cbiAgICAgICAgICAgIGNvbnN0IHRva2VuID0gY3J5cHRvLnJhbmRvbUJ5dGVzKDMyKS50b1N0cmluZygnYmFzZTY0dXJsJyk7XG4gICAgICAgICAgICBjb25zdCBzZWNyZXQgPSBwcm9jZXNzLmVudi5FTUFJTF9UT0tFTl9TRUNSRVQgfHwgJ2xvY2FsLXNlY3JldCc7XG4gICAgICAgICAgICBjb25zdCB0b2tlbkhhc2ggPSBjcnlwdG8uY3JlYXRlSGFzaCgnc2hhMjU2JykudXBkYXRlKHRva2VuICsgc2VjcmV0KS5kaWdlc3QoJ2Jhc2U2NCcpO1xuICAgICAgICAgICAgY29uc3QgZXhwaXJlcyA9IG5ldyBEYXRlKERhdGUubm93KCkgKyAxMDAwICogNjAgKiA2MCAqIDI0KS50b0lTT1N0cmluZygpO1xuXG4gICAgICAgICAgICAvLyBTdG9yZSB0b2tlbiBoYXNoIChub3QgcmF3IHRva2VuKVxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZW1haWxfdmVyaWZpY2F0aW9ucycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmVzb2x1dGlvbj1tZXJnZS1kdXBsaWNhdGVzJyB9LFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHVzZXJfaWQ6IHVzZXIuaWQsIGVtYWlsLCB0b2tlbl9oYXNoOiB0b2tlbkhhc2gsIGV4cGlyZXNfYXQ6IGV4cGlyZXMsIHVzZWRfYXQ6IG51bGwgfSksXG4gICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuXG4gICAgICAgICAgICAvLyBTZW5kIGVtYWlsIHZpYSBTTVRQXG4gICAgICAgICAgICBjb25zdCBob3N0ID0gcHJvY2Vzcy5lbnYuU01UUF9IT1NUO1xuICAgICAgICAgICAgY29uc3QgcG9ydCA9IE51bWJlcihwcm9jZXNzLmVudi5TTVRQX1BPUlQgfHwgNTg3KTtcbiAgICAgICAgICAgIGNvbnN0IHVzZXJTbXRwID0gcHJvY2Vzcy5lbnYuU01UUF9VU0VSO1xuICAgICAgICAgICAgY29uc3QgcGFzc1NtdHAgPSBwcm9jZXNzLmVudi5TTVRQX1BBU1M7XG4gICAgICAgICAgICBjb25zdCBmcm9tID0gcHJvY2Vzcy5lbnYuRU1BSUxfRlJPTSB8fCAnTmV4YUJvdCA8bm8tcmVwbHlAbmV4YWJvdC5haT4nO1xuICAgICAgICAgICAgY29uc3QgYXBwVXJsID0gcHJvY2Vzcy5lbnYuQVBQX1VSTCB8fCAnaHR0cDovL2xvY2FsaG9zdDozMDAwJztcbiAgICAgICAgICAgIGNvbnN0IHZlcmlmeVVybCA9IGAke2FwcFVybH0vYXBpL3ZlcmlmeS1lbWFpbD90b2tlbj0ke3Rva2VufWA7XG5cbiAgICAgICAgICAgIGlmIChob3N0ICYmIHVzZXJTbXRwICYmIHBhc3NTbXRwKSB7XG4gICAgICAgICAgICAgIGNvbnN0IHRyYW5zcG9ydGVyID0gbm9kZW1haWxlci5jcmVhdGVUcmFuc3BvcnQoeyBob3N0LCBwb3J0LCBzZWN1cmU6IHBvcnQgPT09IDQ2NSwgYXV0aDogeyB1c2VyOiB1c2VyU210cCwgcGFzczogcGFzc1NtdHAgfSB9KTtcbiAgICAgICAgICAgICAgY29uc3QgaHRtbCA9IGBcbiAgICAgICAgICAgICAgICA8dGFibGUgc3R5bGU9XCJ3aWR0aDoxMDAlO2JhY2tncm91bmQ6I2Y2ZjhmYjtwYWRkaW5nOjI0cHg7Zm9udC1mYW1pbHk6SW50ZXIsU2Vnb2UgVUksQXJpYWwsc2Fucy1zZXJpZjtjb2xvcjojMGYxNzJhXCI+XG4gICAgICAgICAgICAgICAgICA8dHI+PHRkIGFsaWduPVwiY2VudGVyXCI+XG4gICAgICAgICAgICAgICAgICAgIDx0YWJsZSBzdHlsZT1cIm1heC13aWR0aDo1NjBweDt3aWR0aDoxMDAlO2JhY2tncm91bmQ6I2ZmZmZmZjtib3JkZXI6MXB4IHNvbGlkICNlNWU3ZWI7Ym9yZGVyLXJhZGl1czoxMnB4O292ZXJmbG93OmhpZGRlblwiPlxuICAgICAgICAgICAgICAgICAgICAgIDx0cj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT1cImJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLCM2MzY2ZjEsIzhiNWNmNik7cGFkZGluZzoyMHB4O2NvbG9yOiNmZmY7Zm9udC1zaXplOjE4cHg7Zm9udC13ZWlnaHQ6NzAwXCI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIE5leGFCb3RcbiAgICAgICAgICAgICAgICAgICAgICAgIDwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICAgICAgICA8dHI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9XCJwYWRkaW5nOjI0cHhcIj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgPGgxIHN0eWxlPVwibWFyZ2luOjAgMCA4cHggMDtmb250LXNpemU6MjBweDtjb2xvcjojMTExODI3XCI+Q29uZmlybSB5b3VyIGVtYWlsPC9oMT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgPHAgc3R5bGU9XCJtYXJnaW46MCAwIDE2cHggMDtjb2xvcjojMzc0MTUxO2xpbmUtaGVpZ2h0OjEuNVwiPkhpLCBwbGVhc2UgY29uZmlybSB5b3VyIGVtYWlsIGFkZHJlc3MgdG8gc2VjdXJlIHlvdXIgTmV4YUJvdCBhY2NvdW50IGFuZCBjb21wbGV0ZSBzZXR1cC48L3A+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjAgMCAxNnB4IDA7Y29sb3I6IzM3NDE1MTtsaW5lLWhlaWdodDoxLjVcIj5UaGlzIGxpbmsgZXhwaXJlcyBpbiAyNCBob3Vycy48L3A+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxhIGhyZWY9XCIke3ZlcmlmeVVybH1cIiBzdHlsZT1cImRpc3BsYXk6aW5saW5lLWJsb2NrO2JhY2tncm91bmQ6IzYzNjZmMTtjb2xvcjojZmZmO3RleHQtZGVjb3JhdGlvbjpub25lO3BhZGRpbmc6MTBweCAxNnB4O2JvcmRlci1yYWRpdXM6OHB4O2ZvbnQtd2VpZ2h0OjYwMFwiPlZlcmlmeSBFbWFpbDwvYT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgPHAgc3R5bGU9XCJtYXJnaW46MTZweCAwIDAgMDtjb2xvcjojNmI3MjgwO2ZvbnQtc2l6ZToxMnB4XCI+SWYgdGhlIGJ1dHRvbiBkb2Vzblx1MjAxOXQgd29yaywgY29weSBhbmQgcGFzdGUgdGhpcyBsaW5rIGludG8geW91ciBicm93c2VyOjxicj4ke3ZlcmlmeVVybH08L3A+XG4gICAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICAgICAgPHRyPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPVwicGFkZGluZzoxNnB4IDI0cHg7Y29sb3I6IzZiNzI4MDtmb250LXNpemU6MTJweDtib3JkZXItdG9wOjFweCBzb2xpZCAjZTVlN2ViXCI+XHUwMEE5ICR7bmV3IERhdGUoKS5nZXRGdWxsWWVhcigpfSBOZXhhQm90LiBBbGwgcmlnaHRzIHJlc2VydmVkLjwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICAgICAgPC90YWJsZT5cbiAgICAgICAgICAgICAgICAgIDwvdGQ+PC90cj5cbiAgICAgICAgICAgICAgICA8L3RhYmxlPmA7XG4gICAgICAgICAgICAgIGF3YWl0IHRyYW5zcG9ydGVyLnNlbmRNYWlsKHsgdG86IGVtYWlsLCBmcm9tLCBzdWJqZWN0OiAnVmVyaWZ5IHlvdXIgZW1haWwgZm9yIE5leGFCb3QnLCBodG1sIH0pO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgaWYgKHByb2Nlc3MuZW52Lk5PREVfRU5WICE9PSAncHJvZHVjdGlvbicpIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLndhcm4oJ1tlbWFpbF0gU01UUCBub3QgY29uZmlndXJlZDsgdmVyaWZpY2F0aW9uIFVSTDonLCB2ZXJpZnlVcmwpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogdHJ1ZSB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBWZXJpZnkgbGluayBlbmRwb2ludFxuICAgICAgICAgIGlmIChyZXEudXJsPy5zdGFydHNXaXRoKCcvYXBpL3ZlcmlmeS1lbWFpbCcpICYmIHJlcS5tZXRob2QgPT09ICdHRVQnKSB7XG4gICAgICAgICAgICBjb25zdCB1cmxPYmogPSBuZXcgVVJMKHJlcS51cmwsICdodHRwOi8vbG9jYWwnKTtcbiAgICAgICAgICAgIGNvbnN0IHRva2VuID0gdXJsT2JqLnNlYXJjaFBhcmFtcy5nZXQoJ3Rva2VuJykgfHwgJyc7XG4gICAgICAgICAgICBpZiAoIXRva2VuKSB7XG4gICAgICAgICAgICAgIHJlcy5zdGF0dXNDb2RlID0gNDAwO1xuICAgICAgICAgICAgICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAndGV4dC9odG1sJyk7XG4gICAgICAgICAgICAgIHJldHVybiByZXMuZW5kKCc8cD5JbnZhbGlkIHRva2VuPC9wPicpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRU1BSUxfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC1zZWNyZXQnO1xuICAgICAgICAgICAgY29uc3QgdG9rZW5IYXNoID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZSh0b2tlbiArIHNlY3JldCkuZGlnZXN0KCdiYXNlNjQnKTtcblxuICAgICAgICAgICAgLy8gUHJlZmVyIFJQQyAoc2VjdXJpdHkgZGVmaW5lcikgb24gREI6IHZlcmlmeV9lbWFpbF9oYXNoKHBfaGFzaCB0ZXh0KVxuICAgICAgICAgICAgbGV0IG9rID0gZmFsc2U7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCBycGMgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9ycGMvdmVyaWZ5X2VtYWlsX2hhc2gnLCB7XG4gICAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBwX2hhc2g6IHRva2VuSGFzaCB9KSxcbiAgICAgICAgICAgICAgfSwgcmVxKTtcbiAgICAgICAgICAgICAgaWYgKHJwYyAmJiAocnBjIGFzIGFueSkub2spIG9rID0gdHJ1ZTtcbiAgICAgICAgICAgIH0gY2F0Y2gge31cblxuICAgICAgICAgICAgaWYgKCFvaykge1xuICAgICAgICAgICAgICBjb25zdCBub3dJc28gPSBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCk7XG4gICAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2VtYWlsX3ZlcmlmaWNhdGlvbnM/dG9rZW5faGFzaD1lcS4nICsgZW5jb2RlVVJJQ29tcG9uZW50KHRva2VuSGFzaCkgKyAnJnVzZWRfYXQ9aXMubnVsbCZleHBpcmVzX2F0PWd0LicgKyBlbmNvZGVVUklDb21wb25lbnQobm93SXNvKSwge1xuICAgICAgICAgICAgICAgIG1ldGhvZDogJ1BBVENIJyxcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHVzZWRfYXQ6IG5vd0lzbyB9KSxcbiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3JldHVybj1yZXByZXNlbnRhdGlvbicgfSxcbiAgICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmVzLnN0YXR1c0NvZGUgPSAyMDA7XG4gICAgICAgICAgICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAndGV4dC9odG1sJyk7XG4gICAgICAgICAgICByZXR1cm4gcmVzLmVuZChgPCFkb2N0eXBlIGh0bWw+PG1ldGEgaHR0cC1lcXVpdj1cInJlZnJlc2hcIiBjb250ZW50PVwiMjt1cmw9L1wiPjxzdHlsZT5ib2R5e2ZvbnQtZmFtaWx5OkludGVyLFNlZ29lIFVJLEFyaWFsLHNhbnMtc2VyaWY7YmFja2dyb3VuZDojZjZmOGZiO2NvbG9yOiMxMTE4Mjc7ZGlzcGxheTpncmlkO3BsYWNlLWl0ZW1zOmNlbnRlcjtoZWlnaHQ6MTAwdmh9PC9zdHlsZT48ZGl2PjxoMT5cdTI3MDUgRW1haWwgdmVyaWZpZWQ8L2gxPjxwPllvdSBjYW4gY2xvc2UgdGhpcyB0YWIuPC9wPjwvZGl2PmApO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwNCwgeyBlcnJvcjogJ05vdCBGb3VuZCcgfSk7XG4gICAgICAgIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgICAgICAgIHJldHVybiBlbmRKc29uKDUwMCwgeyBlcnJvcjogJ1NlcnZlciBFcnJvcicgfSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH0sXG4gIH07XG59XG4iXSwKICAibWFwcGluZ3MiOiAiO0FBQTZNLFNBQVMsb0JBQW9CO0FBQzFPLE9BQU8sV0FBVztBQUNsQixPQUFPLFVBQVU7QUFDakIsU0FBUyx1QkFBdUI7OztBQ0ZoQyxPQUFPLFlBQVk7QUFDbkIsT0FBTyxnQkFBZ0I7QUFHdkIsZUFBZSxVQUFVLEtBQVUsUUFBUSxPQUFPLEtBQUs7QUFDckQsU0FBTyxJQUFJLFFBQWEsQ0FBQyxTQUFTLFdBQVc7QUFDM0MsVUFBTSxTQUFtQixDQUFDO0FBQzFCLFFBQUksT0FBTztBQUNYLFFBQUksR0FBRyxRQUFRLENBQUMsTUFBYztBQUM1QixjQUFRLEVBQUU7QUFDVixVQUFJLE9BQU8sT0FBTztBQUNoQixlQUFPLElBQUksTUFBTSxtQkFBbUIsQ0FBQztBQUNyQyxZQUFJLFFBQVE7QUFDWjtBQUFBLE1BQ0Y7QUFDQSxhQUFPLEtBQUssQ0FBQztBQUFBLElBQ2YsQ0FBQztBQUNELFFBQUksR0FBRyxPQUFPLE1BQU07QUFDbEIsVUFBSTtBQUNGLGNBQU0sTUFBTSxPQUFPLE9BQU8sTUFBTSxFQUFFLFNBQVMsTUFBTTtBQUNqRCxjQUFNQSxRQUFPLE1BQU0sS0FBSyxNQUFNLEdBQUcsSUFBSSxDQUFDO0FBQ3RDLGdCQUFRQSxLQUFJO0FBQUEsTUFDZCxTQUFTLEdBQUc7QUFDVixlQUFPLENBQUM7QUFBQSxNQUNWO0FBQUEsSUFDRixDQUFDO0FBQ0QsUUFBSSxHQUFHLFNBQVMsTUFBTTtBQUFBLEVBQ3hCLENBQUM7QUFDSDtBQUVBLFNBQVMsS0FBSyxLQUFVLFFBQWdCLE1BQVcsVUFBa0MsQ0FBQyxHQUFHO0FBQ3ZGLFFBQU0sT0FBTyxLQUFLLFVBQVUsSUFBSTtBQUNoQyxNQUFJLGFBQWE7QUFDakIsTUFBSSxVQUFVLGdCQUFnQixpQ0FBaUM7QUFDL0QsTUFBSSxVQUFVLDBCQUEwQixTQUFTO0FBQ2pELE1BQUksVUFBVSxtQkFBbUIsYUFBYTtBQUM5QyxNQUFJLFVBQVUsbUJBQW1CLE1BQU07QUFDdkMsTUFBSSxVQUFVLG9CQUFvQixlQUFlO0FBQ2pELGFBQVcsQ0FBQyxHQUFHLENBQUMsS0FBSyxPQUFPLFFBQVEsT0FBTyxFQUFHLEtBQUksVUFBVSxHQUFHLENBQUM7QUFDaEUsTUFBSSxJQUFJLElBQUk7QUFDZDtBQUVBLElBQU0sVUFBVSxDQUFDLFFBQWE7QUFDNUIsUUFBTSxRQUFTLElBQUksUUFBUSxtQkFBbUIsS0FBZ0I7QUFDOUQsU0FBTyxVQUFVLFdBQVksSUFBSSxVQUFXLElBQUksT0FBZTtBQUNqRTtBQUVBLFNBQVMsV0FBVyxNQUFjO0FBQ2hDLFFBQU0sSUFBSSxRQUFRLElBQUksSUFBSTtBQUMxQixNQUFJLENBQUMsRUFBRyxPQUFNLElBQUksTUFBTSxHQUFHLElBQUksVUFBVTtBQUN6QyxTQUFPO0FBQ1Q7QUFFQSxlQUFlLGNBQWNDLE9BQWMsU0FBYyxLQUFVO0FBQ2pFLFFBQU0sT0FBTyxXQUFXLGNBQWM7QUFDdEMsUUFBTSxPQUFPLFdBQVcsbUJBQW1CO0FBQzNDLFFBQU0sUUFBUyxJQUFJLFFBQVEsZUFBZSxLQUFnQjtBQUMxRCxRQUFNLFVBQWtDO0FBQUEsSUFDdEMsUUFBUTtBQUFBLElBQ1IsZ0JBQWdCO0FBQUEsRUFDbEI7QUFDQSxNQUFJLE1BQU8sU0FBUSxlQUFlLElBQUk7QUFDdEMsU0FBTyxNQUFNLEdBQUcsSUFBSSxHQUFHQSxLQUFJLElBQUksRUFBRSxHQUFHLFNBQVMsU0FBUyxFQUFFLEdBQUcsU0FBUyxHQUFJLFNBQVMsV0FBVyxDQUFDLEVBQUcsRUFBRSxDQUFDO0FBQ3JHO0FBRUEsU0FBUyxVQUFVLE1BQWM7QUFDL0IsU0FBTyxTQUFTLE9BQU8sV0FBVyxRQUFRLEVBQUUsT0FBTyxJQUFJLEVBQUUsT0FBTyxXQUFXLEVBQUUsTUFBTSxHQUFHLEVBQUU7QUFDMUY7QUFHQSxTQUFTLG9CQUFvQixNQUFjO0FBRXpDLFFBQU0saUJBQWlCLEtBQUssUUFBUSx3Q0FBd0MsR0FBRztBQUMvRSxRQUFNLGdCQUFnQixlQUFlLFFBQVEsc0NBQXNDLEdBQUc7QUFFdEYsUUFBTSxPQUFPLGNBQWMsUUFBUSxZQUFZLEdBQUc7QUFFbEQsU0FBTyxLQUFLLFFBQVEsd0NBQXdDLENBQUMsTUFBTTtBQUNqRSxZQUFRLEdBQUc7QUFBQSxNQUNULEtBQUs7QUFBVSxlQUFPO0FBQUEsTUFDdEIsS0FBSztBQUFTLGVBQU87QUFBQSxNQUNyQixLQUFLO0FBQVEsZUFBTztBQUFBLE1BQ3BCLEtBQUs7QUFBUSxlQUFPO0FBQUEsTUFDcEIsS0FBSztBQUFVLGVBQU87QUFBQSxNQUN0QixLQUFLO0FBQVMsZUFBTztBQUFBLE1BQ3JCO0FBQVMsZUFBTztBQUFBLElBQ2xCO0FBQUEsRUFDRixDQUFDLEVBQUUsUUFBUSxRQUFRLEdBQUcsRUFBRSxLQUFLO0FBQy9CO0FBRUEsZUFBZSxnQkFBZ0IsR0FBVztBQUN4QyxNQUFJO0FBQ0YsVUFBTSxNQUFNLE1BQU0sTUFBTSxHQUFHLEVBQUUsU0FBUyxFQUFFLGNBQWMscUJBQXFCLEVBQUUsQ0FBQztBQUM5RSxRQUFJLENBQUMsSUFBSSxHQUFJLFFBQU87QUFDcEIsVUFBTSxPQUFPLE1BQU0sSUFBSSxLQUFLO0FBQzVCLFdBQU8sb0JBQW9CLElBQUk7QUFBQSxFQUNqQyxTQUFTLEdBQUc7QUFDVixXQUFPO0FBQUEsRUFDVDtBQUNGO0FBRUEsU0FBUyxVQUFVLE1BQWMsV0FBVyxNQUFNO0FBQ2hELFFBQU0sYUFBYSxLQUFLLE1BQU0sZ0JBQWdCLEVBQUUsSUFBSSxPQUFLLEVBQUUsS0FBSyxDQUFDLEVBQUUsT0FBTyxPQUFPO0FBQ2pGLFFBQU0sU0FBbUIsQ0FBQztBQUMxQixNQUFJLE1BQU07QUFDVixhQUFXLEtBQUssWUFBWTtBQUMxQixTQUFLLE1BQU0sTUFBTSxHQUFHLFNBQVMsVUFBVTtBQUNyQyxVQUFJLEtBQUs7QUFBRSxlQUFPLEtBQUssSUFBSSxLQUFLLENBQUM7QUFBRyxjQUFNO0FBQUEsTUFBRyxPQUN4QztBQUFFLGVBQU8sS0FBSyxFQUFFLE1BQU0sR0FBRyxRQUFRLENBQUM7QUFBRyxjQUFNLEVBQUUsTUFBTSxRQUFRO0FBQUEsTUFBRztBQUFBLElBQ3JFLE9BQU87QUFDTCxhQUFPLE1BQU0sTUFBTSxHQUFHLEtBQUs7QUFBQSxJQUM3QjtBQUFBLEVBQ0Y7QUFDQSxNQUFJLElBQUssUUFBTyxLQUFLLElBQUksS0FBSyxDQUFDO0FBQy9CLFNBQU87QUFDVDtBQUVBLGVBQWUsWUFBWSxRQUE4QztBQUN2RSxRQUFNLE1BQU0sUUFBUSxJQUFJO0FBQ3hCLE1BQUksQ0FBQyxJQUFLLFFBQU87QUFDakIsTUFBSTtBQUNGLFVBQU0sT0FBTyxNQUFNLE1BQU0sd0NBQXdDO0FBQUEsTUFDL0QsUUFBUTtBQUFBLE1BQ1IsU0FBUyxFQUFFLGlCQUFpQixVQUFVLEdBQUcsSUFBSSxnQkFBZ0IsbUJBQW1CO0FBQUEsTUFDaEYsTUFBTSxLQUFLLFVBQVUsRUFBRSxPQUFPLFFBQVEsT0FBTyx5QkFBeUIsQ0FBQztBQUFBLElBQ3pFLENBQUM7QUFDRCxRQUFJLENBQUMsS0FBSyxHQUFJLFFBQU87QUFDckIsVUFBTSxJQUFJLE1BQU0sS0FBSyxLQUFLO0FBQzFCLFFBQUksQ0FBQyxFQUFFLEtBQU0sUUFBTztBQUNwQixXQUFPLEVBQUUsS0FBSyxJQUFJLENBQUMsTUFBVyxFQUFFLFNBQXFCO0FBQUEsRUFDdkQsU0FBUyxHQUFHO0FBQ1YsV0FBTztBQUFBLEVBQ1Q7QUFDRjtBQUVBLGVBQWUsZ0JBQWdCLE9BQWUsTUFBVyxLQUFVO0FBQ2pFLFFBQU0sTUFBTSxLQUFLLE9BQU87QUFDeEIsUUFBTSxRQUFrQixNQUFNLFFBQVEsS0FBSyxLQUFLLElBQUksS0FBSyxRQUFRLENBQUM7QUFDbEUsUUFBTSxXQUFXLE9BQU8sTUFBTSxLQUFLLEdBQUcsS0FBSyxLQUFLLElBQUk7QUFDcEQsUUFBTSxRQUFRLFVBQVUsT0FBTztBQUcvQixRQUFNLE9BQThDLENBQUM7QUFFckQsTUFBSSxLQUFLO0FBQ1AsVUFBTSxPQUFPLE1BQU0sZ0JBQWdCLEdBQUc7QUFDdEMsUUFBSSxLQUFNLE1BQUssS0FBSyxFQUFFLFFBQVEsS0FBSyxTQUFTLEtBQUssQ0FBQztBQUFBLEVBQ3BEO0FBR0EsYUFBV0EsU0FBUSxPQUFPO0FBQ3hCLFFBQUk7QUFDRixZQUFNLGVBQWUsUUFBUSxJQUFJO0FBQ2pDLFlBQU0sa0JBQWtCLGVBQWUsc0NBQXNDLG1CQUFtQkEsS0FBSSxDQUFDO0FBQ3JHLFlBQU0sTUFBTSxNQUFNLE1BQU0sZUFBZTtBQUN2QyxVQUFJLENBQUMsSUFBSSxHQUFJO0FBQ2IsWUFBTSxNQUFNLE1BQU0sSUFBSSxZQUFZO0FBRWxDLFlBQU0sU0FBUyxPQUFPLGFBQWEsTUFBTSxNQUFNLElBQUksV0FBVyxJQUFJLE1BQU0sR0FBRyxDQUFDLENBQUMsQ0FBUTtBQUNyRixVQUFJLE9BQU8sU0FBUyxNQUFNLEdBQUc7QUFFM0IsYUFBSyxLQUFLLEVBQUUsUUFBUUEsT0FBTSxTQUFTLHdDQUF3QyxDQUFDO0FBQUEsTUFDOUUsT0FBTztBQUNMLGNBQU0sT0FBTyxJQUFJLFlBQVksRUFBRSxPQUFPLEdBQUc7QUFDekMsY0FBTSxVQUFVLG9CQUFvQixJQUFJO0FBQ3hDLGFBQUssS0FBSyxFQUFFLFFBQVFBLE9BQU0sU0FBUyxXQUFXLGdCQUFnQixDQUFDO0FBQUEsTUFDakU7QUFBQSxJQUNGLFNBQVMsR0FBRztBQUFFO0FBQUEsSUFBVTtBQUFBLEVBQzFCO0FBR0EsYUFBVyxPQUFPLE1BQU07QUFDdEIsVUFBTSxTQUFTLFVBQVUsSUFBSSxPQUFPO0FBQ3BDLFVBQU0sYUFBYSxNQUFNLFlBQVksTUFBTTtBQUczQyxhQUFTLElBQUksR0FBRyxJQUFJLE9BQU8sUUFBUSxLQUFLO0FBQ3RDLFlBQU0sUUFBUSxPQUFPLENBQUM7QUFDdEIsWUFBTSxNQUFNLGFBQWEsV0FBVyxDQUFDLElBQUk7QUFDekMsVUFBSTtBQUNGLGNBQU0sY0FBYywrQkFBK0I7QUFBQSxVQUNqRCxRQUFRO0FBQUEsVUFDUixNQUFNLEtBQUssVUFBVSxFQUFFLFFBQVEsT0FBTyxRQUFRLElBQUksUUFBUSxTQUFTLE9BQU8sV0FBVyxJQUFJLENBQUM7QUFBQSxVQUMxRixTQUFTLEVBQUUsUUFBUSx5QkFBeUIsZ0JBQWdCLG1CQUFtQjtBQUFBLFFBQ2pGLEdBQUcsR0FBRyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBQUEsTUFDMUIsUUFBUTtBQUFBLE1BQUM7QUFBQSxJQUNYO0FBQUEsRUFDRjtBQUdBLE1BQUk7QUFDRixVQUFNLGNBQWMsMEJBQTBCO0FBQUEsTUFDNUMsUUFBUTtBQUFBLE1BQ1IsTUFBTSxLQUFLLFVBQVUsRUFBRSxRQUFRLHNCQUFzQixTQUFTLEVBQUUsT0FBTyxPQUFPLE1BQU0sS0FBSyxPQUFPLEVBQUUsQ0FBQztBQUFBLElBQ3JHLEdBQUcsR0FBRyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBQUEsRUFDMUIsUUFBUTtBQUFBLEVBQUM7QUFDWDtBQUVBLGVBQWUseUJBQXlCLFFBQWdCLEtBQVU7QUFFaEUsTUFBSTtBQUNGLFVBQU0sTUFBTSxNQUFNLGNBQWMsOEJBQThCLG1CQUFtQixNQUFNLENBQUMsSUFBSSxFQUFFLFFBQVEsTUFBTSxHQUFHLEdBQUc7QUFDbEgsUUFBSSxPQUFRLElBQVksSUFBSTtBQUMxQixZQUFNLElBQUksTUFBTyxJQUFpQixLQUFLLEVBQUUsTUFBTSxNQUFNLENBQUMsQ0FBQztBQUN2RCxVQUFJLE1BQU0sUUFBUSxDQUFDLEtBQUssRUFBRSxTQUFTLEtBQUssRUFBRSxDQUFDLEVBQUUsU0FBVSxRQUFPLEVBQUUsVUFBVSxLQUFLO0FBQUEsSUFDakY7QUFBQSxFQUNGLFFBQVE7QUFBQSxFQUFDO0FBR1QsUUFBTSxRQUFRLE9BQU8sWUFBWSxFQUFFLEVBQUUsU0FBUyxXQUFXO0FBQ3pELFFBQU0sU0FBUyxRQUFRLElBQUksOEJBQThCO0FBQ3pELFFBQU0sWUFBWSxPQUFPLFdBQVcsUUFBUSxFQUFFLE9BQU8sUUFBUSxNQUFNLEVBQUUsT0FBTyxRQUFRO0FBQ3BGLFFBQU0sVUFBVSxJQUFJLEtBQUssS0FBSyxJQUFJLElBQUksTUFBTyxLQUFLLEVBQUUsRUFBRSxZQUFZO0FBQ2xFLE1BQUksWUFBMkI7QUFDL0IsTUFBSTtBQUNGLFVBQU0sTUFBTSxNQUFNLGNBQWMsaUNBQWlDO0FBQUEsTUFDL0QsUUFBUTtBQUFBLE1BQ1IsTUFBTSxLQUFLLFVBQVUsRUFBRSxRQUFRLFlBQVksV0FBVyxZQUFZLFNBQVMsU0FBUyxLQUFLLENBQUM7QUFBQSxNQUMxRixTQUFTLEVBQUUsUUFBUSx5QkFBeUIsZ0JBQWdCLG1CQUFtQjtBQUFBLElBQ2pGLEdBQUcsR0FBRyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBQ3hCLFFBQUksT0FBUSxJQUFZLElBQUk7QUFDMUIsWUFBTSxJQUFJLE1BQU8sSUFBaUIsS0FBSyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBQ3pELFVBQUksTUFBTSxRQUFRLENBQUMsS0FBSyxFQUFFLFNBQVMsS0FBSyxFQUFFLENBQUMsRUFBRSxHQUFJLGFBQVksRUFBRSxDQUFDLEVBQUU7QUFBQSxlQUN6RCxLQUFLLEVBQUUsR0FBSSxhQUFZLEVBQUU7QUFBQSxJQUNwQztBQUFBLEVBQ0YsUUFBUTtBQUFBLEVBQUM7QUFFVCxTQUFPLEVBQUUsVUFBVSxPQUFPLE9BQU8sU0FBUyxVQUFVO0FBQ3REO0FBRUEsU0FBUyxrQkFBa0IsT0FBZTtBQUN4QyxNQUFJO0FBQ0YsVUFBTSxlQUFlLFFBQVEsSUFBSSx1QkFBdUI7QUFDeEQsVUFBTSxRQUFRLE1BQU0sTUFBTSxHQUFHO0FBQzdCLFFBQUksTUFBTSxXQUFXLEVBQUcsUUFBTztBQUMvQixVQUFNLFdBQVcsTUFBTSxDQUFDLElBQUksTUFBTSxNQUFNLENBQUM7QUFDekMsVUFBTSxNQUFNLE1BQU0sQ0FBQztBQUNuQixVQUFNLFdBQVcsT0FBTyxXQUFXLFVBQVUsWUFBWSxFQUFFLE9BQU8sUUFBUSxFQUFFLE9BQU8sV0FBVztBQUM5RixRQUFJLFFBQVEsU0FBVSxRQUFPO0FBQzdCLFVBQU0sVUFBVSxLQUFLLE1BQU0sT0FBTyxLQUFLLE1BQU0sQ0FBQyxHQUFHLFdBQVcsRUFBRSxTQUFTLE1BQU0sQ0FBQztBQUM5RSxXQUFPO0FBQUEsRUFDVCxTQUFTLEdBQUc7QUFBRSxXQUFPO0FBQUEsRUFBTTtBQUM3QjtBQUdBLElBQU0sVUFBVSxvQkFBSSxJQUEyQztBQUMvRCxTQUFTLFVBQVUsS0FBYSxPQUFlLFVBQWtCO0FBQy9ELFFBQU0sTUFBTSxLQUFLLElBQUk7QUFDckIsUUFBTSxNQUFNLFFBQVEsSUFBSSxHQUFHO0FBQzNCLE1BQUksQ0FBQyxPQUFPLE1BQU0sSUFBSSxLQUFLLFVBQVU7QUFDbkMsWUFBUSxJQUFJLEtBQUssRUFBRSxPQUFPLEdBQUcsSUFBSSxJQUFJLENBQUM7QUFDdEMsV0FBTztBQUFBLEVBQ1Q7QUFDQSxNQUFJLElBQUksUUFBUSxPQUFPO0FBQ3JCLFFBQUksU0FBUztBQUNiLFdBQU87QUFBQSxFQUNUO0FBQ0EsU0FBTztBQUNUO0FBRU8sU0FBUyxrQkFBMEI7QUFDeEMsU0FBTztBQUFBLElBQ0wsTUFBTTtBQUFBLElBQ04sZ0JBQWdCLFFBQVE7QUFDdEIsYUFBTyxZQUFZLElBQUksT0FBTyxLQUFLLEtBQUssU0FBUztBQUMvQyxZQUFJLENBQUMsSUFBSSxPQUFPLENBQUMsSUFBSSxJQUFJLFdBQVcsT0FBTyxFQUFHLFFBQU8sS0FBSztBQUcxRCxjQUFNLGFBQWEsSUFBSSxRQUFRLFVBQVU7QUFDekMsWUFBSSxVQUFVLHNCQUFzQiwwQ0FBMEM7QUFDOUUsWUFBSSxVQUFVLGdDQUFnQyxhQUFhO0FBRzNELFlBQUksUUFBUSxJQUFJLGFBQWEsZ0JBQWdCLENBQUMsUUFBUSxHQUFHLEdBQUc7QUFDMUQsaUJBQU8sS0FBSyxLQUFLLEtBQUssRUFBRSxPQUFPLGlCQUFpQixHQUFHLEVBQUUsK0JBQStCLE9BQU8sVUFBVSxFQUFFLENBQUM7QUFBQSxRQUMxRztBQUdBLFlBQUksSUFBSSxXQUFXLFdBQVc7QUFDNUIsY0FBSSxVQUFVLCtCQUErQixPQUFPLFVBQVUsQ0FBQztBQUMvRCxjQUFJLFVBQVUsZ0NBQWdDLGtCQUFrQjtBQUNoRSxjQUFJLFVBQVUsZ0NBQWdDLDZCQUE2QjtBQUMzRSxjQUFJLGFBQWE7QUFDakIsaUJBQU8sSUFBSSxJQUFJO0FBQUEsUUFDakI7QUFFQSxjQUFNLFVBQVUsQ0FBQyxRQUFnQixTQUFjLEtBQUssS0FBSyxRQUFRLE1BQU0sRUFBRSwrQkFBK0IsT0FBTyxVQUFVLEVBQUUsQ0FBQztBQUU1SCxZQUFJO0FBQ0YsY0FBSSxJQUFJLFFBQVEsZ0JBQWdCLElBQUksV0FBVyxRQUFRO0FBQ3JELGtCQUFNLEtBQU0sSUFBSSxRQUFRLGlCQUFpQixLQUFnQixJQUFJLE9BQU8saUJBQWlCO0FBQ3JGLGdCQUFJLENBQUMsVUFBVSxXQUFXLElBQUksSUFBSSxHQUFNLEVBQUcsUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLG9CQUFvQixDQUFDO0FBQzdGLGtCQUFNLE9BQU8sTUFBTSxVQUFVLEdBQUcsRUFBRSxNQUFNLE9BQU8sQ0FBQyxFQUFFO0FBQ2xELGtCQUFNLE1BQU0sT0FBTyxNQUFNLFFBQVEsV0FBVyxLQUFLLElBQUksS0FBSyxJQUFJO0FBQzlELGdCQUFJLENBQUMsT0FBTyxDQUFDLE1BQU0sUUFBUSxNQUFNLEtBQUssR0FBRztBQUN2QyxxQkFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLHVCQUF1QixDQUFDO0FBQUEsWUFDdkQ7QUFDQSxnQkFBSSxLQUFLO0FBQ1Asa0JBQUk7QUFDRixzQkFBTSxJQUFJLElBQUksSUFBSSxHQUFHO0FBQ3JCLG9CQUFJLEVBQUUsRUFBRSxhQUFhLFdBQVcsRUFBRSxhQUFhLFVBQVcsT0FBTSxJQUFJLE1BQU0sU0FBUztBQUFBLGNBQ3JGLFFBQVE7QUFDTix1QkFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLGNBQWMsQ0FBQztBQUFBLGNBQzlDO0FBQUEsWUFDRjtBQUdBLGtCQUFNLGNBQWMsMEJBQTBCO0FBQUEsY0FDNUMsUUFBUTtBQUFBLGNBQ1IsTUFBTSxLQUFLLFVBQVUsRUFBRSxRQUFRLGlCQUFpQixTQUFTLEVBQUUsUUFBUSxDQUFDLENBQUMsS0FBSyxXQUFZLE1BQU0sT0FBTyxVQUFXLEVBQUUsRUFBRSxDQUFDO0FBQUEsWUFDckgsR0FBRyxHQUFHLEVBQUUsTUFBTSxNQUFNLElBQUk7QUFFeEIsa0JBQU0sUUFBUSxXQUFXLE9BQU8sTUFBTSxLQUFLLElBQUksQ0FBQztBQUdoRCxhQUFDLFlBQVk7QUFDWCxrQkFBSTtBQUNGLHNCQUFNLGdCQUFnQixPQUFPLEVBQUUsS0FBSyxPQUFPLE1BQU0sUUFBUSxNQUFNLEtBQUssSUFBSSxLQUFLLFFBQVEsQ0FBQyxFQUFFLEdBQUcsR0FBRztBQUFBLGNBQ2hHLFNBQVMsR0FBRztBQUNWLG9CQUFJO0FBQ0Ysd0JBQU0sY0FBYywwQkFBMEI7QUFBQSxvQkFDNUMsUUFBUTtBQUFBLG9CQUNSLE1BQU0sS0FBSyxVQUFVLEVBQUUsUUFBUSxtQkFBbUIsU0FBUyxFQUFFLE9BQU8sT0FBTyxPQUFPLEdBQUcsV0FBVyxDQUFDLEVBQUUsRUFBRSxDQUFDO0FBQUEsa0JBQ3hHLEdBQUcsR0FBRztBQUFBLGdCQUNSLFFBQVE7QUFBQSxnQkFBQztBQUFBLGNBQ1g7QUFBQSxZQUNGLEdBQUc7QUFFSCxtQkFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLFFBQVEsU0FBUyxDQUFDO0FBQUEsVUFDakQ7QUFFQSxjQUFJLElBQUksUUFBUSxrQkFBa0IsSUFBSSxXQUFXLFFBQVE7QUFDdkQsa0JBQU0sT0FBTyxNQUFNLFVBQVUsR0FBRztBQUNoQyxnQkFBSSxNQUFNLFlBQVksVUFBVyxRQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sc0JBQXNCLENBQUM7QUFDckYsa0JBQU0sVUFBVSxNQUFNLE9BQU8sSUFBSSxLQUFLO0FBQ3RDLGtCQUFNLFVBQVUsTUFBTTtBQUNwQixrQkFBSTtBQUFFLHVCQUFPLFNBQVMsSUFBSSxJQUFJLE1BQU0sRUFBRSxPQUFPO0FBQUEsY0FBUyxRQUFRO0FBQUUsdUJBQU87QUFBQSxjQUFTO0FBQUEsWUFDbEYsR0FBRztBQUdILGtCQUFNLE9BQU8sTUFBTSx5QkFBeUIsUUFBUSxHQUFHO0FBQ3ZELGdCQUFJLENBQUMsS0FBSyxVQUFVO0FBRWxCLHFCQUFPLFFBQVEsS0FBSyxFQUFFLFFBQVEseUJBQXlCLGNBQWMsa0RBQWtELEtBQUssS0FBSyxJQUFJLE9BQU8sS0FBSyxPQUFPLFNBQVMsS0FBSyxXQUFXLEtBQUssQ0FBQztBQUFBLFlBQ3pMO0FBRUEsa0JBQU0sT0FBTyxTQUFTLE9BQU8sSUFBSSxRQUFRLGVBQWUsS0FBSztBQUM3RCxrQkFBTSxRQUFRLFVBQVUsSUFBSTtBQUc1QixrQkFBTSxjQUFjLDRCQUE0QjtBQUFBLGNBQzlDLFFBQVE7QUFBQSxjQUNSLE1BQU0sS0FBSyxVQUFVLEVBQUUsUUFBUSxPQUFPLFNBQVMsV0FBVyxRQUFRLFVBQVUsQ0FBQyxFQUFFLENBQUM7QUFBQSxjQUNoRixTQUFTLEVBQUUsUUFBUSw4QkFBOEI7QUFBQSxZQUNuRCxHQUFHLEdBQUcsRUFBRSxNQUFNLE1BQU0sSUFBSTtBQUd4QixrQkFBTSxnQkFBZ0IsRUFBRSxPQUFPLFFBQVEsS0FBSyxLQUFLLE1BQU0sS0FBSyxJQUFJLElBQUUsR0FBSSxFQUFFO0FBQ3hFLGtCQUFNLGVBQWUsUUFBUSxJQUFJLHVCQUF1QjtBQUN4RCxrQkFBTSxTQUFTLEVBQUUsS0FBSyxTQUFTLEtBQUssTUFBTTtBQUMxQyxrQkFBTSxNQUFNLENBQUMsTUFBYyxPQUFPLEtBQUssQ0FBQyxFQUFFLFNBQVMsV0FBVztBQUM5RCxrQkFBTSxXQUFXLElBQUksS0FBSyxVQUFVLE1BQU0sQ0FBQyxJQUFJLE1BQU0sSUFBSSxLQUFLLFVBQVUsYUFBYSxDQUFDO0FBQ3RGLGtCQUFNLE1BQU0sT0FBTyxXQUFXLFVBQVUsWUFBWSxFQUFFLE9BQU8sUUFBUSxFQUFFLE9BQU8sV0FBVztBQUN6RixrQkFBTSxjQUFjLFdBQVcsTUFBTTtBQUVyQyxtQkFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLFlBQVksQ0FBQztBQUFBLFVBQzVDO0FBR0EsY0FBSSxJQUFJLEtBQUssV0FBVyxvQkFBb0IsS0FBSyxJQUFJLFdBQVcsT0FBTztBQUNyRSxrQkFBTSxTQUFTLElBQUksSUFBSSxJQUFJLEtBQUssY0FBYztBQUM5QyxrQkFBTSxRQUFRLE9BQU8sYUFBYSxJQUFJLE9BQU8sS0FBSztBQUNsRCxrQkFBTSxRQUFRLE9BQU8sYUFBYSxJQUFJLE9BQU8sS0FBSztBQUNsRCxnQkFBSSxDQUFDLE1BQU8sUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLGdCQUFnQixDQUFDO0FBQzFELGtCQUFNLFVBQVUsa0JBQWtCLEtBQUs7QUFDdkMsZ0JBQUksQ0FBQyxXQUFXLFFBQVEsVUFBVSxNQUFPLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxnQkFBZ0IsQ0FBQztBQUN2RixnQkFBSTtBQUNGLG9CQUFNLElBQUksTUFBTSxjQUFjLHdDQUF3QyxtQkFBbUIsS0FBSyxJQUFJLGFBQWEsRUFBRSxRQUFRLE1BQU0sR0FBRyxHQUFHLEVBQUUsTUFBTSxNQUFNLElBQUk7QUFDdkosa0JBQUksQ0FBQyxLQUFLLENBQUUsRUFBVSxHQUFJLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxZQUFZLENBQUM7QUFDcEUsb0JBQU0sT0FBTyxNQUFPLEVBQWUsS0FBSyxFQUFFLE1BQU0sTUFBTSxDQUFDLENBQUM7QUFDeEQsb0JBQU0sTUFBTSxNQUFNLFFBQVEsSUFBSSxLQUFLLEtBQUssU0FBUyxJQUFJLEtBQUssQ0FBQyxJQUFJLEVBQUUsVUFBVSxDQUFDLEVBQUU7QUFDOUUscUJBQU8sUUFBUSxLQUFLLEVBQUUsVUFBVSxJQUFJLENBQUM7QUFBQSxZQUN2QyxTQUFTLEdBQUc7QUFBRSxxQkFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLGVBQWUsQ0FBQztBQUFBLFlBQUc7QUFBQSxVQUNoRTtBQUVBLGNBQUksSUFBSSxRQUFRLHNCQUFzQixJQUFJLFdBQVcsUUFBUTtBQUMzRCxrQkFBTSxPQUFPLE1BQU0sVUFBVSxHQUFHLEVBQUUsTUFBTSxPQUFPLENBQUMsRUFBRTtBQUNsRCxrQkFBTSxTQUFTLE9BQU8sTUFBTSxPQUFPLEVBQUUsRUFBRSxLQUFLO0FBQzVDLGdCQUFJLENBQUMsT0FBUSxRQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sY0FBYyxDQUFDO0FBQ3pELGdCQUFJO0FBQ0Ysb0JBQU0sSUFBSSxJQUFJLElBQUksTUFBTTtBQUN4QixrQkFBSSxFQUFFLEVBQUUsYUFBYSxXQUFXLEVBQUUsYUFBYSxVQUFXLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxtQkFBbUIsQ0FBQztBQUFBLFlBQzdHLFNBQVMsR0FBRztBQUNWLHFCQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sY0FBYyxDQUFDO0FBQUEsWUFDOUM7QUFDQSxnQkFBSTtBQUNGLG9CQUFNLElBQUksTUFBTSxNQUFNLFFBQVEsRUFBRSxTQUFTLEVBQUUsY0FBYyxzQkFBc0IsRUFBRSxDQUFDO0FBQ2xGLGtCQUFJLENBQUMsS0FBSyxDQUFDLEVBQUUsR0FBSSxRQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sZ0JBQWdCLFFBQVEsSUFBSSxFQUFFLFNBQVMsRUFBRSxDQUFDO0FBQ3hGLG9CQUFNLE9BQU8sTUFBTSxFQUFFLEtBQUs7QUFFMUIscUJBQU8sUUFBUSxLQUFLLEVBQUUsSUFBSSxNQUFNLEtBQUssUUFBUSxTQUFTLEtBQUssTUFBTSxHQUFHLEdBQUssRUFBRSxDQUFDO0FBQUEsWUFDOUUsU0FBUyxHQUFRO0FBQ2YscUJBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxlQUFlLFNBQVMsT0FBTyxHQUFHLFdBQVcsQ0FBQyxFQUFFLENBQUM7QUFBQSxZQUNoRjtBQUFBLFVBQ0Y7QUFHQSxjQUFJLElBQUksS0FBSyxXQUFXLG1CQUFtQixNQUFNLElBQUksV0FBVyxTQUFTLElBQUksV0FBVyxTQUFTO0FBQy9GLGdCQUFJLFFBQVEsSUFBSSxhQUFhLGNBQWUsUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLFlBQVksQ0FBQztBQUV0RixnQkFBSSxTQUFTO0FBQ2IsZ0JBQUksSUFBSSxXQUFXLE9BQU87QUFDeEIsa0JBQUk7QUFBRSxzQkFBTSxJQUFJLElBQUksSUFBSSxJQUFJLEtBQUssY0FBYztBQUFHLHlCQUFTLEVBQUUsYUFBYSxJQUFJLFFBQVEsS0FBSztBQUFBLGNBQUksUUFBUTtBQUFBLGNBQUM7QUFBQSxZQUMxRyxPQUFPO0FBQ0wsb0JBQU0sSUFBSSxNQUFNLFVBQVUsR0FBRyxFQUFFLE1BQU0sT0FBTyxDQUFDLEVBQUU7QUFBRyx1QkFBUyxPQUFPLEdBQUcsVUFBVSxFQUFFO0FBQUEsWUFDbkY7QUFDQSxnQkFBSSxDQUFDLE9BQVEsUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLGlCQUFpQixDQUFDO0FBQzVELGdCQUFJO0FBQ0Ysb0JBQU0sSUFBSSwyQ0FBMkMsbUJBQW1CLE1BQU0sQ0FBQztBQUMvRSxvQkFBTSxJQUFJLE1BQU0sY0FBYyxHQUFHLEVBQUUsUUFBUSxNQUFNLEdBQUcsR0FBRyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBQ3pFLGtCQUFJLENBQUMsS0FBSyxDQUFFLEVBQVUsR0FBSSxRQUFPLFFBQVEsS0FBSyxFQUFFLFFBQVEsQ0FBQyxFQUFFLENBQUM7QUFDNUQsb0JBQU0sTUFBTSxNQUFPLEVBQWUsS0FBSyxFQUFFLE1BQU0sTUFBTSxDQUFDLENBQUM7QUFDdkQscUJBQU8sUUFBUSxLQUFLLEVBQUUsUUFBUSxNQUFNLFFBQVEsR0FBRyxJQUFJLE1BQU0sQ0FBQyxFQUFFLENBQUM7QUFBQSxZQUMvRCxTQUFTLEdBQUc7QUFDVixxQkFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLGVBQWUsQ0FBQztBQUFBLFlBQy9DO0FBQUEsVUFDRjtBQUVBLGNBQUksSUFBSSxRQUFRLHdCQUF3QixJQUFJLFdBQVcsUUFBUTtBQUM3RCxrQkFBTSxPQUFPLE1BQU0sVUFBVSxHQUFHLEVBQUUsTUFBTSxPQUFPLENBQUMsRUFBRTtBQUNsRCxrQkFBTSxTQUFTLE9BQU8sTUFBTSxVQUFVLEVBQUUsRUFBRSxLQUFLO0FBQy9DLGtCQUFNLFFBQVEsT0FBTyxNQUFNLFNBQVMsRUFBRSxFQUFFLEtBQUs7QUFDN0Msa0JBQU0sVUFBVSxPQUFPLE1BQU0sV0FBVyxFQUFFLEVBQUUsS0FBSztBQUNqRCxnQkFBSSxDQUFDLFVBQVUsQ0FBQyxTQUFTLENBQUMsUUFBUyxRQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sbUNBQW1DLENBQUM7QUFHcEcsa0JBQU0sYUFBYTtBQUFBLGNBQ2pCLFdBQVcsTUFBTTtBQUFBLGNBQ2pCLFVBQVUsTUFBTTtBQUFBLGNBQ2hCLFdBQVcsTUFBTTtBQUFBLGNBQ2pCLFVBQVUsTUFBTTtBQUFBLGNBQ2hCLFdBQVcsTUFBTTtBQUFBLGNBQ2pCLFVBQVUsTUFBTTtBQUFBLFlBQ2xCO0FBR0Esa0JBQU0sTUFBTSxDQUFDLE1BQWMsRUFBRSxRQUFRLHlCQUF5QixNQUFNO0FBQ3BFLGtCQUFNLE9BQU8sSUFBSSxLQUFLO0FBQ3RCLGtCQUFNLFNBQVMsSUFBSSxPQUFPLGlGQUF3RixJQUFJLHdCQUE0QixJQUFJLDBEQUErRCxHQUFHO0FBQ3hOLGtCQUFNLFVBQVUsSUFBSSxPQUFPLG9DQUFxQyxJQUFJLElBQUksR0FBRztBQUUzRSxnQkFBSSxRQUFRO0FBQ1osdUJBQVcsT0FBTyxZQUFZO0FBQzVCLGtCQUFJO0FBQ0Ysc0JBQU0sSUFBSSxNQUFNLE1BQU0sS0FBSyxFQUFFLFNBQVMsRUFBRSxjQUFjLHNCQUFzQixFQUFFLENBQUM7QUFDL0Usb0JBQUksQ0FBQyxLQUFLLENBQUMsRUFBRSxHQUFJO0FBQ2pCLHNCQUFNLE9BQU8sTUFBTSxFQUFFLEtBQUs7QUFDMUIsb0JBQUksT0FBTyxLQUFLLElBQUksS0FBSyxRQUFRLEtBQUssSUFBSSxHQUFHO0FBQzNDLDBCQUFRO0FBQ1I7QUFBQSxnQkFDRjtBQUFBLGNBQ0YsU0FBUyxHQUFHO0FBQUEsY0FFWjtBQUFBLFlBQ0Y7QUFFQSxnQkFBSSxDQUFDLE1BQU8sUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLHVDQUF1QyxDQUFDO0FBR2pGLGdCQUFJO0FBQ0Ysb0JBQU0sVUFBUyxvQkFBSSxLQUFLLEdBQUUsWUFBWTtBQUN0QyxvQkFBTSxTQUFTLFFBQVEsSUFBSSw4QkFBOEI7QUFDekQsb0JBQU0sWUFBWSxPQUFPLFdBQVcsUUFBUSxFQUFFLE9BQU8sUUFBUSxNQUFNLEVBQUUsT0FBTyxRQUFRO0FBRXBGLG9CQUFNLElBQUksdUNBQXVDLG1CQUFtQixPQUFPLENBQUMsY0FBYyxtQkFBbUIsTUFBTSxDQUFDLGtCQUFrQixtQkFBbUIsU0FBUyxDQUFDLGtCQUFrQixtQkFBbUIsTUFBTSxDQUFDO0FBQy9NLG9CQUFNLEtBQUssTUFBTSxjQUFjLEdBQUcsRUFBRSxRQUFRLE1BQU0sR0FBRyxHQUFHLEVBQUUsTUFBTSxNQUFNLElBQUk7QUFDMUUsa0JBQUksQ0FBQyxNQUFNLENBQUUsR0FBVyxHQUFJLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTywyQkFBMkIsQ0FBQztBQUNyRixvQkFBTSxPQUFPLE1BQU8sR0FBZ0IsS0FBSyxFQUFFLE1BQU0sTUFBTSxDQUFDLENBQUM7QUFDekQsa0JBQUksQ0FBQyxNQUFNLFFBQVEsSUFBSSxLQUFLLEtBQUssV0FBVyxFQUFHLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTywyQkFBMkIsQ0FBQztBQUd4RyxvQkFBTSxLQUFLLEtBQUssQ0FBQyxFQUFFO0FBQ25CLG9CQUFNLGNBQWMseUNBQXlDLG1CQUFtQixFQUFFLEdBQUc7QUFBQSxnQkFDbkYsUUFBUTtBQUFBLGdCQUNSLE1BQU0sS0FBSyxVQUFVLEVBQUUsVUFBUyxvQkFBSSxLQUFLLEdBQUUsWUFBWSxFQUFFLENBQUM7QUFBQSxnQkFDMUQsU0FBUyxFQUFFLGdCQUFnQixtQkFBbUI7QUFBQSxjQUNoRCxHQUFHLEdBQUcsRUFBRSxNQUFNLE1BQU0sSUFBSTtBQUV4QixvQkFBTSxjQUFjLG9CQUFvQjtBQUFBLGdCQUN0QyxRQUFRO0FBQUEsZ0JBQ1IsTUFBTSxLQUFLLFVBQVUsRUFBRSxRQUFRLFVBQVUsTUFBTSxjQUFhLG9CQUFJLEtBQUssR0FBRSxZQUFZLEVBQUUsQ0FBQztBQUFBLGdCQUN0RixTQUFTLEVBQUUsUUFBUSwrQkFBK0IsZ0JBQWdCLG1CQUFtQjtBQUFBLGNBQ3ZGLEdBQUcsR0FBRyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBQUEsWUFDMUIsUUFBUTtBQUFBLFlBQUM7QUFFVCxtQkFBTyxRQUFRLEtBQUssRUFBRSxJQUFJLE1BQU0sT0FBTyxDQUFDO0FBQUEsVUFDMUM7QUFFQSxjQUFJLElBQUksUUFBUSxpQkFBaUIsSUFBSSxXQUFXLFFBQVE7QUFDdEQsa0JBQU0sT0FBTyxNQUFNLFVBQVUsR0FBRztBQUNoQyxrQkFBTSxRQUFRLE9BQU8sTUFBTSxTQUFTLEVBQUUsRUFBRSxLQUFLO0FBQzdDLGdCQUFJLENBQUMsTUFBTyxRQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sZ0JBQWdCLENBQUM7QUFDMUQsa0JBQU0sZ0JBQWdCLE1BQU0saUJBQWlCLENBQUM7QUFFOUMsa0JBQU0sY0FBYyx3Q0FBd0MsbUJBQW1CLEtBQUssR0FBRztBQUFBLGNBQ3JGLFFBQVE7QUFBQSxjQUNSLE1BQU0sS0FBSyxVQUFVLEVBQUUsVUFBVSxjQUFjLENBQUM7QUFBQSxjQUNoRCxTQUFTLEVBQUUsZ0JBQWdCLG9CQUFvQixRQUFRLHdCQUF3QjtBQUFBLFlBQ2pGLEdBQUcsR0FBRyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBRXhCLG1CQUFPLFFBQVEsS0FBSyxFQUFFLE1BQU0sQ0FBQztBQUFBLFVBQy9CO0FBRUEsY0FBSSxJQUFJLFFBQVEsZUFBZSxJQUFJLFdBQVcsUUFBUTtBQUNwRCxrQkFBTSxLQUFNLElBQUksUUFBUSxpQkFBaUIsS0FBZ0IsSUFBSSxPQUFPLGlCQUFpQjtBQUNyRixnQkFBSSxDQUFDLFVBQVUsVUFBVSxJQUFJLElBQUksR0FBTSxFQUFHLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxvQkFBb0IsQ0FBQztBQUM1RixrQkFBTSxPQUFPLE1BQU0sVUFBVSxHQUFHLEVBQUUsTUFBTSxPQUFPLENBQUMsRUFBRTtBQUNsRCxrQkFBTSxVQUFVLE9BQU8sTUFBTSxXQUFXLEVBQUUsRUFBRSxNQUFNLEdBQUcsR0FBSTtBQUN6RCxnQkFBSSxDQUFDLFFBQVMsUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLGdCQUFnQixDQUFDO0FBRTVELGtCQUFNLGNBQWMsMEJBQTBCO0FBQUEsY0FDNUMsUUFBUTtBQUFBLGNBQ1IsTUFBTSxLQUFLLFVBQVUsRUFBRSxRQUFRLFFBQVEsU0FBUyxFQUFFLEtBQUssUUFBUSxPQUFPLEVBQUUsQ0FBQztBQUFBLFlBQzNFLEdBQUcsR0FBRyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBRXhCLGtCQUFNLFFBQVE7QUFDZCxtQkFBTyxRQUFRLEtBQUssRUFBRSxNQUFNLENBQUM7QUFBQSxVQUMvQjtBQUdBLGNBQUksSUFBSSxRQUFRLHNCQUFzQixJQUFJLFdBQVcsUUFBUTtBQUMzRCxrQkFBTSxLQUFNLElBQUksUUFBUSxpQkFBaUIsS0FBZ0IsSUFBSSxPQUFPLGlCQUFpQjtBQUNyRixnQkFBSSxDQUFDLFVBQVUsWUFBWSxJQUFJLEdBQUcsS0FBRyxHQUFNLEVBQUcsUUFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLG9CQUFvQixDQUFDO0FBQ2hHLGtCQUFNLE9BQU8sTUFBTSxVQUFVLEdBQUcsRUFBRSxNQUFNLE9BQU8sQ0FBQyxFQUFFO0FBQ2xELGtCQUFNLFFBQVEsT0FBTyxNQUFNLFNBQVMsRUFBRSxFQUFFLEtBQUssRUFBRSxZQUFZO0FBQzNELGdCQUFJLENBQUMsNkJBQTZCLEtBQUssS0FBSyxFQUFHLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxnQkFBZ0IsQ0FBQztBQUc3RixrQkFBTSxPQUFPLE1BQU0sY0FBYyxpQkFBaUIsRUFBRSxRQUFRLE1BQU0sR0FBRyxHQUFHLEVBQUUsTUFBTSxNQUFNLElBQUk7QUFDMUYsZ0JBQUksQ0FBQyxRQUFRLENBQUUsS0FBYSxHQUFJLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxlQUFlLENBQUM7QUFDN0Usa0JBQU0sT0FBTyxNQUFPLEtBQWtCLEtBQUssRUFBRSxNQUFNLE1BQU0sSUFBSTtBQUM3RCxnQkFBSSxDQUFDLFFBQVEsS0FBSyxPQUFPLFlBQVksTUFBTSxNQUFPLFFBQU8sUUFBUSxLQUFLLEVBQUUsT0FBTyxpQkFBaUIsQ0FBQztBQUVqRyxrQkFBTSxRQUFRLE9BQU8sWUFBWSxFQUFFLEVBQUUsU0FBUyxXQUFXO0FBQ3pELGtCQUFNLFNBQVMsUUFBUSxJQUFJLHNCQUFzQjtBQUNqRCxrQkFBTSxZQUFZLE9BQU8sV0FBVyxRQUFRLEVBQUUsT0FBTyxRQUFRLE1BQU0sRUFBRSxPQUFPLFFBQVE7QUFDcEYsa0JBQU0sVUFBVSxJQUFJLEtBQUssS0FBSyxJQUFJLElBQUksTUFBTyxLQUFLLEtBQUssRUFBRSxFQUFFLFlBQVk7QUFHdkUsa0JBQU0sY0FBYyxnQ0FBZ0M7QUFBQSxjQUNsRCxRQUFRO0FBQUEsY0FDUixTQUFTLEVBQUUsUUFBUSw4QkFBOEI7QUFBQSxjQUNqRCxNQUFNLEtBQUssVUFBVSxFQUFFLFNBQVMsS0FBSyxJQUFJLE9BQU8sWUFBWSxXQUFXLFlBQVksU0FBUyxTQUFTLEtBQUssQ0FBQztBQUFBLFlBQzdHLEdBQUcsR0FBRyxFQUFFLE1BQU0sTUFBTSxJQUFJO0FBR3hCLGtCQUFNLE9BQU8sUUFBUSxJQUFJO0FBQ3pCLGtCQUFNLE9BQU8sT0FBTyxRQUFRLElBQUksYUFBYSxHQUFHO0FBQ2hELGtCQUFNLFdBQVcsUUFBUSxJQUFJO0FBQzdCLGtCQUFNLFdBQVcsUUFBUSxJQUFJO0FBQzdCLGtCQUFNLE9BQU8sUUFBUSxJQUFJLGNBQWM7QUFDdkMsa0JBQU0sU0FBUyxRQUFRLElBQUksV0FBVztBQUN0QyxrQkFBTSxZQUFZLEdBQUcsTUFBTSwyQkFBMkIsS0FBSztBQUUzRCxnQkFBSSxRQUFRLFlBQVksVUFBVTtBQUNoQyxvQkFBTSxjQUFjLFdBQVcsZ0JBQWdCLEVBQUUsTUFBTSxNQUFNLFFBQVEsU0FBUyxLQUFLLE1BQU0sRUFBRSxNQUFNLFVBQVUsTUFBTSxTQUFTLEVBQUUsQ0FBQztBQUM3SCxvQkFBTSxPQUFPO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQSxxQ0FjVSxTQUFTO0FBQUEsc0tBQ21ILFNBQVM7QUFBQTtBQUFBO0FBQUE7QUFBQSx3SEFJdEQsb0JBQUksS0FBSyxHQUFFLFlBQVksQ0FBQztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBSzlILG9CQUFNLFlBQVksU0FBUyxFQUFFLElBQUksT0FBTyxNQUFNLFNBQVMsaUNBQWlDLEtBQUssQ0FBQztBQUFBLFlBQ2hHLE9BQU87QUFDTCxrQkFBSSxRQUFRLElBQUksYUFBYSxjQUFjO0FBQ3pDLHdCQUFRLEtBQUssa0RBQWtELFNBQVM7QUFBQSxjQUMxRTtBQUFBLFlBQ0Y7QUFFQSxtQkFBTyxRQUFRLEtBQUssRUFBRSxJQUFJLEtBQUssQ0FBQztBQUFBLFVBQ2xDO0FBR0EsY0FBSSxJQUFJLEtBQUssV0FBVyxtQkFBbUIsS0FBSyxJQUFJLFdBQVcsT0FBTztBQUNwRSxrQkFBTSxTQUFTLElBQUksSUFBSSxJQUFJLEtBQUssY0FBYztBQUM5QyxrQkFBTSxRQUFRLE9BQU8sYUFBYSxJQUFJLE9BQU8sS0FBSztBQUNsRCxnQkFBSSxDQUFDLE9BQU87QUFDVixrQkFBSSxhQUFhO0FBQ2pCLGtCQUFJLFVBQVUsZ0JBQWdCLFdBQVc7QUFDekMscUJBQU8sSUFBSSxJQUFJLHNCQUFzQjtBQUFBLFlBQ3ZDO0FBQ0Esa0JBQU0sU0FBUyxRQUFRLElBQUksc0JBQXNCO0FBQ2pELGtCQUFNLFlBQVksT0FBTyxXQUFXLFFBQVEsRUFBRSxPQUFPLFFBQVEsTUFBTSxFQUFFLE9BQU8sUUFBUTtBQUdwRixnQkFBSSxLQUFLO0FBQ1QsZ0JBQUk7QUFDRixvQkFBTSxNQUFNLE1BQU0sY0FBYyxrQ0FBa0M7QUFBQSxnQkFDaEUsUUFBUTtBQUFBLGdCQUNSLE1BQU0sS0FBSyxVQUFVLEVBQUUsUUFBUSxVQUFVLENBQUM7QUFBQSxjQUM1QyxHQUFHLEdBQUc7QUFDTixrQkFBSSxPQUFRLElBQVksR0FBSSxNQUFLO0FBQUEsWUFDbkMsUUFBUTtBQUFBLFlBQUM7QUFFVCxnQkFBSSxDQUFDLElBQUk7QUFDUCxvQkFBTSxVQUFTLG9CQUFJLEtBQUssR0FBRSxZQUFZO0FBQ3RDLG9CQUFNLGNBQWMsZ0RBQWdELG1CQUFtQixTQUFTLElBQUksb0NBQW9DLG1CQUFtQixNQUFNLEdBQUc7QUFBQSxnQkFDbEssUUFBUTtBQUFBLGdCQUNSLE1BQU0sS0FBSyxVQUFVLEVBQUUsU0FBUyxPQUFPLENBQUM7QUFBQSxnQkFDeEMsU0FBUyxFQUFFLFFBQVEsd0JBQXdCO0FBQUEsY0FDN0MsR0FBRyxHQUFHLEVBQUUsTUFBTSxNQUFNLElBQUk7QUFBQSxZQUMxQjtBQUVBLGdCQUFJLGFBQWE7QUFDakIsZ0JBQUksVUFBVSxnQkFBZ0IsV0FBVztBQUN6QyxtQkFBTyxJQUFJLElBQUksbVJBQThRO0FBQUEsVUFDL1I7QUFFQSxpQkFBTyxRQUFRLEtBQUssRUFBRSxPQUFPLFlBQVksQ0FBQztBQUFBLFFBQzVDLFNBQVMsR0FBUTtBQUNmLGlCQUFPLFFBQVEsS0FBSyxFQUFFLE9BQU8sZUFBZSxDQUFDO0FBQUEsUUFDL0M7QUFBQSxNQUNGLENBQUM7QUFBQSxJQUNIO0FBQUEsRUFDRjtBQUNGOzs7QURwb0JBLElBQU0sbUNBQW1DO0FBT3pDLElBQU8sc0JBQVEsYUFBYSxDQUFDLEVBQUUsS0FBSyxPQUFPO0FBQUEsRUFDekMsUUFBUTtBQUFBLElBQ04sTUFBTTtBQUFBLElBQ04sTUFBTTtBQUFBLEVBQ1I7QUFBQSxFQUNBLFNBQVM7QUFBQSxJQUNQLE1BQU07QUFBQSxJQUNOLFNBQVMsaUJBQ1QsZ0JBQWdCO0FBQUEsSUFDaEIsZ0JBQWdCO0FBQUEsRUFDbEIsRUFBRSxPQUFPLE9BQU87QUFBQSxFQUNoQixTQUFTO0FBQUEsSUFDUCxPQUFPO0FBQUEsTUFDTCxLQUFLLEtBQUssUUFBUSxrQ0FBVyxPQUFPO0FBQUEsSUFDdEM7QUFBQSxFQUNGO0FBQ0YsRUFBRTsiLAogICJuYW1lcyI6IFsianNvbiIsICJwYXRoIl0KfQo=
