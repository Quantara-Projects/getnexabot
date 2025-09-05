// vite.config.ts
import { defineConfig } from "file:///app/code/node_modules/vite/dist/node/index.js";
import react from "file:///app/code/node_modules/@vitejs/plugin-react-swc/index.js";
import path from "path";
import { componentTagger } from "file:///app/code/node_modules/lovable-tagger/dist/index.js";

// src/server/api.ts
import crypto from "crypto";
import nodemailer from "file:///app/code/node_modules/nodemailer/lib/nodemailer.js";
import * as Sentry from "file:///app/code/node_modules/@sentry/node/build/esm/index.js";
try {
  if (process.env.SENTRY_DSN) {
    Sentry.init({ dsn: process.env.SENTRY_DSN, tracesSampleRate: 0.05, environment: process.env.NODE_ENV });
  }
} catch (e) {
  console.warn("Sentry init failed", e);
}
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
async function supabaseAdminFetch(path2, options = {}, req) {
  const base = requireEnv("SUPABASE_URL");
  const serviceKey = requireEnv("SUPABASE_SERVICE_KEY");
  const headers = {
    apikey: serviceKey,
    Authorization: `Bearer ${serviceKey}`,
    "Content-Type": "application/json"
  };
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
async function fetchRichPage(u) {
  try {
    const res = await fetch(u, { headers: { "User-Agent": "NexaBotCrawler/1.0" } });
    if (!res || !res.ok) return "";
    const html = await res.text();
    const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const title = titleMatch ? titleMatch[1].replace(/\s+/g, " ").trim() : "";
    const descMatch = html.match(/<meta[^>]+name=["']description["'][^>]*content=["']([^"']+)["'][^>]*>/i) || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]*name=["']description["'][^>]*>/i);
    const description = descMatch ? descMatch[1].trim() : "";
    const ogMatches = Array.from(html.matchAll(/<meta[^>]+property=["']og:([^"']+)["'][^>]*content=["']([^"']+)["'][^>]*>/ig));
    const og = ogMatches.map((m) => `${m[1]}: ${m[2]}`).join("\n");
    const jsonLdMatches = Array.from(html.matchAll(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/ig));
    const jsonLd = jsonLdMatches.map((m) => m[1].trim()).join("\n");
    const headingMatches = Array.from(html.matchAll(/<h([1-3])[^>]*>([\s\S]*?)<\/h[1-3]>/ig));
    const headings = headingMatches.map((m) => `h${m[1]}: ${m[2].replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim()}`).join("\n");
    const pMatches = Array.from(html.matchAll(/<p[^>]*>([\s\S]*?)<\/p>/ig));
    const paragraphs = pMatches.slice(0, 5).map((m) => m[1].replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim()).filter(Boolean).join("\n\n");
    const visible = extractTextFromHtml(html).slice(0, 1e4);
    const parts = [
      `URL: ${u}`,
      title ? `Title: ${title}` : "",
      description ? `Meta Description: ${description}` : "",
      og ? `OpenGraph:
${og}` : "",
      jsonLd ? `JSON-LD:
${jsonLd}` : "",
      headings ? `Headings:
${headings}` : "",
      paragraphs ? `Top Paragraphs:
${paragraphs}` : "",
      `Visible Text:
${visible}`
    ].filter(Boolean);
    return parts.join("\n\n");
  } catch (e) {
    return "";
  }
}
async function tryFetchUrlText(u) {
  try {
    const urlObj = new URL(u);
    const base = urlObj.origin;
    const candidates = [u, `${base}/about`, `${base}/about-us`, `${base}/contact`, `${base}/contact-us`, `${base}/faq`, `${base}/products`, `${base}/pricing`];
    const seen = /* @__PURE__ */ new Set();
    const collected = [];
    for (const c of candidates) {
      if (seen.has(c)) continue;
      seen.add(c);
      try {
        const s = await fetchRichPage(c);
        if (s) collected.push(s);
      } catch (e) {
      }
      if (collected.join("\n").length > 15e3) break;
    }
    return collected.join("\n\n---\n\n");
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
        let __sentry_tx = null;
        try {
          if (Sentry?.startTransaction) {
            __sentry_tx = Sentry.startTransaction({ op: "http.server", name: `${req.method} ${req.url}` });
            res.on("finish", () => {
              try {
                if (__sentry_tx) {
                  __sentry_tx.setHttpStatus(res.statusCode);
                  __sentry_tx.finish();
                }
              } catch (e) {
              }
            });
          }
        } catch (e) {
        }
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
        if (req.url === "/health" && req.method === "GET") {
          return endJson(200, { ok: true, uptime: process.uptime(), timestamp: (/* @__PURE__ */ new Date()).toISOString() });
        }
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
            const message = String(body?.message || "").slice(0, 3e3);
            const memory = String(body?.memory || "").slice(0, 2e4);
            const imageNote = body?.image ? "IMAGE_PROVIDED" : null;
            if (!message) return endJson(400, { error: "Empty message" });
            await supabaseFetch("/rest/v1/security_logs", {
              method: "POST",
              body: JSON.stringify({ action: "CHAT", details: { len: message.length, hasImage: !!body?.image } })
            }, req).catch(() => null);
            const openaiKey = process.env.OPENAI_API_KEY;
            if (!openaiKey) return endJson(200, { reply: "AI not configured on server." });
            const systemPrompt = `You are a technical assistant specialized in analyzing websites and diagnosing issues, bugs, and configuration problems. ONLY answer questions related to the website, its content, code, deployment, or configuration. If the user's question is not about the website or its issues, respond exactly: ":Sorry I can't answer that question since i am design to answer your questions about the issue/bugs or reports on the website."`;
            const userPrompt = `Memory:
${memory}

User question:
${message}

If an image was provided, note that: ${imageNote || "none"}

Provide a concise, actionable diagnostic and suggested fixes. If you need to ask for more details, ask clearly. Limit the answer to 800 words.`;
            try {
              const resp = await fetch("https://api.openai.com/v1/chat/completions", {
                method: "POST",
                headers: { "Authorization": `Bearer ${openaiKey}`, "Content-Type": "application/json" },
                body: JSON.stringify({ model: "gpt-3.5-turbo", messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userPrompt }], max_tokens: 800 })
              });
              if (!resp.ok) return endJson(200, { reply: "AI request failed" });
              const j = await resp.json();
              const reply = j?.choices?.[0]?.message?.content || "";
              return endJson(200, { reply });
            } catch (e) {
              return endJson(500, { error: "AI error" });
            }
          }
          if (req.url === "/api/analyze-url" && req.method === "POST") {
            const body = await parseJson(req).catch(() => ({}));
            const url = String(body?.url || "").trim();
            if (!url) return endJson(400, { error: "Missing url" });
            const text = await tryFetchUrlText(url).catch(() => "");
            if (!text) return endJson(400, { error: "Could not fetch url" });
            const openaiKey = process.env.OPENAI_API_KEY;
            if (!openaiKey) return endJson(200, { ok: false, message: "AI not configured" });
            const prompt = `You are an AI that analyzes a website given its extracted text. Provide: 1) a short purpose summary, 2) main features and functionality, 3) potential issues or improvements, 4) a breakdown of the content structure (headings, top paragraphs), and 5) extract any meta tags or contact info found. Respond in JSON with keys: summary, features, issues, structure, meta.`;
            try {
              const resp = await fetch("https://api.openai.com/v1/chat/completions", {
                method: "POST",
                headers: { "Authorization": `Bearer ${openaiKey}`, "Content-Type": "application/json" },
                body: JSON.stringify({ model: "gpt-3.5-turbo", messages: [{ role: "system", content: "You are a helpful analyzer." }, { role: "user", content: prompt + "\n\nContent:\n" + text }], max_tokens: 1e3 })
              });
              if (!resp.ok) return endJson(200, { ok: false, message: "AI request failed" });
              const j = await resp.json();
              const analysis = j?.choices?.[0]?.message?.content || "";
              return endJson(200, { ok: true, analysis, raw: text });
            } catch (e) {
              return endJson(500, { error: "AI analyze error" });
            }
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
                        <td style="padding:16px 24px;color:#6b7280;font-size:12px;border-top:1px solid #e5e7eb">\xA9 2025 NexaBot. All rights reserved.</td>
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
          if (req.url === "/api/delete-account" && req.method === "POST") {
            const body = await parseJson(req).catch(() => ({}));
            const userId = String(body?.userId || "").trim();
            if (!userId) return endJson(400, { error: "Missing userId" });
            try {
              const ures = await supabaseFetch("/auth/v1/user", { method: "GET" }, req).catch(() => null);
              if (!ures || !ures.ok) return endJson(401, { error: "Unauthorized" });
              const caller = await ures.json().catch(() => null);
              if (!caller || caller.id !== userId) return endJson(403, { error: "Forbidden" });
            } catch (e) {
              return endJson(401, { error: "Unauthorized" });
            }
            let storageSources = [];
            try {
              const r = await supabaseAdminFetch(`/rest/v1/training_documents?user_id=eq.${encodeURIComponent(userId)}&select=source`, { method: "GET" }, req).catch(() => null);
              if (r && r.ok) {
                const arr = await r.json().catch(() => []);
                if (Array.isArray(arr)) {
                  storageSources = arr.map((x) => String(x?.source || "")).filter(Boolean);
                }
              }
            } catch (e) {
            }
            let deletedStorage = 0;
            try {
              for (const src of storageSources) {
                if (!src) continue;
                if (/^https?:\/\//i.test(src)) continue;
                try {
                  const del = await supabaseAdminFetch(`/storage/v1/object/training/${encodeURIComponent(src)}`, { method: "DELETE" }, req).catch(() => null);
                  if (del && del.ok) deletedStorage++;
                } catch (e) {
                }
              }
            } catch (e) {
            }
            const tables = ["training_documents", "chatbot_configs", "domain_verifications", "email_verifications", "security_logs", "user_settings", "profiles"];
            for (const t of tables) {
              try {
                await supabaseAdminFetch(`/rest/v1/${t}?user_id=eq.${encodeURIComponent(userId)}`, { method: "DELETE" }, req).catch(() => null);
              } catch (e) {
              }
            }
            try {
              const adminRes = await supabaseAdminFetch(`/auth/v1/admin/users/${encodeURIComponent(userId)}`, { method: "DELETE" }, req).catch(() => null);
              if (!adminRes || !adminRes.ok) {
                return endJson(200, { ok: true, deletedAuth: false, deletedStorage, message: "User data removed; failed to delete auth record." });
              }
              return endJson(200, { ok: true, deletedAuth: true, deletedStorage });
            } catch (e) {
              return endJson(200, { ok: true, deletedAuth: false, deletedStorage, message: "User data removed; failed to delete auth record." });
            }
          }
          return endJson(404, { error: "Not Found" });
        } catch (e) {
          try {
            if (Sentry?.captureException) Sentry.captureException(e);
          } catch (err) {
          }
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL3NlcnZlci9hcGkudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGVcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9hcHAvY29kZS92aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vYXBwL2NvZGUvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tIFwidml0ZVwiO1xuaW1wb3J0IHJlYWN0IGZyb20gXCJAdml0ZWpzL3BsdWdpbi1yZWFjdC1zd2NcIjtcbmltcG9ydCBwYXRoIGZyb20gXCJwYXRoXCI7XG5pbXBvcnQgeyBjb21wb25lbnRUYWdnZXIgfSBmcm9tIFwibG92YWJsZS10YWdnZXJcIjtcbmltcG9ydCB7IHNlcnZlckFwaVBsdWdpbiB9IGZyb20gXCIuL3NyYy9zZXJ2ZXIvYXBpXCI7XG5cbi8vIGh0dHBzOi8vdml0ZWpzLmRldi9jb25maWcvXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiAoe1xuICBzZXJ2ZXI6IHtcbiAgICBob3N0OiBcIjo6XCIsXG4gICAgcG9ydDogODA4MCxcbiAgfSxcbiAgcGx1Z2luczogW1xuICAgIHJlYWN0KCksXG4gICAgbW9kZSA9PT0gJ2RldmVsb3BtZW50JyAmJlxuICAgIGNvbXBvbmVudFRhZ2dlcigpLFxuICAgIHNlcnZlckFwaVBsdWdpbigpLFxuICBdLmZpbHRlcihCb29sZWFuKSxcbiAgcmVzb2x2ZToge1xuICAgIGFsaWFzOiB7XG4gICAgICBcIkBcIjogcGF0aC5yZXNvbHZlKF9fZGlybmFtZSwgXCIuL3NyY1wiKSxcbiAgICB9LFxuICB9LFxufSkpO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGUvc3JjL3NlcnZlclwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2FwcC9jb2RlL3NyYy9zZXJ2ZXIvYXBpLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9hcHAvY29kZS9zcmMvc2VydmVyL2FwaS50c1wiO2ltcG9ydCB0eXBlIHsgUGx1Z2luIH0gZnJvbSAndml0ZSc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5pbXBvcnQgbm9kZW1haWxlciBmcm9tICdub2RlbWFpbGVyJztcbmltcG9ydCAqIGFzIFNlbnRyeSBmcm9tICdAc2VudHJ5L25vZGUnO1xuXG4vLyBJbml0aWFsaXplIFNlbnRyeSBpZiBEU04gcHJvdmlkZWRcbnRyeSB7XG4gIGlmIChwcm9jZXNzLmVudi5TRU5UUllfRFNOKSB7XG4gICAgU2VudHJ5LmluaXQoeyBkc246IHByb2Nlc3MuZW52LlNFTlRSWV9EU04sIHRyYWNlc1NhbXBsZVJhdGU6IDAuMDUsIGVudmlyb25tZW50OiBwcm9jZXNzLmVudi5OT0RFX0VOViB9KTtcbiAgfVxufSBjYXRjaCAoZSkge1xuICAvLyBpZ25vcmUgU2VudHJ5IGluaXQgZXJyb3JzIGluIGRldlxuICBjb25zb2xlLndhcm4oJ1NlbnRyeSBpbml0IGZhaWxlZCcsIGUpO1xufVxuXG4vLyBTbWFsbCBKU09OIGJvZHkgcGFyc2VyIHdpdGggc2l6ZSBsaW1pdFxuYXN5bmMgZnVuY3Rpb24gcGFyc2VKc29uKHJlcTogYW55LCBsaW1pdCA9IDEwMjQgKiAxMDApIHtcbiAgcmV0dXJuIG5ldyBQcm9taXNlPGFueT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgIGNvbnN0IGNodW5rczogQnVmZmVyW10gPSBbXTtcbiAgICBsZXQgc2l6ZSA9IDA7XG4gICAgcmVxLm9uKCdkYXRhJywgKGM6IEJ1ZmZlcikgPT4ge1xuICAgICAgc2l6ZSArPSBjLmxlbmd0aDtcbiAgICAgIGlmIChzaXplID4gbGltaXQpIHtcbiAgICAgICAgcmVqZWN0KG5ldyBFcnJvcignUGF5bG9hZCB0b28gbGFyZ2UnKSk7XG4gICAgICAgIHJlcS5kZXN0cm95KCk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIGNodW5rcy5wdXNoKGMpO1xuICAgIH0pO1xuICAgIHJlcS5vbignZW5kJywgKCkgPT4ge1xuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgcmF3ID0gQnVmZmVyLmNvbmNhdChjaHVua3MpLnRvU3RyaW5nKCd1dGY4Jyk7XG4gICAgICAgIGNvbnN0IGpzb24gPSByYXcgPyBKU09OLnBhcnNlKHJhdykgOiB7fTtcbiAgICAgICAgcmVzb2x2ZShqc29uKTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgcmVqZWN0KGUpO1xuICAgICAgfVxuICAgIH0pO1xuICAgIHJlcS5vbignZXJyb3InLCByZWplY3QpO1xuICB9KTtcbn1cblxuZnVuY3Rpb24ganNvbihyZXM6IGFueSwgc3RhdHVzOiBudW1iZXIsIGRhdGE6IGFueSwgaGVhZGVyczogUmVjb3JkPHN0cmluZywgc3RyaW5nPiA9IHt9KSB7XG4gIGNvbnN0IGJvZHkgPSBKU09OLnN0cmluZ2lmeShkYXRhKTtcbiAgcmVzLnN0YXR1c0NvZGUgPSBzdGF0dXM7XG4gIHJlcy5zZXRIZWFkZXIoJ0NvbnRlbnQtVHlwZScsICdhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PXV0Zi04Jyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtQ29udGVudC1UeXBlLU9wdGlvbnMnLCAnbm9zbmlmZicpO1xuICByZXMuc2V0SGVhZGVyKCdSZWZlcnJlci1Qb2xpY3knLCAnbm8tcmVmZXJyZXInKTtcbiAgcmVzLnNldEhlYWRlcignWC1GcmFtZS1PcHRpb25zJywgJ0RFTlknKTtcbiAgcmVzLnNldEhlYWRlcignWC1YU1MtUHJvdGVjdGlvbicsICcxOyBtb2RlPWJsb2NrJyk7XG4gIGZvciAoY29uc3QgW2ssIHZdIG9mIE9iamVjdC5lbnRyaWVzKGhlYWRlcnMpKSByZXMuc2V0SGVhZGVyKGssIHYpO1xuICByZXMuZW5kKGJvZHkpO1xufVxuXG5jb25zdCBpc0h0dHBzID0gKHJlcTogYW55KSA9PiB7XG4gIGNvbnN0IHByb3RvID0gKHJlcS5oZWFkZXJzWyd4LWZvcndhcmRlZC1wcm90byddIGFzIHN0cmluZykgfHwgJyc7XG4gIHJldHVybiBwcm90byA9PT0gJ2h0dHBzJyB8fCAocmVxLnNvY2tldCAmJiAocmVxLnNvY2tldCBhcyBhbnkpLmVuY3J5cHRlZCk7XG59O1xuXG5mdW5jdGlvbiByZXF1aXJlRW52KG5hbWU6IHN0cmluZykge1xuICBjb25zdCB2ID0gcHJvY2Vzcy5lbnZbbmFtZV07XG4gIGlmICghdikgdGhyb3cgbmV3IEVycm9yKGAke25hbWV9IG5vdCBzZXRgKTtcbiAgcmV0dXJuIHY7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHN1cGFiYXNlRmV0Y2gocGF0aDogc3RyaW5nLCBvcHRpb25zOiBhbnksIHJlcTogYW55KSB7XG4gIGNvbnN0IGJhc2UgPSByZXF1aXJlRW52KCdTVVBBQkFTRV9VUkwnKTtcbiAgY29uc3QgYW5vbiA9IHJlcXVpcmVFbnYoJ1NVUEFCQVNFX0FOT05fS0VZJyk7XG4gIGNvbnN0IHRva2VuID0gKHJlcS5oZWFkZXJzWydhdXRob3JpemF0aW9uJ10gYXMgc3RyaW5nKSB8fCAnJztcbiAgY29uc3QgaGVhZGVyczogUmVjb3JkPHN0cmluZywgc3RyaW5nPiA9IHtcbiAgICBhcGlrZXk6IGFub24sXG4gICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyxcbiAgfTtcbiAgaWYgKHRva2VuKSBoZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSB0b2tlbjtcbiAgcmV0dXJuIGZldGNoKGAke2Jhc2V9JHtwYXRofWAsIHsgLi4ub3B0aW9ucywgaGVhZGVyczogeyAuLi5oZWFkZXJzLCAuLi4ob3B0aW9ucz8uaGVhZGVycyB8fCB7fSkgfSB9KTtcbn1cblxuLy8gU3VwYWJhc2UgYWRtaW4gZmV0Y2ggdXNpbmcgc2VydmljZSByb2xlIGtleSAoc2VydmVyLXNpZGUgb25seSlcbmFzeW5jIGZ1bmN0aW9uIHN1cGFiYXNlQWRtaW5GZXRjaChwYXRoOiBzdHJpbmcsIG9wdGlvbnM6IGFueSA9IHt9LCByZXE6IGFueSkge1xuICBjb25zdCBiYXNlID0gcmVxdWlyZUVudignU1VQQUJBU0VfVVJMJyk7XG4gIGNvbnN0IHNlcnZpY2VLZXkgPSByZXF1aXJlRW52KCdTVVBBQkFTRV9TRVJWSUNFX0tFWScpO1xuICBjb25zdCBoZWFkZXJzOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+ID0ge1xuICAgIGFwaWtleTogc2VydmljZUtleSxcbiAgICBBdXRob3JpemF0aW9uOiBgQmVhcmVyICR7c2VydmljZUtleX1gLFxuICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsXG4gIH07XG4gIHJldHVybiBmZXRjaChgJHtiYXNlfSR7cGF0aH1gLCB7IC4uLm9wdGlvbnMsIGhlYWRlcnM6IHsgLi4uaGVhZGVycywgLi4uKG9wdGlvbnM/LmhlYWRlcnMgfHwge30pIH0gfSk7XG59XG5cbmZ1bmN0aW9uIG1ha2VCb3RJZChzZWVkOiBzdHJpbmcpIHtcbiAgcmV0dXJuICdib3RfJyArIGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUoc2VlZCkuZGlnZXN0KCdiYXNlNjR1cmwnKS5zbGljZSgwLCAyMik7XG59XG5cbi8vIEV4dHJhY3QgdmlzaWJsZSB0ZXh0IGZyb20gSFRNTCAobmFpdmUpXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21IdG1sKGh0bWw6IHN0cmluZykge1xuICAvLyByZW1vdmUgc2NyaXB0cy9zdHlsZXNcbiAgY29uc3Qgd2l0aG91dFNjcmlwdHMgPSBodG1sLnJlcGxhY2UoLzxzY3JpcHRbXFxzXFxTXSo/PltcXHNcXFNdKj88XFwvc2NyaXB0Pi9naSwgJyAnKTtcbiAgY29uc3Qgd2l0aG91dFN0eWxlcyA9IHdpdGhvdXRTY3JpcHRzLnJlcGxhY2UoLzxzdHlsZVtcXHNcXFNdKj8+W1xcc1xcU10qPzxcXC9zdHlsZT4vZ2ksICcgJyk7XG4gIC8vIHJlbW92ZSB0YWdzXG4gIGNvbnN0IHRleHQgPSB3aXRob3V0U3R5bGVzLnJlcGxhY2UoLzxbXj5dKz4vZywgJyAnKTtcbiAgLy8gZGVjb2RlIEhUTUwgZW50aXRpZXMgKGJhc2ljKVxuICByZXR1cm4gdGV4dC5yZXBsYWNlKC8mbmJzcDt8JmFtcDt8Jmx0O3wmZ3Q7fCZxdW90O3wmIzM5Oy9nLCAocykgPT4ge1xuICAgIHN3aXRjaCAocykge1xuICAgICAgY2FzZSAnJm5ic3A7JzogcmV0dXJuICcgJztcbiAgICAgIGNhc2UgJyZhbXA7JzogcmV0dXJuICcmJztcbiAgICAgIGNhc2UgJyZsdDsnOiByZXR1cm4gJzwnO1xuICAgICAgY2FzZSAnJmd0Oyc6IHJldHVybiAnPic7XG4gICAgICBjYXNlICcmcXVvdDsnOiByZXR1cm4gJ1wiJztcbiAgICAgIGNhc2UgJyYjMzk7JzogcmV0dXJuICdcXCcnO1xuICAgICAgZGVmYXVsdDogcmV0dXJuIHM7XG4gICAgfVxuICB9KS5yZXBsYWNlKC9cXHMrL2csICcgJykudHJpbSgpO1xufVxuXG4vLyBGZXRjaCBhIHBhZ2UgYW5kIGV4dHJhY3QgcmljaCBzdHJ1Y3R1cmVkIGNvbnRlbnQgKHRpdGxlLCBtZXRhLCBoZWFkaW5ncywgSlNPTi1MRCwgdmlzaWJsZSB0ZXh0KVxuYXN5bmMgZnVuY3Rpb24gZmV0Y2hSaWNoUGFnZSh1OiBzdHJpbmcpIHtcbiAgdHJ5IHtcbiAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCh1LCB7IGhlYWRlcnM6IHsgJ1VzZXItQWdlbnQnOiAnTmV4YUJvdENyYXdsZXIvMS4wJyB9IH0pO1xuICAgIGlmICghcmVzIHx8ICFyZXMub2spIHJldHVybiAnJztcbiAgICBjb25zdCBodG1sID0gYXdhaXQgcmVzLnRleHQoKTtcblxuICAgIC8vIHRpdGxlXG4gICAgY29uc3QgdGl0bGVNYXRjaCA9IGh0bWwubWF0Y2goLzx0aXRsZVtePl0qPihbXFxzXFxTXSo/KTxcXC90aXRsZT4vaSk7XG4gICAgY29uc3QgdGl0bGUgPSB0aXRsZU1hdGNoID8gdGl0bGVNYXRjaFsxXS5yZXBsYWNlKC9cXHMrL2csICcgJykudHJpbSgpIDogJyc7XG5cbiAgICAvLyBtZXRhIGRlc2NyaXB0aW9uXG4gICAgY29uc3QgZGVzY01hdGNoID0gaHRtbC5tYXRjaCgvPG1ldGFbXj5dK25hbWU9W1wiJ11kZXNjcmlwdGlvbltcIiddW14+XSpjb250ZW50PVtcIiddKFteXCInXSspW1wiJ11bXj5dKj4vaSkgfHwgaHRtbC5tYXRjaCgvPG1ldGFbXj5dK2NvbnRlbnQ9W1wiJ10oW15cIiddKylbXCInXVtePl0qbmFtZT1bXCInXWRlc2NyaXB0aW9uW1wiJ11bXj5dKj4vaSk7XG4gICAgY29uc3QgZGVzY3JpcHRpb24gPSBkZXNjTWF0Y2ggPyBkZXNjTWF0Y2hbMV0udHJpbSgpIDogJyc7XG5cbiAgICAvLyBvcGVuIGdyYXBoXG4gICAgY29uc3Qgb2dNYXRjaGVzID0gQXJyYXkuZnJvbShodG1sLm1hdGNoQWxsKC88bWV0YVtePl0rcHJvcGVydHk9W1wiJ11vZzooW15cIiddKylbXCInXVtePl0qY29udGVudD1bXCInXShbXlwiJ10rKVtcIiddW14+XSo+L2lnKSk7XG4gICAgY29uc3Qgb2cgPSBvZ01hdGNoZXMubWFwKG0gPT4gYCR7bVsxXX06ICR7bVsyXX1gKS5qb2luKCdcXG4nKTtcblxuICAgIC8vIEpTT04tTERcbiAgICBjb25zdCBqc29uTGRNYXRjaGVzID0gQXJyYXkuZnJvbShodG1sLm1hdGNoQWxsKC88c2NyaXB0W14+XSp0eXBlPVtcIiddYXBwbGljYXRpb25cXC9sZFxcK2pzb25bXCInXVtePl0qPihbXFxzXFxTXSo/KTxcXC9zY3JpcHQ+L2lnKSk7XG4gICAgY29uc3QganNvbkxkID0ganNvbkxkTWF0Y2hlcy5tYXAobSA9PiBtWzFdLnRyaW0oKSkuam9pbignXFxuJyk7XG5cbiAgICAvLyBoZWFkaW5ncyBoMS1oM1xuICAgIGNvbnN0IGhlYWRpbmdNYXRjaGVzID0gQXJyYXkuZnJvbShodG1sLm1hdGNoQWxsKC88aChbMS0zXSlbXj5dKj4oW1xcc1xcU10qPyk8XFwvaFsxLTNdPi9pZykpO1xuICAgIGNvbnN0IGhlYWRpbmdzID0gaGVhZGluZ01hdGNoZXMubWFwKG0gPT4gYGgke21bMV19OiAke21bMl0ucmVwbGFjZSgvPFtePl0rPi9nLCAnJykucmVwbGFjZSgvXFxzKy9nLCcgJykudHJpbSgpfWApLmpvaW4oJ1xcbicpO1xuXG4gICAgLy8gZmlyc3QgbWVhbmluZ2Z1bCBwYXJhZ3JhcGhzXG4gICAgY29uc3QgcE1hdGNoZXMgPSBBcnJheS5mcm9tKGh0bWwubWF0Y2hBbGwoLzxwW14+XSo+KFtcXHNcXFNdKj8pPFxcL3A+L2lnKSk7XG4gICAgY29uc3QgcGFyYWdyYXBocyA9IHBNYXRjaGVzLnNsaWNlKDAsIDUpLm1hcChtID0+IG1bMV0ucmVwbGFjZSgvPFtePl0rPi9nLCAnJykucmVwbGFjZSgvXFxzKy9nLCcgJykudHJpbSgpKS5maWx0ZXIoQm9vbGVhbikuam9pbignXFxuXFxuJyk7XG5cbiAgICAvLyB2aXNpYmxlIHRleHQgKGZhbGxiYWNrKVxuICAgIGNvbnN0IHZpc2libGUgPSBleHRyYWN0VGV4dEZyb21IdG1sKGh0bWwpLnNsaWNlKDAsIDEwMDAwKTtcblxuICAgIGNvbnN0IHBhcnRzID0gW1xuICAgICAgYFVSTDogJHt1fWAsXG4gICAgICB0aXRsZSA/IGBUaXRsZTogJHt0aXRsZX1gIDogJycsXG4gICAgICBkZXNjcmlwdGlvbiA/IGBNZXRhIERlc2NyaXB0aW9uOiAke2Rlc2NyaXB0aW9ufWAgOiAnJyxcbiAgICAgIG9nID8gYE9wZW5HcmFwaDpcXG4ke29nfWAgOiAnJyxcbiAgICAgIGpzb25MZCA/IGBKU09OLUxEOlxcbiR7anNvbkxkfWAgOiAnJyxcbiAgICAgIGhlYWRpbmdzID8gYEhlYWRpbmdzOlxcbiR7aGVhZGluZ3N9YCA6ICcnLFxuICAgICAgcGFyYWdyYXBocyA/IGBUb3AgUGFyYWdyYXBoczpcXG4ke3BhcmFncmFwaHN9YCA6ICcnLFxuICAgICAgYFZpc2libGUgVGV4dDpcXG4ke3Zpc2libGV9YCxcbiAgICBdLmZpbHRlcihCb29sZWFuKTtcblxuICAgIHJldHVybiBwYXJ0cy5qb2luKCdcXG5cXG4nKTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIHJldHVybiAnJztcbiAgfVxufVxuXG4vLyBUcnkgY29tbW9uIGF1eGlsaWFyeSBwYXRocyBvbiB0aGUgc2FtZSBob3N0IChhYm91dCwgY29udGFjdCwgZmFxLCBwcm9kdWN0cykgdG8gZ2F0aGVyIG1vcmUgY29udGV4dFxuYXN5bmMgZnVuY3Rpb24gdHJ5RmV0Y2hVcmxUZXh0KHU6IHN0cmluZykge1xuICB0cnkge1xuICAgIGNvbnN0IHVybE9iaiA9IG5ldyBVUkwodSk7XG4gICAgY29uc3QgYmFzZSA9IHVybE9iai5vcmlnaW47XG4gICAgY29uc3QgY2FuZGlkYXRlcyA9IFt1LCBgJHtiYXNlfS9hYm91dGAsIGAke2Jhc2V9L2Fib3V0LXVzYCwgYCR7YmFzZX0vY29udGFjdGAsIGAke2Jhc2V9L2NvbnRhY3QtdXNgLCBgJHtiYXNlfS9mYXFgLCBgJHtiYXNlfS9wcm9kdWN0c2AsIGAke2Jhc2V9L3ByaWNpbmdgXTtcbiAgICBjb25zdCBzZWVuID0gbmV3IFNldCgpO1xuICAgIGNvbnN0IGNvbGxlY3RlZDogc3RyaW5nW10gPSBbXTtcbiAgICBmb3IgKGNvbnN0IGMgb2YgY2FuZGlkYXRlcykge1xuICAgICAgaWYgKHNlZW4uaGFzKGMpKSBjb250aW51ZTtcbiAgICAgIHNlZW4uYWRkKGMpO1xuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgcyA9IGF3YWl0IGZldGNoUmljaFBhZ2UoYyk7XG4gICAgICAgIGlmIChzKSBjb2xsZWN0ZWQucHVzaChzKTtcbiAgICAgIH0gY2F0Y2ggKGUpIHt9XG4gICAgICBpZiAoY29sbGVjdGVkLmpvaW4oJ1xcbicpLmxlbmd0aCA+IDE1MDAwKSBicmVhaztcbiAgICB9XG4gICAgcmV0dXJuIGNvbGxlY3RlZC5qb2luKCdcXG5cXG4tLS1cXG5cXG4nKTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIHJldHVybiAnJztcbiAgfVxufVxuXG5mdW5jdGlvbiBjaHVua1RleHQodGV4dDogc3RyaW5nLCBtYXhDaGFycyA9IDE1MDApIHtcbiAgY29uc3QgcGFyYWdyYXBocyA9IHRleHQuc3BsaXQoL1xcbnxcXHJ8XFwufFxcIXxcXD8vKS5tYXAocCA9PiBwLnRyaW0oKSkuZmlsdGVyKEJvb2xlYW4pO1xuICBjb25zdCBjaHVua3M6IHN0cmluZ1tdID0gW107XG4gIGxldCBjdXIgPSAnJztcbiAgZm9yIChjb25zdCBwIG9mIHBhcmFncmFwaHMpIHtcbiAgICBpZiAoKGN1ciArICcgJyArIHApLmxlbmd0aCA+IG1heENoYXJzKSB7XG4gICAgICBpZiAoY3VyKSB7IGNodW5rcy5wdXNoKGN1ci50cmltKCkpOyBjdXIgPSBwOyB9XG4gICAgICBlbHNlIHsgY2h1bmtzLnB1c2gocC5zbGljZSgwLCBtYXhDaGFycykpOyBjdXIgPSBwLnNsaWNlKG1heENoYXJzKTsgfVxuICAgIH0gZWxzZSB7XG4gICAgICBjdXIgPSAoY3VyICsgJyAnICsgcCkudHJpbSgpO1xuICAgIH1cbiAgfVxuICBpZiAoY3VyKSBjaHVua3MucHVzaChjdXIudHJpbSgpKTtcbiAgcmV0dXJuIGNodW5rcztcbn1cblxuYXN5bmMgZnVuY3Rpb24gZW1iZWRDaHVua3MoY2h1bmtzOiBzdHJpbmdbXSk6IFByb21pc2U8bnVtYmVyW11bXSB8IG51bGw+IHtcbiAgY29uc3Qga2V5ID0gcHJvY2Vzcy5lbnYuT1BFTkFJX0FQSV9LRVk7XG4gIGlmICgha2V5KSByZXR1cm4gbnVsbDtcbiAgdHJ5IHtcbiAgICBjb25zdCByZXNwID0gYXdhaXQgZmV0Y2goJ2h0dHBzOi8vYXBpLm9wZW5haS5jb20vdjEvZW1iZWRkaW5ncycsIHtcbiAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgaGVhZGVyczogeyAnQXV0aG9yaXphdGlvbic6IGBCZWFyZXIgJHtrZXl9YCwgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9LFxuICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBpbnB1dDogY2h1bmtzLCBtb2RlbDogJ3RleHQtZW1iZWRkaW5nLTMtc21hbGwnIH0pLFxuICAgIH0pO1xuICAgIGlmICghcmVzcC5vaykgcmV0dXJuIG51bGw7XG4gICAgY29uc3QgaiA9IGF3YWl0IHJlc3AuanNvbigpO1xuICAgIGlmICghai5kYXRhKSByZXR1cm4gbnVsbDtcbiAgICByZXR1cm4gai5kYXRhLm1hcCgoZDogYW55KSA9PiBkLmVtYmVkZGluZyBhcyBudW1iZXJbXSk7XG4gIH0gY2F0Y2ggKGUpIHtcbiAgICByZXR1cm4gbnVsbDtcbiAgfVxufVxuXG5hc3luYyBmdW5jdGlvbiBwcm9jZXNzVHJhaW5Kb2Ioam9iSWQ6IHN0cmluZywgYm9keTogYW55LCByZXE6IGFueSkge1xuICBjb25zdCB1cmwgPSBib2R5LnVybCB8fCAnJztcbiAgY29uc3QgZmlsZXM6IHN0cmluZ1tdID0gQXJyYXkuaXNBcnJheShib2R5LmZpbGVzKSA/IGJvZHkuZmlsZXMgOiBbXTtcbiAgY29uc3QgYm90U2VlZCA9ICh1cmwgfHwgZmlsZXMuam9pbignLCcpKSArIERhdGUubm93KCk7XG4gIGNvbnN0IGJvdElkID0gbWFrZUJvdElkKGJvdFNlZWQpO1xuXG4gIC8vIGdhdGhlciB0ZXh0c1xuICBjb25zdCBkb2NzOiB7IHNvdXJjZTogc3RyaW5nOyBjb250ZW50OiBzdHJpbmcgfVtdID0gW107XG5cbiAgaWYgKHVybCkge1xuICAgIGNvbnN0IHRleHQgPSBhd2FpdCB0cnlGZXRjaFVybFRleHQodXJsKTtcbiAgICBpZiAodGV4dCkgZG9jcy5wdXNoKHsgc291cmNlOiB1cmwsIGNvbnRlbnQ6IHRleHQgfSk7XG4gIH1cblxuICAvLyBmaWxlcyBhcmUgc3RvcmFnZSBwYXRocyBpbiBidWNrZXQvdHJhaW5pbmcvLi4uXG4gIGZvciAoY29uc3QgcGF0aCBvZiBmaWxlcykge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBTVVBBQkFTRV9VUkwgPSBwcm9jZXNzLmVudi5TVVBBQkFTRV9VUkw7XG4gICAgICBjb25zdCBidWNrZXRQdWJsaWNVcmwgPSBTVVBBQkFTRV9VUkwgKyBgL3N0b3JhZ2UvdjEvb2JqZWN0L3B1YmxpYy90cmFpbmluZy8ke2VuY29kZVVSSUNvbXBvbmVudChwYXRoKX1gO1xuICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goYnVja2V0UHVibGljVXJsKTtcbiAgICAgIGlmICghcmVzLm9rKSBjb250aW51ZTtcbiAgICAgIGNvbnN0IGJ1ZiA9IGF3YWl0IHJlcy5hcnJheUJ1ZmZlcigpO1xuICAgICAgLy8gY3J1ZGUgdGV4dCBleHRyYWN0aW9uOiBpZiBpdCdzIHBkZiBvciB0ZXh0XG4gICAgICBjb25zdCBoZWFkZXIgPSBTdHJpbmcuZnJvbUNoYXJDb2RlLmFwcGx5KG51bGwsIG5ldyBVaW50OEFycmF5KGJ1Zi5zbGljZSgwLCA4KSkgYXMgYW55KTtcbiAgICAgIGlmIChoZWFkZXIuaW5jbHVkZXMoJyVQREYnKSkge1xuICAgICAgICAvLyBjYW5ub3QgcGFyc2UgUERGIGhlcmU7IHN0b3JlIHBsYWNlaG9sZGVyXG4gICAgICAgIGRvY3MucHVzaCh7IHNvdXJjZTogcGF0aCwgY29udGVudDogJyhQREYgY29udGVudCAtLSBwcm9jZXNzZWQgZXh0ZXJuYWxseSknIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgY29uc3QgdGV4dCA9IG5ldyBUZXh0RGVjb2RlcigpLmRlY29kZShidWYpO1xuICAgICAgICBjb25zdCBjbGVhbmVkID0gZXh0cmFjdFRleHRGcm9tSHRtbCh0ZXh0KTtcbiAgICAgICAgZG9jcy5wdXNoKHsgc291cmNlOiBwYXRoLCBjb250ZW50OiBjbGVhbmVkIHx8ICcoYmluYXJ5IGZpbGUpJyB9KTtcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlKSB7IGNvbnRpbnVlOyB9XG4gIH1cblxuICAvLyBjaHVuayBhbmQgZW1iZWRcbiAgZm9yIChjb25zdCBkb2Mgb2YgZG9jcykge1xuICAgIGNvbnN0IGNodW5rcyA9IGNodW5rVGV4dChkb2MuY29udGVudCk7XG4gICAgY29uc3QgZW1iZWRkaW5ncyA9IGF3YWl0IGVtYmVkQ2h1bmtzKGNodW5rcyk7XG5cbiAgICAvLyBzdG9yZSBkb2N1bWVudHMgYW5kIGVtYmVkZGluZ3MgaW4gU3VwYWJhc2VcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGNodW5rcy5sZW5ndGg7IGkrKykge1xuICAgICAgY29uc3QgY2h1bmsgPSBjaHVua3NbaV07XG4gICAgICBjb25zdCBlbWIgPSBlbWJlZGRpbmdzID8gZW1iZWRkaW5nc1tpXSA6IG51bGw7XG4gICAgICB0cnkge1xuICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS90cmFpbmluZ19kb2N1bWVudHMnLCB7XG4gICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBib3RfaWQ6IGJvdElkLCBzb3VyY2U6IGRvYy5zb3VyY2UsIGNvbnRlbnQ6IGNodW5rLCBlbWJlZGRpbmc6IGVtYiB9KSxcbiAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3JldHVybj1yZXByZXNlbnRhdGlvbicsICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicgfSxcbiAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgIH0gY2F0Y2gge31cbiAgICB9XG4gIH1cblxuICAvLyBtYXJrIGpvYiBpbiBsb2dzXG4gIHRyeSB7XG4gICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBhY3Rpb246ICdUUkFJTl9KT0JfQ09NUExFVEUnLCBkZXRhaWxzOiB7IGpvYklkLCBib3RJZCwgZG9jczogZG9jcy5sZW5ndGggfSB9KSxcbiAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICB9IGNhdGNoIHt9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGVuc3VyZURvbWFpblZlcmlmaWNhdGlvbihkb21haW46IHN0cmluZywgcmVxOiBhbnkpIHtcbiAgLy8gY2hlY2sgZG9tYWlucyB0YWJsZSBmb3IgdmVyaWZpZWRcbiAgdHJ5IHtcbiAgICBjb25zdCByZXMgPSBhd2FpdCBzdXBhYmFzZUZldGNoKGAvcmVzdC92MS9kb21haW5zP2RvbWFpbj1lcS4ke2VuY29kZVVSSUNvbXBvbmVudChkb21haW4pfWAsIHsgbWV0aG9kOiAnR0VUJyB9LCByZXEpO1xuICAgIGlmIChyZXMgJiYgKHJlcyBhcyBhbnkpLm9rKSB7XG4gICAgICBjb25zdCBqID0gYXdhaXQgKHJlcyBhcyBSZXNwb25zZSkuanNvbigpLmNhdGNoKCgpID0+IFtdKTtcbiAgICAgIGlmIChBcnJheS5pc0FycmF5KGopICYmIGoubGVuZ3RoID4gMCAmJiBqWzBdLnZlcmlmaWVkKSByZXR1cm4geyB2ZXJpZmllZDogdHJ1ZSB9O1xuICAgIH1cbiAgfSBjYXRjaCB7fVxuXG4gIC8vIGFsd2F5cyBjcmVhdGUgYSBmcmVzaCBzaG9ydC1saXZlZCBzaW5nbGUtdXNlIHZlcmlmaWNhdGlvbiB0b2tlbiAoZG8gTk9UIHBlcnNpc3QgcGxhaW50ZXh0KVxuICBjb25zdCB0b2tlbiA9IGNyeXB0by5yYW5kb21CeXRlcygxNikudG9TdHJpbmcoJ2Jhc2U2NHVybCcpO1xuICBjb25zdCBzZWNyZXQgPSBwcm9jZXNzLmVudi5ET01BSU5fVkVSSUZJQ0FUSU9OX1NFQ1JFVCB8fCAnbG9jYWwtZG9tLXNlY3JldCc7XG4gIGNvbnN0IHRva2VuSGFzaCA9IGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUodG9rZW4gKyBzZWNyZXQpLmRpZ2VzdCgnYmFzZTY0Jyk7XG4gIGNvbnN0IGV4cGlyZXMgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgMTAwMCAqIDYwICogNjApLnRvSVNPU3RyaW5nKCk7XG4gIGxldCBjcmVhdGVkSWQ6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuICB0cnkge1xuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2RvbWFpbl92ZXJpZmljYXRpb25zJywge1xuICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGRvbWFpbiwgdG9rZW5faGFzaDogdG9rZW5IYXNoLCBleHBpcmVzX2F0OiBleHBpcmVzLCB1c2VkX2F0OiBudWxsIH0pLFxuICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXR1cm49cmVwcmVzZW50YXRpb24nLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICBpZiAocmVzICYmIChyZXMgYXMgYW55KS5vaykge1xuICAgICAgY29uc3QgaiA9IGF3YWl0IChyZXMgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgIGlmIChBcnJheS5pc0FycmF5KGopICYmIGoubGVuZ3RoID4gMCAmJiBqWzBdLmlkKSBjcmVhdGVkSWQgPSBqWzBdLmlkO1xuICAgICAgZWxzZSBpZiAoaiAmJiBqLmlkKSBjcmVhdGVkSWQgPSBqLmlkO1xuICAgIH1cbiAgfSBjYXRjaCB7fVxuICAvLyBSZXR1cm4gdGhlIHBsYWludGV4dCB0b2tlbiBhbmQgaXRzIERCIGlkIHRvIHRoZSBjYWxsZXIgc28gdGhleSBjYW4gcGxhY2UgaXQgaW4gdGhlaXIgc2l0ZSwgYnV0IGRvIG5vdCBwZXJzaXN0IHBsYWludGV4dFxuICByZXR1cm4geyB2ZXJpZmllZDogZmFsc2UsIHRva2VuLCB0b2tlbklkOiBjcmVhdGVkSWQgfTtcbn1cblxuZnVuY3Rpb24gdmVyaWZ5V2lkZ2V0VG9rZW4odG9rZW46IHN0cmluZykge1xuICB0cnkge1xuICAgIGNvbnN0IHdpZGdldFNlY3JldCA9IHByb2Nlc3MuZW52LldJREdFVF9UT0tFTl9TRUNSRVQgfHwgJ2xvY2FsLXdpZGdldC1zZWNyZXQnO1xuICAgIGNvbnN0IHBhcnRzID0gdG9rZW4uc3BsaXQoJy4nKTtcbiAgICBpZiAocGFydHMubGVuZ3RoICE9PSAzKSByZXR1cm4gbnVsbDtcbiAgICBjb25zdCB1bnNpZ25lZCA9IHBhcnRzWzBdICsgJy4nICsgcGFydHNbMV07XG4gICAgY29uc3Qgc2lnID0gcGFydHNbMl07XG4gICAgY29uc3QgZXhwZWN0ZWQgPSBjcnlwdG8uY3JlYXRlSG1hYygnc2hhMjU2Jywgd2lkZ2V0U2VjcmV0KS51cGRhdGUodW5zaWduZWQpLmRpZ2VzdCgnYmFzZTY0dXJsJyk7XG4gICAgaWYgKHNpZyAhPT0gZXhwZWN0ZWQpIHJldHVybiBudWxsO1xuICAgIGNvbnN0IHBheWxvYWQgPSBKU09OLnBhcnNlKEJ1ZmZlci5mcm9tKHBhcnRzWzFdLCAnYmFzZTY0dXJsJykudG9TdHJpbmcoJ3V0ZjgnKSk7XG4gICAgcmV0dXJuIHBheWxvYWQ7XG4gIH0gY2F0Y2ggKGUpIHsgcmV0dXJuIG51bGw7IH1cbn1cblxuLy8gU2ltcGxlIGluLW1lbW9yeSByYXRlIGxpbWl0ZXJcbmNvbnN0IHJhdGVNYXAgPSBuZXcgTWFwPHN0cmluZywgeyBjb3VudDogbnVtYmVyOyB0czogbnVtYmVyIH0+KCk7XG5mdW5jdGlvbiByYXRlTGltaXQoa2V5OiBzdHJpbmcsIGxpbWl0OiBudW1iZXIsIHdpbmRvd01zOiBudW1iZXIpIHtcbiAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgY29uc3QgcmVjID0gcmF0ZU1hcC5nZXQoa2V5KTtcbiAgaWYgKCFyZWMgfHwgbm93IC0gcmVjLnRzID4gd2luZG93TXMpIHtcbiAgICByYXRlTWFwLnNldChrZXksIHsgY291bnQ6IDEsIHRzOiBub3cgfSk7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cbiAgaWYgKHJlYy5jb3VudCA8IGxpbWl0KSB7XG4gICAgcmVjLmNvdW50ICs9IDE7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cbiAgcmV0dXJuIGZhbHNlO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gc2VydmVyQXBpUGx1Z2luKCk6IFBsdWdpbiB7XG4gIHJldHVybiB7XG4gICAgbmFtZTogJ3NlcnZlci1hcGktcGx1Z2luJyxcbiAgICBjb25maWd1cmVTZXJ2ZXIoc2VydmVyKSB7XG4gICAgICBzZXJ2ZXIubWlkZGxld2FyZXMudXNlKGFzeW5jIChyZXEsIHJlcywgbmV4dCkgPT4ge1xuICAgICAgICBpZiAoIXJlcS51cmwgfHwgIXJlcS51cmwuc3RhcnRzV2l0aCgnL2FwaS8nKSkgcmV0dXJuIG5leHQoKTtcblxuICAgICAgICAvLyBCYXNpYyBzZWN1cml0eSBoZWFkZXJzIGZvciBhbGwgQVBJIHJlc3BvbnNlc1xuICAgICAgICBjb25zdCBjb3JzT3JpZ2luID0gcmVxLmhlYWRlcnMub3JpZ2luIHx8ICcqJztcbiAgICAgICAgcmVzLnNldEhlYWRlcignUGVybWlzc2lvbnMtUG9saWN5JywgJ2dlb2xvY2F0aW9uPSgpLCBtaWNyb3Bob25lPSgpLCBjYW1lcmE9KCknKTtcbiAgICAgICAgcmVzLnNldEhlYWRlcignQ3Jvc3MtT3JpZ2luLVJlc291cmNlLVBvbGljeScsICdzYW1lLW9yaWdpbicpO1xuXG4gICAgICAgIC8vIFN0YXJ0IGEgU2VudHJ5IHRyYW5zYWN0aW9uIGZvciB0aGlzIHJlcXVlc3QgaWYgYXZhaWxhYmxlXG4gICAgICAgIGxldCBfX3NlbnRyeV90eDogYW55ID0gbnVsbDtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBpZiAoKFNlbnRyeSBhcyBhbnkpPy5zdGFydFRyYW5zYWN0aW9uKSB7XG4gICAgICAgICAgICBfX3NlbnRyeV90eCA9IChTZW50cnkgYXMgYW55KS5zdGFydFRyYW5zYWN0aW9uKHsgb3A6ICdodHRwLnNlcnZlcicsIG5hbWU6IGAke3JlcS5tZXRob2R9ICR7cmVxLnVybH1gIH0pO1xuICAgICAgICAgICAgcmVzLm9uKCdmaW5pc2gnLCAoKSA9PiB7XG4gICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgaWYgKF9fc2VudHJ5X3R4KSB7XG4gICAgICAgICAgICAgICAgICBfX3NlbnRyeV90eC5zZXRIdHRwU3RhdHVzKHJlcy5zdGF0dXNDb2RlKTtcbiAgICAgICAgICAgICAgICAgIF9fc2VudHJ5X3R4LmZpbmlzaCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge31cbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfSBjYXRjaCAoZSkge31cblxuICAgICAgICAvLyBJbiBkZXYgYWxsb3cgaHR0cDsgaW4gcHJvZCAoYmVoaW5kIHByb3h5KSwgcmVxdWlyZSBodHRwc1xuICAgICAgICBpZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgPT09ICdwcm9kdWN0aW9uJyAmJiAhaXNIdHRwcyhyZXEpKSB7XG4gICAgICAgICAgcmV0dXJuIGpzb24ocmVzLCA0MDAsIHsgZXJyb3I6ICdIVFRQUyByZXF1aXJlZCcgfSwgeyAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJzogU3RyaW5nKGNvcnNPcmlnaW4pIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQ09SUyBwcmVmbGlnaHRcbiAgICAgICAgaWYgKHJlcS5tZXRob2QgPT09ICdPUFRJT05TJykge1xuICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbicsIFN0cmluZyhjb3JzT3JpZ2luKSk7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctTWV0aG9kcycsICdQT1NULEdFVCxPUFRJT05TJyk7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycycsICdDb250ZW50LVR5cGUsIEF1dGhvcml6YXRpb24nKTtcbiAgICAgICAgICByZXMuc3RhdHVzQ29kZSA9IDIwNDtcbiAgICAgICAgICByZXR1cm4gcmVzLmVuZCgpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZW5kSnNvbiA9IChzdGF0dXM6IG51bWJlciwgZGF0YTogYW55KSA9PiBqc29uKHJlcywgc3RhdHVzLCBkYXRhLCB7ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nOiBTdHJpbmcoY29yc09yaWdpbikgfSk7XG5cbiAgICAgICAgLy8gSGVhbHRoIGNoZWNrIGVuZHBvaW50XG4gICAgICAgIGlmIChyZXEudXJsID09PSAnL2hlYWx0aCcgJiYgcmVxLm1ldGhvZCA9PT0gJ0dFVCcpIHtcbiAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgb2s6IHRydWUsIHVwdGltZTogcHJvY2Vzcy51cHRpbWUoKSwgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkgfSk7XG4gICAgICAgIH1cblxuICAgICAgICB0cnkge1xuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS90cmFpbicgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBpcCA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtZm9yJ10gYXMgc3RyaW5nKSB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJ2lwJztcbiAgICAgICAgICAgIGlmICghcmF0ZUxpbWl0KCd0cmFpbjonICsgaXAsIDIwLCA2MF8wMDApKSByZXR1cm4gZW5kSnNvbig0MjksIHsgZXJyb3I6ICdUb28gTWFueSBSZXF1ZXN0cycgfSk7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCB1cmwgPSB0eXBlb2YgYm9keT8udXJsID09PSAnc3RyaW5nJyA/IGJvZHkudXJsLnRyaW0oKSA6ICcnO1xuICAgICAgICAgICAgaWYgKCF1cmwgJiYgIUFycmF5LmlzQXJyYXkoYm9keT8uZmlsZXMpKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ1Byb3ZpZGUgdXJsIG9yIGZpbGVzJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICh1cmwpIHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmwpO1xuICAgICAgICAgICAgICAgIGlmICghKHUucHJvdG9jb2wgPT09ICdodHRwOicgfHwgdS5wcm90b2NvbCA9PT0gJ2h0dHBzOicpKSB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQnKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCB1cmwnIH0pO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIExvZyBldmVudFxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnVFJBSU5fUkVRVUVTVCcsIGRldGFpbHM6IHsgaGFzVXJsOiAhIXVybCwgZmlsZUNvdW50OiAoYm9keT8uZmlsZXM/Lmxlbmd0aCkgfHwgMCB9IH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgY29uc3Qgam9iSWQgPSBtYWtlQm90SWQoKHVybCB8fCAnJykgKyBEYXRlLm5vdygpKTtcblxuICAgICAgICAgICAgLy8gU3RhcnQgYmFja2dyb3VuZCBwcm9jZXNzaW5nIChub24tYmxvY2tpbmcpXG4gICAgICAgICAgICAoYXN5bmMgKCkgPT4ge1xuICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGF3YWl0IHByb2Nlc3NUcmFpbkpvYihqb2JJZCwgeyB1cmwsIGZpbGVzOiBBcnJheS5pc0FycmF5KGJvZHk/LmZpbGVzKSA/IGJvZHkuZmlsZXMgOiBbXSB9LCByZXEpO1xuICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3NlY3VyaXR5X2xvZ3MnLCB7XG4gICAgICAgICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFjdGlvbjogJ1RSQUlOX0pPQl9FUlJPUicsIGRldGFpbHM6IHsgam9iSWQsIGVycm9yOiBTdHJpbmcoZT8ubWVzc2FnZSB8fCBlKSB9IH0pLFxuICAgICAgICAgICAgICAgICAgfSwgcmVxKTtcbiAgICAgICAgICAgICAgICB9IGNhdGNoIHt9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pKCk7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMiwgeyBqb2JJZCwgc3RhdHVzOiAncXVldWVkJyB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY29ubmVjdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSk7XG4gICAgICAgICAgICBpZiAoYm9keT8uY2hhbm5lbCAhPT0gJ3dlYnNpdGUnKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdVbnN1cHBvcnRlZCBjaGFubmVsJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IHJhd1VybCA9IChib2R5Py51cmwgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGNvbnN0IGRvbWFpbiA9ICgoKSA9PiB7XG4gICAgICAgICAgICAgIHRyeSB7IHJldHVybiByYXdVcmwgPyBuZXcgVVJMKHJhd1VybCkuaG9zdCA6ICdsb2NhbCc7IH0gY2F0Y2ggeyByZXR1cm4gJ2xvY2FsJzsgfVxuICAgICAgICAgICAgfSkoKTtcblxuICAgICAgICAgICAgLy8gRW5zdXJlIGRvbWFpbiB2ZXJpZmljYXRpb25cbiAgICAgICAgICAgIGNvbnN0IHZyZXMgPSBhd2FpdCBlbnN1cmVEb21haW5WZXJpZmljYXRpb24oZG9tYWluLCByZXEpO1xuICAgICAgICAgICAgaWYgKCF2cmVzLnZlcmlmaWVkKSB7XG4gICAgICAgICAgICAgIC8vIHJldHVybiB2ZXJpZmljYXRpb24gcmVxdWlyZWQgYW5kIGluc3RydWN0aW9ucyAoaW5jbHVkZSB0b2tlbiBpZClcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAyLCB7IHN0YXR1czogJ3ZlcmlmaWNhdGlvbl9yZXF1aXJlZCcsIGluc3RydWN0aW9uczogYEFkZCBhIEROUyBUWFQgcmVjb3JkIG9yIGEgbWV0YSB0YWcgd2l0aCB0b2tlbjogJHt2cmVzLnRva2VufWAsIHRva2VuOiB2cmVzLnRva2VuLCB0b2tlbklkOiB2cmVzLnRva2VuSWQgfHwgbnVsbCB9KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgY29uc3Qgc2VlZCA9IGRvbWFpbiArICd8JyArIChyZXEuaGVhZGVyc1snYXV0aG9yaXphdGlvbiddIHx8ICcnKTtcbiAgICAgICAgICAgIGNvbnN0IGJvdElkID0gbWFrZUJvdElkKHNlZWQpO1xuXG4gICAgICAgICAgICAvLyBVcHNlcnQgY2hhdGJvdF9jb25maWdzIChpZiBSTFMgYWxsb3dzIHdpdGggdXNlciB0b2tlbilcbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2NoYXRib3RfY29uZmlncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYm90X2lkOiBib3RJZCwgY2hhbm5lbDogJ3dlYnNpdGUnLCBkb21haW4sIHNldHRpbmdzOiB7fSB9KSxcbiAgICAgICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXNvbHV0aW9uPW1lcmdlLWR1cGxpY2F0ZXMnIH0sXG4gICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuXG4gICAgICAgICAgICAvLyBDcmVhdGUgd2lkZ2V0IHRva2VuIChITUFDIHNpZ25lZClcbiAgICAgICAgICAgIGNvbnN0IHdpZGdldFBheWxvYWQgPSB7IGJvdElkLCBkb21haW4sIGlhdDogTWF0aC5mbG9vcihEYXRlLm5vdygpLzEwMDApIH07XG4gICAgICAgICAgICBjb25zdCB3aWRnZXRTZWNyZXQgPSBwcm9jZXNzLmVudi5XSURHRVRfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC13aWRnZXQtc2VjcmV0JztcbiAgICAgICAgICAgIGNvbnN0IGhlYWRlciA9IHsgYWxnOiAnSFMyNTYnLCB0eXA6ICdKV1QnIH07XG4gICAgICAgICAgICBjb25zdCBiNjQgPSAoczogc3RyaW5nKSA9PiBCdWZmZXIuZnJvbShzKS50b1N0cmluZygnYmFzZTY0dXJsJyk7XG4gICAgICAgICAgICBjb25zdCB1bnNpZ25lZCA9IGI2NChKU09OLnN0cmluZ2lmeShoZWFkZXIpKSArICcuJyArIGI2NChKU09OLnN0cmluZ2lmeSh3aWRnZXRQYXlsb2FkKSk7XG4gICAgICAgICAgICBjb25zdCBzaWcgPSBjcnlwdG8uY3JlYXRlSG1hYygnc2hhMjU2Jywgd2lkZ2V0U2VjcmV0KS51cGRhdGUodW5zaWduZWQpLmRpZ2VzdCgnYmFzZTY0dXJsJyk7XG4gICAgICAgICAgICBjb25zdCB3aWRnZXRUb2tlbiA9IHVuc2lnbmVkICsgJy4nICsgc2lnO1xuXG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgYm90SWQsIHdpZGdldFRva2VuIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIC8vIFdpZGdldCBjb25maWcgZW5kcG9pbnQ6IHJldHVybnMgYm90IHNldHRpbmdzIGZvciB3aWRnZXQgY29uc3VtZXJzIChyZXF1aXJlcyB0b2tlbilcbiAgICAgICAgICBpZiAocmVxLnVybD8uc3RhcnRzV2l0aCgnL2FwaS93aWRnZXQtY29uZmlnJykgJiYgcmVxLm1ldGhvZCA9PT0gJ0dFVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IHVybE9iaiA9IG5ldyBVUkwocmVxLnVybCwgJ2h0dHA6Ly9sb2NhbCcpO1xuICAgICAgICAgICAgY29uc3QgYm90SWQgPSB1cmxPYmouc2VhcmNoUGFyYW1zLmdldCgnYm90SWQnKSB8fCAnJztcbiAgICAgICAgICAgIGNvbnN0IHRva2VuID0gdXJsT2JqLnNlYXJjaFBhcmFtcy5nZXQoJ3Rva2VuJykgfHwgJyc7XG4gICAgICAgICAgICBpZiAoIWJvdElkKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIGJvdElkJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IHBheWxvYWQgPSB2ZXJpZnlXaWRnZXRUb2tlbih0b2tlbik7XG4gICAgICAgICAgICBpZiAoIXBheWxvYWQgfHwgcGF5bG9hZC5ib3RJZCAhPT0gYm90SWQpIHJldHVybiBlbmRKc29uKDQwMSwgeyBlcnJvcjogJ0ludmFsaWQgdG9rZW4nIH0pO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgY29uc3QgciA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2NoYXRib3RfY29uZmlncz9ib3RfaWQ9ZXEuJyArIGVuY29kZVVSSUNvbXBvbmVudChib3RJZCkgKyAnJnNlbGVjdD0qJywgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICAgIGlmICghciB8fCAhKHIgYXMgYW55KS5vaykgcmV0dXJuIGVuZEpzb24oNDA0LCB7IGVycm9yOiAnTm90IGZvdW5kJyB9KTtcbiAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IChyIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gW10pO1xuICAgICAgICAgICAgICBjb25zdCBjZmcgPSBBcnJheS5pc0FycmF5KGRhdGEpICYmIGRhdGEubGVuZ3RoID4gMCA/IGRhdGFbMF0gOiB7IHNldHRpbmdzOiB7fSB9O1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgc2V0dGluZ3M6IGNmZyB9KTtcbiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHsgcmV0dXJuIGVuZEpzb24oNTAwLCB7IGVycm9yOiAnU2VydmVyIGVycm9yJyB9KTsgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9kZWJ1Zy1mZXRjaCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCB1cmxTdHIgPSBTdHJpbmcoYm9keT8udXJsIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBpZiAoIXVybFN0cikgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnTWlzc2luZyB1cmwnIH0pO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgY29uc3QgdSA9IG5ldyBVUkwodXJsU3RyKTtcbiAgICAgICAgICAgICAgaWYgKCEodS5wcm90b2NvbCA9PT0gJ2h0dHA6JyB8fCB1LnByb3RvY29sID09PSAnaHR0cHM6JykpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgcHJvdG9jb2wnIH0pO1xuICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdJbnZhbGlkIHVybCcgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgZmV0Y2godXJsU3RyLCB7IGhlYWRlcnM6IHsgJ1VzZXItQWdlbnQnOiAnTmV4YUJvdFZlcmlmaWVyLzEuMCcgfSB9KTtcbiAgICAgICAgICAgICAgaWYgKCFyIHx8ICFyLm9rKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdGZXRjaCBmYWlsZWQnLCBzdGF0dXM6IHIgPyByLnN0YXR1cyA6IDAgfSk7XG4gICAgICAgICAgICAgIGNvbnN0IHRleHQgPSBhd2FpdCByLnRleHQoKTtcbiAgICAgICAgICAgICAgLy8gcmV0dXJuIGEgc25pcHBldCB0byBhdm9pZCBodWdlIHBheWxvYWRzXG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogdHJ1ZSwgdXJsOiB1cmxTdHIsIHNuaXBwZXQ6IHRleHQuc2xpY2UoMCwgMjAwMDApIH0pO1xuICAgICAgICAgICAgfSBjYXRjaCAoZTogYW55KSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDUwMCwgeyBlcnJvcjogJ0ZldGNoIGVycm9yJywgbWVzc2FnZTogU3RyaW5nKGU/Lm1lc3NhZ2UgfHwgZSkgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gRGVidWc6IGxpc3Qgc3RvcmVkIHZlcmlmaWNhdGlvbiB0b2tlbnMgZm9yIGEgZG9tYWluIChERVYgT05MWSkgXHUyMDE0IGRvIE5PVCBleHBvc2UgdG9rZW4gcGxhaW50ZXh0IGluIHByb2R1Y3Rpb25cbiAgICAgICAgICBpZiAocmVxLnVybD8uc3RhcnRzV2l0aCgnL2FwaS9kZWJ1Zy1kb21haW4nKSAmJiAocmVxLm1ldGhvZCA9PT0gJ0dFVCcgfHwgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSkge1xuICAgICAgICAgICAgaWYgKHByb2Nlc3MuZW52Lk5PREVfRU5WICE9PSAnZGV2ZWxvcG1lbnQnKSByZXR1cm4gZW5kSnNvbig0MDQsIHsgZXJyb3I6ICdOb3QgZm91bmQnIH0pO1xuICAgICAgICAgICAgLy8gQWNjZXB0IGJvdGggcXVlcnkgcGFyYW0gP2RvbWFpbj0gb3IgSlNPTiBib2R5IHsgZG9tYWluIH1cbiAgICAgICAgICAgIGxldCBkb21haW4gPSAnJztcbiAgICAgICAgICAgIGlmIChyZXEubWV0aG9kID09PSAnR0VUJykge1xuICAgICAgICAgICAgICB0cnkgeyBjb25zdCB1ID0gbmV3IFVSTChyZXEudXJsLCAnaHR0cDovL2xvY2FsJyk7IGRvbWFpbiA9IHUuc2VhcmNoUGFyYW1zLmdldCgnZG9tYWluJykgfHwgJyc7IH0gY2F0Y2gge31cbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIGNvbnN0IGIgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTsgZG9tYWluID0gU3RyaW5nKGI/LmRvbWFpbiB8fCAnJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoIWRvbWFpbikgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnTWlzc2luZyBkb21haW4nIH0pO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgY29uc3QgcSA9IGAvcmVzdC92MS9kb21haW5fdmVyaWZpY2F0aW9ucz9kb21haW49ZXEuJHtlbmNvZGVVUklDb21wb25lbnQoZG9tYWluKX0mc2VsZWN0PWlkLHRva2VuX2hhc2gsZXhwaXJlc19hdCx1c2VkX2F0YDtcbiAgICAgICAgICAgICAgY29uc3QgciA9IGF3YWl0IHN1cGFiYXNlRmV0Y2gocSwgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICAgIGlmICghciB8fCAhKHIgYXMgYW55KS5vaykgcmV0dXJuIGVuZEpzb24oMjAwLCB7IHRva2VuczogW10gfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGFyciA9IGF3YWl0IChyIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gW10pO1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgdG9rZW5zOiBBcnJheS5pc0FycmF5KGFycikgPyBhcnIgOiBbXSB9KTtcbiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNTAwLCB7IGVycm9yOiAnU2VydmVyIGVycm9yJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvdmVyaWZ5LWRvbWFpbicgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCBkb21haW4gPSBTdHJpbmcoYm9keT8uZG9tYWluIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IFN0cmluZyhib2R5Py50b2tlbiB8fCAnJykudHJpbSgpO1xuICAgICAgICAgICAgY29uc3QgdG9rZW5JZCA9IFN0cmluZyhib2R5Py50b2tlbklkIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBpZiAoIWRvbWFpbiB8fCAhdG9rZW4gfHwgIXRva2VuSWQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgZG9tYWluLCB0b2tlbiBvciB0b2tlbklkJyB9KTtcblxuICAgICAgICAgICAgLy8gVHJ5IG11bHRpcGxlIGNhbmRpZGF0ZSBVUkxzIGZvciB2ZXJpZmljYXRpb24gKHJvb3QsIGluZGV4Lmh0bWwsIHdlbGwta25vd24pXG4gICAgICAgICAgICBjb25zdCBjYW5kaWRhdGVzID0gW1xuICAgICAgICAgICAgICBgaHR0cHM6Ly8ke2RvbWFpbn1gLFxuICAgICAgICAgICAgICBgaHR0cDovLyR7ZG9tYWlufWAsXG4gICAgICAgICAgICAgIGBodHRwczovLyR7ZG9tYWlufS9pbmRleC5odG1sYCxcbiAgICAgICAgICAgICAgYGh0dHA6Ly8ke2RvbWFpbn0vaW5kZXguaHRtbGAsXG4gICAgICAgICAgICAgIGBodHRwczovLyR7ZG9tYWlufS8ud2VsbC1rbm93bi9uZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25gLFxuICAgICAgICAgICAgICBgaHR0cDovLyR7ZG9tYWlufS8ud2VsbC1rbm93bi9uZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25gLFxuICAgICAgICAgICAgXTtcblxuICAgICAgICAgICAgLy8gQnVpbGQgcm9idXN0IHJlZ2V4IHRvIG1hdGNoIG1ldGEgdGFnIGluIGFueSBhdHRyaWJ1dGUgb3JkZXJcbiAgICAgICAgICAgIGNvbnN0IGVzYyA9IChzOiBzdHJpbmcpID0+IHMucmVwbGFjZSgvWy0vXFxcXF4kKis/LigpfFtcXF17fV0vZywgJ1xcXFwkJicpO1xuICAgICAgICAgICAgY29uc3QgdEVzYyA9IGVzYyh0b2tlbik7XG4gICAgICAgICAgICBjb25zdCBtZXRhUmUgPSBuZXcgUmVnRXhwKGA8bWV0YVtePl0qKD86bmFtZVxccyo9XFxzKlsnXFxcIl1uZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25bJ1xcXCJdW14+XSpjb250ZW50XFxzKj1cXHMqWydcXFwiXSR7dEVzY31bJ1xcXCJdfGNvbnRlbnRcXHMqPVxccypbJ1xcXCJdJHt0RXNjfVsnXFxcIl1bXj5dKm5hbWVcXHMqPVxccypbJ1xcXCJdbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uWydcXFwiXSlgLCAnaScpO1xuICAgICAgICAgICAgY29uc3QgcGxhaW5SZSA9IG5ldyBSZWdFeHAoYG5leGFib3QtZG9tYWluLXZlcmlmaWNhdGlvbls6PV1cXHMqJHt0RXNjfWAsICdpJyk7XG5cbiAgICAgICAgICAgIGxldCBmb3VuZCA9IGZhbHNlO1xuICAgICAgICAgICAgZm9yIChjb25zdCB1cmwgb2YgY2FuZGlkYXRlcykge1xuICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGNvbnN0IHIgPSBhd2FpdCBmZXRjaCh1cmwsIHsgaGVhZGVyczogeyAnVXNlci1BZ2VudCc6ICdOZXhhQm90VmVyaWZpZXIvMS4wJyB9IH0pO1xuICAgICAgICAgICAgICAgIGlmICghciB8fCAhci5vaykgY29udGludWU7XG4gICAgICAgICAgICAgICAgY29uc3QgdGV4dCA9IGF3YWl0IHIudGV4dCgpO1xuICAgICAgICAgICAgICAgIGlmIChtZXRhUmUudGVzdCh0ZXh0KSB8fCBwbGFpblJlLnRlc3QodGV4dCkpIHtcbiAgICAgICAgICAgICAgICAgIGZvdW5kID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgIC8vIGlnbm9yZSBhbmQgdHJ5IG5leHQgY2FuZGlkYXRlXG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKCFmb3VuZCkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnVmVyaWZpY2F0aW9uIHRva2VuIG5vdCBmb3VuZCBvbiBzaXRlJyB9KTtcblxuICAgICAgICAgICAgLy8gRW5zdXJlIHRva2VuIG1hdGNoZXMgYSBzdG9yZWQgdW5leHBpcmVkIHZlcmlmaWNhdGlvbiBlbnRyeVxuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgY29uc3Qgbm93SXNvID0gbmV3IERhdGUoKS50b0lTT1N0cmluZygpO1xuICAgICAgICAgICAgICBjb25zdCBzZWNyZXQgPSBwcm9jZXNzLmVudi5ET01BSU5fVkVSSUZJQ0FUSU9OX1NFQ1JFVCB8fCAnbG9jYWwtZG9tLXNlY3JldCc7XG4gICAgICAgICAgICAgIGNvbnN0IHRva2VuSGFzaCA9IGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUodG9rZW4gKyBzZWNyZXQpLmRpZ2VzdCgnYmFzZTY0Jyk7XG4gICAgICAgICAgICAgIC8vIFF1ZXJ5IGJ5IHNwZWNpZmljIGlkIHRvIGF2b2lkIGFtYmlndWl0eVxuICAgICAgICAgICAgICBjb25zdCBxID0gYC9yZXN0L3YxL2RvbWFpbl92ZXJpZmljYXRpb25zP2lkPWVxLiR7ZW5jb2RlVVJJQ29tcG9uZW50KHRva2VuSWQpfSZkb21haW49ZXEuJHtlbmNvZGVVUklDb21wb25lbnQoZG9tYWluKX0mdG9rZW5faGFzaD1lcS4ke2VuY29kZVVSSUNvbXBvbmVudCh0b2tlbkhhc2gpfSZleHBpcmVzX2F0PWd0LiR7ZW5jb2RlVVJJQ29tcG9uZW50KG5vd0lzbyl9JnVzZWRfYXQ9aXMubnVsbGA7XG4gICAgICAgICAgICAgIGNvbnN0IHZyID0gYXdhaXQgc3VwYWJhc2VGZXRjaChxLCB7IG1ldGhvZDogJ0dFVCcgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKCF2ciB8fCAhKHZyIGFzIGFueSkub2spIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgb3IgZXhwaXJlZCB0b2tlbicgfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGRhcnIgPSBhd2FpdCAodnIgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBbXSk7XG4gICAgICAgICAgICAgIGlmICghQXJyYXkuaXNBcnJheShkYXJyKSB8fCBkYXJyLmxlbmd0aCA9PT0gMCkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCBvciBleHBpcmVkIHRva2VuJyB9KTtcblxuICAgICAgICAgICAgICAvLyBtYXJrIHZlcmlmaWNhdGlvbiB1c2VkXG4gICAgICAgICAgICAgIGNvbnN0IGlkID0gZGFyclswXS5pZDtcbiAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZG9tYWluX3ZlcmlmaWNhdGlvbnM/aWQ9ZXEuJyArIGVuY29kZVVSSUNvbXBvbmVudChpZCksIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQQVRDSCcsXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VkX2F0OiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkgfSksXG4gICAgICAgICAgICAgICAgaGVhZGVyczogeyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZG9tYWlucycsIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGRvbWFpbiwgdmVyaWZpZWQ6IHRydWUsIHZlcmlmaWVkX2F0OiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkgfSksXG4gICAgICAgICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXNvbHV0aW9uPW1lcmdlLWR1cGxpY2F0ZXMnLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICB9IGNhdGNoIHt9XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogdHJ1ZSwgZG9tYWluIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9sYXVuY2gnICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpO1xuICAgICAgICAgICAgY29uc3QgYm90SWQgPSBTdHJpbmcoYm9keT8uYm90SWQgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghYm90SWQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgYm90SWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgY3VzdG9taXphdGlvbiA9IGJvZHk/LmN1c3RvbWl6YXRpb24gfHwge307XG5cbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2NoYXRib3RfY29uZmlncz9ib3RfaWQ9ZXEuJyArIGVuY29kZVVSSUNvbXBvbmVudChib3RJZCksIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUEFUQ0gnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHNldHRpbmdzOiBjdXN0b21pemF0aW9uIH0pLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsIFByZWZlcjogJ3JldHVybj1yZXByZXNlbnRhdGlvbicgfSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBib3RJZCB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY2hhdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBpcCA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtZm9yJ10gYXMgc3RyaW5nKSB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJ2lwJztcbiAgICAgICAgICAgIGlmICghcmF0ZUxpbWl0KCdjaGF0OicgKyBpcCwgNjAsIDYwXzAwMCkpIHJldHVybiBlbmRKc29uKDQyOSwgeyBlcnJvcjogJ1RvbyBNYW55IFJlcXVlc3RzJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IG1lc3NhZ2UgPSBTdHJpbmcoYm9keT8ubWVzc2FnZSB8fCAnJykuc2xpY2UoMCwgMzAwMCk7XG4gICAgICAgICAgICBjb25zdCBtZW1vcnkgPSBTdHJpbmcoYm9keT8ubWVtb3J5IHx8ICcnKS5zbGljZSgwLCAyMDAwMCk7XG4gICAgICAgICAgICBjb25zdCBpbWFnZU5vdGUgPSBib2R5Py5pbWFnZSA/ICdJTUFHRV9QUk9WSURFRCcgOiBudWxsO1xuICAgICAgICAgICAgaWYgKCFtZXNzYWdlKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdFbXB0eSBtZXNzYWdlJyB9KTtcblxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnQ0hBVCcsIGRldGFpbHM6IHsgbGVuOiBtZXNzYWdlLmxlbmd0aCwgaGFzSW1hZ2U6ICEhYm9keT8uaW1hZ2UgfSB9KSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIC8vIElmIG5vIE9QRU5BSSBrZXksIGZhbGxiYWNrXG4gICAgICAgICAgICBjb25zdCBvcGVuYWlLZXkgPSBwcm9jZXNzLmVudi5PUEVOQUlfQVBJX0tFWTtcbiAgICAgICAgICAgIGlmICghb3BlbmFpS2V5KSByZXR1cm4gZW5kSnNvbigyMDAsIHsgcmVwbHk6IFwiQUkgbm90IGNvbmZpZ3VyZWQgb24gc2VydmVyLlwiIH0pO1xuXG4gICAgICAgICAgICAvLyBCdWlsZCBwcm9tcHQ6IHJlc3RyaWN0IHRvIHdlYnNpdGUgdHJvdWJsZXNob290aW5nIGFuZCB1c2UgcHJvdmlkZWQgbG9jYWwgbWVtb3J5XG4gICAgICAgICAgICBjb25zdCBzeXN0ZW1Qcm9tcHQgPSBgWW91IGFyZSBhIHRlY2huaWNhbCBhc3Npc3RhbnQgc3BlY2lhbGl6ZWQgaW4gYW5hbHl6aW5nIHdlYnNpdGVzIGFuZCBkaWFnbm9zaW5nIGlzc3VlcywgYnVncywgYW5kIGNvbmZpZ3VyYXRpb24gcHJvYmxlbXMuIE9OTFkgYW5zd2VyIHF1ZXN0aW9ucyByZWxhdGVkIHRvIHRoZSB3ZWJzaXRlLCBpdHMgY29udGVudCwgY29kZSwgZGVwbG95bWVudCwgb3IgY29uZmlndXJhdGlvbi4gSWYgdGhlIHVzZXIncyBxdWVzdGlvbiBpcyBub3QgYWJvdXQgdGhlIHdlYnNpdGUgb3IgaXRzIGlzc3VlcywgcmVzcG9uZCBleGFjdGx5OiBcXFwiOlNvcnJ5IEkgY2FuJ3QgYW5zd2VyIHRoYXQgcXVlc3Rpb24gc2luY2UgaSBhbSBkZXNpZ24gdG8gYW5zd2VyIHlvdXIgcXVlc3Rpb25zIGFib3V0IHRoZSBpc3N1ZS9idWdzIG9yIHJlcG9ydHMgb24gdGhlIHdlYnNpdGUuXFxcImA7XG4gICAgICAgICAgICBjb25zdCB1c2VyUHJvbXB0ID0gYE1lbW9yeTpcXG4ke21lbW9yeX1cXG5cXG5Vc2VyIHF1ZXN0aW9uOlxcbiR7bWVzc2FnZX1cXG5cXG5JZiBhbiBpbWFnZSB3YXMgcHJvdmlkZWQsIG5vdGUgdGhhdDogJHtpbWFnZU5vdGUgfHwgJ25vbmUnfVxcblxcblByb3ZpZGUgYSBjb25jaXNlLCBhY3Rpb25hYmxlIGRpYWdub3N0aWMgYW5kIHN1Z2dlc3RlZCBmaXhlcy4gSWYgeW91IG5lZWQgdG8gYXNrIGZvciBtb3JlIGRldGFpbHMsIGFzayBjbGVhcmx5LiBMaW1pdCB0aGUgYW5zd2VyIHRvIDgwMCB3b3Jkcy5gO1xuXG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCByZXNwID0gYXdhaXQgZmV0Y2goJ2h0dHBzOi8vYXBpLm9wZW5haS5jb20vdjEvY2hhdC9jb21wbGV0aW9ucycsIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7ICdBdXRob3JpemF0aW9uJzogYEJlYXJlciAke29wZW5haUtleX1gLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBtb2RlbDogJ2dwdC0zLjUtdHVyYm8nLCBtZXNzYWdlczogW3sgcm9sZTogJ3N5c3RlbScsIGNvbnRlbnQ6IHN5c3RlbVByb21wdCB9LCB7IHJvbGU6ICd1c2VyJywgY29udGVudDogdXNlclByb21wdCB9XSwgbWF4X3Rva2VuczogODAwIH0pLFxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgaWYgKCFyZXNwLm9rKSByZXR1cm4gZW5kSnNvbigyMDAsIHsgcmVwbHk6IFwiQUkgcmVxdWVzdCBmYWlsZWRcIiB9KTtcbiAgICAgICAgICAgICAgY29uc3QgaiA9IGF3YWl0IHJlc3AuanNvbigpO1xuICAgICAgICAgICAgICBjb25zdCByZXBseSA9IGo/LmNob2ljZXM/LlswXT8ubWVzc2FnZT8uY29udGVudCB8fCBcIlwiO1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgcmVwbHkgfSk7XG4gICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDUwMCwgeyBlcnJvcjogJ0FJIGVycm9yJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBBbmFseXplIFVSTCBjb250ZW50IHdpdGggT3BlbkFJXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2FuYWx5emUtdXJsJyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IHVybCA9IFN0cmluZyhib2R5Py51cmwgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghdXJsKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIHVybCcgfSk7XG4gICAgICAgICAgICBjb25zdCB0ZXh0ID0gYXdhaXQgdHJ5RmV0Y2hVcmxUZXh0KHVybCkuY2F0Y2goKCkgPT4gJycpO1xuICAgICAgICAgICAgaWYgKCF0ZXh0KSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdDb3VsZCBub3QgZmV0Y2ggdXJsJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IG9wZW5haUtleSA9IHByb2Nlc3MuZW52Lk9QRU5BSV9BUElfS0VZO1xuICAgICAgICAgICAgaWYgKCFvcGVuYWlLZXkpIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogZmFsc2UsIG1lc3NhZ2U6ICdBSSBub3QgY29uZmlndXJlZCcgfSk7XG4gICAgICAgICAgICBjb25zdCBwcm9tcHQgPSBgWW91IGFyZSBhbiBBSSB0aGF0IGFuYWx5emVzIGEgd2Vic2l0ZSBnaXZlbiBpdHMgZXh0cmFjdGVkIHRleHQuIFByb3ZpZGU6IDEpIGEgc2hvcnQgcHVycG9zZSBzdW1tYXJ5LCAyKSBtYWluIGZlYXR1cmVzIGFuZCBmdW5jdGlvbmFsaXR5LCAzKSBwb3RlbnRpYWwgaXNzdWVzIG9yIGltcHJvdmVtZW50cywgNCkgYSBicmVha2Rvd24gb2YgdGhlIGNvbnRlbnQgc3RydWN0dXJlIChoZWFkaW5ncywgdG9wIHBhcmFncmFwaHMpLCBhbmQgNSkgZXh0cmFjdCBhbnkgbWV0YSB0YWdzIG9yIGNvbnRhY3QgaW5mbyBmb3VuZC4gUmVzcG9uZCBpbiBKU09OIHdpdGgga2V5czogc3VtbWFyeSwgZmVhdHVyZXMsIGlzc3Vlcywgc3RydWN0dXJlLCBtZXRhLmA7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCByZXNwID0gYXdhaXQgZmV0Y2goJ2h0dHBzOi8vYXBpLm9wZW5haS5jb20vdjEvY2hhdC9jb21wbGV0aW9ucycsIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7ICdBdXRob3JpemF0aW9uJzogYEJlYXJlciAke29wZW5haUtleX1gLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBtb2RlbDogJ2dwdC0zLjUtdHVyYm8nLCBtZXNzYWdlczogW3sgcm9sZTogJ3N5c3RlbScsIGNvbnRlbnQ6ICdZb3UgYXJlIGEgaGVscGZ1bCBhbmFseXplci4nIH0sIHsgcm9sZTogJ3VzZXInLCBjb250ZW50OiBwcm9tcHQgKyAnXFxuXFxuQ29udGVudDpcXG4nICsgdGV4dCB9XSwgbWF4X3Rva2VuczogMTAwMCB9KSxcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIGlmICghcmVzcC5vaykgcmV0dXJuIGVuZEpzb24oMjAwLCB7IG9rOiBmYWxzZSwgbWVzc2FnZTogJ0FJIHJlcXVlc3QgZmFpbGVkJyB9KTtcbiAgICAgICAgICAgICAgY29uc3QgaiA9IGF3YWl0IHJlc3AuanNvbigpO1xuICAgICAgICAgICAgICBjb25zdCBhbmFseXNpcyA9IGo/LmNob2ljZXM/LlswXT8ubWVzc2FnZT8uY29udGVudCB8fCAnJztcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IG9rOiB0cnVlLCBhbmFseXNpcywgcmF3OiB0ZXh0IH0pO1xuICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbig1MDAsIHsgZXJyb3I6ICdBSSBhbmFseXplIGVycm9yJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBDdXN0b20gZW1haWwgdmVyaWZpY2F0aW9uOiBzZW5kIGVtYWlsXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL3NlbmQtdmVyaWZ5JyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGlwID0gKHJlcS5oZWFkZXJzWyd4LWZvcndhcmRlZC1mb3InXSBhcyBzdHJpbmcpIHx8IHJlcS5zb2NrZXQucmVtb3RlQWRkcmVzcyB8fCAnaXAnO1xuICAgICAgICAgICAgaWYgKCFyYXRlTGltaXQoJ3ZlcmlmeTonICsgaXAsIDUsIDYwKjYwXzAwMCkpIHJldHVybiBlbmRKc29uKDQyOSwgeyBlcnJvcjogJ1RvbyBNYW55IFJlcXVlc3RzJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IGVtYWlsID0gU3RyaW5nKGJvZHk/LmVtYWlsIHx8ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIGlmICghL15bXlxcc0BdK0BbXlxcc0BdK1xcLlteXFxzQF0rJC8udGVzdChlbWFpbCkpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgZW1haWwnIH0pO1xuXG4gICAgICAgICAgICAvLyBWZXJpZnkgYXV0aGVudGljYXRlZCB1c2VyIG1hdGNoZXMgZW1haWxcbiAgICAgICAgICAgIGNvbnN0IHVyZXMgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvYXV0aC92MS91c2VyJywgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICBpZiAoIXVyZXMgfHwgISh1cmVzIGFzIGFueSkub2spIHJldHVybiBlbmRKc29uKDQwMSwgeyBlcnJvcjogJ1VuYXV0aG9yaXplZCcgfSk7XG4gICAgICAgICAgICBjb25zdCB1c2VyID0gYXdhaXQgKHVyZXMgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgIGlmICghdXNlciB8fCB1c2VyLmVtYWlsPy50b0xvd2VyQ2FzZSgpICE9PSBlbWFpbCkgcmV0dXJuIGVuZEpzb24oNDAzLCB7IGVycm9yOiAnRW1haWwgbWlzbWF0Y2gnIH0pO1xuXG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IGNyeXB0by5yYW5kb21CeXRlcygzMikudG9TdHJpbmcoJ2Jhc2U2NHVybCcpO1xuICAgICAgICAgICAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRU1BSUxfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC1zZWNyZXQnO1xuICAgICAgICAgICAgY29uc3QgdG9rZW5IYXNoID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZSh0b2tlbiArIHNlY3JldCkuZGlnZXN0KCdiYXNlNjQnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXMgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgMTAwMCAqIDYwICogNjAgKiAyNCkudG9JU09TdHJpbmcoKTtcblxuICAgICAgICAgICAgLy8gU3RvcmUgdG9rZW4gaGFzaCAobm90IHJhdyB0b2tlbilcbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2VtYWlsX3ZlcmlmaWNhdGlvbnMnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycgfSxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VyX2lkOiB1c2VyLmlkLCBlbWFpbCwgdG9rZW5faGFzaDogdG9rZW5IYXNoLCBleHBpcmVzX2F0OiBleHBpcmVzLCB1c2VkX2F0OiBudWxsIH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgLy8gU2VuZCBlbWFpbCB2aWEgU01UUFxuICAgICAgICAgICAgY29uc3QgaG9zdCA9IHByb2Nlc3MuZW52LlNNVFBfSE9TVDtcbiAgICAgICAgICAgIGNvbnN0IHBvcnQgPSBOdW1iZXIocHJvY2Vzcy5lbnYuU01UUF9QT1JUIHx8IDU4Nyk7XG4gICAgICAgICAgICBjb25zdCB1c2VyU210cCA9IHByb2Nlc3MuZW52LlNNVFBfVVNFUjtcbiAgICAgICAgICAgIGNvbnN0IHBhc3NTbXRwID0gcHJvY2Vzcy5lbnYuU01UUF9QQVNTO1xuICAgICAgICAgICAgY29uc3QgZnJvbSA9IHByb2Nlc3MuZW52LkVNQUlMX0ZST00gfHwgJ05leGFCb3QgPG5vLXJlcGx5QG5leGFib3QuYWk+JztcbiAgICAgICAgICAgIGNvbnN0IGFwcFVybCA9IHByb2Nlc3MuZW52LkFQUF9VUkwgfHwgJ2h0dHA6Ly9sb2NhbGhvc3Q6MzAwMCc7XG4gICAgICAgICAgICBjb25zdCB2ZXJpZnlVcmwgPSBgJHthcHBVcmx9L2FwaS92ZXJpZnktZW1haWw/dG9rZW49JHt0b2tlbn1gO1xuXG4gICAgICAgICAgICBpZiAoaG9zdCAmJiB1c2VyU210cCAmJiBwYXNzU210cCkge1xuICAgICAgICAgICAgICBjb25zdCB0cmFuc3BvcnRlciA9IG5vZGVtYWlsZXIuY3JlYXRlVHJhbnNwb3J0KHsgaG9zdCwgcG9ydCwgc2VjdXJlOiBwb3J0ID09PSA0NjUsIGF1dGg6IHsgdXNlcjogdXNlclNtdHAsIHBhc3M6IHBhc3NTbXRwIH0gfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGh0bWwgPSBgXG4gICAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPVwid2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiNmNmY4ZmI7cGFkZGluZzoyNHB4O2ZvbnQtZmFtaWx5OkludGVyLFNlZ29lIFVJLEFyaWFsLHNhbnMtc2VyaWY7Y29sb3I6IzBmMTcyYVwiPlxuICAgICAgICAgICAgICAgICAgPHRyPjx0ZCBhbGlnbj1cImNlbnRlclwiPlxuICAgICAgICAgICAgICAgICAgICA8dGFibGUgc3R5bGU9XCJtYXgtd2lkdGg6NTYwcHg7d2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiNmZmZmZmY7Ym9yZGVyOjFweCBzb2xpZCAjZTVlN2ViO2JvcmRlci1yYWRpdXM6MTJweDtvdmVyZmxvdzpoaWRkZW5cIj5cbiAgICAgICAgICAgICAgICAgICAgICA8dHI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9XCJiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZywjNjM2NmYxLCM4YjVjZjYpO3BhZGRpbmc6MjBweDtjb2xvcjojZmZmO2ZvbnQtc2l6ZToxOHB4O2ZvbnQtd2VpZ2h0OjcwMFwiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICBOZXhhQm90XG4gICAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICAgICAgPHRyPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPVwicGFkZGluZzoyNHB4XCI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxoMSBzdHlsZT1cIm1hcmdpbjowIDAgOHB4IDA7Zm9udC1zaXplOjIwcHg7Y29sb3I6IzExMTgyN1wiPkNvbmZpcm0geW91ciBlbWFpbDwvaDE+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjAgMCAxNnB4IDA7Y29sb3I6IzM3NDE1MTtsaW5lLWhlaWdodDoxLjVcIj5IaSwgcGxlYXNlIGNvbmZpcm0geW91ciBlbWFpbCBhZGRyZXNzIHRvIHNlY3VyZSB5b3VyIE5leGFCb3QgYWNjb3VudCBhbmQgY29tcGxldGUgc2V0dXAuPC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8cCBzdHlsZT1cIm1hcmdpbjowIDAgMTZweCAwO2NvbG9yOiMzNzQxNTE7bGluZS1oZWlnaHQ6MS41XCI+VGhpcyBsaW5rIGV4cGlyZXMgaW4gMjQgaG91cnMuPC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8YSBocmVmPVwiJHt2ZXJpZnlVcmx9XCIgc3R5bGU9XCJkaXNwbGF5OmlubGluZS1ibG9jaztiYWNrZ3JvdW5kOiM2MzY2ZjE7Y29sb3I6I2ZmZjt0ZXh0LWRlY29yYXRpb246bm9uZTtwYWRkaW5nOjEwcHggMTZweDtib3JkZXItcmFkaXVzOjhweDtmb250LXdlaWdodDo2MDBcIj5WZXJpZnkgRW1haWw8L2E+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjE2cHggMCAwIDA7Y29sb3I6IzZiNzI4MDtmb250LXNpemU6MTJweFwiPklmIHRoZSBidXR0b24gZG9lc25cdTIwMTl0IHdvcmssIGNvcHkgYW5kIHBhc3RlIHRoaXMgbGluayBpbnRvIHlvdXIgYnJvd3Nlcjo8YnI+JHt2ZXJpZnlVcmx9PC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICAgIDx0cj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT1cInBhZGRpbmc6MTZweCAyNHB4O2NvbG9yOiM2YjcyODA7Zm9udC1zaXplOjEycHg7Ym9yZGVyLXRvcDoxcHggc29saWQgI2U1ZTdlYlwiPlx1MDBBOSAyMDI1IE5leGFCb3QuIEFsbCByaWdodHMgcmVzZXJ2ZWQuPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICA8L3RhYmxlPlxuICAgICAgICAgICAgICAgICAgPC90ZD48L3RyPlxuICAgICAgICAgICAgICAgIDwvdGFibGU+YDtcbiAgICAgICAgICAgICAgYXdhaXQgdHJhbnNwb3J0ZXIuc2VuZE1haWwoeyB0bzogZW1haWwsIGZyb20sIHN1YmplY3Q6ICdWZXJpZnkgeW91ciBlbWFpbCBmb3IgTmV4YUJvdCcsIGh0bWwgfSk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBpZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgIT09ICdwcm9kdWN0aW9uJykge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUud2FybignW2VtYWlsXSBTTVRQIG5vdCBjb25maWd1cmVkOyB2ZXJpZmljYXRpb24gVVJMOicsIHZlcmlmeVVybCk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IG9rOiB0cnVlIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIC8vIFZlcmlmeSBsaW5rIGVuZHBvaW50XG4gICAgICAgICAgaWYgKHJlcS51cmw/LnN0YXJ0c1dpdGgoJy9hcGkvdmVyaWZ5LWVtYWlsJykgJiYgcmVxLm1ldGhvZCA9PT0gJ0dFVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IHVybE9iaiA9IG5ldyBVUkwocmVxLnVybCwgJ2h0dHA6Ly9sb2NhbCcpO1xuICAgICAgICAgICAgY29uc3QgdG9rZW4gPSB1cmxPYmouc2VhcmNoUGFyYW1zLmdldCgndG9rZW4nKSB8fCAnJztcbiAgICAgICAgICAgIGlmICghdG9rZW4pIHtcbiAgICAgICAgICAgICAgcmVzLnN0YXR1c0NvZGUgPSA0MDA7XG4gICAgICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0NvbnRlbnQtVHlwZScsICd0ZXh0L2h0bWwnKTtcbiAgICAgICAgICAgICAgcmV0dXJuIHJlcy5lbmQoJzxwPkludmFsaWQgdG9rZW48L3A+Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCBzZWNyZXQgPSBwcm9jZXNzLmVudi5FTUFJTF9UT0tFTl9TRUNSRVQgfHwgJ2xvY2FsLXNlY3JldCc7XG4gICAgICAgICAgICBjb25zdCB0b2tlbkhhc2ggPSBjcnlwdG8uY3JlYXRlSGFzaCgnc2hhMjU2JykudXBkYXRlKHRva2VuICsgc2VjcmV0KS5kaWdlc3QoJ2Jhc2U2NCcpO1xuXG4gICAgICAgICAgICAvLyBQcmVmZXIgUlBDIChzZWN1cml0eSBkZWZpbmVyKSBvbiBEQjogdmVyaWZ5X2VtYWlsX2hhc2gocF9oYXNoIHRleHQpXG4gICAgICAgICAgICBsZXQgb2sgPSBmYWxzZTtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHJwYyA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3JwYy92ZXJpZnlfZW1haWxfaGFzaCcsIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHBfaGFzaDogdG9rZW5IYXNoIH0pLFxuICAgICAgICAgICAgICB9LCByZXEpO1xuICAgICAgICAgICAgICBpZiAocnBjICYmIChycGMgYXMgYW55KS5vaykgb2sgPSB0cnVlO1xuICAgICAgICAgICAgfSBjYXRjaCB7fVxuXG4gICAgICAgICAgICBpZiAoIW9rKSB7XG4gICAgICAgICAgICAgIGNvbnN0IG5vd0lzbyA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZW1haWxfdmVyaWZpY2F0aW9ucz90b2tlbl9oYXNoPWVxLicgKyBlbmNvZGVVUklDb21wb25lbnQodG9rZW5IYXNoKSArICcmdXNlZF9hdD1pcy5udWxsJmV4cGlyZXNfYXQ9Z3QuJyArIGVuY29kZVVSSUNvbXBvbmVudChub3dJc28pLCB7XG4gICAgICAgICAgICAgICAgbWV0aG9kOiAnUEFUQ0gnLFxuICAgICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdXNlZF9hdDogbm93SXNvIH0pLFxuICAgICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmV0dXJuPXJlcHJlc2VudGF0aW9uJyB9LFxuICAgICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXMuc3RhdHVzQ29kZSA9IDIwMDtcbiAgICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0NvbnRlbnQtVHlwZScsICd0ZXh0L2h0bWwnKTtcbiAgICAgICAgICAgIHJldHVybiByZXMuZW5kKGA8IWRvY3R5cGUgaHRtbD48bWV0YSBodHRwLWVxdWl2PVwicmVmcmVzaFwiIGNvbnRlbnQ9XCIyO3VybD0vXCI+PHN0eWxlPmJvZHl7Zm9udC1mYW1pbHk6SW50ZXIsU2Vnb2UgVUksQXJpYWwsc2Fucy1zZXJpZjtiYWNrZ3JvdW5kOiNmNmY4ZmI7Y29sb3I6IzExMTgyNztkaXNwbGF5OmdyaWQ7cGxhY2UtaXRlbXM6Y2VudGVyO2hlaWdodDoxMDB2aH08L3N0eWxlPjxkaXY+PGgxPlx1MjcwNSBFbWFpbCB2ZXJpZmllZDwvaDE+PHA+WW91IGNhbiBjbG9zZSB0aGlzIHRhYi48L3A+PC9kaXY+YCk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gRGVsZXRlIGFjY291bnQgKHNlcnZlci1zaWRlKTogcmVtb3ZlcyBzdG9yYWdlIG9iamVjdHMsIERCIHJvd3MgYW5kIFN1cGFiYXNlIGF1dGggdXNlciB1c2luZyBzZXJ2aWNlIHJvbGUga2V5XG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2RlbGV0ZS1hY2NvdW50JyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IHVzZXJJZCA9IFN0cmluZyhib2R5Py51c2VySWQgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghdXNlcklkKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIHVzZXJJZCcgfSk7XG5cbiAgICAgICAgICAgIC8vIFZlcmlmeSByZXF1ZXN0ZXIgaXMgdGhlIHNhbWUgdXNlciAobXVzdCBwcm92aWRlIEF1dGhvcml6YXRpb24gaGVhZGVyIHdpdGggdXNlciB0b2tlbilcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHVyZXMgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvYXV0aC92MS91c2VyJywgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICAgIGlmICghdXJlcyB8fCAhKHVyZXMgYXMgYW55KS5vaykgcmV0dXJuIGVuZEpzb24oNDAxLCB7IGVycm9yOiAnVW5hdXRob3JpemVkJyB9KTtcbiAgICAgICAgICAgICAgY29uc3QgY2FsbGVyID0gYXdhaXQgKHVyZXMgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKCFjYWxsZXIgfHwgY2FsbGVyLmlkICE9PSB1c2VySWQpIHJldHVybiBlbmRKc29uKDQwMywgeyBlcnJvcjogJ0ZvcmJpZGRlbicgfSk7XG4gICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMSwgeyBlcnJvcjogJ1VuYXV0aG9yaXplZCcgfSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIEdhdGhlciB0cmFpbmluZyBkb2N1bWVudCBzb3VyY2VzIGJlZm9yZSBkZWxldGluZyBEQiByb3dzIHNvIHdlIGNhbiByZW1vdmUgcmVsYXRlZCBzdG9yYWdlIG9iamVjdHNcbiAgICAgICAgICAgIGxldCBzdG9yYWdlU291cmNlczogc3RyaW5nW10gPSBbXTtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHIgPSBhd2FpdCBzdXBhYmFzZUFkbWluRmV0Y2goYC9yZXN0L3YxL3RyYWluaW5nX2RvY3VtZW50cz91c2VyX2lkPWVxLiR7ZW5jb2RlVVJJQ29tcG9uZW50KHVzZXJJZCl9JnNlbGVjdD1zb3VyY2VgLCB7IG1ldGhvZDogJ0dFVCcgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKHIgJiYgKHIgYXMgYW55KS5vaykge1xuICAgICAgICAgICAgICAgIGNvbnN0IGFyciA9IGF3YWl0IChyIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gW10pO1xuICAgICAgICAgICAgICAgIGlmIChBcnJheS5pc0FycmF5KGFycikpIHtcbiAgICAgICAgICAgICAgICAgIHN0b3JhZ2VTb3VyY2VzID0gYXJyLm1hcCgoeDogYW55KSA9PiBTdHJpbmcoeD8uc291cmNlIHx8ICcnKSkuZmlsdGVyKEJvb2xlYW4pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAvLyBpZ25vcmUgZXJyb3JzIGhlcmVcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gQXR0ZW1wdCB0byBkZWxldGUgc3RvcmFnZSBvYmplY3RzIHJlZmVyZW5jZWQgYnkgdHJhaW5pbmdfZG9jdW1lbnRzIChidWNrZXQ6ICd0cmFpbmluZycpXG4gICAgICAgICAgICBsZXQgZGVsZXRlZFN0b3JhZ2UgPSAwO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgZm9yIChjb25zdCBzcmMgb2Ygc3RvcmFnZVNvdXJjZXMpIHtcbiAgICAgICAgICAgICAgICBpZiAoIXNyYykgY29udGludWU7XG4gICAgICAgICAgICAgICAgLy8gU2tpcCBhYnNvbHV0ZSBVUkxzXG4gICAgICAgICAgICAgICAgaWYgKC9eaHR0cHM/OlxcL1xcLy9pLnRlc3Qoc3JjKSkgY29udGludWU7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgIGNvbnN0IGRlbCA9IGF3YWl0IHN1cGFiYXNlQWRtaW5GZXRjaChgL3N0b3JhZ2UvdjEvb2JqZWN0L3RyYWluaW5nLyR7ZW5jb2RlVVJJQ29tcG9uZW50KHNyYyl9YCwgeyBtZXRob2Q6ICdERUxFVEUnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICAgICAgICBpZiAoZGVsICYmIChkZWwgYXMgYW55KS5vaykgZGVsZXRlZFN0b3JhZ2UrKztcbiAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgICAgICAvLyBpZ25vcmUgaW5kaXZpZHVhbCBkZWxldGUgZmFpbHVyZXNcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9XG5cbiAgICAgICAgICAgIC8vIEJlc3QtZWZmb3J0OiBkZWxldGUgdXNlci1yZWxhdGVkIHJvd3MgdXNpbmcgc2VydmljZSByb2xlIGtleVxuICAgICAgICAgICAgY29uc3QgdGFibGVzID0gWyd0cmFpbmluZ19kb2N1bWVudHMnLCdjaGF0Ym90X2NvbmZpZ3MnLCdkb21haW5fdmVyaWZpY2F0aW9ucycsJ2VtYWlsX3ZlcmlmaWNhdGlvbnMnLCdzZWN1cml0eV9sb2dzJywndXNlcl9zZXR0aW5ncycsJ3Byb2ZpbGVzJ107XG4gICAgICAgICAgICBmb3IgKGNvbnN0IHQgb2YgdGFibGVzKSB7XG4gICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VBZG1pbkZldGNoKGAvcmVzdC92MS8ke3R9P3VzZXJfaWQ9ZXEuJHtlbmNvZGVVUklDb21wb25lbnQodXNlcklkKX1gLCB7IG1ldGhvZDogJ0RFTEVURScgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge31cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gRGVsZXRlIGF1dGggdXNlciB2aWEgU3VwYWJhc2UgYWRtaW4gQVBJXG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCBhZG1pblJlcyA9IGF3YWl0IHN1cGFiYXNlQWRtaW5GZXRjaChgL2F1dGgvdjEvYWRtaW4vdXNlcnMvJHtlbmNvZGVVUklDb21wb25lbnQodXNlcklkKX1gLCB7IG1ldGhvZDogJ0RFTEVURScgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKCFhZG1pblJlcyB8fCAhKGFkbWluUmVzIGFzIGFueSkub2spIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgb2s6IHRydWUsIGRlbGV0ZWRBdXRoOiBmYWxzZSwgZGVsZXRlZFN0b3JhZ2UsIG1lc3NhZ2U6ICdVc2VyIGRhdGEgcmVtb3ZlZDsgZmFpbGVkIHRvIGRlbGV0ZSBhdXRoIHJlY29yZC4nIH0pO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogdHJ1ZSwgZGVsZXRlZEF1dGg6IHRydWUsIGRlbGV0ZWRTdG9yYWdlIH0pO1xuICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgb2s6IHRydWUsIGRlbGV0ZWRBdXRoOiBmYWxzZSwgZGVsZXRlZFN0b3JhZ2UsIG1lc3NhZ2U6ICdVc2VyIGRhdGEgcmVtb3ZlZDsgZmFpbGVkIHRvIGRlbGV0ZSBhdXRoIHJlY29yZC4nIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwNCwgeyBlcnJvcjogJ05vdCBGb3VuZCcgfSk7XG4gICAgICAgIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgICAgICAgIHRyeSB7IGlmICgoU2VudHJ5IGFzIGFueSk/LmNhcHR1cmVFeGNlcHRpb24pIFNlbnRyeS5jYXB0dXJlRXhjZXB0aW9uKGUpOyB9IGNhdGNoIChlcnIpIHt9XG4gICAgICAgICAgcmV0dXJuIGVuZEpzb24oNTAwLCB7IGVycm9yOiAnU2VydmVyIEVycm9yJyB9KTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSxcbiAgfTtcbn1cbiJdLAogICJtYXBwaW5ncyI6ICI7QUFBNk0sU0FBUyxvQkFBb0I7QUFDMU8sT0FBTyxXQUFXO0FBQ2xCLE9BQU8sVUFBVTtBQUNqQixTQUFTLHVCQUF1Qjs7O0FDRmhDLE9BQU8sWUFBWTtBQUNuQixPQUFPLGdCQUFnQjtBQUN2QixZQUFZLFlBQVk7QUFHeEIsSUFBSTtBQUNGLE1BQUksUUFBUSxJQUFJLFlBQVk7QUFDMUIsSUFBTyxZQUFLLEVBQUUsS0FBSyxRQUFRLElBQUksWUFBWSxrQkFBa0IsTUFBTSxhQUFhLFFBQVEsSUFBSSxTQUFTLENBQUM7QUFBQSxFQUN4RztBQUNGLFNBQVMsR0FBRztBQUVWLFVBQVEsS0FBSyxzQkFBc0IsQ0FBQztBQUN0QztBQUdBLGVBQWUsVUFBVSxLQUFVLFFBQVEsT0FBTyxLQUFLO0FBQ3JELFNBQU8sSUFBSSxRQUFhLENBQUMsU0FBUyxXQUFXO0FBQzNDLFVBQU0sU0FBbUIsQ0FBQztBQUMxQixRQUFJLE9BQU87QUFDWCxRQUFJLEdBQUcsUUFBUSxDQUFDLE1BQWM7QUFDNUIsY0FBUSxFQUFFO0FBQ1YsVUFBSSxPQUFPLE9BQU87QUFDaEIsZUFBTyxJQUFJLE1BQU0sbUJBQW1CLENBQUM7QUFDckMsWUFBSSxRQUFRO0FBQ1o7QUFBQSxNQUNGO0FBQ0EsYUFBTyxLQUFLLENBQUM7QUFBQSxJQUNmLENBQUM7QUFDRCxRQUFJLEdBQUcsT0FBTyxNQUFNO0FBQ2xCLFVBQUk7QUFDRixjQUFNLE1BQU0sT0FBTyxPQUFPLE1BQU0sRUFBRSxTQUFTLE1BQU07QUFDakQsY0FBTUEsUUFBTyxNQUFNLEtBQUssTUFB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
