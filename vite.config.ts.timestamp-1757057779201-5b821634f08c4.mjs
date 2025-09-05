// vite.config.ts
import { defineConfig } from "file:///app/code/node_modules/vite/dist/node/index.js";
import react from "file:///app/code/node_modules/@vitejs/plugin-react-swc/index.js";
import path from "path";
import { componentTagger } from "file:///app/code/node_modules/lovable-tagger/dist/index.js";

// src/server/api.ts
import crypto from "crypto";
import nodemailer from "file:///app/code/node_modules/nodemailer/lib/nodemailer.js";
import Sentry from "@sentry/node";
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL3NlcnZlci9hcGkudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGVcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9hcHAvY29kZS92aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vYXBwL2NvZGUvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tIFwidml0ZVwiO1xuaW1wb3J0IHJlYWN0IGZyb20gXCJAdml0ZWpzL3BsdWdpbi1yZWFjdC1zd2NcIjtcbmltcG9ydCBwYXRoIGZyb20gXCJwYXRoXCI7XG5pbXBvcnQgeyBjb21wb25lbnRUYWdnZXIgfSBmcm9tIFwibG92YWJsZS10YWdnZXJcIjtcbmltcG9ydCB7IHNlcnZlckFwaVBsdWdpbiB9IGZyb20gXCIuL3NyYy9zZXJ2ZXIvYXBpXCI7XG5cbi8vIGh0dHBzOi8vdml0ZWpzLmRldi9jb25maWcvXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiAoe1xuICBzZXJ2ZXI6IHtcbiAgICBob3N0OiBcIjo6XCIsXG4gICAgcG9ydDogODA4MCxcbiAgfSxcbiAgcGx1Z2luczogW1xuICAgIHJlYWN0KCksXG4gICAgbW9kZSA9PT0gJ2RldmVsb3BtZW50JyAmJlxuICAgIGNvbXBvbmVudFRhZ2dlcigpLFxuICAgIHNlcnZlckFwaVBsdWdpbigpLFxuICBdLmZpbHRlcihCb29sZWFuKSxcbiAgcmVzb2x2ZToge1xuICAgIGFsaWFzOiB7XG4gICAgICBcIkBcIjogcGF0aC5yZXNvbHZlKF9fZGlybmFtZSwgXCIuL3NyY1wiKSxcbiAgICB9LFxuICB9LFxufSkpO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGUvc3JjL3NlcnZlclwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2FwcC9jb2RlL3NyYy9zZXJ2ZXIvYXBpLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9hcHAvY29kZS9zcmMvc2VydmVyL2FwaS50c1wiO2ltcG9ydCB0eXBlIHsgUGx1Z2luIH0gZnJvbSAndml0ZSc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5pbXBvcnQgbm9kZW1haWxlciBmcm9tICdub2RlbWFpbGVyJztcbmltcG9ydCBTZW50cnkgZnJvbSAnQHNlbnRyeS9ub2RlJztcblxuLy8gSW5pdGlhbGl6ZSBTZW50cnkgaWYgRFNOIHByb3ZpZGVkXG50cnkge1xuICBpZiAocHJvY2Vzcy5lbnYuU0VOVFJZX0RTTikge1xuICAgIFNlbnRyeS5pbml0KHsgZHNuOiBwcm9jZXNzLmVudi5TRU5UUllfRFNOLCB0cmFjZXNTYW1wbGVSYXRlOiAwLjA1LCBlbnZpcm9ubWVudDogcHJvY2Vzcy5lbnYuTk9ERV9FTlYgfSk7XG4gIH1cbn0gY2F0Y2ggKGUpIHtcbiAgLy8gaWdub3JlIFNlbnRyeSBpbml0IGVycm9ycyBpbiBkZXZcbiAgY29uc29sZS53YXJuKCdTZW50cnkgaW5pdCBmYWlsZWQnLCBlKTtcbn1cblxuLy8gU21hbGwgSlNPTiBib2R5IHBhcnNlciB3aXRoIHNpemUgbGltaXRcbmFzeW5jIGZ1bmN0aW9uIHBhcnNlSnNvbihyZXE6IGFueSwgbGltaXQgPSAxMDI0ICogMTAwKSB7XG4gIHJldHVybiBuZXcgUHJvbWlzZTxhbnk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICBjb25zdCBjaHVua3M6IEJ1ZmZlcltdID0gW107XG4gICAgbGV0IHNpemUgPSAwO1xuICAgIHJlcS5vbignZGF0YScsIChjOiBCdWZmZXIpID0+IHtcbiAgICAgIHNpemUgKz0gYy5sZW5ndGg7XG4gICAgICBpZiAoc2l6ZSA+IGxpbWl0KSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1BheWxvYWQgdG9vIGxhcmdlJykpO1xuICAgICAgICByZXEuZGVzdHJveSgpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjaHVua3MucHVzaChjKTtcbiAgICB9KTtcbiAgICByZXEub24oJ2VuZCcsICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJhdyA9IEJ1ZmZlci5jb25jYXQoY2h1bmtzKS50b1N0cmluZygndXRmOCcpO1xuICAgICAgICBjb25zdCBqc29uID0gcmF3ID8gSlNPTi5wYXJzZShyYXcpIDoge307XG4gICAgICAgIHJlc29sdmUoanNvbik7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHJlamVjdChlKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICByZXEub24oJ2Vycm9yJywgcmVqZWN0KTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIGpzb24ocmVzOiBhbnksIHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnksIGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7fSkge1xuICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7XG4gIHJlcy5zdGF0dXNDb2RlID0gc3RhdHVzO1xuICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCcpO1xuICByZXMuc2V0SGVhZGVyKCdYLUNvbnRlbnQtVHlwZS1PcHRpb25zJywgJ25vc25pZmYnKTtcbiAgcmVzLnNldEhlYWRlcignUmVmZXJyZXItUG9saWN5JywgJ25vLXJlZmVycmVyJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtRnJhbWUtT3B0aW9ucycsICdERU5ZJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtWFNTLVByb3RlY3Rpb24nLCAnMTsgbW9kZT1ibG9jaycpO1xuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhoZWFkZXJzKSkgcmVzLnNldEhlYWRlcihrLCB2KTtcbiAgcmVzLmVuZChib2R5KTtcbn1cblxuY29uc3QgaXNIdHRwcyA9IChyZXE6IGFueSkgPT4ge1xuICBjb25zdCBwcm90byA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtcHJvdG8nXSBhcyBzdHJpbmcpIHx8ICcnO1xuICByZXR1cm4gcHJvdG8gPT09ICdodHRwcycgfHwgKHJlcS5zb2NrZXQgJiYgKHJlcS5zb2NrZXQgYXMgYW55KS5lbmNyeXB0ZWQpO1xufTtcblxuZnVuY3Rpb24gcmVxdWlyZUVudihuYW1lOiBzdHJpbmcpIHtcbiAgY29uc3QgdiA9IHByb2Nlc3MuZW52W25hbWVdO1xuICBpZiAoIXYpIHRocm93IG5ldyBFcnJvcihgJHtuYW1lfSBub3Qgc2V0YCk7XG4gIHJldHVybiB2O1xufVxuXG5hc3luYyBmdW5jdGlvbiBzdXBhYmFzZUZldGNoKHBhdGg6IHN0cmluZywgb3B0aW9uczogYW55LCByZXE6IGFueSkge1xuICBjb25zdCBiYXNlID0gcmVxdWlyZUVudignU1VQQUJBU0VfVVJMJyk7XG4gIGNvbnN0IGFub24gPSByZXF1aXJlRW52KCdTVVBBQkFTRV9BTk9OX0tFWScpO1xuICBjb25zdCB0b2tlbiA9IChyZXEuaGVhZGVyc1snYXV0aG9yaXphdGlvbiddIGFzIHN0cmluZykgfHwgJyc7XG4gIGNvbnN0IGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7XG4gICAgYXBpa2V5OiBhbm9uLFxuICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsXG4gIH07XG4gIGlmICh0b2tlbikgaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gdG9rZW47XG4gIHJldHVybiBmZXRjaChgJHtiYXNlfSR7cGF0aH1gLCB7IC4uLm9wdGlvbnMsIGhlYWRlcnM6IHsgLi4uaGVhZGVycywgLi4uKG9wdGlvbnM/LmhlYWRlcnMgfHwge30pIH0gfSk7XG59XG5cbi8vIFN1cGFiYXNlIGFkbWluIGZldGNoIHVzaW5nIHNlcnZpY2Ugcm9sZSBrZXkgKHNlcnZlci1zaWRlIG9ubHkpXG5hc3luYyBmdW5jdGlvbiBzdXBhYmFzZUFkbWluRmV0Y2gocGF0aDogc3RyaW5nLCBvcHRpb25zOiBhbnkgPSB7fSwgcmVxOiBhbnkpIHtcbiAgY29uc3QgYmFzZSA9IHJlcXVpcmVFbnYoJ1NVUEFCQVNFX1VSTCcpO1xuICBjb25zdCBzZXJ2aWNlS2V5ID0gcmVxdWlyZUVudignU1VQQUJBU0VfU0VSVklDRV9LRVknKTtcbiAgY29uc3QgaGVhZGVyczogUmVjb3JkPHN0cmluZywgc3RyaW5nPiA9IHtcbiAgICBhcGlrZXk6IHNlcnZpY2VLZXksXG4gICAgQXV0aG9yaXphdGlvbjogYEJlYXJlciAke3NlcnZpY2VLZXl9YCxcbiAgICAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLFxuICB9O1xuICByZXR1cm4gZmV0Y2goYCR7YmFzZX0ke3BhdGh9YCwgeyAuLi5vcHRpb25zLCBoZWFkZXJzOiB7IC4uLmhlYWRlcnMsIC4uLihvcHRpb25zPy5oZWFkZXJzIHx8IHt9KSB9IH0pO1xufVxuXG5mdW5jdGlvbiBtYWtlQm90SWQoc2VlZDogc3RyaW5nKSB7XG4gIHJldHVybiAnYm90XycgKyBjcnlwdG8uY3JlYXRlSGFzaCgnc2hhMjU2JykudXBkYXRlKHNlZWQpLmRpZ2VzdCgnYmFzZTY0dXJsJykuc2xpY2UoMCwgMjIpO1xufVxuXG4vLyBFeHRyYWN0IHZpc2libGUgdGV4dCBmcm9tIEhUTUwgKG5haXZlKVxuZnVuY3Rpb24gZXh0cmFjdFRleHRGcm9tSHRtbChodG1sOiBzdHJpbmcpIHtcbiAgLy8gcmVtb3ZlIHNjcmlwdHMvc3R5bGVzXG4gIGNvbnN0IHdpdGhvdXRTY3JpcHRzID0gaHRtbC5yZXBsYWNlKC88c2NyaXB0W1xcc1xcU10qPz5bXFxzXFxTXSo/PFxcL3NjcmlwdD4vZ2ksICcgJyk7XG4gIGNvbnN0IHdpdGhvdXRTdHlsZXMgPSB3aXRob3V0U2NyaXB0cy5yZXBsYWNlKC88c3R5bGVbXFxzXFxTXSo/PltcXHNcXFNdKj88XFwvc3R5bGU+L2dpLCAnICcpO1xuICAvLyByZW1vdmUgdGFnc1xuICBjb25zdCB0ZXh0ID0gd2l0aG91dFN0eWxlcy5yZXBsYWNlKC88W14+XSs+L2csICcgJyk7XG4gIC8vIGRlY29kZSBIVE1MIGVudGl0aWVzIChiYXNpYylcbiAgcmV0dXJuIHRleHQucmVwbGFjZSgvJm5ic3A7fCZhbXA7fCZsdDt8Jmd0O3wmcXVvdDt8JiMzOTsvZywgKHMpID0+IHtcbiAgICBzd2l0Y2ggKHMpIHtcbiAgICAgIGNhc2UgJyZuYnNwOyc6IHJldHVybiAnICc7XG4gICAgICBjYXNlICcmYW1wOyc6IHJldHVybiAnJic7XG4gICAgICBjYXNlICcmbHQ7JzogcmV0dXJuICc8JztcbiAgICAgIGNhc2UgJyZndDsnOiByZXR1cm4gJz4nO1xuICAgICAgY2FzZSAnJnF1b3Q7JzogcmV0dXJuICdcIic7XG4gICAgICBjYXNlICcmIzM5Oyc6IHJldHVybiAnXFwnJztcbiAgICAgIGRlZmF1bHQ6IHJldHVybiBzO1xuICAgIH1cbiAgfSkucmVwbGFjZSgvXFxzKy9nLCAnICcpLnRyaW0oKTtcbn1cblxuLy8gRmV0Y2ggYSBwYWdlIGFuZCBleHRyYWN0IHJpY2ggc3RydWN0dXJlZCBjb250ZW50ICh0aXRsZSwgbWV0YSwgaGVhZGluZ3MsIEpTT04tTEQsIHZpc2libGUgdGV4dClcbmFzeW5jIGZ1bmN0aW9uIGZldGNoUmljaFBhZ2UodTogc3RyaW5nKSB7XG4gIHRyeSB7XG4gICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2godSwgeyBoZWFkZXJzOiB7ICdVc2VyLUFnZW50JzogJ05leGFCb3RDcmF3bGVyLzEuMCcgfSB9KTtcbiAgICBpZiAoIXJlcyB8fCAhcmVzLm9rKSByZXR1cm4gJyc7XG4gICAgY29uc3QgaHRtbCA9IGF3YWl0IHJlcy50ZXh0KCk7XG5cbiAgICAvLyB0aXRsZVxuICAgIGNvbnN0IHRpdGxlTWF0Y2ggPSBodG1sLm1hdGNoKC88dGl0bGVbXj5dKj4oW1xcc1xcU10qPyk8XFwvdGl0bGU+L2kpO1xuICAgIGNvbnN0IHRpdGxlID0gdGl0bGVNYXRjaCA/IHRpdGxlTWF0Y2hbMV0ucmVwbGFjZSgvXFxzKy9nLCAnICcpLnRyaW0oKSA6ICcnO1xuXG4gICAgLy8gbWV0YSBkZXNjcmlwdGlvblxuICAgIGNvbnN0IGRlc2NNYXRjaCA9IGh0bWwubWF0Y2goLzxtZXRhW14+XStuYW1lPVtcIiddZGVzY3JpcHRpb25bXCInXVtePl0qY29udGVudD1bXCInXShbXlwiJ10rKVtcIiddW14+XSo+L2kpIHx8IGh0bWwubWF0Y2goLzxtZXRhW14+XStjb250ZW50PVtcIiddKFteXCInXSspW1wiJ11bXj5dKm5hbWU9W1wiJ11kZXNjcmlwdGlvbltcIiddW14+XSo+L2kpO1xuICAgIGNvbnN0IGRlc2NyaXB0aW9uID0gZGVzY01hdGNoID8gZGVzY01hdGNoWzFdLnRyaW0oKSA6ICcnO1xuXG4gICAgLy8gb3BlbiBncmFwaFxuICAgIGNvbnN0IG9nTWF0Y2hlcyA9IEFycmF5LmZyb20oaHRtbC5tYXRjaEFsbCgvPG1ldGFbXj5dK3Byb3BlcnR5PVtcIiddb2c6KFteXCInXSspW1wiJ11bXj5dKmNvbnRlbnQ9W1wiJ10oW15cIiddKylbXCInXVtePl0qPi9pZykpO1xuICAgIGNvbnN0IG9nID0gb2dNYXRjaGVzLm1hcChtID0+IGAke21bMV19OiAke21bMl19YCkuam9pbignXFxuJyk7XG5cbiAgICAvLyBKU09OLUxEXG4gICAgY29uc3QganNvbkxkTWF0Y2hlcyA9IEFycmF5LmZyb20oaHRtbC5tYXRjaEFsbCgvPHNjcmlwdFtePl0qdHlwZT1bXCInXWFwcGxpY2F0aW9uXFwvbGRcXCtqc29uW1wiJ11bXj5dKj4oW1xcc1xcU10qPyk8XFwvc2NyaXB0Pi9pZykpO1xuICAgIGNvbnN0IGpzb25MZCA9IGpzb25MZE1hdGNoZXMubWFwKG0gPT4gbVsxXS50cmltKCkpLmpvaW4oJ1xcbicpO1xuXG4gICAgLy8gaGVhZGluZ3MgaDEtaDNcbiAgICBjb25zdCBoZWFkaW5nTWF0Y2hlcyA9IEFycmF5LmZyb20oaHRtbC5tYXRjaEFsbCgvPGgoWzEtM10pW14+XSo+KFtcXHNcXFNdKj8pPFxcL2hbMS0zXT4vaWcpKTtcbiAgICBjb25zdCBoZWFkaW5ncyA9IGhlYWRpbmdNYXRjaGVzLm1hcChtID0+IGBoJHttWzFdfTogJHttWzJdLnJlcGxhY2UoLzxbXj5dKz4vZywgJycpLnJlcGxhY2UoL1xccysvZywnICcpLnRyaW0oKX1gKS5qb2luKCdcXG4nKTtcblxuICAgIC8vIGZpcnN0IG1lYW5pbmdmdWwgcGFyYWdyYXBoc1xuICAgIGNvbnN0IHBNYXRjaGVzID0gQXJyYXkuZnJvbShodG1sLm1hdGNoQWxsKC88cFtePl0qPihbXFxzXFxTXSo/KTxcXC9wPi9pZykpO1xuICAgIGNvbnN0IHBhcmFncmFwaHMgPSBwTWF0Y2hlcy5zbGljZSgwLCA1KS5tYXAobSA9PiBtWzFdLnJlcGxhY2UoLzxbXj5dKz4vZywgJycpLnJlcGxhY2UoL1xccysvZywnICcpLnRyaW0oKSkuZmlsdGVyKEJvb2xlYW4pLmpvaW4oJ1xcblxcbicpO1xuXG4gICAgLy8gdmlzaWJsZSB0ZXh0IChmYWxsYmFjaylcbiAgICBjb25zdCB2aXNpYmxlID0gZXh0cmFjdFRleHRGcm9tSHRtbChodG1sKS5zbGljZSgwLCAxMDAwMCk7XG5cbiAgICBjb25zdCBwYXJ0cyA9IFtcbiAgICAgIGBVUkw6ICR7dX1gLFxuICAgICAgdGl0bGUgPyBgVGl0bGU6ICR7dGl0bGV9YCA6ICcnLFxuICAgICAgZGVzY3JpcHRpb24gPyBgTWV0YSBEZXNjcmlwdGlvbjogJHtkZXNjcmlwdGlvbn1gIDogJycsXG4gICAgICBvZyA/IGBPcGVuR3JhcGg6XFxuJHtvZ31gIDogJycsXG4gICAgICBqc29uTGQgPyBgSlNPTi1MRDpcXG4ke2pzb25MZH1gIDogJycsXG4gICAgICBoZWFkaW5ncyA/IGBIZWFkaW5nczpcXG4ke2hlYWRpbmdzfWAgOiAnJyxcbiAgICAgIHBhcmFncmFwaHMgPyBgVG9wIFBhcmFncmFwaHM6XFxuJHtwYXJhZ3JhcGhzfWAgOiAnJyxcbiAgICAgIGBWaXNpYmxlIFRleHQ6XFxuJHt2aXNpYmxlfWAsXG4gICAgXS5maWx0ZXIoQm9vbGVhbik7XG5cbiAgICByZXR1cm4gcGFydHMuam9pbignXFxuXFxuJyk7XG4gIH0gY2F0Y2ggKGUpIHtcbiAgICByZXR1cm4gJyc7XG4gIH1cbn1cblxuLy8gVHJ5IGNvbW1vbiBhdXhpbGlhcnkgcGF0aHMgb24gdGhlIHNhbWUgaG9zdCAoYWJvdXQsIGNvbnRhY3QsIGZhcSwgcHJvZHVjdHMpIHRvIGdhdGhlciBtb3JlIGNvbnRleHRcbmFzeW5jIGZ1bmN0aW9uIHRyeUZldGNoVXJsVGV4dCh1OiBzdHJpbmcpIHtcbiAgdHJ5IHtcbiAgICBjb25zdCB1cmxPYmogPSBuZXcgVVJMKHUpO1xuICAgIGNvbnN0IGJhc2UgPSB1cmxPYmoub3JpZ2luO1xuICAgIGNvbnN0IGNhbmRpZGF0ZXMgPSBbdSwgYCR7YmFzZX0vYWJvdXRgLCBgJHtiYXNlfS9hYm91dC11c2AsIGAke2Jhc2V9L2NvbnRhY3RgLCBgJHtiYXNlfS9jb250YWN0LXVzYCwgYCR7YmFzZX0vZmFxYCwgYCR7YmFzZX0vcHJvZHVjdHNgLCBgJHtiYXNlfS9wcmljaW5nYF07XG4gICAgY29uc3Qgc2VlbiA9IG5ldyBTZXQoKTtcbiAgICBjb25zdCBjb2xsZWN0ZWQ6IHN0cmluZ1tdID0gW107XG4gICAgZm9yIChjb25zdCBjIG9mIGNhbmRpZGF0ZXMpIHtcbiAgICAgIGlmIChzZWVuLmhhcyhjKSkgY29udGludWU7XG4gICAgICBzZWVuLmFkZChjKTtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHMgPSBhd2FpdCBmZXRjaFJpY2hQYWdlKGMpO1xuICAgICAgICBpZiAocykgY29sbGVjdGVkLnB1c2gocyk7XG4gICAgICB9IGNhdGNoIChlKSB7fVxuICAgICAgaWYgKGNvbGxlY3RlZC5qb2luKCdcXG4nKS5sZW5ndGggPiAxNTAwMCkgYnJlYWs7XG4gICAgfVxuICAgIHJldHVybiBjb2xsZWN0ZWQuam9pbignXFxuXFxuLS0tXFxuXFxuJyk7XG4gIH0gY2F0Y2ggKGUpIHtcbiAgICByZXR1cm4gJyc7XG4gIH1cbn1cblxuZnVuY3Rpb24gY2h1bmtUZXh0KHRleHQ6IHN0cmluZywgbWF4Q2hhcnMgPSAxNTAwKSB7XG4gIGNvbnN0IHBhcmFncmFwaHMgPSB0ZXh0LnNwbGl0KC9cXG58XFxyfFxcLnxcXCF8XFw/LykubWFwKHAgPT4gcC50cmltKCkpLmZpbHRlcihCb29sZWFuKTtcbiAgY29uc3QgY2h1bmtzOiBzdHJpbmdbXSA9IFtdO1xuICBsZXQgY3VyID0gJyc7XG4gIGZvciAoY29uc3QgcCBvZiBwYXJhZ3JhcGhzKSB7XG4gICAgaWYgKChjdXIgKyAnICcgKyBwKS5sZW5ndGggPiBtYXhDaGFycykge1xuICAgICAgaWYgKGN1cikgeyBjaHVua3MucHVzaChjdXIudHJpbSgpKTsgY3VyID0gcDsgfVxuICAgICAgZWxzZSB7IGNodW5rcy5wdXNoKHAuc2xpY2UoMCwgbWF4Q2hhcnMpKTsgY3VyID0gcC5zbGljZShtYXhDaGFycyk7IH1cbiAgICB9IGVsc2Uge1xuICAgICAgY3VyID0gKGN1ciArICcgJyArIHApLnRyaW0oKTtcbiAgICB9XG4gIH1cbiAgaWYgKGN1cikgY2h1bmtzLnB1c2goY3VyLnRyaW0oKSk7XG4gIHJldHVybiBjaHVua3M7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGVtYmVkQ2h1bmtzKGNodW5rczogc3RyaW5nW10pOiBQcm9taXNlPG51bWJlcltdW10gfCBudWxsPiB7XG4gIGNvbnN0IGtleSA9IHByb2Nlc3MuZW52Lk9QRU5BSV9BUElfS0VZO1xuICBpZiAoIWtleSkgcmV0dXJuIG51bGw7XG4gIHRyeSB7XG4gICAgY29uc3QgcmVzcCA9IGF3YWl0IGZldGNoKCdodHRwczovL2FwaS5vcGVuYWkuY29tL3YxL2VtYmVkZGluZ3MnLCB7XG4gICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgIGhlYWRlcnM6IHsgJ0F1dGhvcml6YXRpb24nOiBgQmVhcmVyICR7a2V5fWAsICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicgfSxcbiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgaW5wdXQ6IGNodW5rcywgbW9kZWw6ICd0ZXh0LWVtYmVkZGluZy0zLXNtYWxsJyB9KSxcbiAgICB9KTtcbiAgICBpZiAoIXJlc3Aub2spIHJldHVybiBudWxsO1xuICAgIGNvbnN0IGogPSBhd2FpdCByZXNwLmpzb24oKTtcbiAgICBpZiAoIWouZGF0YSkgcmV0dXJuIG51bGw7XG4gICAgcmV0dXJuIGouZGF0YS5tYXAoKGQ6IGFueSkgPT4gZC5lbWJlZGRpbmcgYXMgbnVtYmVyW10pO1xuICB9IGNhdGNoIChlKSB7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cbn1cblxuYXN5bmMgZnVuY3Rpb24gcHJvY2Vzc1RyYWluSm9iKGpvYklkOiBzdHJpbmcsIGJvZHk6IGFueSwgcmVxOiBhbnkpIHtcbiAgY29uc3QgdXJsID0gYm9keS51cmwgfHwgJyc7XG4gIGNvbnN0IGZpbGVzOiBzdHJpbmdbXSA9IEFycmF5LmlzQXJyYXkoYm9keS5maWxlcykgPyBib2R5LmZpbGVzIDogW107XG4gIGNvbnN0IGJvdFNlZWQgPSAodXJsIHx8IGZpbGVzLmpvaW4oJywnKSkgKyBEYXRlLm5vdygpO1xuICBjb25zdCBib3RJZCA9IG1ha2VCb3RJZChib3RTZWVkKTtcblxuICAvLyBnYXRoZXIgdGV4dHNcbiAgY29uc3QgZG9jczogeyBzb3VyY2U6IHN0cmluZzsgY29udGVudDogc3RyaW5nIH1bXSA9IFtdO1xuXG4gIGlmICh1cmwpIHtcbiAgICBjb25zdCB0ZXh0ID0gYXdhaXQgdHJ5RmV0Y2hVcmxUZXh0KHVybCk7XG4gICAgaWYgKHRleHQpIGRvY3MucHVzaCh7IHNvdXJjZTogdXJsLCBjb250ZW50OiB0ZXh0IH0pO1xuICB9XG5cbiAgLy8gZmlsZXMgYXJlIHN0b3JhZ2UgcGF0aHMgaW4gYnVja2V0L3RyYWluaW5nLy4uLlxuICBmb3IgKGNvbnN0IHBhdGggb2YgZmlsZXMpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgU1VQQUJBU0VfVVJMID0gcHJvY2Vzcy5lbnYuU1VQQUJBU0VfVVJMO1xuICAgICAgY29uc3QgYnVja2V0UHVibGljVXJsID0gU1VQQUJBU0VfVVJMICsgYC9zdG9yYWdlL3YxL29iamVjdC9wdWJsaWMvdHJhaW5pbmcvJHtlbmNvZGVVUklDb21wb25lbnQocGF0aCl9YDtcbiAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKGJ1Y2tldFB1YmxpY1VybCk7XG4gICAgICBpZiAoIXJlcy5vaykgY29udGludWU7XG4gICAgICBjb25zdCBidWYgPSBhd2FpdCByZXMuYXJyYXlCdWZmZXIoKTtcbiAgICAgIC8vIGNydWRlIHRleHQgZXh0cmFjdGlvbjogaWYgaXQncyBwZGYgb3IgdGV4dFxuICAgICAgY29uc3QgaGVhZGVyID0gU3RyaW5nLmZyb21DaGFyQ29kZS5hcHBseShudWxsLCBuZXcgVWludDhBcnJheShidWYuc2xpY2UoMCwgOCkpIGFzIGFueSk7XG4gICAgICBpZiAoaGVhZGVyLmluY2x1ZGVzKCclUERGJykpIHtcbiAgICAgICAgLy8gY2Fubm90IHBhcnNlIFBERiBoZXJlOyBzdG9yZSBwbGFjZWhvbGRlclxuICAgICAgICBkb2NzLnB1c2goeyBzb3VyY2U6IHBhdGgsIGNvbnRlbnQ6ICcoUERGIGNvbnRlbnQgLS0gcHJvY2Vzc2VkIGV4dGVybmFsbHkpJyB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGNvbnN0IHRleHQgPSBuZXcgVGV4dERlY29kZXIoKS5kZWNvZGUoYnVmKTtcbiAgICAgICAgY29uc3QgY2xlYW5lZCA9IGV4dHJhY3RUZXh0RnJvbUh0bWwodGV4dCk7XG4gICAgICAgIGRvY3MucHVzaCh7IHNvdXJjZTogcGF0aCwgY29udGVudDogY2xlYW5lZCB8fCAnKGJpbmFyeSBmaWxlKScgfSk7XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZSkgeyBjb250aW51ZTsgfVxuICB9XG5cbiAgLy8gY2h1bmsgYW5kIGVtYmVkXG4gIGZvciAoY29uc3QgZG9jIG9mIGRvY3MpIHtcbiAgICBjb25zdCBjaHVua3MgPSBjaHVua1RleHQoZG9jLmNvbnRlbnQpO1xuICAgIGNvbnN0IGVtYmVkZGluZ3MgPSBhd2FpdCBlbWJlZENodW5rcyhjaHVua3MpO1xuXG4gICAgLy8gc3RvcmUgZG9jdW1lbnRzIGFuZCBlbWJlZGRpbmdzIGluIFN1cGFiYXNlXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBjaHVua3MubGVuZ3RoOyBpKyspIHtcbiAgICAgIGNvbnN0IGNodW5rID0gY2h1bmtzW2ldO1xuICAgICAgY29uc3QgZW1iID0gZW1iZWRkaW5ncyA/IGVtYmVkZGluZ3NbaV0gOiBudWxsO1xuICAgICAgdHJ5IHtcbiAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvdHJhaW5pbmdfZG9jdW1lbnRzJywge1xuICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYm90X2lkOiBib3RJZCwgc291cmNlOiBkb2Muc291cmNlLCBjb250ZW50OiBjaHVuaywgZW1iZWRkaW5nOiBlbWIgfSksXG4gICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXR1cm49cmVwcmVzZW50YXRpb24nLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICB9IGNhdGNoIHt9XG4gICAgfVxuICB9XG5cbiAgLy8gbWFyayBqb2IgaW4gbG9nc1xuICB0cnkge1xuICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3NlY3VyaXR5X2xvZ3MnLCB7XG4gICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnVFJBSU5fSk9CX0NPTVBMRVRFJywgZGV0YWlsczogeyBqb2JJZCwgYm90SWQsIGRvY3M6IGRvY3MubGVuZ3RoIH0gfSksXG4gICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgfSBjYXRjaCB7fVxufVxuXG5hc3luYyBmdW5jdGlvbiBlbnN1cmVEb21haW5WZXJpZmljYXRpb24oZG9tYWluOiBzdHJpbmcsIHJlcTogYW55KSB7XG4gIC8vIGNoZWNrIGRvbWFpbnMgdGFibGUgZm9yIHZlcmlmaWVkXG4gIHRyeSB7XG4gICAgY29uc3QgcmVzID0gYXdhaXQgc3VwYWJhc2VGZXRjaChgL3Jlc3QvdjEvZG9tYWlucz9kb21haW49ZXEuJHtlbmNvZGVVUklDb21wb25lbnQoZG9tYWluKX1gLCB7IG1ldGhvZDogJ0dFVCcgfSwgcmVxKTtcbiAgICBpZiAocmVzICYmIChyZXMgYXMgYW55KS5vaykge1xuICAgICAgY29uc3QgaiA9IGF3YWl0IChyZXMgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBbXSk7XG4gICAgICBpZiAoQXJyYXkuaXNBcnJheShqKSAmJiBqLmxlbmd0aCA+IDAgJiYgalswXS52ZXJpZmllZCkgcmV0dXJuIHsgdmVyaWZpZWQ6IHRydWUgfTtcbiAgICB9XG4gIH0gY2F0Y2gge31cblxuICAvLyBhbHdheXMgY3JlYXRlIGEgZnJlc2ggc2hvcnQtbGl2ZWQgc2luZ2xlLXVzZSB2ZXJpZmljYXRpb24gdG9rZW4gKGRvIE5PVCBwZXJzaXN0IHBsYWludGV4dClcbiAgY29uc3QgdG9rZW4gPSBjcnlwdG8ucmFuZG9tQnl0ZXMoMTYpLnRvU3RyaW5nKCdiYXNlNjR1cmwnKTtcbiAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRE9NQUlOX1ZFUklGSUNBVElPTl9TRUNSRVQgfHwgJ2xvY2FsLWRvbS1zZWNyZXQnO1xuICBjb25zdCB0b2tlbkhhc2ggPSBjcnlwdG8uY3JlYXRlSGFzaCgnc2hhMjU2JykudXBkYXRlKHRva2VuICsgc2VjcmV0KS5kaWdlc3QoJ2Jhc2U2NCcpO1xuICBjb25zdCBleHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIDEwMDAgKiA2MCAqIDYwKS50b0lTT1N0cmluZygpO1xuICBsZXQgY3JlYXRlZElkOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcbiAgdHJ5IHtcbiAgICBjb25zdCByZXMgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9kb21haW5fdmVyaWZpY2F0aW9ucycsIHtcbiAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBkb21haW4sIHRva2VuX2hhc2g6IHRva2VuSGFzaCwgZXhwaXJlc19hdDogZXhwaXJlcywgdXNlZF9hdDogbnVsbCB9KSxcbiAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmV0dXJuPXJlcHJlc2VudGF0aW9uJywgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9LFxuICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgaWYgKHJlcyAmJiAocmVzIGFzIGFueSkub2spIHtcbiAgICAgIGNvbnN0IGogPSBhd2FpdCAocmVzIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICBpZiAoQXJyYXkuaXNBcnJheShqKSAmJiBqLmxlbmd0aCA+IDAgJiYgalswXS5pZCkgY3JlYXRlZElkID0galswXS5pZDtcbiAgICAgIGVsc2UgaWYgKGogJiYgai5pZCkgY3JlYXRlZElkID0gai5pZDtcbiAgICB9XG4gIH0gY2F0Y2gge31cbiAgLy8gUmV0dXJuIHRoZSBwbGFpbnRleHQgdG9rZW4gYW5kIGl0cyBEQiBpZCB0byB0aGUgY2FsbGVyIHNvIHRoZXkgY2FuIHBsYWNlIGl0IGluIHRoZWlyIHNpdGUsIGJ1dCBkbyBub3QgcGVyc2lzdCBwbGFpbnRleHRcbiAgcmV0dXJuIHsgdmVyaWZpZWQ6IGZhbHNlLCB0b2tlbiwgdG9rZW5JZDogY3JlYXRlZElkIH07XG59XG5cbmZ1bmN0aW9uIHZlcmlmeVdpZGdldFRva2VuKHRva2VuOiBzdHJpbmcpIHtcbiAgdHJ5IHtcbiAgICBjb25zdCB3aWRnZXRTZWNyZXQgPSBwcm9jZXNzLmVudi5XSURHRVRfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC13aWRnZXQtc2VjcmV0JztcbiAgICBjb25zdCBwYXJ0cyA9IHRva2VuLnNwbGl0KCcuJyk7XG4gICAgaWYgKHBhcnRzLmxlbmd0aCAhPT0gMykgcmV0dXJuIG51bGw7XG4gICAgY29uc3QgdW5zaWduZWQgPSBwYXJ0c1swXSArICcuJyArIHBhcnRzWzFdO1xuICAgIGNvbnN0IHNpZyA9IHBhcnRzWzJdO1xuICAgIGNvbnN0IGV4cGVjdGVkID0gY3J5cHRvLmNyZWF0ZUhtYWMoJ3NoYTI1NicsIHdpZGdldFNlY3JldCkudXBkYXRlKHVuc2lnbmVkKS5kaWdlc3QoJ2Jhc2U2NHVybCcpO1xuICAgIGlmIChzaWcgIT09IGV4cGVjdGVkKSByZXR1cm4gbnVsbDtcbiAgICBjb25zdCBwYXlsb2FkID0gSlNPTi5wYXJzZShCdWZmZXIuZnJvbShwYXJ0c1sxXSwgJ2Jhc2U2NHVybCcpLnRvU3RyaW5nKCd1dGY4JykpO1xuICAgIHJldHVybiBwYXlsb2FkO1xuICB9IGNhdGNoIChlKSB7IHJldHVybiBudWxsOyB9XG59XG5cbi8vIFNpbXBsZSBpbi1tZW1vcnkgcmF0ZSBsaW1pdGVyXG5jb25zdCByYXRlTWFwID0gbmV3IE1hcDxzdHJpbmcsIHsgY291bnQ6IG51bWJlcjsgdHM6IG51bWJlciB9PigpO1xuZnVuY3Rpb24gcmF0ZUxpbWl0KGtleTogc3RyaW5nLCBsaW1pdDogbnVtYmVyLCB3aW5kb3dNczogbnVtYmVyKSB7XG4gIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gIGNvbnN0IHJlYyA9IHJhdGVNYXAuZ2V0KGtleSk7XG4gIGlmICghcmVjIHx8IG5vdyAtIHJlYy50cyA+IHdpbmRvd01zKSB7XG4gICAgcmF0ZU1hcC5zZXQoa2V5LCB7IGNvdW50OiAxLCB0czogbm93IH0pO1xuICAgIHJldHVybiB0cnVlO1xuICB9XG4gIGlmIChyZWMuY291bnQgPCBsaW1pdCkge1xuICAgIHJlYy5jb3VudCArPSAxO1xuICAgIHJldHVybiB0cnVlO1xuICB9XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHNlcnZlckFwaVBsdWdpbigpOiBQbHVnaW4ge1xuICByZXR1cm4ge1xuICAgIG5hbWU6ICdzZXJ2ZXItYXBpLXBsdWdpbicsXG4gICAgY29uZmlndXJlU2VydmVyKHNlcnZlcikge1xuICAgICAgc2VydmVyLm1pZGRsZXdhcmVzLnVzZShhc3luYyAocmVxLCByZXMsIG5leHQpID0+IHtcbiAgICAgICAgaWYgKCFyZXEudXJsIHx8ICFyZXEudXJsLnN0YXJ0c1dpdGgoJy9hcGkvJykpIHJldHVybiBuZXh0KCk7XG5cbiAgICAgICAgLy8gQmFzaWMgc2VjdXJpdHkgaGVhZGVycyBmb3IgYWxsIEFQSSByZXNwb25zZXNcbiAgICAgICAgY29uc3QgY29yc09yaWdpbiA9IHJlcS5oZWFkZXJzLm9yaWdpbiB8fCAnKic7XG4gICAgICAgIHJlcy5zZXRIZWFkZXIoJ1Blcm1pc3Npb25zLVBvbGljeScsICdnZW9sb2NhdGlvbj0oKSwgbWljcm9waG9uZT0oKSwgY2FtZXJhPSgpJyk7XG4gICAgICAgIHJlcy5zZXRIZWFkZXIoJ0Nyb3NzLU9yaWdpbi1SZXNvdXJjZS1Qb2xpY3knLCAnc2FtZS1vcmlnaW4nKTtcblxuICAgICAgICAvLyBJbiBkZXYgYWxsb3cgaHR0cDsgaW4gcHJvZCAoYmVoaW5kIHByb3h5KSwgcmVxdWlyZSBodHRwc1xuICAgICAgICBpZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgPT09ICdwcm9kdWN0aW9uJyAmJiAhaXNIdHRwcyhyZXEpKSB7XG4gICAgICAgICAgcmV0dXJuIGpzb24ocmVzLCA0MDAsIHsgZXJyb3I6ICdIVFRQUyByZXF1aXJlZCcgfSwgeyAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJzogU3RyaW5nKGNvcnNPcmlnaW4pIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQ09SUyBwcmVmbGlnaHRcbiAgICAgICAgaWYgKHJlcS5tZXRob2QgPT09ICdPUFRJT05TJykge1xuICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbicsIFN0cmluZyhjb3JzT3JpZ2luKSk7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctTWV0aG9kcycsICdQT1NULEdFVCxPUFRJT05TJyk7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycycsICdDb250ZW50LVR5cGUsIEF1dGhvcml6YXRpb24nKTtcbiAgICAgICAgICByZXMuc3RhdHVzQ29kZSA9IDIwNDtcbiAgICAgICAgICByZXR1cm4gcmVzLmVuZCgpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZW5kSnNvbiA9IChzdGF0dXM6IG51bWJlciwgZGF0YTogYW55KSA9PiBqc29uKHJlcywgc3RhdHVzLCBkYXRhLCB7ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nOiBTdHJpbmcoY29yc09yaWdpbikgfSk7XG5cbiAgICAgICAgLy8gSGVhbHRoIGNoZWNrIGVuZHBvaW50XG4gICAgICAgIGlmIChyZXEudXJsID09PSAnL2hlYWx0aCcgJiYgcmVxLm1ldGhvZCA9PT0gJ0dFVCcpIHtcbiAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgb2s6IHRydWUsIHVwdGltZTogcHJvY2Vzcy51cHRpbWUoKSwgdGltZXN0YW1wOiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkgfSk7XG4gICAgICAgIH1cblxuICAgICAgICB0cnkge1xuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS90cmFpbicgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBpcCA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtZm9yJ10gYXMgc3RyaW5nKSB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJ2lwJztcbiAgICAgICAgICAgIGlmICghcmF0ZUxpbWl0KCd0cmFpbjonICsgaXAsIDIwLCA2MF8wMDApKSByZXR1cm4gZW5kSnNvbig0MjksIHsgZXJyb3I6ICdUb28gTWFueSBSZXF1ZXN0cycgfSk7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCB1cmwgPSB0eXBlb2YgYm9keT8udXJsID09PSAnc3RyaW5nJyA/IGJvZHkudXJsLnRyaW0oKSA6ICcnO1xuICAgICAgICAgICAgaWYgKCF1cmwgJiYgIUFycmF5LmlzQXJyYXkoYm9keT8uZmlsZXMpKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ1Byb3ZpZGUgdXJsIG9yIGZpbGVzJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICh1cmwpIHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmwpO1xuICAgICAgICAgICAgICAgIGlmICghKHUucHJvdG9jb2wgPT09ICdodHRwOicgfHwgdS5wcm90b2NvbCA9PT0gJ2h0dHBzOicpKSB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQnKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCB1cmwnIH0pO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIExvZyBldmVudFxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnVFJBSU5fUkVRVUVTVCcsIGRldGFpbHM6IHsgaGFzVXJsOiAhIXVybCwgZmlsZUNvdW50OiAoYm9keT8uZmlsZXM/Lmxlbmd0aCkgfHwgMCB9IH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgY29uc3Qgam9iSWQgPSBtYWtlQm90SWQoKHVybCB8fCAnJykgKyBEYXRlLm5vdygpKTtcblxuICAgICAgICAgICAgLy8gU3RhcnQgYmFja2dyb3VuZCBwcm9jZXNzaW5nIChub24tYmxvY2tpbmcpXG4gICAgICAgICAgICAoYXN5bmMgKCkgPT4ge1xuICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGF3YWl0IHByb2Nlc3NUcmFpbkpvYihqb2JJZCwgeyB1cmwsIGZpbGVzOiBBcnJheS5pc0FycmF5KGJvZHk/LmZpbGVzKSA/IGJvZHkuZmlsZXMgOiBbXSB9LCByZXEpO1xuICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3NlY3VyaXR5X2xvZ3MnLCB7XG4gICAgICAgICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFjdGlvbjogJ1RSQUlOX0pPQl9FUlJPUicsIGRldGFpbHM6IHsgam9iSWQsIGVycm9yOiBTdHJpbmcoZT8ubWVzc2FnZSB8fCBlKSB9IH0pLFxuICAgICAgICAgICAgICAgICAgfSwgcmVxKTtcbiAgICAgICAgICAgICAgICB9IGNhdGNoIHt9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pKCk7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMiwgeyBqb2JJZCwgc3RhdHVzOiAncXVldWVkJyB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY29ubmVjdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSk7XG4gICAgICAgICAgICBpZiAoYm9keT8uY2hhbm5lbCAhPT0gJ3dlYnNpdGUnKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdVbnN1cHBvcnRlZCBjaGFubmVsJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IHJhd1VybCA9IChib2R5Py51cmwgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGNvbnN0IGRvbWFpbiA9ICgoKSA9PiB7XG4gICAgICAgICAgICAgIHRyeSB7IHJldHVybiByYXdVcmwgPyBuZXcgVVJMKHJhd1VybCkuaG9zdCA6ICdsb2NhbCc7IH0gY2F0Y2ggeyByZXR1cm4gJ2xvY2FsJzsgfVxuICAgICAgICAgICAgfSkoKTtcblxuICAgICAgICAgICAgLy8gRW5zdXJlIGRvbWFpbiB2ZXJpZmljYXRpb25cbiAgICAgICAgICAgIGNvbnN0IHZyZXMgPSBhd2FpdCBlbnN1cmVEb21haW5WZXJpZmljYXRpb24oZG9tYWluLCByZXEpO1xuICAgICAgICAgICAgaWYgKCF2cmVzLnZlcmlmaWVkKSB7XG4gICAgICAgICAgICAgIC8vIHJldHVybiB2ZXJpZmljYXRpb24gcmVxdWlyZWQgYW5kIGluc3RydWN0aW9ucyAoaW5jbHVkZSB0b2tlbiBpZClcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAyLCB7IHN0YXR1czogJ3ZlcmlmaWNhdGlvbl9yZXF1aXJlZCcsIGluc3RydWN0aW9uczogYEFkZCBhIEROUyBUWFQgcmVjb3JkIG9yIGEgbWV0YSB0YWcgd2l0aCB0b2tlbjogJHt2cmVzLnRva2VufWAsIHRva2VuOiB2cmVzLnRva2VuLCB0b2tlbklkOiB2cmVzLnRva2VuSWQgfHwgbnVsbCB9KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgY29uc3Qgc2VlZCA9IGRvbWFpbiArICd8JyArIChyZXEuaGVhZGVyc1snYXV0aG9yaXphdGlvbiddIHx8ICcnKTtcbiAgICAgICAgICAgIGNvbnN0IGJvdElkID0gbWFrZUJvdElkKHNlZWQpO1xuXG4gICAgICAgICAgICAvLyBVcHNlcnQgY2hhdGJvdF9jb25maWdzIChpZiBSTFMgYWxsb3dzIHdpdGggdXNlciB0b2tlbilcbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2NoYXRib3RfY29uZmlncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYm90X2lkOiBib3RJZCwgY2hhbm5lbDogJ3dlYnNpdGUnLCBkb21haW4sIHNldHRpbmdzOiB7fSB9KSxcbiAgICAgICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXNvbHV0aW9uPW1lcmdlLWR1cGxpY2F0ZXMnIH0sXG4gICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuXG4gICAgICAgICAgICAvLyBDcmVhdGUgd2lkZ2V0IHRva2VuIChITUFDIHNpZ25lZClcbiAgICAgICAgICAgIGNvbnN0IHdpZGdldFBheWxvYWQgPSB7IGJvdElkLCBkb21haW4sIGlhdDogTWF0aC5mbG9vcihEYXRlLm5vdygpLzEwMDApIH07XG4gICAgICAgICAgICBjb25zdCB3aWRnZXRTZWNyZXQgPSBwcm9jZXNzLmVudi5XSURHRVRfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC13aWRnZXQtc2VjcmV0JztcbiAgICAgICAgICAgIGNvbnN0IGhlYWRlciA9IHsgYWxnOiAnSFMyNTYnLCB0eXA6ICdKV1QnIH07XG4gICAgICAgICAgICBjb25zdCBiNjQgPSAoczogc3RyaW5nKSA9PiBCdWZmZXIuZnJvbShzKS50b1N0cmluZygnYmFzZTY0dXJsJyk7XG4gICAgICAgICAgICBjb25zdCB1bnNpZ25lZCA9IGI2NChKU09OLnN0cmluZ2lmeShoZWFkZXIpKSArICcuJyArIGI2NChKU09OLnN0cmluZ2lmeSh3aWRnZXRQYXlsb2FkKSk7XG4gICAgICAgICAgICBjb25zdCBzaWcgPSBjcnlwdG8uY3JlYXRlSG1hYygnc2hhMjU2Jywgd2lkZ2V0U2VjcmV0KS51cGRhdGUodW5zaWduZWQpLmRpZ2VzdCgnYmFzZTY0dXJsJyk7XG4gICAgICAgICAgICBjb25zdCB3aWRnZXRUb2tlbiA9IHVuc2lnbmVkICsgJy4nICsgc2lnO1xuXG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgYm90SWQsIHdpZGdldFRva2VuIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIC8vIFdpZGdldCBjb25maWcgZW5kcG9pbnQ6IHJldHVybnMgYm90IHNldHRpbmdzIGZvciB3aWRnZXQgY29uc3VtZXJzIChyZXF1aXJlcyB0b2tlbilcbiAgICAgICAgICBpZiAocmVxLnVybD8uc3RhcnRzV2l0aCgnL2FwaS93aWRnZXQtY29uZmlnJykgJiYgcmVxLm1ldGhvZCA9PT0gJ0dFVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IHVybE9iaiA9IG5ldyBVUkwocmVxLnVybCwgJ2h0dHA6Ly9sb2NhbCcpO1xuICAgICAgICAgICAgY29uc3QgYm90SWQgPSB1cmxPYmouc2VhcmNoUGFyYW1zLmdldCgnYm90SWQnKSB8fCAnJztcbiAgICAgICAgICAgIGNvbnN0IHRva2VuID0gdXJsT2JqLnNlYXJjaFBhcmFtcy5nZXQoJ3Rva2VuJykgfHwgJyc7XG4gICAgICAgICAgICBpZiAoIWJvdElkKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIGJvdElkJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IHBheWxvYWQgPSB2ZXJpZnlXaWRnZXRUb2tlbih0b2tlbik7XG4gICAgICAgICAgICBpZiAoIXBheWxvYWQgfHwgcGF5bG9hZC5ib3RJZCAhPT0gYm90SWQpIHJldHVybiBlbmRKc29uKDQwMSwgeyBlcnJvcjogJ0ludmFsaWQgdG9rZW4nIH0pO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgY29uc3QgciA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2NoYXRib3RfY29uZmlncz9ib3RfaWQ9ZXEuJyArIGVuY29kZVVSSUNvbXBvbmVudChib3RJZCkgKyAnJnNlbGVjdD0qJywgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICAgIGlmICghciB8fCAhKHIgYXMgYW55KS5vaykgcmV0dXJuIGVuZEpzb24oNDA0LCB7IGVycm9yOiAnTm90IGZvdW5kJyB9KTtcbiAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IChyIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gW10pO1xuICAgICAgICAgICAgICBjb25zdCBjZmcgPSBBcnJheS5pc0FycmF5KGRhdGEpICYmIGRhdGEubGVuZ3RoID4gMCA/IGRhdGFbMF0gOiB7IHNldHRpbmdzOiB7fSB9O1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgc2V0dGluZ3M6IGNmZyB9KTtcbiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHsgcmV0dXJuIGVuZEpzb24oNTAwLCB7IGVycm9yOiAnU2VydmVyIGVycm9yJyB9KTsgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9kZWJ1Zy1mZXRjaCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCB1cmxTdHIgPSBTdHJpbmcoYm9keT8udXJsIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBpZiAoIXVybFN0cikgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnTWlzc2luZyB1cmwnIH0pO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgY29uc3QgdSA9IG5ldyBVUkwodXJsU3RyKTtcbiAgICAgICAgICAgICAgaWYgKCEodS5wcm90b2NvbCA9PT0gJ2h0dHA6JyB8fCB1LnByb3RvY29sID09PSAnaHR0cHM6JykpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgcHJvdG9jb2wnIH0pO1xuICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdJbnZhbGlkIHVybCcgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCByID0gYXdhaXQgZmV0Y2godXJsU3RyLCB7IGhlYWRlcnM6IHsgJ1VzZXItQWdlbnQnOiAnTmV4YUJvdFZlcmlmaWVyLzEuMCcgfSB9KTtcbiAgICAgICAgICAgICAgaWYgKCFyIHx8ICFyLm9rKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdGZXRjaCBmYWlsZWQnLCBzdGF0dXM6IHIgPyByLnN0YXR1cyA6IDAgfSk7XG4gICAgICAgICAgICAgIGNvbnN0IHRleHQgPSBhd2FpdCByLnRleHQoKTtcbiAgICAgICAgICAgICAgLy8gcmV0dXJuIGEgc25pcHBldCB0byBhdm9pZCBodWdlIHBheWxvYWRzXG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogdHJ1ZSwgdXJsOiB1cmxTdHIsIHNuaXBwZXQ6IHRleHQuc2xpY2UoMCwgMjAwMDApIH0pO1xuICAgICAgICAgICAgfSBjYXRjaCAoZTogYW55KSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDUwMCwgeyBlcnJvcjogJ0ZldGNoIGVycm9yJywgbWVzc2FnZTogU3RyaW5nKGU/Lm1lc3NhZ2UgfHwgZSkgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gRGVidWc6IGxpc3Qgc3RvcmVkIHZlcmlmaWNhdGlvbiB0b2tlbnMgZm9yIGEgZG9tYWluIChERVYgT05MWSkgXHUyMDE0IGRvIE5PVCBleHBvc2UgdG9rZW4gcGxhaW50ZXh0IGluIHByb2R1Y3Rpb25cbiAgICAgICAgICBpZiAocmVxLnVybD8uc3RhcnRzV2l0aCgnL2FwaS9kZWJ1Zy1kb21haW4nKSAmJiAocmVxLm1ldGhvZCA9PT0gJ0dFVCcgfHwgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSkge1xuICAgICAgICAgICAgaWYgKHByb2Nlc3MuZW52Lk5PREVfRU5WICE9PSAnZGV2ZWxvcG1lbnQnKSByZXR1cm4gZW5kSnNvbig0MDQsIHsgZXJyb3I6ICdOb3QgZm91bmQnIH0pO1xuICAgICAgICAgICAgLy8gQWNjZXB0IGJvdGggcXVlcnkgcGFyYW0gP2RvbWFpbj0gb3IgSlNPTiBib2R5IHsgZG9tYWluIH1cbiAgICAgICAgICAgIGxldCBkb21haW4gPSAnJztcbiAgICAgICAgICAgIGlmIChyZXEubWV0aG9kID09PSAnR0VUJykge1xuICAgICAgICAgICAgICB0cnkgeyBjb25zdCB1ID0gbmV3IFVSTChyZXEudXJsLCAnaHR0cDovL2xvY2FsJyk7IGRvbWFpbiA9IHUuc2VhcmNoUGFyYW1zLmdldCgnZG9tYWluJykgfHwgJyc7IH0gY2F0Y2gge31cbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIGNvbnN0IGIgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTsgZG9tYWluID0gU3RyaW5nKGI/LmRvbWFpbiB8fCAnJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoIWRvbWFpbikgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnTWlzc2luZyBkb21haW4nIH0pO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgY29uc3QgcSA9IGAvcmVzdC92MS9kb21haW5fdmVyaWZpY2F0aW9ucz9kb21haW49ZXEuJHtlbmNvZGVVUklDb21wb25lbnQoZG9tYWluKX0mc2VsZWN0PWlkLHRva2VuX2hhc2gsZXhwaXJlc19hdCx1c2VkX2F0YDtcbiAgICAgICAgICAgICAgY29uc3QgciA9IGF3YWl0IHN1cGFiYXNlRmV0Y2gocSwgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICAgIGlmICghciB8fCAhKHIgYXMgYW55KS5vaykgcmV0dXJuIGVuZEpzb24oMjAwLCB7IHRva2VuczogW10gfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGFyciA9IGF3YWl0IChyIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gW10pO1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgdG9rZW5zOiBBcnJheS5pc0FycmF5KGFycikgPyBhcnIgOiBbXSB9KTtcbiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNTAwLCB7IGVycm9yOiAnU2VydmVyIGVycm9yJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvdmVyaWZ5LWRvbWFpbicgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCBkb21haW4gPSBTdHJpbmcoYm9keT8uZG9tYWluIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IFN0cmluZyhib2R5Py50b2tlbiB8fCAnJykudHJpbSgpO1xuICAgICAgICAgICAgY29uc3QgdG9rZW5JZCA9IFN0cmluZyhib2R5Py50b2tlbklkIHx8ICcnKS50cmltKCk7XG4gICAgICAgICAgICBpZiAoIWRvbWFpbiB8fCAhdG9rZW4gfHwgIXRva2VuSWQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgZG9tYWluLCB0b2tlbiBvciB0b2tlbklkJyB9KTtcblxuICAgICAgICAgICAgLy8gVHJ5IG11bHRpcGxlIGNhbmRpZGF0ZSBVUkxzIGZvciB2ZXJpZmljYXRpb24gKHJvb3QsIGluZGV4Lmh0bWwsIHdlbGwta25vd24pXG4gICAgICAgICAgICBjb25zdCBjYW5kaWRhdGVzID0gW1xuICAgICAgICAgICAgICBgaHR0cHM6Ly8ke2RvbWFpbn1gLFxuICAgICAgICAgICAgICBgaHR0cDovLyR7ZG9tYWlufWAsXG4gICAgICAgICAgICAgIGBodHRwczovLyR7ZG9tYWlufS9pbmRleC5odG1sYCxcbiAgICAgICAgICAgICAgYGh0dHA6Ly8ke2RvbWFpbn0vaW5kZXguaHRtbGAsXG4gICAgICAgICAgICAgIGBodHRwczovLyR7ZG9tYWlufS8ud2VsbC1rbm93bi9uZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25gLFxuICAgICAgICAgICAgICBgaHR0cDovLyR7ZG9tYWlufS8ud2VsbC1rbm93bi9uZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25gLFxuICAgICAgICAgICAgXTtcblxuICAgICAgICAgICAgLy8gQnVpbGQgcm9idXN0IHJlZ2V4IHRvIG1hdGNoIG1ldGEgdGFnIGluIGFueSBhdHRyaWJ1dGUgb3JkZXJcbiAgICAgICAgICAgIGNvbnN0IGVzYyA9IChzOiBzdHJpbmcpID0+IHMucmVwbGFjZSgvWy0vXFxcXF4kKis/LigpfFtcXF17fV0vZywgJ1xcXFwkJicpO1xuICAgICAgICAgICAgY29uc3QgdEVzYyA9IGVzYyh0b2tlbik7XG4gICAgICAgICAgICBjb25zdCBtZXRhUmUgPSBuZXcgUmVnRXhwKGA8bWV0YVtePl0qKD86bmFtZVxccyo9XFxzKlsnXFxcIl1uZXhhYm90LWRvbWFpbi12ZXJpZmljYXRpb25bJ1xcXCJdW14+XSpjb250ZW50XFxzKj1cXHMqWydcXFwiXSR7dEVzY31bJ1xcXCJdfGNvbnRlbnRcXHMqPVxccypbJ1xcXCJdJHt0RXNjfVsnXFxcIl1bXj5dKm5hbWVcXHMqPVxccypbJ1xcXCJdbmV4YWJvdC1kb21haW4tdmVyaWZpY2F0aW9uWydcXFwiXSlgLCAnaScpO1xuICAgICAgICAgICAgY29uc3QgcGxhaW5SZSA9IG5ldyBSZWdFeHAoYG5leGFib3QtZG9tYWluLXZlcmlmaWNhdGlvbls6PV1cXHMqJHt0RXNjfWAsICdpJyk7XG5cbiAgICAgICAgICAgIGxldCBmb3VuZCA9IGZhbHNlO1xuICAgICAgICAgICAgZm9yIChjb25zdCB1cmwgb2YgY2FuZGlkYXRlcykge1xuICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGNvbnN0IHIgPSBhd2FpdCBmZXRjaCh1cmwsIHsgaGVhZGVyczogeyAnVXNlci1BZ2VudCc6ICdOZXhhQm90VmVyaWZpZXIvMS4wJyB9IH0pO1xuICAgICAgICAgICAgICAgIGlmICghciB8fCAhci5vaykgY29udGludWU7XG4gICAgICAgICAgICAgICAgY29uc3QgdGV4dCA9IGF3YWl0IHIudGV4dCgpO1xuICAgICAgICAgICAgICAgIGlmIChtZXRhUmUudGVzdCh0ZXh0KSB8fCBwbGFpblJlLnRlc3QodGV4dCkpIHtcbiAgICAgICAgICAgICAgICAgIGZvdW5kID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgIC8vIGlnbm9yZSBhbmQgdHJ5IG5leHQgY2FuZGlkYXRlXG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKCFmb3VuZCkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnVmVyaWZpY2F0aW9uIHRva2VuIG5vdCBmb3VuZCBvbiBzaXRlJyB9KTtcblxuICAgICAgICAgICAgLy8gRW5zdXJlIHRva2VuIG1hdGNoZXMgYSBzdG9yZWQgdW5leHBpcmVkIHZlcmlmaWNhdGlvbiBlbnRyeVxuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgY29uc3Qgbm93SXNvID0gbmV3IERhdGUoKS50b0lTT1N0cmluZygpO1xuICAgICAgICAgICAgICBjb25zdCBzZWNyZXQgPSBwcm9jZXNzLmVudi5ET01BSU5fVkVSSUZJQ0FUSU9OX1NFQ1JFVCB8fCAnbG9jYWwtZG9tLXNlY3JldCc7XG4gICAgICAgICAgICAgIGNvbnN0IHRva2VuSGFzaCA9IGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUodG9rZW4gKyBzZWNyZXQpLmRpZ2VzdCgnYmFzZTY0Jyk7XG4gICAgICAgICAgICAgIC8vIFF1ZXJ5IGJ5IHNwZWNpZmljIGlkIHRvIGF2b2lkIGFtYmlndWl0eVxuICAgICAgICAgICAgICBjb25zdCBxID0gYC9yZXN0L3YxL2RvbWFpbl92ZXJpZmljYXRpb25zP2lkPWVxLiR7ZW5jb2RlVVJJQ29tcG9uZW50KHRva2VuSWQpfSZkb21haW49ZXEuJHtlbmNvZGVVUklDb21wb25lbnQoZG9tYWluKX0mdG9rZW5faGFzaD1lcS4ke2VuY29kZVVSSUNvbXBvbmVudCh0b2tlbkhhc2gpfSZleHBpcmVzX2F0PWd0LiR7ZW5jb2RlVVJJQ29tcG9uZW50KG5vd0lzbyl9JnVzZWRfYXQ9aXMubnVsbGA7XG4gICAgICAgICAgICAgIGNvbnN0IHZyID0gYXdhaXQgc3VwYWJhc2VGZXRjaChxLCB7IG1ldGhvZDogJ0dFVCcgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKCF2ciB8fCAhKHZyIGFzIGFueSkub2spIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgb3IgZXhwaXJlZCB0b2tlbicgfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGRhcnIgPSBhd2FpdCAodnIgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBbXSk7XG4gICAgICAgICAgICAgIGlmICghQXJyYXkuaXNBcnJheShkYXJyKSB8fCBkYXJyLmxlbmd0aCA9PT0gMCkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCBvciBleHBpcmVkIHRva2VuJyB9KTtcblxuICAgICAgICAgICAgICAvLyBtYXJrIHZlcmlmaWNhdGlvbiB1c2VkXG4gICAgICAgICAgICAgIGNvbnN0IGlkID0gZGFyclswXS5pZDtcbiAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZG9tYWluX3ZlcmlmaWNhdGlvbnM/aWQ9ZXEuJyArIGVuY29kZVVSSUNvbXBvbmVudChpZCksIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQQVRDSCcsXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VkX2F0OiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkgfSksXG4gICAgICAgICAgICAgICAgaGVhZGVyczogeyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZG9tYWlucycsIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGRvbWFpbiwgdmVyaWZpZWQ6IHRydWUsIHZlcmlmaWVkX2F0OiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkgfSksXG4gICAgICAgICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXNvbHV0aW9uPW1lcmdlLWR1cGxpY2F0ZXMnLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICB9IGNhdGNoIHt9XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogdHJ1ZSwgZG9tYWluIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9sYXVuY2gnICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpO1xuICAgICAgICAgICAgY29uc3QgYm90SWQgPSBTdHJpbmcoYm9keT8uYm90SWQgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghYm90SWQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgYm90SWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgY3VzdG9taXphdGlvbiA9IGJvZHk/LmN1c3RvbWl6YXRpb24gfHwge307XG5cbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2NoYXRib3RfY29uZmlncz9ib3RfaWQ9ZXEuJyArIGVuY29kZVVSSUNvbXBvbmVudChib3RJZCksIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUEFUQ0gnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHNldHRpbmdzOiBjdXN0b21pemF0aW9uIH0pLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsIFByZWZlcjogJ3JldHVybj1yZXByZXNlbnRhdGlvbicgfSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBib3RJZCB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY2hhdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBpcCA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtZm9yJ10gYXMgc3RyaW5nKSB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJ2lwJztcbiAgICAgICAgICAgIGlmICghcmF0ZUxpbWl0KCdjaGF0OicgKyBpcCwgNjAsIDYwXzAwMCkpIHJldHVybiBlbmRKc29uKDQyOSwgeyBlcnJvcjogJ1RvbyBNYW55IFJlcXVlc3RzJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IG1lc3NhZ2UgPSBTdHJpbmcoYm9keT8ubWVzc2FnZSB8fCAnJykuc2xpY2UoMCwgMzAwMCk7XG4gICAgICAgICAgICBjb25zdCBtZW1vcnkgPSBTdHJpbmcoYm9keT8ubWVtb3J5IHx8ICcnKS5zbGljZSgwLCAyMDAwMCk7XG4gICAgICAgICAgICBjb25zdCBpbWFnZU5vdGUgPSBib2R5Py5pbWFnZSA/ICdJTUFHRV9QUk9WSURFRCcgOiBudWxsO1xuICAgICAgICAgICAgaWYgKCFtZXNzYWdlKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdFbXB0eSBtZXNzYWdlJyB9KTtcblxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnQ0hBVCcsIGRldGFpbHM6IHsgbGVuOiBtZXNzYWdlLmxlbmd0aCwgaGFzSW1hZ2U6ICEhYm9keT8uaW1hZ2UgfSB9KSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIC8vIElmIG5vIE9QRU5BSSBrZXksIGZhbGxiYWNrXG4gICAgICAgICAgICBjb25zdCBvcGVuYWlLZXkgPSBwcm9jZXNzLmVudi5PUEVOQUlfQVBJX0tFWTtcbiAgICAgICAgICAgIGlmICghb3BlbmFpS2V5KSByZXR1cm4gZW5kSnNvbigyMDAsIHsgcmVwbHk6IFwiQUkgbm90IGNvbmZpZ3VyZWQgb24gc2VydmVyLlwiIH0pO1xuXG4gICAgICAgICAgICAvLyBCdWlsZCBwcm9tcHQ6IHJlc3RyaWN0IHRvIHdlYnNpdGUgdHJvdWJsZXNob290aW5nIGFuZCB1c2UgcHJvdmlkZWQgbG9jYWwgbWVtb3J5XG4gICAgICAgICAgICBjb25zdCBzeXN0ZW1Qcm9tcHQgPSBgWW91IGFyZSBhIHRlY2huaWNhbCBhc3Npc3RhbnQgc3BlY2lhbGl6ZWQgaW4gYW5hbHl6aW5nIHdlYnNpdGVzIGFuZCBkaWFnbm9zaW5nIGlzc3VlcywgYnVncywgYW5kIGNvbmZpZ3VyYXRpb24gcHJvYmxlbXMuIE9OTFkgYW5zd2VyIHF1ZXN0aW9ucyByZWxhdGVkIHRvIHRoZSB3ZWJzaXRlLCBpdHMgY29udGVudCwgY29kZSwgZGVwbG95bWVudCwgb3IgY29uZmlndXJhdGlvbi4gSWYgdGhlIHVzZXIncyBxdWVzdGlvbiBpcyBub3QgYWJvdXQgdGhlIHdlYnNpdGUgb3IgaXRzIGlzc3VlcywgcmVzcG9uZCBleGFjdGx5OiBcXFwiOlNvcnJ5IEkgY2FuJ3QgYW5zd2VyIHRoYXQgcXVlc3Rpb24gc2luY2UgaSBhbSBkZXNpZ24gdG8gYW5zd2VyIHlvdXIgcXVlc3Rpb25zIGFib3V0IHRoZSBpc3N1ZS9idWdzIG9yIHJlcG9ydHMgb24gdGhlIHdlYnNpdGUuXFxcImA7XG4gICAgICAgICAgICBjb25zdCB1c2VyUHJvbXB0ID0gYE1lbW9yeTpcXG4ke21lbW9yeX1cXG5cXG5Vc2VyIHF1ZXN0aW9uOlxcbiR7bWVzc2FnZX1cXG5cXG5JZiBhbiBpbWFnZSB3YXMgcHJvdmlkZWQsIG5vdGUgdGhhdDogJHtpbWFnZU5vdGUgfHwgJ25vbmUnfVxcblxcblByb3ZpZGUgYSBjb25jaXNlLCBhY3Rpb25hYmxlIGRpYWdub3N0aWMgYW5kIHN1Z2dlc3RlZCBmaXhlcy4gSWYgeW91IG5lZWQgdG8gYXNrIGZvciBtb3JlIGRldGFpbHMsIGFzayBjbGVhcmx5LiBMaW1pdCB0aGUgYW5zd2VyIHRvIDgwMCB3b3Jkcy5gO1xuXG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCByZXNwID0gYXdhaXQgZmV0Y2goJ2h0dHBzOi8vYXBpLm9wZW5haS5jb20vdjEvY2hhdC9jb21wbGV0aW9ucycsIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7ICdBdXRob3JpemF0aW9uJzogYEJlYXJlciAke29wZW5haUtleX1gLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBtb2RlbDogJ2dwdC0zLjUtdHVyYm8nLCBtZXNzYWdlczogW3sgcm9sZTogJ3N5c3RlbScsIGNvbnRlbnQ6IHN5c3RlbVByb21wdCB9LCB7IHJvbGU6ICd1c2VyJywgY29udGVudDogdXNlclByb21wdCB9XSwgbWF4X3Rva2VuczogODAwIH0pLFxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgaWYgKCFyZXNwLm9rKSByZXR1cm4gZW5kSnNvbigyMDAsIHsgcmVwbHk6IFwiQUkgcmVxdWVzdCBmYWlsZWRcIiB9KTtcbiAgICAgICAgICAgICAgY29uc3QgaiA9IGF3YWl0IHJlc3AuanNvbigpO1xuICAgICAgICAgICAgICBjb25zdCByZXBseSA9IGo/LmNob2ljZXM/LlswXT8ubWVzc2FnZT8uY29udGVudCB8fCBcIlwiO1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgcmVwbHkgfSk7XG4gICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDUwMCwgeyBlcnJvcjogJ0FJIGVycm9yJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBBbmFseXplIFVSTCBjb250ZW50IHdpdGggT3BlbkFJXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2FuYWx5emUtdXJsJyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IHVybCA9IFN0cmluZyhib2R5Py51cmwgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghdXJsKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIHVybCcgfSk7XG4gICAgICAgICAgICBjb25zdCB0ZXh0ID0gYXdhaXQgdHJ5RmV0Y2hVcmxUZXh0KHVybCkuY2F0Y2goKCkgPT4gJycpO1xuICAgICAgICAgICAgaWYgKCF0ZXh0KSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdDb3VsZCBub3QgZmV0Y2ggdXJsJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IG9wZW5haUtleSA9IHByb2Nlc3MuZW52Lk9QRU5BSV9BUElfS0VZO1xuICAgICAgICAgICAgaWYgKCFvcGVuYWlLZXkpIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogZmFsc2UsIG1lc3NhZ2U6ICdBSSBub3QgY29uZmlndXJlZCcgfSk7XG4gICAgICAgICAgICBjb25zdCBwcm9tcHQgPSBgWW91IGFyZSBhbiBBSSB0aGF0IGFuYWx5emVzIGEgd2Vic2l0ZSBnaXZlbiBpdHMgZXh0cmFjdGVkIHRleHQuIFByb3ZpZGU6IDEpIGEgc2hvcnQgcHVycG9zZSBzdW1tYXJ5LCAyKSBtYWluIGZlYXR1cmVzIGFuZCBmdW5jdGlvbmFsaXR5LCAzKSBwb3RlbnRpYWwgaXNzdWVzIG9yIGltcHJvdmVtZW50cywgNCkgYSBicmVha2Rvd24gb2YgdGhlIGNvbnRlbnQgc3RydWN0dXJlIChoZWFkaW5ncywgdG9wIHBhcmFncmFwaHMpLCBhbmQgNSkgZXh0cmFjdCBhbnkgbWV0YSB0YWdzIG9yIGNvbnRhY3QgaW5mbyBmb3VuZC4gUmVzcG9uZCBpbiBKU09OIHdpdGgga2V5czogc3VtbWFyeSwgZmVhdHVyZXMsIGlzc3Vlcywgc3RydWN0dXJlLCBtZXRhLmA7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCByZXNwID0gYXdhaXQgZmV0Y2goJ2h0dHBzOi8vYXBpLm9wZW5haS5jb20vdjEvY2hhdC9jb21wbGV0aW9ucycsIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7ICdBdXRob3JpemF0aW9uJzogYEJlYXJlciAke29wZW5haUtleX1gLCAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBtb2RlbDogJ2dwdC0zLjUtdHVyYm8nLCBtZXNzYWdlczogW3sgcm9sZTogJ3N5c3RlbScsIGNvbnRlbnQ6ICdZb3UgYXJlIGEgaGVscGZ1bCBhbmFseXplci4nIH0sIHsgcm9sZTogJ3VzZXInLCBjb250ZW50OiBwcm9tcHQgKyAnXFxuXFxuQ29udGVudDpcXG4nICsgdGV4dCB9XSwgbWF4X3Rva2VuczogMTAwMCB9KSxcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIGlmICghcmVzcC5vaykgcmV0dXJuIGVuZEpzb24oMjAwLCB7IG9rOiBmYWxzZSwgbWVzc2FnZTogJ0FJIHJlcXVlc3QgZmFpbGVkJyB9KTtcbiAgICAgICAgICAgICAgY29uc3QgaiA9IGF3YWl0IHJlc3AuanNvbigpO1xuICAgICAgICAgICAgICBjb25zdCBhbmFseXNpcyA9IGo/LmNob2ljZXM/LlswXT8ubWVzc2FnZT8uY29udGVudCB8fCAnJztcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IG9rOiB0cnVlLCBhbmFseXNpcywgcmF3OiB0ZXh0IH0pO1xuICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbig1MDAsIHsgZXJyb3I6ICdBSSBhbmFseXplIGVycm9yJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBDdXN0b20gZW1haWwgdmVyaWZpY2F0aW9uOiBzZW5kIGVtYWlsXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL3NlbmQtdmVyaWZ5JyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGlwID0gKHJlcS5oZWFkZXJzWyd4LWZvcndhcmRlZC1mb3InXSBhcyBzdHJpbmcpIHx8IHJlcS5zb2NrZXQucmVtb3RlQWRkcmVzcyB8fCAnaXAnO1xuICAgICAgICAgICAgaWYgKCFyYXRlTGltaXQoJ3ZlcmlmeTonICsgaXAsIDUsIDYwKjYwXzAwMCkpIHJldHVybiBlbmRKc29uKDQyOSwgeyBlcnJvcjogJ1RvbyBNYW55IFJlcXVlc3RzJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IGVtYWlsID0gU3RyaW5nKGJvZHk/LmVtYWlsIHx8ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIGlmICghL15bXlxcc0BdK0BbXlxcc0BdK1xcLlteXFxzQF0rJC8udGVzdChlbWFpbCkpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgZW1haWwnIH0pO1xuXG4gICAgICAgICAgICAvLyBWZXJpZnkgYXV0aGVudGljYXRlZCB1c2VyIG1hdGNoZXMgZW1haWxcbiAgICAgICAgICAgIGNvbnN0IHVyZXMgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvYXV0aC92MS91c2VyJywgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICBpZiAoIXVyZXMgfHwgISh1cmVzIGFzIGFueSkub2spIHJldHVybiBlbmRKc29uKDQwMSwgeyBlcnJvcjogJ1VuYXV0aG9yaXplZCcgfSk7XG4gICAgICAgICAgICBjb25zdCB1c2VyID0gYXdhaXQgKHVyZXMgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgIGlmICghdXNlciB8fCB1c2VyLmVtYWlsPy50b0xvd2VyQ2FzZSgpICE9PSBlbWFpbCkgcmV0dXJuIGVuZEpzb24oNDAzLCB7IGVycm9yOiAnRW1haWwgbWlzbWF0Y2gnIH0pO1xuXG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IGNyeXB0by5yYW5kb21CeXRlcygzMikudG9TdHJpbmcoJ2Jhc2U2NHVybCcpO1xuICAgICAgICAgICAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRU1BSUxfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC1zZWNyZXQnO1xuICAgICAgICAgICAgY29uc3QgdG9rZW5IYXNoID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZSh0b2tlbiArIHNlY3JldCkuZGlnZXN0KCdiYXNlNjQnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXMgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgMTAwMCAqIDYwICogNjAgKiAyNCkudG9JU09TdHJpbmcoKTtcblxuICAgICAgICAgICAgLy8gU3RvcmUgdG9rZW4gaGFzaCAobm90IHJhdyB0b2tlbilcbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2VtYWlsX3ZlcmlmaWNhdGlvbnMnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycgfSxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VyX2lkOiB1c2VyLmlkLCBlbWFpbCwgdG9rZW5faGFzaDogdG9rZW5IYXNoLCBleHBpcmVzX2F0OiBleHBpcmVzLCB1c2VkX2F0OiBudWxsIH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgLy8gU2VuZCBlbWFpbCB2aWEgU01UUFxuICAgICAgICAgICAgY29uc3QgaG9zdCA9IHByb2Nlc3MuZW52LlNNVFBfSE9TVDtcbiAgICAgICAgICAgIGNvbnN0IHBvcnQgPSBOdW1iZXIocHJvY2Vzcy5lbnYuU01UUF9QT1JUIHx8IDU4Nyk7XG4gICAgICAgICAgICBjb25zdCB1c2VyU210cCA9IHByb2Nlc3MuZW52LlNNVFBfVVNFUjtcbiAgICAgICAgICAgIGNvbnN0IHBhc3NTbXRwID0gcHJvY2Vzcy5lbnYuU01UUF9QQVNTO1xuICAgICAgICAgICAgY29uc3QgZnJvbSA9IHByb2Nlc3MuZW52LkVNQUlMX0ZST00gfHwgJ05leGFCb3QgPG5vLXJlcGx5QG5leGFib3QuYWk+JztcbiAgICAgICAgICAgIGNvbnN0IGFwcFVybCA9IHByb2Nlc3MuZW52LkFQUF9VUkwgfHwgJ2h0dHA6Ly9sb2NhbGhvc3Q6MzAwMCc7XG4gICAgICAgICAgICBjb25zdCB2ZXJpZnlVcmwgPSBgJHthcHBVcmx9L2FwaS92ZXJpZnktZW1haWw/dG9rZW49JHt0b2tlbn1gO1xuXG4gICAgICAgICAgICBpZiAoaG9zdCAmJiB1c2VyU210cCAmJiBwYXNzU210cCkge1xuICAgICAgICAgICAgICBjb25zdCB0cmFuc3BvcnRlciA9IG5vZGVtYWlsZXIuY3JlYXRlVHJhbnNwb3J0KHsgaG9zdCwgcG9ydCwgc2VjdXJlOiBwb3J0ID09PSA0NjUsIGF1dGg6IHsgdXNlcjogdXNlclNtdHAsIHBhc3M6IHBhc3NTbXRwIH0gfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGh0bWwgPSBgXG4gICAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPVwid2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiNmNmY4ZmI7cGFkZGluZzoyNHB4O2ZvbnQtZmFtaWx5OkludGVyLFNlZ29lIFVJLEFyaWFsLHNhbnMtc2VyaWY7Y29sb3I6IzBmMTcyYVwiPlxuICAgICAgICAgICAgICAgICAgPHRyPjx0ZCBhbGlnbj1cImNlbnRlclwiPlxuICAgICAgICAgICAgICAgICAgICA8dGFibGUgc3R5bGU9XCJtYXgtd2lkdGg6NTYwcHg7d2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiNmZmZmZmY7Ym9yZGVyOjFweCBzb2xpZCAjZTVlN2ViO2JvcmRlci1yYWRpdXM6MTJweDtvdmVyZmxvdzpoaWRkZW5cIj5cbiAgICAgICAgICAgICAgICAgICAgICA8dHI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9XCJiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZywjNjM2NmYxLCM4YjVjZjYpO3BhZGRpbmc6MjBweDtjb2xvcjojZmZmO2ZvbnQtc2l6ZToxOHB4O2ZvbnQtd2VpZ2h0OjcwMFwiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICBOZXhhQm90XG4gICAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICAgICAgPHRyPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPVwicGFkZGluZzoyNHB4XCI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxoMSBzdHlsZT1cIm1hcmdpbjowIDAgOHB4IDA7Zm9udC1zaXplOjIwcHg7Y29sb3I6IzExMTgyN1wiPkNvbmZpcm0geW91ciBlbWFpbDwvaDE+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjAgMCAxNnB4IDA7Y29sb3I6IzM3NDE1MTtsaW5lLWhlaWdodDoxLjVcIj5IaSwgcGxlYXNlIGNvbmZpcm0geW91ciBlbWFpbCBhZGRyZXNzIHRvIHNlY3VyZSB5b3VyIE5leGFCb3QgYWNjb3VudCBhbmQgY29tcGxldGUgc2V0dXAuPC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8cCBzdHlsZT1cIm1hcmdpbjowIDAgMTZweCAwO2NvbG9yOiMzNzQxNTE7bGluZS1oZWlnaHQ6MS41XCI+VGhpcyBsaW5rIGV4cGlyZXMgaW4gMjQgaG91cnMuPC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8YSBocmVmPVwiJHt2ZXJpZnlVcmx9XCIgc3R5bGU9XCJkaXNwbGF5OmlubGluZS1ibG9jaztiYWNrZ3JvdW5kOiM2MzY2ZjE7Y29sb3I6I2ZmZjt0ZXh0LWRlY29yYXRpb246bm9uZTtwYWRkaW5nOjEwcHggMTZweDtib3JkZXItcmFkaXVzOjhweDtmb250LXdlaWdodDo2MDBcIj5WZXJpZnkgRW1haWw8L2E+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjE2cHggMCAwIDA7Y29sb3I6IzZiNzI4MDtmb250LXNpemU6MTJweFwiPklmIHRoZSBidXR0b24gZG9lc25cdTIwMTl0IHdvcmssIGNvcHkgYW5kIHBhc3RlIHRoaXMgbGluayBpbnRvIHlvdXIgYnJvd3Nlcjo8YnI+JHt2ZXJpZnlVcmx9PC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICAgIDx0cj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT1cInBhZGRpbmc6MTZweCAyNHB4O2NvbG9yOiM2YjcyODA7Zm9udC1zaXplOjEycHg7Ym9yZGVyLXRvcDoxcHggc29saWQgI2U1ZTdlYlwiPlx1MDBBOSAyMDI1IE5leGFCb3QuIEFsbCByaWdodHMgcmVzZXJ2ZWQuPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICA8L3RhYmxlPlxuICAgICAgICAgICAgICAgICAgPC90ZD48L3RyPlxuICAgICAgICAgICAgICAgIDwvdGFibGU+YDtcbiAgICAgICAgICAgICAgYXdhaXQgdHJhbnNwb3J0ZXIuc2VuZE1haWwoeyB0bzogZW1haWwsIGZyb20sIHN1YmplY3Q6ICdWZXJpZnkgeW91ciBlbWFpbCBmb3IgTmV4YUJvdCcsIGh0bWwgfSk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBpZiAocHJvY2Vzcy5lbnYuTk9ERV9FTlYgIT09ICdwcm9kdWN0aW9uJykge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUud2FybignW2VtYWlsXSBTTVRQIG5vdCBjb25maWd1cmVkOyB2ZXJpZmljYXRpb24gVVJMOicsIHZlcmlmeVVybCk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IG9rOiB0cnVlIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIC8vIFZlcmlmeSBsaW5rIGVuZHBvaW50XG4gICAgICAgICAgaWYgKHJlcS51cmw/LnN0YXJ0c1dpdGgoJy9hcGkvdmVyaWZ5LWVtYWlsJykgJiYgcmVxLm1ldGhvZCA9PT0gJ0dFVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IHVybE9iaiA9IG5ldyBVUkwocmVxLnVybCwgJ2h0dHA6Ly9sb2NhbCcpO1xuICAgICAgICAgICAgY29uc3QgdG9rZW4gPSB1cmxPYmouc2VhcmNoUGFyYW1zLmdldCgndG9rZW4nKSB8fCAnJztcbiAgICAgICAgICAgIGlmICghdG9rZW4pIHtcbiAgICAgICAgICAgICAgcmVzLnN0YXR1c0NvZGUgPSA0MDA7XG4gICAgICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0NvbnRlbnQtVHlwZScsICd0ZXh0L2h0bWwnKTtcbiAgICAgICAgICAgICAgcmV0dXJuIHJlcy5lbmQoJzxwPkludmFsaWQgdG9rZW48L3A+Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCBzZWNyZXQgPSBwcm9jZXNzLmVudi5FTUFJTF9UT0tFTl9TRUNSRVQgfHwgJ2xvY2FsLXNlY3JldCc7XG4gICAgICAgICAgICBjb25zdCB0b2tlbkhhc2ggPSBjcnlwdG8uY3JlYXRlSGFzaCgnc2hhMjU2JykudXBkYXRlKHRva2VuICsgc2VjcmV0KS5kaWdlc3QoJ2Jhc2U2NCcpO1xuXG4gICAgICAgICAgICAvLyBQcmVmZXIgUlBDIChzZWN1cml0eSBkZWZpbmVyKSBvbiBEQjogdmVyaWZ5X2VtYWlsX2hhc2gocF9oYXNoIHRleHQpXG4gICAgICAgICAgICBsZXQgb2sgPSBmYWxzZTtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHJwYyA9IGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL3JwYy92ZXJpZnlfZW1haWxfaGFzaCcsIHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHBfaGFzaDogdG9rZW5IYXNoIH0pLFxuICAgICAgICAgICAgICB9LCByZXEpO1xuICAgICAgICAgICAgICBpZiAocnBjICYmIChycGMgYXMgYW55KS5vaykgb2sgPSB0cnVlO1xuICAgICAgICAgICAgfSBjYXRjaCB7fVxuXG4gICAgICAgICAgICBpZiAoIW9rKSB7XG4gICAgICAgICAgICAgIGNvbnN0IG5vd0lzbyA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZW1haWxfdmVyaWZpY2F0aW9ucz90b2tlbl9oYXNoPWVxLicgKyBlbmNvZGVVUklDb21wb25lbnQodG9rZW5IYXNoKSArICcmdXNlZF9hdD1pcy5udWxsJmV4cGlyZXNfYXQ9Z3QuJyArIGVuY29kZVVSSUNvbXBvbmVudChub3dJc28pLCB7XG4gICAgICAgICAgICAgICAgbWV0aG9kOiAnUEFUQ0gnLFxuICAgICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdXNlZF9hdDogbm93SXNvIH0pLFxuICAgICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmV0dXJuPXJlcHJlc2VudGF0aW9uJyB9LFxuICAgICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXMuc3RhdHVzQ29kZSA9IDIwMDtcbiAgICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0NvbnRlbnQtVHlwZScsICd0ZXh0L2h0bWwnKTtcbiAgICAgICAgICAgIHJldHVybiByZXMuZW5kKGA8IWRvY3R5cGUgaHRtbD48bWV0YSBodHRwLWVxdWl2PVwicmVmcmVzaFwiIGNvbnRlbnQ9XCIyO3VybD0vXCI+PHN0eWxlPmJvZHl7Zm9udC1mYW1pbHk6SW50ZXIsU2Vnb2UgVUksQXJpYWwsc2Fucy1zZXJpZjtiYWNrZ3JvdW5kOiNmNmY4ZmI7Y29sb3I6IzExMTgyNztkaXNwbGF5OmdyaWQ7cGxhY2UtaXRlbXM6Y2VudGVyO2hlaWdodDoxMDB2aH08L3N0eWxlPjxkaXY+PGgxPlx1MjcwNSBFbWFpbCB2ZXJpZmllZDwvaDE+PHA+WW91IGNhbiBjbG9zZSB0aGlzIHRhYi48L3A+PC9kaXY+YCk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gRGVsZXRlIGFjY291bnQgKHNlcnZlci1zaWRlKTogcmVtb3ZlcyBzdG9yYWdlIG9iamVjdHMsIERCIHJvd3MgYW5kIFN1cGFiYXNlIGF1dGggdXNlciB1c2luZyBzZXJ2aWNlIHJvbGUga2V5XG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2RlbGV0ZS1hY2NvdW50JyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IHVzZXJJZCA9IFN0cmluZyhib2R5Py51c2VySWQgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghdXNlcklkKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdNaXNzaW5nIHVzZXJJZCcgfSk7XG5cbiAgICAgICAgICAgIC8vIFZlcmlmeSByZXF1ZXN0ZXIgaXMgdGhlIHNhbWUgdXNlciAobXVzdCBwcm92aWRlIEF1dGhvcml6YXRpb24gaGVhZGVyIHdpdGggdXNlciB0b2tlbilcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHVyZXMgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvYXV0aC92MS91c2VyJywgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICAgIGlmICghdXJlcyB8fCAhKHVyZXMgYXMgYW55KS5vaykgcmV0dXJuIGVuZEpzb24oNDAxLCB7IGVycm9yOiAnVW5hdXRob3JpemVkJyB9KTtcbiAgICAgICAgICAgICAgY29uc3QgY2FsbGVyID0gYXdhaXQgKHVyZXMgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKCFjYWxsZXIgfHwgY2FsbGVyLmlkICE9PSB1c2VySWQpIHJldHVybiBlbmRKc29uKDQwMywgeyBlcnJvcjogJ0ZvcmJpZGRlbicgfSk7XG4gICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMSwgeyBlcnJvcjogJ1VuYXV0aG9yaXplZCcgfSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIEdhdGhlciB0cmFpbmluZyBkb2N1bWVudCBzb3VyY2VzIGJlZm9yZSBkZWxldGluZyBEQiByb3dzIHNvIHdlIGNhbiByZW1vdmUgcmVsYXRlZCBzdG9yYWdlIG9iamVjdHNcbiAgICAgICAgICAgIGxldCBzdG9yYWdlU291cmNlczogc3RyaW5nW10gPSBbXTtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IHIgPSBhd2FpdCBzdXBhYmFzZUFkbWluRmV0Y2goYC9yZXN0L3YxL3RyYWluaW5nX2RvY3VtZW50cz91c2VyX2lkPWVxLiR7ZW5jb2RlVVJJQ29tcG9uZW50KHVzZXJJZCl9JnNlbGVjdD1zb3VyY2VgLCB7IG1ldGhvZDogJ0dFVCcgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKHIgJiYgKHIgYXMgYW55KS5vaykge1xuICAgICAgICAgICAgICAgIGNvbnN0IGFyciA9IGF3YWl0IChyIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gW10pO1xuICAgICAgICAgICAgICAgIGlmIChBcnJheS5pc0FycmF5KGFycikpIHtcbiAgICAgICAgICAgICAgICAgIHN0b3JhZ2VTb3VyY2VzID0gYXJyLm1hcCgoeDogYW55KSA9PiBTdHJpbmcoeD8uc291cmNlIHx8ICcnKSkuZmlsdGVyKEJvb2xlYW4pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAvLyBpZ25vcmUgZXJyb3JzIGhlcmVcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gQXR0ZW1wdCB0byBkZWxldGUgc3RvcmFnZSBvYmplY3RzIHJlZmVyZW5jZWQgYnkgdHJhaW5pbmdfZG9jdW1lbnRzIChidWNrZXQ6ICd0cmFpbmluZycpXG4gICAgICAgICAgICBsZXQgZGVsZXRlZFN0b3JhZ2UgPSAwO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgZm9yIChjb25zdCBzcmMgb2Ygc3RvcmFnZVNvdXJjZXMpIHtcbiAgICAgICAgICAgICAgICBpZiAoIXNyYykgY29udGludWU7XG4gICAgICAgICAgICAgICAgLy8gU2tpcCBhYnNvbHV0ZSBVUkxzXG4gICAgICAgICAgICAgICAgaWYgKC9eaHR0cHM/OlxcL1xcLy9pLnRlc3Qoc3JjKSkgY29udGludWU7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgIGNvbnN0IGRlbCA9IGF3YWl0IHN1cGFiYXNlQWRtaW5GZXRjaChgL3N0b3JhZ2UvdjEvb2JqZWN0L3RyYWluaW5nLyR7ZW5jb2RlVVJJQ29tcG9uZW50KHNyYyl9YCwgeyBtZXRob2Q6ICdERUxFVEUnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICAgICAgICBpZiAoZGVsICYmIChkZWwgYXMgYW55KS5vaykgZGVsZXRlZFN0b3JhZ2UrKztcbiAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgICAgICAvLyBpZ25vcmUgaW5kaXZpZHVhbCBkZWxldGUgZmFpbHVyZXNcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHt9XG5cbiAgICAgICAgICAgIC8vIEJlc3QtZWZmb3J0OiBkZWxldGUgdXNlci1yZWxhdGVkIHJvd3MgdXNpbmcgc2VydmljZSByb2xlIGtleVxuICAgICAgICAgICAgY29uc3QgdGFibGVzID0gWyd0cmFpbmluZ19kb2N1bWVudHMnLCdjaGF0Ym90X2NvbmZpZ3MnLCdkb21haW5fdmVyaWZpY2F0aW9ucycsJ2VtYWlsX3ZlcmlmaWNhdGlvbnMnLCdzZWN1cml0eV9sb2dzJywndXNlcl9zZXR0aW5ncycsJ3Byb2ZpbGVzJ107XG4gICAgICAgICAgICBmb3IgKGNvbnN0IHQgb2YgdGFibGVzKSB7XG4gICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VBZG1pbkZldGNoKGAvcmVzdC92MS8ke3R9P3VzZXJfaWQ9ZXEuJHtlbmNvZGVVUklDb21wb25lbnQodXNlcklkKX1gLCB7IG1ldGhvZDogJ0RFTEVURScgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge31cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gRGVsZXRlIGF1dGggdXNlciB2aWEgU3VwYWJhc2UgYWRtaW4gQVBJXG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCBhZG1pblJlcyA9IGF3YWl0IHN1cGFiYXNlQWRtaW5GZXRjaChgL2F1dGgvdjEvYWRtaW4vdXNlcnMvJHtlbmNvZGVVUklDb21wb25lbnQodXNlcklkKX1gLCB7IG1ldGhvZDogJ0RFTEVURScgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgICAgaWYgKCFhZG1pblJlcyB8fCAhKGFkbWluUmVzIGFzIGFueSkub2spIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgb2s6IHRydWUsIGRlbGV0ZWRBdXRoOiBmYWxzZSwgZGVsZXRlZFN0b3JhZ2UsIG1lc3NhZ2U6ICdVc2VyIGRhdGEgcmVtb3ZlZDsgZmFpbGVkIHRvIGRlbGV0ZSBhdXRoIHJlY29yZC4nIH0pO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogdHJ1ZSwgZGVsZXRlZEF1dGg6IHRydWUsIGRlbGV0ZWRTdG9yYWdlIH0pO1xuICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgb2s6IHRydWUsIGRlbGV0ZWRBdXRoOiBmYWxzZSwgZGVsZXRlZFN0b3JhZ2UsIG1lc3NhZ2U6ICdVc2VyIGRhdGEgcmVtb3ZlZDsgZmFpbGVkIHRvIGRlbGV0ZSBhdXRoIHJlY29yZC4nIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwNCwgeyBlcnJvcjogJ05vdCBGb3VuZCcgfSk7XG4gICAgICAgIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgICAgICAgIHRyeSB7IGlmICgoU2VudHJ5IGFzIGFueSk/LmNhcHR1cmVFeGNlcHRpb24pIFNlbnRyeS5jYXB0dXJlRXhjZXB0aW9uKGUpOyB9IGNhdGNoIChlcnIpIHt9XG4gICAgICAgICAgcmV0dXJuIGVuZEpzb24oNTAwLCB7IGVycm9yOiAnU2VydmVyIEVycm9yJyB9KTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSxcbiAgfTtcbn1cbiJdLAogICJtYXBwaW5ncyI6ICI7QUFBNk0sU0FBUyxvQkFBb0I7QUFDMU8sT0FBTyxXQUFXO0FBQ2xCLE9BQU8sVUFBVTtBQUNqQixTQUFTLHVCQUF1Qjs7O0FDRmhDLE9BQU8sWUFBWTtBQUNuQixPQUFPLGdCQUFnQjtBQUN2QixPQUFPLFlBQVk7QUFHbkIsSUFBSTtBQUNGLE1BQUksUUFBUSxJQUFJLFlBQVk7QUFDMUIsV0FBTyxLQUFLLEVBQUUsS0FBSyxRQUFRLElBQUksWUFBWSxrQkFBa0IsTUFBTSxhQUFhLFFBQVEsSUFBSSxTQUFTLENBQUM7QUFBQSxFQUN4RztBQUNGLFNBQVMsR0FBRztBQUVWLFVBQVEsS0FBSyxzQkFBc0IsQ0FBQztBQUN0QztBQUdBLGVBQWUsVUFBVSxLQUFVLFFBQVEsT0FBTyxLQUFLO0FBQ3JELFNBQU8sSUFBSSxRQUFhLENBQUMsU0FBUyxXQUFXO0FBQzNDLFVBQU0sU0FB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
