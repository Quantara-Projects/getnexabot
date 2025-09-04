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
async function supabaseFetch(path2, options, req) {
  const base = process.env.SUPABASE_URL || "https://fzygxynereijjfbcvwoh.supabase.co";
  const anon = process.env.SUPABASE_ANON_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZ6eWd4eW5lcmVpampmYmN2d29oIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTY5NTYxMzMsImV4cCI6MjA3MjUzMjEzM30.-JnUwaXflcWmvL8_fu08uEzeBnIhxvAkd6_hqVeSYlI";
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
            const seed = domain + "|" + (req.headers["authorization"] || "");
            const botId = makeBotId(seed);
            await supabaseFetch("/rest/v1/chatbot_configs", {
              method: "POST",
              body: JSON.stringify({ bot_id: botId, channel: "website", domain, settings: {} }),
              headers: { Prefer: "resolution=merge-duplicates" }
            }, req).catch(() => null);
            return endJson(200, { botId });
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
              console.warn("[email] SMTP not configured; verification URL:", verifyUrl);
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL3NlcnZlci9hcGkudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGVcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9hcHAvY29kZS92aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vYXBwL2NvZGUvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tIFwidml0ZVwiO1xuaW1wb3J0IHJlYWN0IGZyb20gXCJAdml0ZWpzL3BsdWdpbi1yZWFjdC1zd2NcIjtcbmltcG9ydCBwYXRoIGZyb20gXCJwYXRoXCI7XG5pbXBvcnQgeyBjb21wb25lbnRUYWdnZXIgfSBmcm9tIFwibG92YWJsZS10YWdnZXJcIjtcbmltcG9ydCB7IHNlcnZlckFwaVBsdWdpbiB9IGZyb20gXCIuL3NyYy9zZXJ2ZXIvYXBpXCI7XG5cbi8vIGh0dHBzOi8vdml0ZWpzLmRldi9jb25maWcvXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiAoe1xuICBzZXJ2ZXI6IHtcbiAgICBob3N0OiBcIjo6XCIsXG4gICAgcG9ydDogODA4MCxcbiAgfSxcbiAgcGx1Z2luczogW1xuICAgIHJlYWN0KCksXG4gICAgbW9kZSA9PT0gJ2RldmVsb3BtZW50JyAmJlxuICAgIGNvbXBvbmVudFRhZ2dlcigpLFxuICAgIHNlcnZlckFwaVBsdWdpbigpLFxuICBdLmZpbHRlcihCb29sZWFuKSxcbiAgcmVzb2x2ZToge1xuICAgIGFsaWFzOiB7XG4gICAgICBcIkBcIjogcGF0aC5yZXNvbHZlKF9fZGlybmFtZSwgXCIuL3NyY1wiKSxcbiAgICB9LFxuICB9LFxufSkpO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGUvc3JjL3NlcnZlclwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2FwcC9jb2RlL3NyYy9zZXJ2ZXIvYXBpLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9hcHAvY29kZS9zcmMvc2VydmVyL2FwaS50c1wiO2ltcG9ydCB0eXBlIHsgUGx1Z2luIH0gZnJvbSAndml0ZSc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5pbXBvcnQgbm9kZW1haWxlciBmcm9tICdub2RlbWFpbGVyJztcblxuLy8gU21hbGwgSlNPTiBib2R5IHBhcnNlciB3aXRoIHNpemUgbGltaXRcbmFzeW5jIGZ1bmN0aW9uIHBhcnNlSnNvbihyZXE6IGFueSwgbGltaXQgPSAxMDI0ICogMTAwKSB7XG4gIHJldHVybiBuZXcgUHJvbWlzZTxhbnk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICBjb25zdCBjaHVua3M6IEJ1ZmZlcltdID0gW107XG4gICAgbGV0IHNpemUgPSAwO1xuICAgIHJlcS5vbignZGF0YScsIChjOiBCdWZmZXIpID0+IHtcbiAgICAgIHNpemUgKz0gYy5sZW5ndGg7XG4gICAgICBpZiAoc2l6ZSA+IGxpbWl0KSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1BheWxvYWQgdG9vIGxhcmdlJykpO1xuICAgICAgICByZXEuZGVzdHJveSgpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjaHVua3MucHVzaChjKTtcbiAgICB9KTtcbiAgICByZXEub24oJ2VuZCcsICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJhdyA9IEJ1ZmZlci5jb25jYXQoY2h1bmtzKS50b1N0cmluZygndXRmOCcpO1xuICAgICAgICBjb25zdCBqc29uID0gcmF3ID8gSlNPTi5wYXJzZShyYXcpIDoge307XG4gICAgICAgIHJlc29sdmUoanNvbik7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHJlamVjdChlKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICByZXEub24oJ2Vycm9yJywgcmVqZWN0KTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIGpzb24ocmVzOiBhbnksIHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnksIGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7fSkge1xuICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7XG4gIHJlcy5zdGF0dXNDb2RlID0gc3RhdHVzO1xuICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCcpO1xuICByZXMuc2V0SGVhZGVyKCdYLUNvbnRlbnQtVHlwZS1PcHRpb25zJywgJ25vc25pZmYnKTtcbiAgcmVzLnNldEhlYWRlcignUmVmZXJyZXItUG9saWN5JywgJ25vLXJlZmVycmVyJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtRnJhbWUtT3B0aW9ucycsICdERU5ZJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtWFNTLVByb3RlY3Rpb24nLCAnMTsgbW9kZT1ibG9jaycpO1xuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhoZWFkZXJzKSkgcmVzLnNldEhlYWRlcihrLCB2KTtcbiAgcmVzLmVuZChib2R5KTtcbn1cblxuY29uc3QgaXNIdHRwcyA9IChyZXE6IGFueSkgPT4ge1xuICBjb25zdCBwcm90byA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtcHJvdG8nXSBhcyBzdHJpbmcpIHx8ICcnO1xuICByZXR1cm4gcHJvdG8gPT09ICdodHRwcycgfHwgKHJlcS5zb2NrZXQgJiYgKHJlcS5zb2NrZXQgYXMgYW55KS5lbmNyeXB0ZWQpO1xufTtcblxuYXN5bmMgZnVuY3Rpb24gc3VwYWJhc2VGZXRjaChwYXRoOiBzdHJpbmcsIG9wdGlvbnM6IGFueSwgcmVxOiBhbnkpIHtcbiAgY29uc3QgYmFzZSA9IHByb2Nlc3MuZW52LlNVUEFCQVNFX1VSTCB8fCAnaHR0cHM6Ly9menlneHluZXJlaWpqZmJjdndvaC5zdXBhYmFzZS5jbyc7XG4gIGNvbnN0IGFub24gPSBwcm9jZXNzLmVudi5TVVBBQkFTRV9BTk9OX0tFWSB8fCAnZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBjM01pT2lKemRYQmhZbUZ6WlNJc0luSmxaaUk2SW1aNmVXZDRlVzVsY21WcGFtcG1ZbU4yZDI5b0lpd2ljbTlzWlNJNkltRnViMjRpTENKcFlYUWlPakUzTlRZNU5UWXhNek1zSW1WNGNDSTZNakEzTWpVek1qRXpNMzAuLUpuVXdhWGZsY1dtdkw4X2Z1MDh1RXplQm5JaHh2QWtkNl9ocVZlU1lsSSc7XG4gIGNvbnN0IHRva2VuID0gKHJlcS5oZWFkZXJzWydhdXRob3JpemF0aW9uJ10gYXMgc3RyaW5nKSB8fCAnJztcbiAgY29uc3QgaGVhZGVyczogUmVjb3JkPHN0cmluZywgc3RyaW5nPiA9IHtcbiAgICBhcGlrZXk6IGFub24sXG4gICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyxcbiAgfTtcbiAgaWYgKHRva2VuKSBoZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSB0b2tlbjtcbiAgcmV0dXJuIGZldGNoKGAke2Jhc2V9JHtwYXRofWAsIHsgLi4ub3B0aW9ucywgaGVhZGVyczogeyAuLi5oZWFkZXJzLCAuLi4ob3B0aW9ucz8uaGVhZGVycyB8fCB7fSkgfSB9KTtcbn1cblxuZnVuY3Rpb24gbWFrZUJvdElkKHNlZWQ6IHN0cmluZykge1xuICByZXR1cm4gJ2JvdF8nICsgY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZShzZWVkKS5kaWdlc3QoJ2Jhc2U2NHVybCcpLnNsaWNlKDAsIDIyKTtcbn1cblxuLy8gU2ltcGxlIGluLW1lbW9yeSByYXRlIGxpbWl0ZXJcbmNvbnN0IHJhdGVNYXAgPSBuZXcgTWFwPHN0cmluZywgeyBjb3VudDogbnVtYmVyOyB0czogbnVtYmVyIH0+KCk7XG5mdW5jdGlvbiByYXRlTGltaXQoa2V5OiBzdHJpbmcsIGxpbWl0OiBudW1iZXIsIHdpbmRvd01zOiBudW1iZXIpIHtcbiAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgY29uc3QgcmVjID0gcmF0ZU1hcC5nZXQoa2V5KTtcbiAgaWYgKCFyZWMgfHwgbm93IC0gcmVjLnRzID4gd2luZG93TXMpIHtcbiAgICByYXRlTWFwLnNldChrZXksIHsgY291bnQ6IDEsIHRzOiBub3cgfSk7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cbiAgaWYgKHJlYy5jb3VudCA8IGxpbWl0KSB7XG4gICAgcmVjLmNvdW50ICs9IDE7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cbiAgcmV0dXJuIGZhbHNlO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gc2VydmVyQXBpUGx1Z2luKCk6IFBsdWdpbiB7XG4gIHJldHVybiB7XG4gICAgbmFtZTogJ3NlcnZlci1hcGktcGx1Z2luJyxcbiAgICBjb25maWd1cmVTZXJ2ZXIoc2VydmVyKSB7XG4gICAgICBzZXJ2ZXIubWlkZGxld2FyZXMudXNlKGFzeW5jIChyZXEsIHJlcywgbmV4dCkgPT4ge1xuICAgICAgICBpZiAoIXJlcS51cmwgfHwgIXJlcS51cmwuc3RhcnRzV2l0aCgnL2FwaS8nKSkgcmV0dXJuIG5leHQoKTtcblxuICAgICAgICAvLyBCYXNpYyBzZWN1cml0eSBoZWFkZXJzIGZvciBhbGwgQVBJIHJlc3BvbnNlc1xuICAgICAgICBjb25zdCBjb3JzT3JpZ2luID0gcmVxLmhlYWRlcnMub3JpZ2luIHx8ICcqJztcbiAgICAgICAgcmVzLnNldEhlYWRlcignUGVybWlzc2lvbnMtUG9saWN5JywgJ2dlb2xvY2F0aW9uPSgpLCBtaWNyb3Bob25lPSgpLCBjYW1lcmE9KCknKTtcbiAgICAgICAgcmVzLnNldEhlYWRlcignQ3Jvc3MtT3JpZ2luLVJlc291cmNlLVBvbGljeScsICdzYW1lLW9yaWdpbicpO1xuXG4gICAgICAgIC8vIEluIGRldiBhbGxvdyBodHRwOyBpbiBwcm9kIChiZWhpbmQgcHJveHkpLCByZXF1aXJlIGh0dHBzXG4gICAgICAgIGlmIChwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ3Byb2R1Y3Rpb24nICYmICFpc0h0dHBzKHJlcSkpIHtcbiAgICAgICAgICByZXR1cm4ganNvbihyZXMsIDQwMCwgeyBlcnJvcjogJ0hUVFBTIHJlcXVpcmVkJyB9LCB7ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nOiBTdHJpbmcoY29yc09yaWdpbikgfSk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDT1JTIHByZWZsaWdodFxuICAgICAgICBpZiAocmVxLm1ldGhvZCA9PT0gJ09QVElPTlMnKSB7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJywgU3RyaW5nKGNvcnNPcmlnaW4pKTtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1NZXRob2RzJywgJ1BPU1QsR0VULE9QVElPTlMnKTtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzJywgJ0NvbnRlbnQtVHlwZSwgQXV0aG9yaXphdGlvbicpO1xuICAgICAgICAgIHJlcy5zdGF0dXNDb2RlID0gMjA0O1xuICAgICAgICAgIHJldHVybiByZXMuZW5kKCk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBlbmRKc29uID0gKHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnkpID0+IGpzb24ocmVzLCBzdGF0dXMsIGRhdGEsIHsgJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbic6IFN0cmluZyhjb3JzT3JpZ2luKSB9KTtcblxuICAgICAgICB0cnkge1xuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS90cmFpbicgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBpcCA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtZm9yJ10gYXMgc3RyaW5nKSB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJ2lwJztcbiAgICAgICAgICAgIGlmICghcmF0ZUxpbWl0KCd0cmFpbjonICsgaXAsIDIwLCA2MF8wMDApKSByZXR1cm4gZW5kSnNvbig0MjksIHsgZXJyb3I6ICdUb28gTWFueSBSZXF1ZXN0cycgfSk7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCB1cmwgPSB0eXBlb2YgYm9keT8udXJsID09PSAnc3RyaW5nJyA/IGJvZHkudXJsLnRyaW0oKSA6ICcnO1xuICAgICAgICAgICAgaWYgKCF1cmwgJiYgIUFycmF5LmlzQXJyYXkoYm9keT8uZmlsZXMpKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ1Byb3ZpZGUgdXJsIG9yIGZpbGVzJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICh1cmwpIHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmwpO1xuICAgICAgICAgICAgICAgIGlmICghKHUucHJvdG9jb2wgPT09ICdodHRwOicgfHwgdS5wcm90b2NvbCA9PT0gJ2h0dHBzOicpKSB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQnKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCB1cmwnIH0pO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIExvZyBldmVudFxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnVFJBSU5fUkVRVUVTVCcsIGRldGFpbHM6IHsgaGFzVXJsOiAhIXVybCwgZmlsZUNvdW50OiAoYm9keT8uZmlsZXM/Lmxlbmd0aCkgfHwgMCB9IH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgY29uc3Qgam9iSWQgPSBtYWtlQm90SWQoKHVybCB8fCAnJykgKyBEYXRlLm5vdygpKTtcbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMiwgeyBqb2JJZCwgc3RhdHVzOiAncXVldWVkJyB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY29ubmVjdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSk7XG4gICAgICAgICAgICBpZiAoYm9keT8uY2hhbm5lbCAhPT0gJ3dlYnNpdGUnKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdVbnN1cHBvcnRlZCBjaGFubmVsJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IHJhd1VybCA9IChib2R5Py51cmwgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGNvbnN0IGRvbWFpbiA9ICgoKSA9PiB7XG4gICAgICAgICAgICAgIHRyeSB7IHJldHVybiByYXdVcmwgPyBuZXcgVVJMKHJhd1VybCkuaG9zdCA6ICdsb2NhbCc7IH0gY2F0Y2ggeyByZXR1cm4gJ2xvY2FsJzsgfVxuICAgICAgICAgICAgfSkoKTtcbiAgICAgICAgICAgIGNvbnN0IHNlZWQgPSBkb21haW4gKyAnfCcgKyAocmVxLmhlYWRlcnNbJ2F1dGhvcml6YXRpb24nXSB8fCAnJyk7XG4gICAgICAgICAgICBjb25zdCBib3RJZCA9IG1ha2VCb3RJZChzZWVkKTtcblxuICAgICAgICAgICAgLy8gVXBzZXJ0IGNoYXRib3RfY29uZmlncyAoaWYgUkxTIGFsbG93cyB3aXRoIHVzZXIgdG9rZW4pXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9jaGF0Ym90X2NvbmZpZ3MnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGJvdF9pZDogYm90SWQsIGNoYW5uZWw6ICd3ZWJzaXRlJywgZG9tYWluLCBzZXR0aW5nczoge30gfSksXG4gICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmVzb2x1dGlvbj1tZXJnZS1kdXBsaWNhdGVzJyB9LFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IGJvdElkIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9sYXVuY2gnICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpO1xuICAgICAgICAgICAgY29uc3QgYm90SWQgPSBTdHJpbmcoYm9keT8uYm90SWQgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghYm90SWQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgYm90SWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgY3VzdG9taXphdGlvbiA9IGJvZHk/LmN1c3RvbWl6YXRpb24gfHwge307XG5cbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2NoYXRib3RfY29uZmlncz9ib3RfaWQ9ZXEuJyArIGVuY29kZVVSSUNvbXBvbmVudChib3RJZCksIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUEFUQ0gnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHNldHRpbmdzOiBjdXN0b21pemF0aW9uIH0pLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsIFByZWZlcjogJ3JldHVybj1yZXByZXNlbnRhdGlvbicgfSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBib3RJZCB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY2hhdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBpcCA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtZm9yJ10gYXMgc3RyaW5nKSB8fCByZXEuc29ja2V0LnJlbW90ZUFkZHJlc3MgfHwgJ2lwJztcbiAgICAgICAgICAgIGlmICghcmF0ZUxpbWl0KCdjaGF0OicgKyBpcCwgNjAsIDYwXzAwMCkpIHJldHVybiBlbmRKc29uKDQyOSwgeyBlcnJvcjogJ1RvbyBNYW55IFJlcXVlc3RzJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IG1lc3NhZ2UgPSBTdHJpbmcoYm9keT8ubWVzc2FnZSB8fCAnJykuc2xpY2UoMCwgMjAwMCk7XG4gICAgICAgICAgICBpZiAoIW1lc3NhZ2UpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0VtcHR5IG1lc3NhZ2UnIH0pO1xuXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBhY3Rpb246ICdDSEFUJywgZGV0YWlsczogeyBsZW46IG1lc3NhZ2UubGVuZ3RoIH0gfSksXG4gICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuXG4gICAgICAgICAgICBjb25zdCByZXBseSA9IFwiSSdtIHN0aWxsIGxlYXJuaW5nLCBidXQgb3VyIHRlYW0gd2lsbCBnZXQgYmFjayB0byB5b3Ugc29vbi5cIjtcbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyByZXBseSB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBDdXN0b20gZW1haWwgdmVyaWZpY2F0aW9uOiBzZW5kIGVtYWlsXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL3NlbmQtdmVyaWZ5JyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGlwID0gKHJlcS5oZWFkZXJzWyd4LWZvcndhcmRlZC1mb3InXSBhcyBzdHJpbmcpIHx8IHJlcS5zb2NrZXQucmVtb3RlQWRkcmVzcyB8fCAnaXAnO1xuICAgICAgICAgICAgaWYgKCFyYXRlTGltaXQoJ3ZlcmlmeTonICsgaXAsIDUsIDYwKjYwXzAwMCkpIHJldHVybiBlbmRKc29uKDQyOSwgeyBlcnJvcjogJ1RvbyBNYW55IFJlcXVlc3RzJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IGVtYWlsID0gU3RyaW5nKGJvZHk/LmVtYWlsIHx8ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIGlmICghL15bXlxcc0BdK0BbXlxcc0BdK1xcLlteXFxzQF0rJC8udGVzdChlbWFpbCkpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgZW1haWwnIH0pO1xuXG4gICAgICAgICAgICAvLyBWZXJpZnkgYXV0aGVudGljYXRlZCB1c2VyIG1hdGNoZXMgZW1haWxcbiAgICAgICAgICAgIGNvbnN0IHVyZXMgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvYXV0aC92MS91c2VyJywgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICBpZiAoIXVyZXMgfHwgISh1cmVzIGFzIGFueSkub2spIHJldHVybiBlbmRKc29uKDQwMSwgeyBlcnJvcjogJ1VuYXV0aG9yaXplZCcgfSk7XG4gICAgICAgICAgICBjb25zdCB1c2VyID0gYXdhaXQgKHVyZXMgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgIGlmICghdXNlciB8fCB1c2VyLmVtYWlsPy50b0xvd2VyQ2FzZSgpICE9PSBlbWFpbCkgcmV0dXJuIGVuZEpzb24oNDAzLCB7IGVycm9yOiAnRW1haWwgbWlzbWF0Y2gnIH0pO1xuXG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IGNyeXB0by5yYW5kb21CeXRlcygzMikudG9TdHJpbmcoJ2Jhc2U2NHVybCcpO1xuICAgICAgICAgICAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRU1BSUxfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC1zZWNyZXQnO1xuICAgICAgICAgICAgY29uc3QgdG9rZW5IYXNoID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZSh0b2tlbiArIHNlY3JldCkuZGlnZXN0KCdiYXNlNjQnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXMgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgMTAwMCAqIDYwICogNjAgKiAyNCkudG9JU09TdHJpbmcoKTtcblxuICAgICAgICAgICAgLy8gU3RvcmUgdG9rZW4gaGFzaCAobm90IHJhdyB0b2tlbilcbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2VtYWlsX3ZlcmlmaWNhdGlvbnMnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycgfSxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VyX2lkOiB1c2VyLmlkLCBlbWFpbCwgdG9rZW5faGFzaDogdG9rZW5IYXNoLCBleHBpcmVzX2F0OiBleHBpcmVzLCB1c2VkX2F0OiBudWxsIH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgLy8gU2VuZCBlbWFpbCB2aWEgU01UUFxuICAgICAgICAgICAgY29uc3QgaG9zdCA9IHByb2Nlc3MuZW52LlNNVFBfSE9TVDtcbiAgICAgICAgICAgIGNvbnN0IHBvcnQgPSBOdW1iZXIocHJvY2Vzcy5lbnYuU01UUF9QT1JUIHx8IDU4Nyk7XG4gICAgICAgICAgICBjb25zdCB1c2VyU210cCA9IHByb2Nlc3MuZW52LlNNVFBfVVNFUjtcbiAgICAgICAgICAgIGNvbnN0IHBhc3NTbXRwID0gcHJvY2Vzcy5lbnYuU01UUF9QQVNTO1xuICAgICAgICAgICAgY29uc3QgZnJvbSA9IHByb2Nlc3MuZW52LkVNQUlMX0ZST00gfHwgJ05leGFCb3QgPG5vLXJlcGx5QG5leGFib3QuYWk+JztcbiAgICAgICAgICAgIGNvbnN0IGFwcFVybCA9IHByb2Nlc3MuZW52LkFQUF9VUkwgfHwgJ2h0dHA6Ly9sb2NhbGhvc3Q6MzAwMCc7XG4gICAgICAgICAgICBjb25zdCB2ZXJpZnlVcmwgPSBgJHthcHBVcmx9L2FwaS92ZXJpZnktZW1haWw/dG9rZW49JHt0b2tlbn1gO1xuXG4gICAgICAgICAgICBpZiAoaG9zdCAmJiB1c2VyU210cCAmJiBwYXNzU210cCkge1xuICAgICAgICAgICAgICBjb25zdCB0cmFuc3BvcnRlciA9IG5vZGVtYWlsZXIuY3JlYXRlVHJhbnNwb3J0KHsgaG9zdCwgcG9ydCwgc2VjdXJlOiBwb3J0ID09PSA0NjUsIGF1dGg6IHsgdXNlcjogdXNlclNtdHAsIHBhc3M6IHBhc3NTbXRwIH0gfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGh0bWwgPSBgXG4gICAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPVwid2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiNmNmY4ZmI7cGFkZGluZzoyNHB4O2ZvbnQtZmFtaWx5OkludGVyLFNlZ29lIFVJLEFyaWFsLHNhbnMtc2VyaWY7Y29sb3I6IzBmMTcyYVwiPlxuICAgICAgICAgICAgICAgICAgPHRyPjx0ZCBhbGlnbj1cImNlbnRlclwiPlxuICAgICAgICAgICAgICAgICAgICA8dGFibGUgc3R5bGU9XCJtYXgtd2lkdGg6NTYwcHg7d2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiNmZmZmZmY7Ym9yZGVyOjFweCBzb2xpZCAjZTVlN2ViO2JvcmRlci1yYWRpdXM6MTJweDtvdmVyZmxvdzpoaWRkZW5cIj5cbiAgICAgICAgICAgICAgICAgICAgICA8dHI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9XCJiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZywjNjM2NmYxLCM4YjVjZjYpO3BhZGRpbmc6MjBweDtjb2xvcjojZmZmO2ZvbnQtc2l6ZToxOHB4O2ZvbnQtd2VpZ2h0OjcwMFwiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICBOZXhhQm90XG4gICAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICAgICAgPHRyPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPVwicGFkZGluZzoyNHB4XCI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxoMSBzdHlsZT1cIm1hcmdpbjowIDAgOHB4IDA7Zm9udC1zaXplOjIwcHg7Y29sb3I6IzExMTgyN1wiPkNvbmZpcm0geW91ciBlbWFpbDwvaDE+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjAgMCAxNnB4IDA7Y29sb3I6IzM3NDE1MTtsaW5lLWhlaWdodDoxLjVcIj5IaSwgcGxlYXNlIGNvbmZpcm0geW91ciBlbWFpbCBhZGRyZXNzIHRvIHNlY3VyZSB5b3VyIE5leGFCb3QgYWNjb3VudCBhbmQgY29tcGxldGUgc2V0dXAuPC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8cCBzdHlsZT1cIm1hcmdpbjowIDAgMTZweCAwO2NvbG9yOiMzNzQxNTE7bGluZS1oZWlnaHQ6MS41XCI+VGhpcyBsaW5rIGV4cGlyZXMgaW4gMjQgaG91cnMuPC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8YSBocmVmPVwiJHt2ZXJpZnlVcmx9XCIgc3R5bGU9XCJkaXNwbGF5OmlubGluZS1ibG9jaztiYWNrZ3JvdW5kOiM2MzY2ZjE7Y29sb3I6I2ZmZjt0ZXh0LWRlY29yYXRpb246bm9uZTtwYWRkaW5nOjEwcHggMTZweDtib3JkZXItcmFkaXVzOjhweDtmb250LXdlaWdodDo2MDBcIj5WZXJpZnkgRW1haWw8L2E+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjE2cHggMCAwIDA7Y29sb3I6IzZiNzI4MDtmb250LXNpemU6MTJweFwiPklmIHRoZSBidXR0b24gZG9lc25cdTIwMTl0IHdvcmssIGNvcHkgYW5kIHBhc3RlIHRoaXMgbGluayBpbnRvIHlvdXIgYnJvd3Nlcjo8YnI+JHt2ZXJpZnlVcmx9PC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICAgIDx0cj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT1cInBhZGRpbmc6MTZweCAyNHB4O2NvbG9yOiM2YjcyODA7Zm9udC1zaXplOjEycHg7Ym9yZGVyLXRvcDoxcHggc29saWQgI2U1ZTdlYlwiPlx1MDBBOSAke25ldyBEYXRlKCkuZ2V0RnVsbFllYXIoKX0gTmV4YUJvdC4gQWxsIHJpZ2h0cyByZXNlcnZlZC48L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICAgIDwvdGFibGU+XG4gICAgICAgICAgICAgICAgICA8L3RkPjwvdHI+XG4gICAgICAgICAgICAgICAgPC90YWJsZT5gO1xuICAgICAgICAgICAgICBhd2FpdCB0cmFuc3BvcnRlci5zZW5kTWFpbCh7IHRvOiBlbWFpbCwgZnJvbSwgc3ViamVjdDogJ1ZlcmlmeSB5b3VyIGVtYWlsIGZvciBOZXhhQm90JywgaHRtbCB9KTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIGNvbnNvbGUud2FybignW2VtYWlsXSBTTVRQIG5vdCBjb25maWd1cmVkOyB2ZXJpZmljYXRpb24gVVJMOicsIHZlcmlmeVVybCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogdHJ1ZSB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBWZXJpZnkgbGluayBlbmRwb2ludFxuICAgICAgICAgIGlmIChyZXEudXJsPy5zdGFydHNXaXRoKCcvYXBpL3ZlcmlmeS1lbWFpbCcpICYmIHJlcS5tZXRob2QgPT09ICdHRVQnKSB7XG4gICAgICAgICAgICBjb25zdCB1cmxPYmogPSBuZXcgVVJMKHJlcS51cmwsICdodHRwOi8vbG9jYWwnKTtcbiAgICAgICAgICAgIGNvbnN0IHRva2VuID0gdXJsT2JqLnNlYXJjaFBhcmFtcy5nZXQoJ3Rva2VuJykgfHwgJyc7XG4gICAgICAgICAgICBpZiAoIXRva2VuKSB7XG4gICAgICAgICAgICAgIHJlcy5zdGF0dXNDb2RlID0gNDAwO1xuICAgICAgICAgICAgICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAndGV4dC9odG1sJyk7XG4gICAgICAgICAgICAgIHJldHVybiByZXMuZW5kKCc8cD5JbnZhbGlkIHRva2VuPC9wPicpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRU1BSUxfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC1zZWNyZXQnO1xuICAgICAgICAgICAgY29uc3QgdG9rZW5IYXNoID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZSh0b2tlbiArIHNlY3JldCkuZGlnZXN0KCdiYXNlNjQnKTtcblxuICAgICAgICAgICAgLy8gUHJlZmVyIFJQQyAoc2VjdXJpdHkgZGVmaW5lcikgb24gREI6IHZlcmlmeV9lbWFpbF9oYXNoKHBfaGFzaCB0ZXh0KVxuICAgICAgICAgICAgbGV0IG9rID0gZmFsc2U7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCBycGMgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9ycGMvdmVyaWZ5X2VtYWlsX2hhc2gnLCB7XG4gICAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBwX2hhc2g6IHRva2VuSGFzaCB9KSxcbiAgICAgICAgICAgICAgfSwgcmVxKTtcbiAgICAgICAgICAgICAgaWYgKHJwYyAmJiAocnBjIGFzIGFueSkub2spIG9rID0gdHJ1ZTtcbiAgICAgICAgICAgIH0gY2F0Y2gge31cblxuICAgICAgICAgICAgaWYgKCFvaykge1xuICAgICAgICAgICAgICBjb25zdCBub3dJc28gPSBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCk7XG4gICAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2VtYWlsX3ZlcmlmaWNhdGlvbnM/dG9rZW5faGFzaD1lcS4nICsgZW5jb2RlVVJJQ29tcG9uZW50KHRva2VuSGFzaCkgKyAnJnVzZWRfYXQ9aXMubnVsbCZleHBpcmVzX2F0PWd0LicgKyBlbmNvZGVVUklDb21wb25lbnQobm93SXNvKSwge1xuICAgICAgICAgICAgICAgIG1ldGhvZDogJ1BBVENIJyxcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHVzZWRfYXQ6IG5vd0lzbyB9KSxcbiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3JldHVybj1yZXByZXNlbnRhdGlvbicgfSxcbiAgICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmVzLnN0YXR1c0NvZGUgPSAyMDA7XG4gICAgICAgICAgICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAndGV4dC9odG1sJyk7XG4gICAgICAgICAgICByZXR1cm4gcmVzLmVuZChgPCFkb2N0eXBlIGh0bWw+PG1ldGEgaHR0cC1lcXVpdj1cInJlZnJlc2hcIiBjb250ZW50PVwiMjt1cmw9L1wiPjxzdHlsZT5ib2R5e2ZvbnQtZmFtaWx5OkludGVyLFNlZ29lIFVJLEFyaWFsLHNhbnMtc2VyaWY7YmFja2dyb3VuZDojZjZmOGZiO2NvbG9yOiMxMTE4Mjc7ZGlzcGxheTpncmlkO3BsYWNlLWl0ZW1zOmNlbnRlcjtoZWlnaHQ6MTAwdmh9PC9zdHlsZT48ZGl2PjxoMT5cdTI3MDUgRW1haWwgdmVyaWZpZWQ8L2gxPjxwPllvdSBjYW4gY2xvc2UgdGhpcyB0YWIuPC9wPjwvZGl2PmApO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwNCwgeyBlcnJvcjogJ05vdCBGb3VuZCcgfSk7XG4gICAgICAgIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgICAgICAgIHJldHVybiBlbmRKc29uKDUwMCwgeyBlcnJvcjogJ1NlcnZlciBFcnJvcicgfSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH0sXG4gIH07XG59XG4iXSwKICAibWFwcGluZ3MiOiAiO0FBQTZNLFNBQVMsb0JBQW9CO0FBQzFPLE9BQU8sV0FBVztBQUNsQixPQUFPLFVBQVU7QUFDakIsU0FBUyx1QkFBdUI7OztBQ0ZoQyxPQUFPLFlBQVk7QUFDbkIsT0FBTyxnQkFBZ0I7QUFHdkIsZUFBZSxVQUFVLEtBQVUsUUFBUSxPQUFPLEtBQUs7QUFDckQsU0FBTyxJQUFJLFFBQWEsQ0FBQyxTQUFTLFdBQVc7QUFDM0MsVUFBTSxTQUFtQixDQUFDO0FBQzFCLFFBQUksT0FBTztBQUNYLFFBQUksR0FBRyxR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
