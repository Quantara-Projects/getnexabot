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
            await supabaseFetch("/rest/v1/chatbot_configs", {
              method: "PATCH",
              body: JSON.stringify({ settings: customization }),
              headers: { "Content-Type": "application/json", Prefer: "resolution=merge-duplicates" }
            }, req).catch(() => null);
            return endJson(200, { botId });
          }
          if (req.url === "/api/chat" && req.method === "POST") {
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
            const nowIso = (/* @__PURE__ */ new Date()).toISOString();
            await supabaseFetch("/rest/v1/email_verifications?token_hash=eq." + encodeURIComponent(tokenHash) + "&used_at=is.null&expires_at=gt." + encodeURIComponent(nowIso), {
              method: "PATCH",
              body: JSON.stringify({ used_at: nowIso }),
              headers: { Prefer: "return=representation" }
            }, req).catch(() => null);
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL3NlcnZlci9hcGkudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGVcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9hcHAvY29kZS92aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vYXBwL2NvZGUvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tIFwidml0ZVwiO1xuaW1wb3J0IHJlYWN0IGZyb20gXCJAdml0ZWpzL3BsdWdpbi1yZWFjdC1zd2NcIjtcbmltcG9ydCBwYXRoIGZyb20gXCJwYXRoXCI7XG5pbXBvcnQgeyBjb21wb25lbnRUYWdnZXIgfSBmcm9tIFwibG92YWJsZS10YWdnZXJcIjtcbmltcG9ydCB7IHNlcnZlckFwaVBsdWdpbiB9IGZyb20gXCIuL3NyYy9zZXJ2ZXIvYXBpXCI7XG5cbi8vIGh0dHBzOi8vdml0ZWpzLmRldi9jb25maWcvXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiAoe1xuICBzZXJ2ZXI6IHtcbiAgICBob3N0OiBcIjo6XCIsXG4gICAgcG9ydDogODA4MCxcbiAgfSxcbiAgcGx1Z2luczogW1xuICAgIHJlYWN0KCksXG4gICAgbW9kZSA9PT0gJ2RldmVsb3BtZW50JyAmJlxuICAgIGNvbXBvbmVudFRhZ2dlcigpLFxuICAgIHNlcnZlckFwaVBsdWdpbigpLFxuICBdLmZpbHRlcihCb29sZWFuKSxcbiAgcmVzb2x2ZToge1xuICAgIGFsaWFzOiB7XG4gICAgICBcIkBcIjogcGF0aC5yZXNvbHZlKF9fZGlybmFtZSwgXCIuL3NyY1wiKSxcbiAgICB9LFxuICB9LFxufSkpO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGUvc3JjL3NlcnZlclwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2FwcC9jb2RlL3NyYy9zZXJ2ZXIvYXBpLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9hcHAvY29kZS9zcmMvc2VydmVyL2FwaS50c1wiO2ltcG9ydCB0eXBlIHsgUGx1Z2luIH0gZnJvbSAndml0ZSc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5pbXBvcnQgbm9kZW1haWxlciBmcm9tICdub2RlbWFpbGVyJztcblxuLy8gU21hbGwgSlNPTiBib2R5IHBhcnNlciB3aXRoIHNpemUgbGltaXRcbmFzeW5jIGZ1bmN0aW9uIHBhcnNlSnNvbihyZXE6IGFueSwgbGltaXQgPSAxMDI0ICogMTAwKSB7XG4gIHJldHVybiBuZXcgUHJvbWlzZTxhbnk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICBjb25zdCBjaHVua3M6IEJ1ZmZlcltdID0gW107XG4gICAgbGV0IHNpemUgPSAwO1xuICAgIHJlcS5vbignZGF0YScsIChjOiBCdWZmZXIpID0+IHtcbiAgICAgIHNpemUgKz0gYy5sZW5ndGg7XG4gICAgICBpZiAoc2l6ZSA+IGxpbWl0KSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1BheWxvYWQgdG9vIGxhcmdlJykpO1xuICAgICAgICByZXEuZGVzdHJveSgpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjaHVua3MucHVzaChjKTtcbiAgICB9KTtcbiAgICByZXEub24oJ2VuZCcsICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJhdyA9IEJ1ZmZlci5jb25jYXQoY2h1bmtzKS50b1N0cmluZygndXRmOCcpO1xuICAgICAgICBjb25zdCBqc29uID0gcmF3ID8gSlNPTi5wYXJzZShyYXcpIDoge307XG4gICAgICAgIHJlc29sdmUoanNvbik7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHJlamVjdChlKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICByZXEub24oJ2Vycm9yJywgcmVqZWN0KTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIGpzb24ocmVzOiBhbnksIHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnksIGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7fSkge1xuICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7XG4gIHJlcy5zdGF0dXNDb2RlID0gc3RhdHVzO1xuICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCcpO1xuICByZXMuc2V0SGVhZGVyKCdYLUNvbnRlbnQtVHlwZS1PcHRpb25zJywgJ25vc25pZmYnKTtcbiAgcmVzLnNldEhlYWRlcignUmVmZXJyZXItUG9saWN5JywgJ25vLXJlZmVycmVyJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtRnJhbWUtT3B0aW9ucycsICdERU5ZJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtWFNTLVByb3RlY3Rpb24nLCAnMTsgbW9kZT1ibG9jaycpO1xuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhoZWFkZXJzKSkgcmVzLnNldEhlYWRlcihrLCB2KTtcbiAgcmVzLmVuZChib2R5KTtcbn1cblxuY29uc3QgaXNIdHRwcyA9IChyZXE6IGFueSkgPT4ge1xuICBjb25zdCBwcm90byA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtcHJvdG8nXSBhcyBzdHJpbmcpIHx8ICcnO1xuICByZXR1cm4gcHJvdG8gPT09ICdodHRwcycgfHwgKHJlcS5zb2NrZXQgJiYgKHJlcS5zb2NrZXQgYXMgYW55KS5lbmNyeXB0ZWQpO1xufTtcblxuYXN5bmMgZnVuY3Rpb24gc3VwYWJhc2VGZXRjaChwYXRoOiBzdHJpbmcsIG9wdGlvbnM6IGFueSwgcmVxOiBhbnkpIHtcbiAgY29uc3QgYmFzZSA9IHByb2Nlc3MuZW52LlNVUEFCQVNFX1VSTCB8fCAnaHR0cHM6Ly9menlneHluZXJlaWpqZmJjdndvaC5zdXBhYmFzZS5jbyc7XG4gIGNvbnN0IGFub24gPSBwcm9jZXNzLmVudi5TVVBBQkFTRV9BTk9OX0tFWSB8fCAnZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBjM01pT2lKemRYQmhZbUZ6WlNJc0luSmxaaUk2SW1aNmVXZDRlVzVsY21WcGFtcG1ZbU4yZDI5b0lpd2ljbTlzWlNJNkltRnViMjRpTENKcFlYUWlPakUzTlRZNU5UWXhNek1zSW1WNGNDSTZNakEzTWpVek1qRXpNMzAuLUpuVXdhWGZsY1dtdkw4X2Z1MDh1RXplQm5JaHh2QWtkNl9ocVZlU1lsSSc7XG4gIGNvbnN0IHRva2VuID0gKHJlcS5oZWFkZXJzWydhdXRob3JpemF0aW9uJ10gYXMgc3RyaW5nKSB8fCAnJztcbiAgY29uc3QgaGVhZGVyczogUmVjb3JkPHN0cmluZywgc3RyaW5nPiA9IHtcbiAgICBhcGlrZXk6IGFub24sXG4gICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyxcbiAgfTtcbiAgaWYgKHRva2VuKSBoZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSB0b2tlbjtcbiAgcmV0dXJuIGZldGNoKGAke2Jhc2V9JHtwYXRofWAsIHsgLi4ub3B0aW9ucywgaGVhZGVyczogeyAuLi5oZWFkZXJzLCAuLi4ob3B0aW9ucz8uaGVhZGVycyB8fCB7fSkgfSB9KTtcbn1cblxuZnVuY3Rpb24gbWFrZUJvdElkKHNlZWQ6IHN0cmluZykge1xuICByZXR1cm4gJ2JvdF8nICsgY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZShzZWVkKS5kaWdlc3QoJ2Jhc2U2NHVybCcpLnNsaWNlKDAsIDIyKTtcbn1cblxuLy8gU2ltcGxlIGluLW1lbW9yeSByYXRlIGxpbWl0ZXJcbmNvbnN0IHJhdGVNYXAgPSBuZXcgTWFwPHN0cmluZywgeyBjb3VudDogbnVtYmVyOyB0czogbnVtYmVyIH0+KCk7XG5mdW5jdGlvbiByYXRlTGltaXQoa2V5OiBzdHJpbmcsIGxpbWl0OiBudW1iZXIsIHdpbmRvd01zOiBudW1iZXIpIHtcbiAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgY29uc3QgcmVjID0gcmF0ZU1hcC5nZXQoa2V5KTtcbiAgaWYgKCFyZWMgfHwgbm93IC0gcmVjLnRzID4gd2luZG93TXMpIHtcbiAgICByYXRlTWFwLnNldChrZXksIHsgY291bnQ6IDEsIHRzOiBub3cgfSk7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cbiAgaWYgKHJlYy5jb3VudCA8IGxpbWl0KSB7XG4gICAgcmVjLmNvdW50ICs9IDE7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cbiAgcmV0dXJuIGZhbHNlO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gc2VydmVyQXBpUGx1Z2luKCk6IFBsdWdpbiB7XG4gIHJldHVybiB7XG4gICAgbmFtZTogJ3NlcnZlci1hcGktcGx1Z2luJyxcbiAgICBjb25maWd1cmVTZXJ2ZXIoc2VydmVyKSB7XG4gICAgICBzZXJ2ZXIubWlkZGxld2FyZXMudXNlKGFzeW5jIChyZXEsIHJlcywgbmV4dCkgPT4ge1xuICAgICAgICBpZiAoIXJlcS51cmwgfHwgIXJlcS51cmwuc3RhcnRzV2l0aCgnL2FwaS8nKSkgcmV0dXJuIG5leHQoKTtcblxuICAgICAgICAvLyBCYXNpYyBzZWN1cml0eSBoZWFkZXJzIGZvciBhbGwgQVBJIHJlc3BvbnNlc1xuICAgICAgICBjb25zdCBjb3JzT3JpZ2luID0gcmVxLmhlYWRlcnMub3JpZ2luIHx8ICcqJztcbiAgICAgICAgcmVzLnNldEhlYWRlcignUGVybWlzc2lvbnMtUG9saWN5JywgJ2dlb2xvY2F0aW9uPSgpLCBtaWNyb3Bob25lPSgpLCBjYW1lcmE9KCknKTtcbiAgICAgICAgcmVzLnNldEhlYWRlcignQ3Jvc3MtT3JpZ2luLVJlc291cmNlLVBvbGljeScsICdzYW1lLW9yaWdpbicpO1xuXG4gICAgICAgIC8vIEluIGRldiBhbGxvdyBodHRwOyBpbiBwcm9kIChiZWhpbmQgcHJveHkpLCByZXF1aXJlIGh0dHBzXG4gICAgICAgIGlmIChwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ3Byb2R1Y3Rpb24nICYmICFpc0h0dHBzKHJlcSkpIHtcbiAgICAgICAgICByZXR1cm4ganNvbihyZXMsIDQwMCwgeyBlcnJvcjogJ0hUVFBTIHJlcXVpcmVkJyB9LCB7ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nOiBTdHJpbmcoY29yc09yaWdpbikgfSk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDT1JTIHByZWZsaWdodFxuICAgICAgICBpZiAocmVxLm1ldGhvZCA9PT0gJ09QVElPTlMnKSB7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJywgU3RyaW5nKGNvcnNPcmlnaW4pKTtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1NZXRob2RzJywgJ1BPU1QsR0VULE9QVElPTlMnKTtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzJywgJ0NvbnRlbnQtVHlwZSwgQXV0aG9yaXphdGlvbicpO1xuICAgICAgICAgIHJlcy5zdGF0dXNDb2RlID0gMjA0O1xuICAgICAgICAgIHJldHVybiByZXMuZW5kKCk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBlbmRKc29uID0gKHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnkpID0+IGpzb24ocmVzLCBzdGF0dXMsIGRhdGEsIHsgJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbic6IFN0cmluZyhjb3JzT3JpZ2luKSB9KTtcblxuICAgICAgICB0cnkge1xuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS90cmFpbicgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCB1cmwgPSB0eXBlb2YgYm9keT8udXJsID09PSAnc3RyaW5nJyA/IGJvZHkudXJsLnRyaW0oKSA6ICcnO1xuICAgICAgICAgICAgaWYgKCF1cmwgJiYgIUFycmF5LmlzQXJyYXkoYm9keT8uZmlsZXMpKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ1Byb3ZpZGUgdXJsIG9yIGZpbGVzJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICh1cmwpIHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmwpO1xuICAgICAgICAgICAgICAgIGlmICghKHUucHJvdG9jb2wgPT09ICdodHRwOicgfHwgdS5wcm90b2NvbCA9PT0gJ2h0dHBzOicpKSB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQnKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCB1cmwnIH0pO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIExvZyBldmVudFxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnVFJBSU5fUkVRVUVTVCcsIGRldGFpbHM6IHsgaGFzVXJsOiAhIXVybCwgZmlsZUNvdW50OiAoYm9keT8uZmlsZXM/Lmxlbmd0aCkgfHwgMCB9IH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgY29uc3Qgam9iSWQgPSBtYWtlQm90SWQoKHVybCB8fCAnJykgKyBEYXRlLm5vdygpKTtcbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMiwgeyBqb2JJZCwgc3RhdHVzOiAncXVldWVkJyB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY29ubmVjdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSk7XG4gICAgICAgICAgICBpZiAoYm9keT8uY2hhbm5lbCAhPT0gJ3dlYnNpdGUnKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdVbnN1cHBvcnRlZCBjaGFubmVsJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IHJhd1VybCA9IChib2R5Py51cmwgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGNvbnN0IGRvbWFpbiA9ICgoKSA9PiB7XG4gICAgICAgICAgICAgIHRyeSB7IHJldHVybiByYXdVcmwgPyBuZXcgVVJMKHJhd1VybCkuaG9zdCA6ICdsb2NhbCc7IH0gY2F0Y2ggeyByZXR1cm4gJ2xvY2FsJzsgfVxuICAgICAgICAgICAgfSkoKTtcbiAgICAgICAgICAgIGNvbnN0IHNlZWQgPSBkb21haW4gKyAnfCcgKyAocmVxLmhlYWRlcnNbJ2F1dGhvcml6YXRpb24nXSB8fCAnJyk7XG4gICAgICAgICAgICBjb25zdCBib3RJZCA9IG1ha2VCb3RJZChzZWVkKTtcblxuICAgICAgICAgICAgLy8gVXBzZXJ0IGNoYXRib3RfY29uZmlncyAoaWYgUkxTIGFsbG93cyB3aXRoIHVzZXIgdG9rZW4pXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9jaGF0Ym90X2NvbmZpZ3MnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGJvdF9pZDogYm90SWQsIGNoYW5uZWw6ICd3ZWJzaXRlJywgZG9tYWluLCBzZXR0aW5nczoge30gfSksXG4gICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmVzb2x1dGlvbj1tZXJnZS1kdXBsaWNhdGVzJyB9LFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IGJvdElkIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9sYXVuY2gnICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpO1xuICAgICAgICAgICAgY29uc3QgYm90SWQgPSBTdHJpbmcoYm9keT8uYm90SWQgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghYm90SWQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgYm90SWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgY3VzdG9taXphdGlvbiA9IGJvZHk/LmN1c3RvbWl6YXRpb24gfHwge307XG5cbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2NoYXRib3RfY29uZmlncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUEFUQ0gnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHNldHRpbmdzOiBjdXN0b21pemF0aW9uIH0pLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsIFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycgfSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBib3RJZCB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY2hhdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCBtZXNzYWdlID0gU3RyaW5nKGJvZHk/Lm1lc3NhZ2UgfHwgJycpLnNsaWNlKDAsIDIwMDApO1xuICAgICAgICAgICAgaWYgKCFtZXNzYWdlKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdFbXB0eSBtZXNzYWdlJyB9KTtcblxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnQ0hBVCcsIGRldGFpbHM6IHsgbGVuOiBtZXNzYWdlLmxlbmd0aCB9IH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgY29uc3QgcmVwbHkgPSBcIkknbSBzdGlsbCBsZWFybmluZywgYnV0IG91ciB0ZWFtIHdpbGwgZ2V0IGJhY2sgdG8geW91IHNvb24uXCI7XG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgcmVwbHkgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gQ3VzdG9tIGVtYWlsIHZlcmlmaWNhdGlvbjogc2VuZCBlbWFpbFxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9zZW5kLXZlcmlmeScgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCBlbWFpbCA9IFN0cmluZyhib2R5Py5lbWFpbCB8fCAnJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgICBpZiAoIS9eW15cXHNAXStAW15cXHNAXStcXC5bXlxcc0BdKyQvLnRlc3QoZW1haWwpKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdJbnZhbGlkIGVtYWlsJyB9KTtcblxuICAgICAgICAgICAgLy8gVmVyaWZ5IGF1dGhlbnRpY2F0ZWQgdXNlciBtYXRjaGVzIGVtYWlsXG4gICAgICAgICAgICBjb25zdCB1cmVzID0gYXdhaXQgc3VwYWJhc2VGZXRjaCgnL2F1dGgvdjEvdXNlcicsIHsgbWV0aG9kOiAnR0VUJyB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgaWYgKCF1cmVzIHx8ICEodXJlcyBhcyBhbnkpLm9rKSByZXR1cm4gZW5kSnNvbig0MDEsIHsgZXJyb3I6ICdVbmF1dGhvcml6ZWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgdXNlciA9IGF3YWl0ICh1cmVzIGFzIFJlc3BvbnNlKS5qc29uKCkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICBpZiAoIXVzZXIgfHwgdXNlci5lbWFpbD8udG9Mb3dlckNhc2UoKSAhPT0gZW1haWwpIHJldHVybiBlbmRKc29uKDQwMywgeyBlcnJvcjogJ0VtYWlsIG1pc21hdGNoJyB9KTtcblxuICAgICAgICAgICAgY29uc3QgdG9rZW4gPSBjcnlwdG8ucmFuZG9tQnl0ZXMoMzIpLnRvU3RyaW5nKCdiYXNlNjR1cmwnKTtcbiAgICAgICAgICAgIGNvbnN0IHNlY3JldCA9IHByb2Nlc3MuZW52LkVNQUlMX1RPS0VOX1NFQ1JFVCB8fCAnbG9jYWwtc2VjcmV0JztcbiAgICAgICAgICAgIGNvbnN0IHRva2VuSGFzaCA9IGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUodG9rZW4gKyBzZWNyZXQpLmRpZ2VzdCgnYmFzZTY0Jyk7XG4gICAgICAgICAgICBjb25zdCBleHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIDEwMDAgKiA2MCAqIDYwICogMjQpLnRvSVNPU3RyaW5nKCk7XG5cbiAgICAgICAgICAgIC8vIFN0b3JlIHRva2VuIGhhc2ggKG5vdCByYXcgdG9rZW4pXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9lbWFpbF92ZXJpZmljYXRpb25zJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXNvbHV0aW9uPW1lcmdlLWR1cGxpY2F0ZXMnIH0sXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdXNlcl9pZDogdXNlci5pZCwgZW1haWwsIHRva2VuX2hhc2g6IHRva2VuSGFzaCwgZXhwaXJlc19hdDogZXhwaXJlcywgdXNlZF9hdDogbnVsbCB9KSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIC8vIFNlbmQgZW1haWwgdmlhIFNNVFBcbiAgICAgICAgICAgIGNvbnN0IGhvc3QgPSBwcm9jZXNzLmVudi5TTVRQX0hPU1Q7XG4gICAgICAgICAgICBjb25zdCBwb3J0ID0gTnVtYmVyKHByb2Nlc3MuZW52LlNNVFBfUE9SVCB8fCA1ODcpO1xuICAgICAgICAgICAgY29uc3QgdXNlclNtdHAgPSBwcm9jZXNzLmVudi5TTVRQX1VTRVI7XG4gICAgICAgICAgICBjb25zdCBwYXNzU210cCA9IHByb2Nlc3MuZW52LlNNVFBfUEFTUztcbiAgICAgICAgICAgIGNvbnN0IGZyb20gPSBwcm9jZXNzLmVudi5FTUFJTF9GUk9NIHx8ICdOZXhhQm90IDxuby1yZXBseUBuZXhhYm90LmFpPic7XG4gICAgICAgICAgICBjb25zdCBhcHBVcmwgPSBwcm9jZXNzLmVudi5BUFBfVVJMIHx8ICdodHRwOi8vbG9jYWxob3N0OjMwMDAnO1xuICAgICAgICAgICAgY29uc3QgdmVyaWZ5VXJsID0gYCR7YXBwVXJsfS9hcGkvdmVyaWZ5LWVtYWlsP3Rva2VuPSR7dG9rZW59YDtcblxuICAgICAgICAgICAgaWYgKGhvc3QgJiYgdXNlclNtdHAgJiYgcGFzc1NtdHApIHtcbiAgICAgICAgICAgICAgY29uc3QgdHJhbnNwb3J0ZXIgPSBub2RlbWFpbGVyLmNyZWF0ZVRyYW5zcG9ydCh7IGhvc3QsIHBvcnQsIHNlY3VyZTogcG9ydCA9PT0gNDY1LCBhdXRoOiB7IHVzZXI6IHVzZXJTbXRwLCBwYXNzOiBwYXNzU210cCB9IH0pO1xuICAgICAgICAgICAgICBjb25zdCBodG1sID0gYFxuICAgICAgICAgICAgICAgIDx0YWJsZSBzdHlsZT1cIndpZHRoOjEwMCU7YmFja2dyb3VuZDojZjZmOGZiO3BhZGRpbmc6MjRweDtmb250LWZhbWlseTpJbnRlcixTZWdvZSBVSSxBcmlhbCxzYW5zLXNlcmlmO2NvbG9yOiMwZjE3MmFcIj5cbiAgICAgICAgICAgICAgICAgIDx0cj48dGQgYWxpZ249XCJjZW50ZXJcIj5cbiAgICAgICAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPVwibWF4LXdpZHRoOjU2MHB4O3dpZHRoOjEwMCU7YmFja2dyb3VuZDojZmZmZmZmO2JvcmRlcjoxcHggc29saWQgI2U1ZTdlYjtib3JkZXItcmFkaXVzOjEycHg7b3ZlcmZsb3c6aGlkZGVuXCI+XG4gICAgICAgICAgICAgICAgICAgICAgPHRyPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPVwiYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsIzYzNjZmMSwjOGI1Y2Y2KTtwYWRkaW5nOjIwcHg7Y29sb3I6I2ZmZjtmb250LXNpemU6MThweDtmb250LXdlaWdodDo3MDBcIj5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgTmV4YUJvdFxuICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICAgIDx0cj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT1cInBhZGRpbmc6MjRweFwiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8aDEgc3R5bGU9XCJtYXJnaW46MCAwIDhweCAwO2ZvbnQtc2l6ZToyMHB4O2NvbG9yOiMxMTE4MjdcIj5Db25maXJtIHlvdXIgZW1haWw8L2gxPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8cCBzdHlsZT1cIm1hcmdpbjowIDAgMTZweCAwO2NvbG9yOiMzNzQxNTE7bGluZS1oZWlnaHQ6MS41XCI+SGksIHBsZWFzZSBjb25maXJtIHlvdXIgZW1haWwgYWRkcmVzcyB0byBzZWN1cmUgeW91ciBOZXhhQm90IGFjY291bnQgYW5kIGNvbXBsZXRlIHNldHVwLjwvcD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgPHAgc3R5bGU9XCJtYXJnaW46MCAwIDE2cHggMDtjb2xvcjojMzc0MTUxO2xpbmUtaGVpZ2h0OjEuNVwiPlRoaXMgbGluayBleHBpcmVzIGluIDI0IGhvdXJzLjwvcD5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgPGEgaHJlZj1cIiR7dmVyaWZ5VXJsfVwiIHN0eWxlPVwiZGlzcGxheTppbmxpbmUtYmxvY2s7YmFja2dyb3VuZDojNjM2NmYxO2NvbG9yOiNmZmY7dGV4dC1kZWNvcmF0aW9uOm5vbmU7cGFkZGluZzoxMHB4IDE2cHg7Ym9yZGVyLXJhZGl1czo4cHg7Zm9udC13ZWlnaHQ6NjAwXCI+VmVyaWZ5IEVtYWlsPC9hPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8cCBzdHlsZT1cIm1hcmdpbjoxNnB4IDAgMCAwO2NvbG9yOiM2YjcyODA7Zm9udC1zaXplOjEycHhcIj5JZiB0aGUgYnV0dG9uIGRvZXNuXHUyMDE5dCB3b3JrLCBjb3B5IGFuZCBwYXN0ZSB0aGlzIGxpbmsgaW50byB5b3VyIGJyb3dzZXI6PGJyPiR7dmVyaWZ5VXJsfTwvcD5cbiAgICAgICAgICAgICAgICAgICAgICAgIDwvdGQ+XG4gICAgICAgICAgICAgICAgICAgICAgPC90cj5cbiAgICAgICAgICAgICAgICAgICAgICA8dHI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9XCJwYWRkaW5nOjE2cHggMjRweDtjb2xvcjojNmI3MjgwO2ZvbnQtc2l6ZToxMnB4O2JvcmRlci10b3A6MXB4IHNvbGlkICNlNWU3ZWJcIj5cdTAwQTkgJHtuZXcgRGF0ZSgpLmdldEZ1bGxZZWFyKCl9IE5leGFCb3QuIEFsbCByaWdodHMgcmVzZXJ2ZWQuPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICA8L3RhYmxlPlxuICAgICAgICAgICAgICAgICAgPC90ZD48L3RyPlxuICAgICAgICAgICAgICAgIDwvdGFibGU+YDtcbiAgICAgICAgICAgICAgYXdhaXQgdHJhbnNwb3J0ZXIuc2VuZE1haWwoeyB0bzogZW1haWwsIGZyb20sIHN1YmplY3Q6ICdWZXJpZnkgeW91ciBlbWFpbCBmb3IgTmV4YUJvdCcsIGh0bWwgfSk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBjb25zb2xlLndhcm4oJ1tlbWFpbF0gU01UUCBub3QgY29uZmlndXJlZDsgdmVyaWZpY2F0aW9uIFVSTDonLCB2ZXJpZnlVcmwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgb2s6IHRydWUgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gVmVyaWZ5IGxpbmsgZW5kcG9pbnRcbiAgICAgICAgICBpZiAocmVxLnVybD8uc3RhcnRzV2l0aCgnL2FwaS92ZXJpZnktZW1haWwnKSAmJiByZXEubWV0aG9kID09PSAnR0VUJykge1xuICAgICAgICAgICAgY29uc3QgdXJsT2JqID0gbmV3IFVSTChyZXEudXJsLCAnaHR0cDovL2xvY2FsJyk7XG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IHVybE9iai5zZWFyY2hQYXJhbXMuZ2V0KCd0b2tlbicpIHx8ICcnO1xuICAgICAgICAgICAgaWYgKCF0b2tlbikge1xuICAgICAgICAgICAgICByZXMuc3RhdHVzQ29kZSA9IDQwMDtcbiAgICAgICAgICAgICAgcmVzLnNldEhlYWRlcignQ29udGVudC1UeXBlJywgJ3RleHQvaHRtbCcpO1xuICAgICAgICAgICAgICByZXR1cm4gcmVzLmVuZCgnPHA+SW52YWxpZCB0b2tlbjwvcD4nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHNlY3JldCA9IHByb2Nlc3MuZW52LkVNQUlMX1RPS0VOX1NFQ1JFVCB8fCAnbG9jYWwtc2VjcmV0JztcbiAgICAgICAgICAgIGNvbnN0IHRva2VuSGFzaCA9IGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUodG9rZW4gKyBzZWNyZXQpLmRpZ2VzdCgnYmFzZTY0Jyk7XG5cbiAgICAgICAgICAgIC8vIE1hcmsgYXMgdXNlZCBpZiB2YWxpZCBhbmQgbm90IGV4cGlyZWRcbiAgICAgICAgICAgIGNvbnN0IG5vd0lzbyA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2VtYWlsX3ZlcmlmaWNhdGlvbnM/dG9rZW5faGFzaD1lcS4nICsgZW5jb2RlVVJJQ29tcG9uZW50KHRva2VuSGFzaCkgKyAnJnVzZWRfYXQ9aXMubnVsbCZleHBpcmVzX2F0PWd0LicgKyBlbmNvZGVVUklDb21wb25lbnQobm93SXNvKSwge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQQVRDSCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdXNlZF9hdDogbm93SXNvIH0pLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3JldHVybj1yZXByZXNlbnRhdGlvbicgfSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIHJlcy5zdGF0dXNDb2RlID0gMjAwO1xuICAgICAgICAgICAgcmVzLnNldEhlYWRlcignQ29udGVudC1UeXBlJywgJ3RleHQvaHRtbCcpO1xuICAgICAgICAgICAgcmV0dXJuIHJlcy5lbmQoYDwhZG9jdHlwZSBodG1sPjxtZXRhIGh0dHAtZXF1aXY9XCJyZWZyZXNoXCIgY29udGVudD1cIjI7dXJsPS9cIj48c3R5bGU+Ym9keXtmb250LWZhbWlseTpJbnRlcixTZWdvZSBVSSxBcmlhbCxzYW5zLXNlcmlmO2JhY2tncm91bmQ6I2Y2ZjhmYjtjb2xvcjojMTExODI3O2Rpc3BsYXk6Z3JpZDtwbGFjZS1pdGVtczpjZW50ZXI7aGVpZ2h0OjEwMHZofTwvc3R5bGU+PGRpdj48aDE+XHUyNzA1IEVtYWlsIHZlcmlmaWVkPC9oMT48cD5Zb3UgY2FuIGNsb3NlIHRoaXMgdGFiLjwvcD48L2Rpdj5gKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gZW5kSnNvbig0MDQsIHsgZXJyb3I6ICdOb3QgRm91bmQnIH0pO1xuICAgICAgICB9IGNhdGNoIChlOiBhbnkpIHtcbiAgICAgICAgICByZXR1cm4gZW5kSnNvbig1MDAsIHsgZXJyb3I6ICdTZXJ2ZXIgRXJyb3InIH0pO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9LFxuICB9O1xufVxuIl0sCiAgIm1hcHBpbmdzIjogIjtBQUE2TSxTQUFTLG9CQUFvQjtBQUMxTyxPQUFPLFdBQVc7QUFDbEIsT0FBTyxVQUFVO0FBQ2pCLFNBQVMsdUJBQXVCOzs7QUNGaEMsT0FBTyxZQUFZO0FBQ25CLE9BQU8sZ0JBQWdCO0FBR3ZCLGVBQWUsVUFBVSxLQUFVLFFBQVEsT0FBTyxLQUFLO0FBQ3JELFNBQU8sSUFBSSxRQUFhLENBQUMsU0FBUyxXQUFXO0FBQzNDLFVBQU0sU0FBbUIsQ0FBQztBQUMxQixRQUFJLE9BQU87QUFDWCxRQUFJLEdBQUcsUUFBUSxDQUFDLE1BQWM7QUFDNUIsY0FBUSxFQUFFO0FBQ1YsVUFBSSxPQUFPLE9BQU87QUFDaEIsZUFBTyxJQUFJLE1BQU0sbUJBQW1CLENBQUM7QUFDckMsWUFBSSxRQUFRO0FBQ1o7QUFBQSxNQUNGO0FBQ0EsYUFBTyxLQUFLLENBQUM7QUFBQSxJQUNmLENBQUM7QUFDRCxRQUFJLEdBQUcsT0FBTyxNQUFNO0FBQ2xCLFVBQUk7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
