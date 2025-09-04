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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL3NlcnZlci9hcGkudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGVcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9hcHAvY29kZS92aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vYXBwL2NvZGUvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tIFwidml0ZVwiO1xuaW1wb3J0IHJlYWN0IGZyb20gXCJAdml0ZWpzL3BsdWdpbi1yZWFjdC1zd2NcIjtcbmltcG9ydCBwYXRoIGZyb20gXCJwYXRoXCI7XG5pbXBvcnQgeyBjb21wb25lbnRUYWdnZXIgfSBmcm9tIFwibG92YWJsZS10YWdnZXJcIjtcbmltcG9ydCB7IHNlcnZlckFwaVBsdWdpbiB9IGZyb20gXCIuL3NyYy9zZXJ2ZXIvYXBpXCI7XG5cbi8vIGh0dHBzOi8vdml0ZWpzLmRldi9jb25maWcvXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiAoe1xuICBzZXJ2ZXI6IHtcbiAgICBob3N0OiBcIjo6XCIsXG4gICAgcG9ydDogODA4MCxcbiAgfSxcbiAgcGx1Z2luczogW1xuICAgIHJlYWN0KCksXG4gICAgbW9kZSA9PT0gJ2RldmVsb3BtZW50JyAmJlxuICAgIGNvbXBvbmVudFRhZ2dlcigpLFxuICAgIHNlcnZlckFwaVBsdWdpbigpLFxuICBdLmZpbHRlcihCb29sZWFuKSxcbiAgcmVzb2x2ZToge1xuICAgIGFsaWFzOiB7XG4gICAgICBcIkBcIjogcGF0aC5yZXNvbHZlKF9fZGlybmFtZSwgXCIuL3NyY1wiKSxcbiAgICB9LFxuICB9LFxufSkpO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGUvc3JjL3NlcnZlclwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2FwcC9jb2RlL3NyYy9zZXJ2ZXIvYXBpLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9hcHAvY29kZS9zcmMvc2VydmVyL2FwaS50c1wiO2ltcG9ydCB0eXBlIHsgUGx1Z2luIH0gZnJvbSAndml0ZSc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5pbXBvcnQgbm9kZW1haWxlciBmcm9tICdub2RlbWFpbGVyJztcblxuLy8gU21hbGwgSlNPTiBib2R5IHBhcnNlciB3aXRoIHNpemUgbGltaXRcbmFzeW5jIGZ1bmN0aW9uIHBhcnNlSnNvbihyZXE6IGFueSwgbGltaXQgPSAxMDI0ICogMTAwKSB7XG4gIHJldHVybiBuZXcgUHJvbWlzZTxhbnk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICBjb25zdCBjaHVua3M6IEJ1ZmZlcltdID0gW107XG4gICAgbGV0IHNpemUgPSAwO1xuICAgIHJlcS5vbignZGF0YScsIChjOiBCdWZmZXIpID0+IHtcbiAgICAgIHNpemUgKz0gYy5sZW5ndGg7XG4gICAgICBpZiAoc2l6ZSA+IGxpbWl0KSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1BheWxvYWQgdG9vIGxhcmdlJykpO1xuICAgICAgICByZXEuZGVzdHJveSgpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjaHVua3MucHVzaChjKTtcbiAgICB9KTtcbiAgICByZXEub24oJ2VuZCcsICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJhdyA9IEJ1ZmZlci5jb25jYXQoY2h1bmtzKS50b1N0cmluZygndXRmOCcpO1xuICAgICAgICBjb25zdCBqc29uID0gcmF3ID8gSlNPTi5wYXJzZShyYXcpIDoge307XG4gICAgICAgIHJlc29sdmUoanNvbik7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHJlamVjdChlKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICByZXEub24oJ2Vycm9yJywgcmVqZWN0KTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIGpzb24ocmVzOiBhbnksIHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnksIGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7fSkge1xuICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7XG4gIHJlcy5zdGF0dXNDb2RlID0gc3RhdHVzO1xuICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCcpO1xuICByZXMuc2V0SGVhZGVyKCdYLUNvbnRlbnQtVHlwZS1PcHRpb25zJywgJ25vc25pZmYnKTtcbiAgcmVzLnNldEhlYWRlcignUmVmZXJyZXItUG9saWN5JywgJ25vLXJlZmVycmVyJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtRnJhbWUtT3B0aW9ucycsICdERU5ZJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1gtWFNTLVByb3RlY3Rpb24nLCAnMTsgbW9kZT1ibG9jaycpO1xuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhoZWFkZXJzKSkgcmVzLnNldEhlYWRlcihrLCB2KTtcbiAgcmVzLmVuZChib2R5KTtcbn1cblxuY29uc3QgaXNIdHRwcyA9IChyZXE6IGFueSkgPT4ge1xuICBjb25zdCBwcm90byA9IChyZXEuaGVhZGVyc1sneC1mb3J3YXJkZWQtcHJvdG8nXSBhcyBzdHJpbmcpIHx8ICcnO1xuICByZXR1cm4gcHJvdG8gPT09ICdodHRwcycgfHwgKHJlcS5zb2NrZXQgJiYgKHJlcS5zb2NrZXQgYXMgYW55KS5lbmNyeXB0ZWQpO1xufTtcblxuYXN5bmMgZnVuY3Rpb24gc3VwYWJhc2VGZXRjaChwYXRoOiBzdHJpbmcsIG9wdGlvbnM6IGFueSwgcmVxOiBhbnkpIHtcbiAgY29uc3QgYmFzZSA9IHByb2Nlc3MuZW52LlNVUEFCQVNFX1VSTCB8fCAnaHR0cHM6Ly9menlneHluZXJlaWpqZmJjdndvaC5zdXBhYmFzZS5jbyc7XG4gIGNvbnN0IGFub24gPSBwcm9jZXNzLmVudi5TVVBBQkFTRV9BTk9OX0tFWSB8fCAnZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBjM01pT2lKemRYQmhZbUZ6WlNJc0luSmxaaUk2SW1aNmVXZDRlVzVsY21WcGFtcG1ZbU4yZDI5b0lpd2ljbTlzWlNJNkltRnViMjRpTENKcFlYUWlPakUzTlRZNU5UWXhNek1zSW1WNGNDSTZNakEzTWpVek1qRXpNMzAuLUpuVXdhWGZsY1dtdkw4X2Z1MDh1RXplQm5JaHh2QWtkNl9ocVZlU1lsSSc7XG4gIGNvbnN0IHRva2VuID0gKHJlcS5oZWFkZXJzWydhdXRob3JpemF0aW9uJ10gYXMgc3RyaW5nKSB8fCAnJztcbiAgY29uc3QgaGVhZGVyczogUmVjb3JkPHN0cmluZywgc3RyaW5nPiA9IHtcbiAgICBhcGlrZXk6IGFub24sXG4gICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyxcbiAgfTtcbiAgaWYgKHRva2VuKSBoZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSB0b2tlbjtcbiAgcmV0dXJuIGZldGNoKGAke2Jhc2V9JHtwYXRofWAsIHsgLi4ub3B0aW9ucywgaGVhZGVyczogeyAuLi5oZWFkZXJzLCAuLi4ob3B0aW9ucz8uaGVhZGVycyB8fCB7fSkgfSB9KTtcbn1cblxuZnVuY3Rpb24gbWFrZUJvdElkKHNlZWQ6IHN0cmluZykge1xuICByZXR1cm4gJ2JvdF8nICsgY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZShzZWVkKS5kaWdlc3QoJ2Jhc2U2NHVybCcpLnNsaWNlKDAsIDIyKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHNlcnZlckFwaVBsdWdpbigpOiBQbHVnaW4ge1xuICByZXR1cm4ge1xuICAgIG5hbWU6ICdzZXJ2ZXItYXBpLXBsdWdpbicsXG4gICAgY29uZmlndXJlU2VydmVyKHNlcnZlcikge1xuICAgICAgc2VydmVyLm1pZGRsZXdhcmVzLnVzZShhc3luYyAocmVxLCByZXMsIG5leHQpID0+IHtcbiAgICAgICAgaWYgKCFyZXEudXJsIHx8ICFyZXEudXJsLnN0YXJ0c1dpdGgoJy9hcGkvJykpIHJldHVybiBuZXh0KCk7XG5cbiAgICAgICAgLy8gQmFzaWMgc2VjdXJpdHkgaGVhZGVycyBmb3IgYWxsIEFQSSByZXNwb25zZXNcbiAgICAgICAgY29uc3QgY29yc09yaWdpbiA9IHJlcS5oZWFkZXJzLm9yaWdpbiB8fCAnKic7XG5cbiAgICAgICAgLy8gSW4gZGV2IGFsbG93IGh0dHA7IGluIHByb2QgKGJlaGluZCBwcm94eSksIHJlcXVpcmUgaHR0cHNcbiAgICAgICAgaWYgKHByb2Nlc3MuZW52Lk5PREVfRU5WID09PSAncHJvZHVjdGlvbicgJiYgIWlzSHR0cHMocmVxKSkge1xuICAgICAgICAgIHJldHVybiBqc29uKHJlcywgNDAwLCB7IGVycm9yOiAnSFRUUFMgcmVxdWlyZWQnIH0sIHsgJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbic6IFN0cmluZyhjb3JzT3JpZ2luKSB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIENPUlMgcHJlZmxpZ2h0XG4gICAgICAgIGlmIChyZXEubWV0aG9kID09PSAnT1BUSU9OUycpIHtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nLCBTdHJpbmcoY29yc09yaWdpbikpO1xuICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0FjY2Vzcy1Db250cm9sLUFsbG93LU1ldGhvZHMnLCAnUE9TVCxHRVQsT1BUSU9OUycpO1xuICAgICAgICAgIHJlcy5zZXRIZWFkZXIoJ0FjY2Vzcy1Db250cm9sLUFsbG93LUhlYWRlcnMnLCAnQ29udGVudC1UeXBlLCBBdXRob3JpemF0aW9uJyk7XG4gICAgICAgICAgcmVzLnN0YXR1c0NvZGUgPSAyMDQ7XG4gICAgICAgICAgcmV0dXJuIHJlcy5lbmQoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGVuZEpzb24gPSAoc3RhdHVzOiBudW1iZXIsIGRhdGE6IGFueSkgPT4ganNvbihyZXMsIHN0YXR1cywgZGF0YSwgeyAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJzogU3RyaW5nKGNvcnNPcmlnaW4pIH0pO1xuXG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL3RyYWluJyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IHVybCA9IHR5cGVvZiBib2R5Py51cmwgPT09ICdzdHJpbmcnID8gYm9keS51cmwudHJpbSgpIDogJyc7XG4gICAgICAgICAgICBpZiAoIXVybCAmJiAhQXJyYXkuaXNBcnJheShib2R5Py5maWxlcykpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnUHJvdmlkZSB1cmwgb3IgZmlsZXMnIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKHVybCkge1xuICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGNvbnN0IHUgPSBuZXcgVVJMKHVybCk7XG4gICAgICAgICAgICAgICAgaWYgKCEodS5wcm90b2NvbCA9PT0gJ2h0dHA6JyB8fCB1LnByb3RvY29sID09PSAnaHR0cHM6JykpIHRocm93IG5ldyBFcnJvcignaW52YWxpZCcpO1xuICAgICAgICAgICAgICB9IGNhdGNoIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdJbnZhbGlkIHVybCcgfSk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gTG9nIGV2ZW50XG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBhY3Rpb246ICdUUkFJTl9SRVFVRVNUJywgZGV0YWlsczogeyBoYXNVcmw6ICEhdXJsLCBmaWxlQ291bnQ6IChib2R5Py5maWxlcz8ubGVuZ3RoKSB8fCAwIH0gfSksXG4gICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuXG4gICAgICAgICAgICBjb25zdCBqb2JJZCA9IG1ha2VCb3RJZCgodXJsIHx8ICcnKSArIERhdGUubm93KCkpO1xuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAyLCB7IGpvYklkLCBzdGF0dXM6ICdxdWV1ZWQnIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9jb25uZWN0JyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKTtcbiAgICAgICAgICAgIGlmIChib2R5Py5jaGFubmVsICE9PSAnd2Vic2l0ZScpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ1Vuc3VwcG9ydGVkIGNoYW5uZWwnIH0pO1xuICAgICAgICAgICAgY29uc3QgcmF3VXJsID0gKGJvZHk/LnVybCB8fCAnJykudHJpbSgpO1xuICAgICAgICAgICAgY29uc3QgZG9tYWluID0gKCgpID0+IHtcbiAgICAgICAgICAgICAgdHJ5IHsgcmV0dXJuIHJhd1VybCA/IG5ldyBVUkwocmF3VXJsKS5ob3N0IDogJ2xvY2FsJzsgfSBjYXRjaCB7IHJldHVybiAnbG9jYWwnOyB9XG4gICAgICAgICAgICB9KSgpO1xuICAgICAgICAgICAgY29uc3Qgc2VlZCA9IGRvbWFpbiArICd8JyArIChyZXEuaGVhZGVyc1snYXV0aG9yaXphdGlvbiddIHx8ICcnKTtcbiAgICAgICAgICAgIGNvbnN0IGJvdElkID0gbWFrZUJvdElkKHNlZWQpO1xuXG4gICAgICAgICAgICAvLyBVcHNlcnQgY2hhdGJvdF9jb25maWdzIChpZiBSTFMgYWxsb3dzIHdpdGggdXNlciB0b2tlbilcbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2NoYXRib3RfY29uZmlncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYm90X2lkOiBib3RJZCwgY2hhbm5lbDogJ3dlYnNpdGUnLCBkb21haW4sIHNldHRpbmdzOiB7fSB9KSxcbiAgICAgICAgICAgICAgaGVhZGVyczogeyBQcmVmZXI6ICdyZXNvbHV0aW9uPW1lcmdlLWR1cGxpY2F0ZXMnIH0sXG4gICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuXG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgYm90SWQgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL2xhdW5jaCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSk7XG4gICAgICAgICAgICBjb25zdCBib3RJZCA9IFN0cmluZyhib2R5Py5ib3RJZCB8fCAnJykudHJpbSgpO1xuICAgICAgICAgICAgaWYgKCFib3RJZCkgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnTWlzc2luZyBib3RJZCcgfSk7XG4gICAgICAgICAgICBjb25zdCBjdXN0b21pemF0aW9uID0gYm9keT8uY3VzdG9taXphdGlvbiB8fCB7fTtcblxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvY2hhdGJvdF9jb25maWdzJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQQVRDSCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgc2V0dGluZ3M6IGN1c3RvbWl6YXRpb24gfSksXG4gICAgICAgICAgICAgIGhlYWRlcnM6IHsgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJywgUHJlZmVyOiAncmVzb2x1dGlvbj1tZXJnZS1kdXBsaWNhdGVzJyB9LFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IGJvdElkIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9jaGF0JyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IG1lc3NhZ2UgPSBTdHJpbmcoYm9keT8ubWVzc2FnZSB8fCAnJykuc2xpY2UoMCwgMjAwMCk7XG4gICAgICAgICAgICBpZiAoIW1lc3NhZ2UpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0VtcHR5IG1lc3NhZ2UnIH0pO1xuXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9zZWN1cml0eV9sb2dzJywge1xuICAgICAgICAgICAgICBtZXRob2Q6ICdQT1NUJyxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBhY3Rpb246ICdDSEFUJywgZGV0YWlsczogeyBsZW46IG1lc3NhZ2UubGVuZ3RoIH0gfSksXG4gICAgICAgICAgICB9LCByZXEpLmNhdGNoKCgpID0+IG51bGwpO1xuXG4gICAgICAgICAgICBjb25zdCByZXBseSA9IFwiSSdtIHN0aWxsIGxlYXJuaW5nLCBidXQgb3VyIHRlYW0gd2lsbCBnZXQgYmFjayB0byB5b3Ugc29vbi5cIjtcbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyByZXBseSB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBDdXN0b20gZW1haWwgdmVyaWZpY2F0aW9uOiBzZW5kIGVtYWlsXG4gICAgICAgICAgaWYgKHJlcS51cmwgPT09ICcvYXBpL3NlbmQtdmVyaWZ5JyAmJiByZXEubWV0aG9kID09PSAnUE9TVCcpIHtcbiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSBhd2FpdCBwYXJzZUpzb24ocmVxKS5jYXRjaCgoKSA9PiAoe30pKTtcbiAgICAgICAgICAgIGNvbnN0IGVtYWlsID0gU3RyaW5nKGJvZHk/LmVtYWlsIHx8ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIGlmICghL15bXlxcc0BdK0BbXlxcc0BdK1xcLlteXFxzQF0rJC8udGVzdChlbWFpbCkpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ0ludmFsaWQgZW1haWwnIH0pO1xuXG4gICAgICAgICAgICAvLyBWZXJpZnkgYXV0aGVudGljYXRlZCB1c2VyIG1hdGNoZXMgZW1haWxcbiAgICAgICAgICAgIGNvbnN0IHVyZXMgPSBhd2FpdCBzdXBhYmFzZUZldGNoKCcvYXV0aC92MS91c2VyJywgeyBtZXRob2Q6ICdHRVQnIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgICBpZiAoIXVyZXMgfHwgISh1cmVzIGFzIGFueSkub2spIHJldHVybiBlbmRKc29uKDQwMSwgeyBlcnJvcjogJ1VuYXV0aG9yaXplZCcgfSk7XG4gICAgICAgICAgICBjb25zdCB1c2VyID0gYXdhaXQgKHVyZXMgYXMgUmVzcG9uc2UpLmpzb24oKS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgIGlmICghdXNlciB8fCB1c2VyLmVtYWlsPy50b0xvd2VyQ2FzZSgpICE9PSBlbWFpbCkgcmV0dXJuIGVuZEpzb24oNDAzLCB7IGVycm9yOiAnRW1haWwgbWlzbWF0Y2gnIH0pO1xuXG4gICAgICAgICAgICBjb25zdCB0b2tlbiA9IGNyeXB0by5yYW5kb21CeXRlcygzMikudG9TdHJpbmcoJ2Jhc2U2NHVybCcpO1xuICAgICAgICAgICAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRU1BSUxfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC1zZWNyZXQnO1xuICAgICAgICAgICAgY29uc3QgdG9rZW5IYXNoID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZSh0b2tlbiArIHNlY3JldCkuZGlnZXN0KCdiYXNlNjQnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXMgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgMTAwMCAqIDYwICogNjAgKiAyNCkudG9JU09TdHJpbmcoKTtcblxuICAgICAgICAgICAgLy8gU3RvcmUgdG9rZW4gaGFzaCAobm90IHJhdyB0b2tlbilcbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2VtYWlsX3ZlcmlmaWNhdGlvbnMnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7IFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycgfSxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VyX2lkOiB1c2VyLmlkLCBlbWFpbCwgdG9rZW5faGFzaDogdG9rZW5IYXNoLCBleHBpcmVzX2F0OiBleHBpcmVzLCB1c2VkX2F0OiBudWxsIH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgLy8gU2VuZCBlbWFpbCB2aWEgU01UUFxuICAgICAgICAgICAgY29uc3QgaG9zdCA9IHByb2Nlc3MuZW52LlNNVFBfSE9TVDtcbiAgICAgICAgICAgIGNvbnN0IHBvcnQgPSBOdW1iZXIocHJvY2Vzcy5lbnYuU01UUF9QT1JUIHx8IDU4Nyk7XG4gICAgICAgICAgICBjb25zdCB1c2VyU210cCA9IHByb2Nlc3MuZW52LlNNVFBfVVNFUjtcbiAgICAgICAgICAgIGNvbnN0IHBhc3NTbXRwID0gcHJvY2Vzcy5lbnYuU01UUF9QQVNTO1xuICAgICAgICAgICAgY29uc3QgZnJvbSA9IHByb2Nlc3MuZW52LkVNQUlMX0ZST00gfHwgJ05leGFCb3QgPG5vLXJlcGx5QG5leGFib3QuYWk+JztcbiAgICAgICAgICAgIGNvbnN0IGFwcFVybCA9IHByb2Nlc3MuZW52LkFQUF9VUkwgfHwgJ2h0dHA6Ly9sb2NhbGhvc3Q6MzAwMCc7XG4gICAgICAgICAgICBjb25zdCB2ZXJpZnlVcmwgPSBgJHthcHBVcmx9L2FwaS92ZXJpZnktZW1haWw/dG9rZW49JHt0b2tlbn1gO1xuXG4gICAgICAgICAgICBpZiAoaG9zdCAmJiB1c2VyU210cCAmJiBwYXNzU210cCkge1xuICAgICAgICAgICAgICBjb25zdCB0cmFuc3BvcnRlciA9IG5vZGVtYWlsZXIuY3JlYXRlVHJhbnNwb3J0KHsgaG9zdCwgcG9ydCwgc2VjdXJlOiBwb3J0ID09PSA0NjUsIGF1dGg6IHsgdXNlcjogdXNlclNtdHAsIHBhc3M6IHBhc3NTbXRwIH0gfSk7XG4gICAgICAgICAgICAgIGNvbnN0IGh0bWwgPSBgXG4gICAgICAgICAgICAgICAgPHRhYmxlIHN0eWxlPVwid2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiNmNmY4ZmI7cGFkZGluZzoyNHB4O2ZvbnQtZmFtaWx5OkludGVyLFNlZ29lIFVJLEFyaWFsLHNhbnMtc2VyaWY7Y29sb3I6IzBmMTcyYVwiPlxuICAgICAgICAgICAgICAgICAgPHRyPjx0ZCBhbGlnbj1cImNlbnRlclwiPlxuICAgICAgICAgICAgICAgICAgICA8dGFibGUgc3R5bGU9XCJtYXgtd2lkdGg6NTYwcHg7d2lkdGg6MTAwJTtiYWNrZ3JvdW5kOiNmZmZmZmY7Ym9yZGVyOjFweCBzb2xpZCAjZTVlN2ViO2JvcmRlci1yYWRpdXM6MTJweDtvdmVyZmxvdzpoaWRkZW5cIj5cbiAgICAgICAgICAgICAgICAgICAgICA8dHI+XG4gICAgICAgICAgICAgICAgICAgICAgICA8dGQgc3R5bGU9XCJiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZywjNjM2NmYxLCM4YjVjZjYpO3BhZGRpbmc6MjBweDtjb2xvcjojZmZmO2ZvbnQtc2l6ZToxOHB4O2ZvbnQtd2VpZ2h0OjcwMFwiPlxuICAgICAgICAgICAgICAgICAgICAgICAgICBOZXhhQm90XG4gICAgICAgICAgICAgICAgICAgICAgICA8L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICAgICAgPHRyPlxuICAgICAgICAgICAgICAgICAgICAgICAgPHRkIHN0eWxlPVwicGFkZGluZzoyNHB4XCI+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxoMSBzdHlsZT1cIm1hcmdpbjowIDAgOHB4IDA7Zm9udC1zaXplOjIwcHg7Y29sb3I6IzExMTgyN1wiPkNvbmZpcm0geW91ciBlbWFpbDwvaDE+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjAgMCAxNnB4IDA7Y29sb3I6IzM3NDE1MTtsaW5lLWhlaWdodDoxLjVcIj5IaSwgcGxlYXNlIGNvbmZpcm0geW91ciBlbWFpbCBhZGRyZXNzIHRvIHNlY3VyZSB5b3VyIE5leGFCb3QgYWNjb3VudCBhbmQgY29tcGxldGUgc2V0dXAuPC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8cCBzdHlsZT1cIm1hcmdpbjowIDAgMTZweCAwO2NvbG9yOiMzNzQxNTE7bGluZS1oZWlnaHQ6MS41XCI+VGhpcyBsaW5rIGV4cGlyZXMgaW4gMjQgaG91cnMuPC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgICA8YSBocmVmPVwiJHt2ZXJpZnlVcmx9XCIgc3R5bGU9XCJkaXNwbGF5OmlubGluZS1ibG9jaztiYWNrZ3JvdW5kOiM2MzY2ZjE7Y29sb3I6I2ZmZjt0ZXh0LWRlY29yYXRpb246bm9uZTtwYWRkaW5nOjEwcHggMTZweDtib3JkZXItcmFkaXVzOjhweDtmb250LXdlaWdodDo2MDBcIj5WZXJpZnkgRW1haWw8L2E+XG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxwIHN0eWxlPVwibWFyZ2luOjE2cHggMCAwIDA7Y29sb3I6IzZiNzI4MDtmb250LXNpemU6MTJweFwiPklmIHRoZSBidXR0b24gZG9lc25cdTIwMTl0IHdvcmssIGNvcHkgYW5kIHBhc3RlIHRoaXMgbGluayBpbnRvIHlvdXIgYnJvd3Nlcjo8YnI+JHt2ZXJpZnlVcmx9PC9wPlxuICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cbiAgICAgICAgICAgICAgICAgICAgICA8L3RyPlxuICAgICAgICAgICAgICAgICAgICAgIDx0cj5cbiAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBzdHlsZT1cInBhZGRpbmc6MTZweCAyNHB4O2NvbG9yOiM2YjcyODA7Zm9udC1zaXplOjEycHg7Ym9yZGVyLXRvcDoxcHggc29saWQgI2U1ZTdlYlwiPlx1MDBBOSAke25ldyBEYXRlKCkuZ2V0RnVsbFllYXIoKX0gTmV4YUJvdC4gQWxsIHJpZ2h0cyByZXNlcnZlZC48L3RkPlxuICAgICAgICAgICAgICAgICAgICAgIDwvdHI+XG4gICAgICAgICAgICAgICAgICAgIDwvdGFibGU+XG4gICAgICAgICAgICAgICAgICA8L3RkPjwvdHI+XG4gICAgICAgICAgICAgICAgPC90YWJsZT5gO1xuICAgICAgICAgICAgICBhd2FpdCB0cmFuc3BvcnRlci5zZW5kTWFpbCh7IHRvOiBlbWFpbCwgZnJvbSwgc3ViamVjdDogJ1ZlcmlmeSB5b3VyIGVtYWlsIGZvciBOZXhhQm90JywgaHRtbCB9KTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIGNvbnNvbGUud2FybignW2VtYWlsXSBTTVRQIG5vdCBjb25maWd1cmVkOyB2ZXJpZmljYXRpb24gVVJMOicsIHZlcmlmeVVybCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBvazogdHJ1ZSB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBWZXJpZnkgbGluayBlbmRwb2ludFxuICAgICAgICAgIGlmIChyZXEudXJsPy5zdGFydHNXaXRoKCcvYXBpL3ZlcmlmeS1lbWFpbCcpICYmIHJlcS5tZXRob2QgPT09ICdHRVQnKSB7XG4gICAgICAgICAgICBjb25zdCB1cmxPYmogPSBuZXcgVVJMKHJlcS51cmwsICdodHRwOi8vbG9jYWwnKTtcbiAgICAgICAgICAgIGNvbnN0IHRva2VuID0gdXJsT2JqLnNlYXJjaFBhcmFtcy5nZXQoJ3Rva2VuJykgfHwgJyc7XG4gICAgICAgICAgICBpZiAoIXRva2VuKSB7XG4gICAgICAgICAgICAgIHJlcy5zdGF0dXNDb2RlID0gNDAwO1xuICAgICAgICAgICAgICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAndGV4dC9odG1sJyk7XG4gICAgICAgICAgICAgIHJldHVybiByZXMuZW5kKCc8cD5JbnZhbGlkIHRva2VuPC9wPicpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY29uc3Qgc2VjcmV0ID0gcHJvY2Vzcy5lbnYuRU1BSUxfVE9LRU5fU0VDUkVUIHx8ICdsb2NhbC1zZWNyZXQnO1xuICAgICAgICAgICAgY29uc3QgdG9rZW5IYXNoID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZSh0b2tlbiArIHNlY3JldCkuZGlnZXN0KCdiYXNlNjQnKTtcblxuICAgICAgICAgICAgLy8gTWFyayBhcyB1c2VkIGlmIHZhbGlkIGFuZCBub3QgZXhwaXJlZFxuICAgICAgICAgICAgY29uc3Qgbm93SXNvID0gbmV3IERhdGUoKS50b0lTT1N0cmluZygpO1xuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvZW1haWxfdmVyaWZpY2F0aW9ucz90b2tlbl9oYXNoPWVxLicgKyBlbmNvZGVVUklDb21wb25lbnQodG9rZW5IYXNoKSArICcmdXNlZF9hdD1pcy5udWxsJmV4cGlyZXNfYXQ9Z3QuJyArIGVuY29kZVVSSUNvbXBvbmVudChub3dJc28pLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BBVENIJyxcbiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VkX2F0OiBub3dJc28gfSksXG4gICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmV0dXJuPXJlcHJlc2VudGF0aW9uJyB9LFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgcmVzLnN0YXR1c0NvZGUgPSAyMDA7XG4gICAgICAgICAgICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAndGV4dC9odG1sJyk7XG4gICAgICAgICAgICByZXR1cm4gcmVzLmVuZChgPCFkb2N0eXBlIGh0bWw+PG1ldGEgaHR0cC1lcXVpdj1cInJlZnJlc2hcIiBjb250ZW50PVwiMjt1cmw9L1wiPjxzdHlsZT5ib2R5e2ZvbnQtZmFtaWx5OkludGVyLFNlZ29lIFVJLEFyaWFsLHNhbnMtc2VyaWY7YmFja2dyb3VuZDojZjZmOGZiO2NvbG9yOiMxMTE4Mjc7ZGlzcGxheTpncmlkO3BsYWNlLWl0ZW1zOmNlbnRlcjtoZWlnaHQ6MTAwdmh9PC9zdHlsZT48ZGl2PjxoMT5cdTI3MDUgRW1haWwgdmVyaWZpZWQ8L2gxPjxwPllvdSBjYW4gY2xvc2UgdGhpcyB0YWIuPC9wPjwvZGl2PmApO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwNCwgeyBlcnJvcjogJ05vdCBGb3VuZCcgfSk7XG4gICAgICAgIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgICAgICAgIHJldHVybiBlbmRKc29uKDUwMCwgeyBlcnJvcjogJ1NlcnZlciBFcnJvcicgfSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH0sXG4gIH07XG59XG4iXSwKICAibWFwcGluZ3MiOiAiO0FBQTZNLFNBQVMsb0JBQW9CO0FBQzFPLE9BQU8sV0FBVztBQUNsQixPQUFPLFVBQVU7QUFDakIsU0FBUyx1QkFBdUI7OztBQ0ZoQyxPQUFPLFlBQVk7QUFDbkIsT0FBTyxnQkFBZ0I7QUFHdkIs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
