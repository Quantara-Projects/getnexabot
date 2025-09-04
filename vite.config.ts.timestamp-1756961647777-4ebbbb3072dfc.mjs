// vite.config.ts
import { defineConfig } from "file:///app/code/node_modules/vite/dist/node/index.js";
import react from "file:///app/code/node_modules/@vitejs/plugin-react-swc/index.js";
import path from "path";
import { componentTagger } from "file:///app/code/node_modules/lovable-tagger/dist/index.js";

// src/server/api.ts
import crypto from "crypto";
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL3NlcnZlci9hcGkudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGVcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9hcHAvY29kZS92aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vYXBwL2NvZGUvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tIFwidml0ZVwiO1xuaW1wb3J0IHJlYWN0IGZyb20gXCJAdml0ZWpzL3BsdWdpbi1yZWFjdC1zd2NcIjtcbmltcG9ydCBwYXRoIGZyb20gXCJwYXRoXCI7XG5pbXBvcnQgeyBjb21wb25lbnRUYWdnZXIgfSBmcm9tIFwibG92YWJsZS10YWdnZXJcIjtcbmltcG9ydCB7IHNlcnZlckFwaVBsdWdpbiB9IGZyb20gXCIuL3NyYy9zZXJ2ZXIvYXBpXCI7XG5cbi8vIGh0dHBzOi8vdml0ZWpzLmRldi9jb25maWcvXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiAoe1xuICBzZXJ2ZXI6IHtcbiAgICBob3N0OiBcIjo6XCIsXG4gICAgcG9ydDogODA4MCxcbiAgfSxcbiAgcGx1Z2luczogW1xuICAgIHJlYWN0KCksXG4gICAgbW9kZSA9PT0gJ2RldmVsb3BtZW50JyAmJlxuICAgIGNvbXBvbmVudFRhZ2dlcigpLFxuICAgIHNlcnZlckFwaVBsdWdpbigpLFxuICBdLmZpbHRlcihCb29sZWFuKSxcbiAgcmVzb2x2ZToge1xuICAgIGFsaWFzOiB7XG4gICAgICBcIkBcIjogcGF0aC5yZXNvbHZlKF9fZGlybmFtZSwgXCIuL3NyY1wiKSxcbiAgICB9LFxuICB9LFxufSkpO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvYXBwL2NvZGUvc3JjL3NlcnZlclwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2FwcC9jb2RlL3NyYy9zZXJ2ZXIvYXBpLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9hcHAvY29kZS9zcmMvc2VydmVyL2FwaS50c1wiO2ltcG9ydCB0eXBlIHsgUGx1Z2luIH0gZnJvbSAndml0ZSc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5cbi8vIFNtYWxsIEpTT04gYm9keSBwYXJzZXIgd2l0aCBzaXplIGxpbWl0XG5hc3luYyBmdW5jdGlvbiBwYXJzZUpzb24ocmVxOiBhbnksIGxpbWl0ID0gMTAyNCAqIDEwMCkge1xuICByZXR1cm4gbmV3IFByb21pc2U8YW55PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgY29uc3QgY2h1bmtzOiBCdWZmZXJbXSA9IFtdO1xuICAgIGxldCBzaXplID0gMDtcbiAgICByZXEub24oJ2RhdGEnLCAoYzogQnVmZmVyKSA9PiB7XG4gICAgICBzaXplICs9IGMubGVuZ3RoO1xuICAgICAgaWYgKHNpemUgPiBsaW1pdCkge1xuICAgICAgICByZWplY3QobmV3IEVycm9yKCdQYXlsb2FkIHRvbyBsYXJnZScpKTtcbiAgICAgICAgcmVxLmRlc3Ryb3koKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgY2h1bmtzLnB1c2goYyk7XG4gICAgfSk7XG4gICAgcmVxLm9uKCdlbmQnLCAoKSA9PiB7XG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCByYXcgPSBCdWZmZXIuY29uY2F0KGNodW5rcykudG9TdHJpbmcoJ3V0ZjgnKTtcbiAgICAgICAgY29uc3QganNvbiA9IHJhdyA/IEpTT04ucGFyc2UocmF3KSA6IHt9O1xuICAgICAgICByZXNvbHZlKGpzb24pO1xuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICByZWplY3QoZSk7XG4gICAgICB9XG4gICAgfSk7XG4gICAgcmVxLm9uKCdlcnJvcicsIHJlamVjdCk7XG4gIH0pO1xufVxuXG5mdW5jdGlvbiBqc29uKHJlczogYW55LCBzdGF0dXM6IG51bWJlciwgZGF0YTogYW55LCBoZWFkZXJzOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+ID0ge30pIHtcbiAgY29uc3QgYm9keSA9IEpTT04uc3RyaW5naWZ5KGRhdGEpO1xuICByZXMuc3RhdHVzQ29kZSA9IHN0YXR1cztcbiAgcmVzLnNldEhlYWRlcignQ29udGVudC1UeXBlJywgJ2FwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9dXRmLTgnKTtcbiAgcmVzLnNldEhlYWRlcignWC1Db250ZW50LVR5cGUtT3B0aW9ucycsICdub3NuaWZmJyk7XG4gIHJlcy5zZXRIZWFkZXIoJ1JlZmVycmVyLVBvbGljeScsICduby1yZWZlcnJlcicpO1xuICByZXMuc2V0SGVhZGVyKCdYLUZyYW1lLU9wdGlvbnMnLCAnREVOWScpO1xuICByZXMuc2V0SGVhZGVyKCdYLVhTUy1Qcm90ZWN0aW9uJywgJzE7IG1vZGU9YmxvY2snKTtcbiAgZm9yIChjb25zdCBbaywgdl0gb2YgT2JqZWN0LmVudHJpZXMoaGVhZGVycykpIHJlcy5zZXRIZWFkZXIoaywgdik7XG4gIHJlcy5lbmQoYm9keSk7XG59XG5cbmNvbnN0IGlzSHR0cHMgPSAocmVxOiBhbnkpID0+IHtcbiAgY29uc3QgcHJvdG8gPSAocmVxLmhlYWRlcnNbJ3gtZm9yd2FyZGVkLXByb3RvJ10gYXMgc3RyaW5nKSB8fCAnJztcbiAgcmV0dXJuIHByb3RvID09PSAnaHR0cHMnIHx8IChyZXEuc29ja2V0ICYmIChyZXEuc29ja2V0IGFzIGFueSkuZW5jcnlwdGVkKTtcbn07XG5cbmFzeW5jIGZ1bmN0aW9uIHN1cGFiYXNlRmV0Y2gocGF0aDogc3RyaW5nLCBvcHRpb25zOiBhbnksIHJlcTogYW55KSB7XG4gIGNvbnN0IGJhc2UgPSBwcm9jZXNzLmVudi5TVVBBQkFTRV9VUkwgfHwgJ2h0dHBzOi8vZnp5Z3h5bmVyZWlqamZiY3Z3b2guc3VwYWJhc2UuY28nO1xuICBjb25zdCBhbm9uID0gcHJvY2Vzcy5lbnYuU1VQQUJBU0VfQU5PTl9LRVkgfHwgJ2V5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpwYzNNaU9pSnpkWEJoWW1GelpTSXNJbkpsWmlJNkltWjZlV2Q0ZVc1bGNtVnBhbXBtWW1OMmQyOW9JaXdpY205c1pTSTZJbUZ1YjI0aUxDSnBZWFFpT2pFM05UWTVOVFl4TXpNc0ltVjRjQ0k2TWpBM01qVXpNakV6TTMwLi1KblV3YVhmbGNXbXZMOF9mdTA4dUV6ZUJuSWh4dkFrZDZfaHFWZVNZbEknO1xuICBjb25zdCB0b2tlbiA9IChyZXEuaGVhZGVyc1snYXV0aG9yaXphdGlvbiddIGFzIHN0cmluZykgfHwgJyc7XG4gIGNvbnN0IGhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7XG4gICAgYXBpa2V5OiBhbm9uLFxuICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsXG4gIH07XG4gIGlmICh0b2tlbikgaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gdG9rZW47XG4gIHJldHVybiBmZXRjaChgJHtiYXNlfSR7cGF0aH1gLCB7IC4uLm9wdGlvbnMsIGhlYWRlcnM6IHsgLi4uaGVhZGVycywgLi4uKG9wdGlvbnM/LmhlYWRlcnMgfHwge30pIH0gfSk7XG59XG5cbmZ1bmN0aW9uIG1ha2VCb3RJZChzZWVkOiBzdHJpbmcpIHtcbiAgcmV0dXJuICdib3RfJyArIGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUoc2VlZCkuZGlnZXN0KCdiYXNlNjR1cmwnKS5zbGljZSgwLCAyMik7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBzZXJ2ZXJBcGlQbHVnaW4oKTogUGx1Z2luIHtcbiAgcmV0dXJuIHtcbiAgICBuYW1lOiAnc2VydmVyLWFwaS1wbHVnaW4nLFxuICAgIGNvbmZpZ3VyZVNlcnZlcihzZXJ2ZXIpIHtcbiAgICAgIHNlcnZlci5taWRkbGV3YXJlcy51c2UoYXN5bmMgKHJlcSwgcmVzLCBuZXh0KSA9PiB7XG4gICAgICAgIGlmICghcmVxLnVybCB8fCAhcmVxLnVybC5zdGFydHNXaXRoKCcvYXBpLycpKSByZXR1cm4gbmV4dCgpO1xuXG4gICAgICAgIC8vIEJhc2ljIHNlY3VyaXR5IGhlYWRlcnMgZm9yIGFsbCBBUEkgcmVzcG9uc2VzXG4gICAgICAgIGNvbnN0IGNvcnNPcmlnaW4gPSByZXEuaGVhZGVycy5vcmlnaW4gfHwgJyonO1xuXG4gICAgICAgIC8vIEluIGRldiBhbGxvdyBodHRwOyBpbiBwcm9kIChiZWhpbmQgcHJveHkpLCByZXF1aXJlIGh0dHBzXG4gICAgICAgIGlmIChwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ3Byb2R1Y3Rpb24nICYmICFpc0h0dHBzKHJlcSkpIHtcbiAgICAgICAgICByZXR1cm4ganNvbihyZXMsIDQwMCwgeyBlcnJvcjogJ0hUVFBTIHJlcXVpcmVkJyB9LCB7ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nOiBTdHJpbmcoY29yc09yaWdpbikgfSk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDT1JTIHByZWZsaWdodFxuICAgICAgICBpZiAocmVxLm1ldGhvZCA9PT0gJ09QVElPTlMnKSB7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJywgU3RyaW5nKGNvcnNPcmlnaW4pKTtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1NZXRob2RzJywgJ1BPU1QsR0VULE9QVElPTlMnKTtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzJywgJ0NvbnRlbnQtVHlwZSwgQXV0aG9yaXphdGlvbicpO1xuICAgICAgICAgIHJlcy5zdGF0dXNDb2RlID0gMjA0O1xuICAgICAgICAgIHJldHVybiByZXMuZW5kKCk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBlbmRKc29uID0gKHN0YXR1czogbnVtYmVyLCBkYXRhOiBhbnkpID0+IGpzb24ocmVzLCBzdGF0dXMsIGRhdGEsIHsgJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbic6IFN0cmluZyhjb3JzT3JpZ2luKSB9KTtcblxuICAgICAgICB0cnkge1xuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS90cmFpbicgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCB1cmwgPSB0eXBlb2YgYm9keT8udXJsID09PSAnc3RyaW5nJyA/IGJvZHkudXJsLnRyaW0oKSA6ICcnO1xuICAgICAgICAgICAgaWYgKCF1cmwgJiYgIUFycmF5LmlzQXJyYXkoYm9keT8uZmlsZXMpKSB7XG4gICAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ1Byb3ZpZGUgdXJsIG9yIGZpbGVzJyB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICh1cmwpIHtcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmwpO1xuICAgICAgICAgICAgICAgIGlmICghKHUucHJvdG9jb2wgPT09ICdodHRwOicgfHwgdS5wcm90b2NvbCA9PT0gJ2h0dHBzOicpKSB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQnKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDAwLCB7IGVycm9yOiAnSW52YWxpZCB1cmwnIH0pO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIExvZyBldmVudFxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnVFJBSU5fUkVRVUVTVCcsIGRldGFpbHM6IHsgaGFzVXJsOiAhIXVybCwgZmlsZUNvdW50OiAoYm9keT8uZmlsZXM/Lmxlbmd0aCkgfHwgMCB9IH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgY29uc3Qgam9iSWQgPSBtYWtlQm90SWQoKHVybCB8fCAnJykgKyBEYXRlLm5vdygpKTtcbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMiwgeyBqb2JJZCwgc3RhdHVzOiAncXVldWVkJyB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY29ubmVjdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSk7XG4gICAgICAgICAgICBpZiAoYm9keT8uY2hhbm5lbCAhPT0gJ3dlYnNpdGUnKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdVbnN1cHBvcnRlZCBjaGFubmVsJyB9KTtcbiAgICAgICAgICAgIGNvbnN0IHJhd1VybCA9IChib2R5Py51cmwgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGNvbnN0IGRvbWFpbiA9ICgoKSA9PiB7XG4gICAgICAgICAgICAgIHRyeSB7IHJldHVybiByYXdVcmwgPyBuZXcgVVJMKHJhd1VybCkuaG9zdCA6ICdsb2NhbCc7IH0gY2F0Y2ggeyByZXR1cm4gJ2xvY2FsJzsgfVxuICAgICAgICAgICAgfSkoKTtcbiAgICAgICAgICAgIGNvbnN0IHNlZWQgPSBkb21haW4gKyAnfCcgKyAocmVxLmhlYWRlcnNbJ2F1dGhvcml6YXRpb24nXSB8fCAnJyk7XG4gICAgICAgICAgICBjb25zdCBib3RJZCA9IG1ha2VCb3RJZChzZWVkKTtcblxuICAgICAgICAgICAgLy8gVXBzZXJ0IGNoYXRib3RfY29uZmlncyAoaWYgUkxTIGFsbG93cyB3aXRoIHVzZXIgdG9rZW4pXG4gICAgICAgICAgICBhd2FpdCBzdXBhYmFzZUZldGNoKCcvcmVzdC92MS9jaGF0Ym90X2NvbmZpZ3MnLCB7XG4gICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGJvdF9pZDogYm90SWQsIGNoYW5uZWw6ICd3ZWJzaXRlJywgZG9tYWluLCBzZXR0aW5nczoge30gfSksXG4gICAgICAgICAgICAgIGhlYWRlcnM6IHsgUHJlZmVyOiAncmVzb2x1dGlvbj1tZXJnZS1kdXBsaWNhdGVzJyB9LFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgcmV0dXJuIGVuZEpzb24oMjAwLCB7IGJvdElkIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChyZXEudXJsID09PSAnL2FwaS9sYXVuY2gnICYmIHJlcS5tZXRob2QgPT09ICdQT1NUJykge1xuICAgICAgICAgICAgY29uc3QgYm9keSA9IGF3YWl0IHBhcnNlSnNvbihyZXEpO1xuICAgICAgICAgICAgY29uc3QgYm90SWQgPSBTdHJpbmcoYm9keT8uYm90SWQgfHwgJycpLnRyaW0oKTtcbiAgICAgICAgICAgIGlmICghYm90SWQpIHJldHVybiBlbmRKc29uKDQwMCwgeyBlcnJvcjogJ01pc3NpbmcgYm90SWQnIH0pO1xuICAgICAgICAgICAgY29uc3QgY3VzdG9taXphdGlvbiA9IGJvZHk/LmN1c3RvbWl6YXRpb24gfHwge307XG5cbiAgICAgICAgICAgIGF3YWl0IHN1cGFiYXNlRmV0Y2goJy9yZXN0L3YxL2NoYXRib3RfY29uZmlncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUEFUQ0gnLFxuICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHNldHRpbmdzOiBjdXN0b21pemF0aW9uIH0pLFxuICAgICAgICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsIFByZWZlcjogJ3Jlc29sdXRpb249bWVyZ2UtZHVwbGljYXRlcycgfSxcbiAgICAgICAgICAgIH0sIHJlcSkuY2F0Y2goKCkgPT4gbnVsbCk7XG5cbiAgICAgICAgICAgIHJldHVybiBlbmRKc29uKDIwMCwgeyBib3RJZCB9KTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocmVxLnVybCA9PT0gJy9hcGkvY2hhdCcgJiYgcmVxLm1ldGhvZCA9PT0gJ1BPU1QnKSB7XG4gICAgICAgICAgICBjb25zdCBib2R5ID0gYXdhaXQgcGFyc2VKc29uKHJlcSkuY2F0Y2goKCkgPT4gKHt9KSk7XG4gICAgICAgICAgICBjb25zdCBtZXNzYWdlID0gU3RyaW5nKGJvZHk/Lm1lc3NhZ2UgfHwgJycpLnNsaWNlKDAsIDIwMDApO1xuICAgICAgICAgICAgaWYgKCFtZXNzYWdlKSByZXR1cm4gZW5kSnNvbig0MDAsIHsgZXJyb3I6ICdFbXB0eSBtZXNzYWdlJyB9KTtcblxuICAgICAgICAgICAgYXdhaXQgc3VwYWJhc2VGZXRjaCgnL3Jlc3QvdjEvc2VjdXJpdHlfbG9ncycsIHtcbiAgICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgYWN0aW9uOiAnQ0hBVCcsIGRldGFpbHM6IHsgbGVuOiBtZXNzYWdlLmxlbmd0aCB9IH0pLFxuICAgICAgICAgICAgfSwgcmVxKS5jYXRjaCgoKSA9PiBudWxsKTtcblxuICAgICAgICAgICAgY29uc3QgcmVwbHkgPSBcIkknbSBzdGlsbCBsZWFybmluZywgYnV0IG91ciB0ZWFtIHdpbGwgZ2V0IGJhY2sgdG8geW91IHNvb24uXCI7XG4gICAgICAgICAgICByZXR1cm4gZW5kSnNvbigyMDAsIHsgcmVwbHkgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuIGVuZEpzb24oNDA0LCB7IGVycm9yOiAnTm90IEZvdW5kJyB9KTtcbiAgICAgICAgfSBjYXRjaCAoZTogYW55KSB7XG4gICAgICAgICAgcmV0dXJuIGVuZEpzb24oNTAwLCB7IGVycm9yOiAnU2VydmVyIEVycm9yJyB9KTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSxcbiAgfTtcbn1cbiJdLAogICJtYXBwaW5ncyI6ICI7QUFBNk0sU0FBUyxvQkFBb0I7QUFDMU8sT0FBTyxXQUFXO0FBQ2xCLE9BQU8sVUFBVTtBQUNqQixTQUFTLHVCQUF1Qjs7O0FDRmhDLE9BQU8sWUFBWTtBQUduQixlQUFlLFVBQVUsS0FBVSxRQUFRLE9BQU8sS0FBSztBQUNyRCxTQUFPLElBQUksUUFBYSxDQUFDLFNBQVMsV0FBVztBQUMzQyxVQUFNLFNBQW1CLENBQUM7QUFDMUIsUUFBSSxPQUFPO0FBQ1gsUUFBSSxHQUFHLFFBQVEsQ0FBQyxNQUFjO0FBQzVCLGNBQVEsRUFBRTtBQUNWLFVBQUksT0FBTyxPQUFPO0FBQ2hCLGVBQU8sSUFBSSxNQUFNLG1CQUFtQixDQUFDO0FBQ3JDLFlBQUksUUFBUTtBQUNaO0FBQUEsTUFDRjtBQUNBLGFBQU8sS0FBSyxDQUFDO0FBQUEsSUFDZixDQUFDO0FBQ0QsUUFBSSxHQUFHLE9BQU8sTUFBTTtBQUNsQixVQUFJO0FBQ0YsY0FBTSxNQUFNLE9BQU8sT0FBTyxNQUFNLEVBQUUsU0FBUyxNQUFNO0FBQ2pELGNBQU1BLFFBQU8sTUFBTSxLQUFLLE1BQU0sR0FBRyxJQUFJLENBQUM7QUFDdEMsZ0JBQVFBLEtBQUk7QUFBQSxNQUNkLFNBQVMsR0FBRztBQUNWLGVBQU8sQ0FBQztBQUFBLE1BQ1Y7QUFBQSxJQUNGLENBQUM7QUFDRCxRQUFJLEdBQUcsU0FBUyxNQUFNO0FBQUEsRUFDeEIsQ0FBQztBQUNIO0FBRUEsU0FBUyxLQUFLLEtBQVUsUUFBZ0IsTUFBVyxVQUFrQyxDQUFDLEdBQUc7QUFDdkYsUUFBTSxPQUFPLEtBQUssVUFBVSxJQUFJO0FBQ2hDLE1BQUks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
