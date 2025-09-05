export function getServerApiPath(path: string) {
  // In development the Vite dev server exposes the express-like /api routes via the server plugin.
  // In production on Netlify, functions are available under /.netlify/functions/<name>
  const clean = path.startsWith('/') ? path.slice(1) : path;
  if (import.meta.env.DEV) return `/api/${clean}`;
  // For Netlify Functions, map /send-verify -> /.netlify/functions/send-verify
  return `/.netlify/functions/${clean}`;
}
