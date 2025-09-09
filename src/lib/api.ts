export function getServerApiPath(path: string) {
  const clean = path.startsWith('/') ? path.slice(1) : path;
  const base = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/+$/, '');

  // In development, if no external API base is set, use local Vite middleware /api
  if (import.meta.env.DEV && !base) {
    return `/api/${clean}`;
  }

  // If a base URL is configured (e.g., Render, Railway, Fly), use it
  if (base) {
    return `${base}/${clean}`;
  }

  // Fallback for Netlify Functions in production
  return `/.netlify/functions/${clean}`;
}
