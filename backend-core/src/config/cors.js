'use strict';

// Backend-core also serves the frontend statically (same-origin), so CORS
// only matters when the frontend is hosted separately (e.g. a CDN) or during
// local dev when the frontend is served from a different port.
const DEFAULT_DEV_ORIGINS = [
  'http://localhost', 'http://127.0.0.1',
  'http://localhost:5500', 'http://127.0.0.1:5500',
  'http://localhost:3000', 'http://127.0.0.1:3000',
  'http://localhost:80', 'http://127.0.0.1:80',
  'http://localhost:8080', 'http://127.0.0.1:8080',
  'http://localhost:8000', 'http://127.0.0.1:8000'
];

function buildAllowedOrigins() {
  const fromEnv = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

  if (process.env.NODE_ENV === 'production') {
    return fromEnv;
  }
  return [...new Set([...fromEnv, ...DEFAULT_DEV_ORIGINS])];
}

// Checks if origin matches an allowed pattern.
// Supports wildcard prefix patterns like "https://*.vercel.app"
function originMatches(origin, pattern) {
  if (pattern === origin) return true;
  if (pattern.includes('*')) {
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace('\\*', '.*');
    return new RegExp(`^${escaped}$`).test(origin);
  }
  return false;
}

function corsOptions() {
  const allowedOrigins = buildAllowedOrigins();
  return {
    origin(origin, callback) {
      // Same-origin / non-browser requests (curl, server-to-server) have no Origin header.
      if (!origin || origin === 'null') return callback(null, true);
      // Allow any Vercel domain automatically (e.g. cryptoscan-new-ruby.vercel.app)
      if (/\.vercel\.app$/.test(origin) || origin.includes('vercel.app')) {
        return callback(null, true);
      }
      // In development, allow localhost/127.0.0.1 on any port
      if (process.env.NODE_ENV !== 'production' && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
        return callback(null, true);
      }
      if (allowedOrigins.some(pattern => originMatches(origin, pattern))) {
        return callback(null, true);
      }
      return callback(null, true);
    },
    credentials: true,
  };
}

module.exports = { corsOptions };
