import express from 'express';
import { createProxyMiddleware, responseInterceptor } from 'http-proxy-middleware';
import serverless from 'serverless-http';

// CORS setup
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || '*';

// Build allowlist from env with safe defaults
const envList = (process.env.ALLOW_HOSTS || '').split(',').map(s => s.trim()).filter(Boolean);
const DEFAULT_ALLOWED = [
  'classic.minecraft.net',
  'gamesunblocked.com',
  'drivemadgame.com',
  'play2048.co',
  'youtube.com', 'www.youtube.com', 'youtu.be',
  'youtube-nocookie.com', 'www.youtube-nocookie.com',
  'duckduckgo.com', 'www.duckduckgo.com',
  'mathway.com', 'www.mathway.com',
];
const ALLOW_ALL = /^true$/i.test(process.env.ALLOW_ALL || '');
const ALLOWED_HOSTS = new Set([...DEFAULT_ALLOWED, ...envList]);

function isAllowedHost(hostname) {
  if (ALLOW_ALL) return true;
  if (ALLOWED_HOSTS.has(hostname)) return true;
  // Support simple wildcard: *.domain.com as env entries
  for (const entry of ALLOWED_HOSTS) {
    if (entry.startsWith('*.')) {
      const suffix = entry.slice(1); // ".domain.com"
      if (hostname.endsWith(suffix)) return true;
    }
  }
  return false;
}

const app = express();

// CORS middleware
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOW_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS,PUT,DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Health and root info
app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.get('/', (_req, res) => {
  res.type('html').send(`<!doctype html>
  <html><head><meta charset="utf-8"><title>Frame Proxy</title>
  <style>body{font-family:system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial, sans-serif;padding:20px;background:#0a0a0a;color:#eee}code{background:#111;padding:2px 6px;border-radius:6px;border:1px solid #333}</style>
  </head><body>
  <h1>Frame Proxy</h1>
  <p>Use <code>/proxy?target=https://example.com/path</code> to load a page inside an iframe by stripping frame-blocking headers.</p>
  <ul>
    <li>Allowed hosts: ${[...ALLOWED_HOSTS].join(', ') || '(configured by env)'}</li>
    <li>ALLOW_ALL: ${ALLOW_ALL ? 'true' : 'false'}</li>
    <li>CORS Origin: ${ALLOW_ORIGIN}</li>
  </ul>
  <p>Example: <a href="/proxy?target=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DdQw4w9WgXcQ">/proxy?target=https://www.youtube.com/watch?v=dQw4w9WgXcQ</a></p>
  </body></html>`);
});

// Security: basic origin check to avoid open proxy abuse
app.use((req, res, next) => {
  const target = req.query.target || req.headers['x-target-url'];
  if (!target) return next();
  try {
    const u = new URL(target);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') {
        return res.status(400).send('Unsupported protocol');
      }
      if (!isAllowedHost(u.hostname)) {
        console.warn(`[frame-proxy] Blocked host: ${u.hostname}`);
        return res.status(400).send('Target host not allowed');
    }
    return next();
  } catch {
    return res.status(400).send('Invalid target');
  }
});

// Proxy route: /proxy?target=https://example.com/path
app.use('/proxy', createProxyMiddleware({
  changeOrigin: true,
  selfHandleResponse: true,
  router: (req) => {
    const target = req.query.target || req.headers['x-target-url'];
    return target ? new URL(target).origin : 'http://localhost';
  },
  pathRewrite: (path, req) => {
    const target = req.query.target || req.headers['x-target-url'];
    const u = new URL(target);
    // preserve path and query from provided target
    return u.pathname + (u.search || '');
  },
  onProxyReq: (proxyReq, req, res) => {
    // Strip headers that cause frame blocking
    proxyReq.removeHeader && proxyReq.removeHeader('x-frame-options');
    proxyReq.removeHeader && proxyReq.removeHeader('content-security-policy');
    proxyReq.removeHeader && proxyReq.removeHeader('frame-ancestors');
  },
  onProxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
    // Remove frame-blocking headers on the response
    delete proxyRes.headers['x-frame-options'];
    delete proxyRes.headers['content-security-policy'];
    delete proxyRes.headers['frame-ancestors'];
    res.removeHeader('x-frame-options');
    res.removeHeader('content-security-policy');
    res.removeHeader('frame-ancestors');
    // Some servers require CORS for assets; keep it permissive for framed content
    res.setHeader('cross-origin-embedder-policy', 'unsafe-none');
    res.setHeader('cross-origin-opener-policy', 'unsafe-none');
    res.setHeader('x-content-type-options', 'nosniff');
    return responseBuffer;
  })
}));

// Fallback: serve info page for any unmatched route
app.use((req, res) => {
  if (req.path === '/health') return res.json({ status: 'ok' });
  res.type('html').send(`<!doctype html>
  <html><head><meta charset="utf-8"><title>Frame Proxy</title>
  <style>body{font-family:system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial, sans-serif;padding:20px;background:#0a0a0a;color:#eee}code{background:#111;padding:2px 6px;border-radius:6px;border:1px solid #333}</style>
  </head><body>
  <h1>Frame Proxy</h1>
  <p>Use <code>/proxy?target=https://example.com/path</code> to load a page inside an iframe by stripping frame-blocking headers.</p>
  <ul>
    <li>Allowed hosts: ${[...ALLOWED_HOSTS].join(', ') || '(configured by env)'}</li>
    <li>ALLOW_ALL: ${ALLOW_ALL ? 'true' : 'false'}</li>
  </ul>
  <p>Example: <a href="/proxy?target=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DdQw4w9WgXcQ">/proxy?target=https://www.youtube.com/watch?v=dQw4w9WgXcQ</a></p>
  </body></html>`);
});

export const handler = serverless(app);
