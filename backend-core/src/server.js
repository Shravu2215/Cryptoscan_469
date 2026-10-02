require('../../shared/preflight'); // ML-DSA Node version check — must be first
require('dotenv').config();
const { validateEnv } = require('./utils/validateEnv');
validateEnv();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');

const authRoutes = require('./routes/auth');
const repoRoutes = require('./routes/repos');
const scanRoutes = require('./routes/scans');
const { auditMiddleware } = require('./services/auditLog');
const { corsOptions } = require('./config/cors');
const { apiLimiter, heavyLimiter, authLimiter } = require('./middleware/rateLimit');

const app = express();

app.set('trust proxy', 1); // behind nginx/load balancer in production
app.use(helmet({
  contentSecurityPolicy: {
    reportOnly: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'", "http://localhost:3000"],
      reportUri: ['/api/csp-report'],
    },
  },
}));

app.post('/api/csp-report', express.json({ type: 'application/csp-report' }), (req, res) => {
  console.warn('[CSP-REPORT]', JSON.stringify(req.body));
  res.status(204).end();
});
app.use(cors(corsOptions()));
app.use(express.json());
const path = require('path');
// Serve static frontend files first (pages, CSS, JS, images are not subject to API rate limits)
app.use(express.static(path.join(__dirname, '../../frontend')));

app.use(cookieParser());
app.use(apiLimiter);
app.use(auditMiddleware);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const { execSync } = require('child_process');
let commitHash = process.env.VERCEL_GIT_COMMIT_SHA || process.env.RENDER_GIT_COMMIT || process.env.GIT_COMMIT || '';
if (!commitHash) {
  try {
    commitHash = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim();
  } catch (_) {
    commitHash = 'dev';
  }
}

const getVersionInfo = (req, res) => res.json({
  service: 'backend-core',
  version: '2.1.0',
  commit: commitHash,
  scanner_version: '2.1.0',
  timestamp: new Date().toISOString()
});

app.get('/version', getVersionInfo);
app.get('/api/version', getVersionInfo);

app.use('/auth', authLimiter, authRoutes);
app.use('/api/auth', authLimiter, authRoutes);
app.use('/repos', heavyLimiter, repoRoutes);
app.use('/scan', heavyLimiter, scanRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Global error handler (e.g. multer file-size errors)
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

const PORT = process.env.PORT || 3000;

async function startServer() {
  if (process.env.NODE_ENV === 'production') {
    try {
      const { getRedisClient } = require('./utils/redisClient');
      await getRedisClient().ping();
    } catch (err) {
      console.error('FATAL ERROR: Redis is unreachable in production.', err.message);
      process.exit(1);
    }
  }

  app.listen(PORT, () => {
    console.log(`CryptoScan backend-core running on http://localhost:${PORT}`);
  });
}

async function startServices() {
  if (process.env.RUN_SCAN_WORKER === 'true') {
    const { startWorker } = require('./queue/scanWorker');
    await startWorker();
  }
  await startServer();
}

startServices().catch((err) => {
  console.error('FATAL: Application startup failed.', err.message);
  process.exit(1);
});
