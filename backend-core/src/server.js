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
const quantumRiskRoutes = require('./routes/quantumRisk');
const runtimeRoutes = require('./routes/runtime');
const cryptotwinRoutes = require('./routes/cryptotwin');
const cryptoshieldRoutes = require('./routes/cryptoshield');
const { auditMiddleware } = require('./services/auditLog');
const { corsOptions } = require('./config/cors');
const { apiLimiter, heavyLimiter, authLimiter } = require('./middleware/rateLimit');

const app = express();

app.set('trust proxy', 1); // behind nginx/load balancer in production
app.use(helmet({ contentSecurityPolicy: false }));
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
app.use('/scan/:scanId/quantum-risk', quantumRiskRoutes);
app.use('/runtime', heavyLimiter, runtimeRoutes);
app.use('/api/runtime', heavyLimiter, runtimeRoutes);
app.use('/api/cryptotwin', heavyLimiter, cryptotwinRoutes);
app.use('/cryptotwin', heavyLimiter, cryptotwinRoutes);
app.use('/api/cryptoshield', heavyLimiter, cryptoshieldRoutes);
app.use('/cryptoshield', heavyLimiter, cryptoshieldRoutes);

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

startServer();
