'use strict';

// Fails fast at startup rather than letting the app run half-configured.
// No fallback defaults are permitted — any missing or weak secret is fatal.

function validateEnv() {
  const isProd = process.env.NODE_ENV === 'production';
  const errors = [];

  // ── Access token secret ──────────────────────────────────────────────────
  if (!process.env.JWT_ACCESS_SECRET) {
    errors.push('JWT_ACCESS_SECRET is not set');
  } else if (process.env.JWT_ACCESS_SECRET.length < 32) {
    errors.push('JWT_ACCESS_SECRET must be at least 32 characters');
  }

  // ── Refresh token secret (must differ from access secret) ────────────────
  if (!process.env.JWT_REFRESH_SECRET) {
    errors.push('JWT_REFRESH_SECRET is not set');
  } else if (process.env.JWT_REFRESH_SECRET.length < 32) {
    errors.push('JWT_REFRESH_SECRET must be at least 32 characters');
  } else if (process.env.JWT_REFRESH_SECRET === process.env.JWT_ACCESS_SECRET) {
    errors.push('JWT_REFRESH_SECRET must be different from JWT_ACCESS_SECRET');
  }

  // ── Database ─────────────────────────────────────────────────────────────
  if (!process.env.DATABASE_URL) {
    errors.push('DATABASE_URL is not set');
  }

  // ── AES-256 encryption key ───────────────────────────────────────────────
  if (!process.env.DATA_ENCRYPTION_KEY) {
    errors.push('DATA_ENCRYPTION_KEY is not set (base64-encoded 32-byte AES-256 key)');
  } else {
    const decoded = Buffer.from(process.env.DATA_ENCRYPTION_KEY, 'base64');
    if (decoded.length !== 32) {
      errors.push('DATA_ENCRYPTION_KEY must decode to exactly 32 bytes');
    }
  }

  // ── Production-only guards ───────────────────────────────────────────────
  if (isProd) {
    if (!process.env.REDIS_URL) {
      errors.push('REDIS_URL must be set in production for rate limits and revocation');
    }
    if (!process.env.ALLOWED_ORIGINS) {
      errors.push('ALLOWED_ORIGINS must be set in production (comma-separated list of allowed frontend origins)');
    }
    if (!process.env.PRIVATE_KEY && process.env.KMS_PROVIDER !== 'aws-kms') {
      errors.push('PRIVATE_KEY is not set and KMS_PROVIDER is not aws-kms — anchoring will fail');
    }
  }

  if (errors.length > 0) {
    // eslint-disable-next-line no-console
    console.error('Refusing to start: invalid configuration:\n' + errors.map(e => `  - ${e}`).join('\n'));
    process.exit(1);
  }
}

module.exports = { validateEnv };
