'use strict';

const rateLimit = require('express-rate-limit');

const isDev = process.env.NODE_ENV !== 'production';

function buildStore(prefix) {
  if (isDev && !process.env.REDIS_URL) {
    return undefined; // in-memory fallback for dev only
  }

  try {
    const { getRedisClient } = require('../utils/redisClient');
    const { RedisStore } = require('rate-limit-redis');
    const client = getRedisClient();
    return new RedisStore({ prefix: prefix || 'rl:', sendCommand: (...args) => client.call(...args) });
  } catch (err) {
    if (!isDev) {
      console.error('FATAL ERROR: Redis store setup failed in production:', err.message);
      process.exit(1);
    }
    console.warn('Redis rate-limit store unavailable, falling back to in-memory:', err.message);
    return undefined;
  }
}

// Loosest for normal API read traffic
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_API_WINDOW || 15) * 60 * 1000,
  limit: parseInt(process.env.RATE_LIMIT_API_MAX || (isDev ? 10000 : 600)),
  standardHeaders: true,
  legacyHeaders: false,
  store: buildStore('rl:api:'),
});

// Moderate limit for heavy endpoints (uploads, scans)
const heavyLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_HEAVY_WINDOW || 15) * 60 * 1000,
  limit: parseInt(process.env.RATE_LIMIT_HEAVY_MAX || (isDev ? 1000 : 50)),
  standardHeaders: true,
  legacyHeaders: false,
  store: buildStore('rl:heavy:'),
  message: { error: 'Too many heavy operations, please try again later' },
});

// Strictest for auth (login, signup, reset).
// Uses a custom key generator to limit by IP *and* by email (if provided) to prevent distributed brute force on a single account.
const authLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_AUTH_WINDOW || 15) * 60 * 1000,
  limit: parseInt(process.env.RATE_LIMIT_AUTH_MAX || (isDev ? 200 : 10)),
  standardHeaders: true,
  legacyHeaders: false,
  store: buildStore('rl:auth:'),
  keyGenerator: (req, res) => {
    let email = '';
    if (req.body && req.body.email) {
      email = req.body.email.trim().toLowerCase();
    }
    return email ? `${req.ip}:${email}` : req.ip;
  },
  message: { error: 'Too many auth attempts, please try again later' },
});

module.exports = { apiLimiter, heavyLimiter, authLimiter };
