'use strict';

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Secrets are validated at startup by validateEnv — guaranteed non-empty here.
const ACCESS_SECRET = () => process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = () => process.env.JWT_REFRESH_SECRET;

const ACCESS_TTL_SECONDS = 15 * 60;       // 15 minutes
const REFRESH_TTL_SECONDS = 7 * 24 * 3600; // 7 days

/**
 * Issue a signed access token.
 * @param {{ id: string, email: string, role: string }} user
 * @returns {{ token: string, jti: string, expiresAt: Date }}
 */
function issueAccessToken(user) {
  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role, jti },
    ACCESS_SECRET(),
    { expiresIn: ACCESS_TTL_SECONDS }
  );
  return { token, jti, expiresAt: new Date(Date.now() + ACCESS_TTL_SECONDS * 1000) };
}

/**
 * Issue a signed refresh token.
 * @param {{ id: string }} user
 * @returns {{ token: string, jti: string, expiresAt: Date }}
 */
function issueRefreshToken(user) {
  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { id: user.id, jti },
    REFRESH_SECRET(),
    { expiresIn: REFRESH_TTL_SECONDS }
  );
  return { token, jti, expiresAt: new Date(Date.now() + REFRESH_TTL_SECONDS * 1000) };
}

/**
 * Verify an access token. Throws on invalid/expired.
 * @param {string} token
 * @returns {object} decoded payload
 */
function verifyAccessToken(token) {
  return jwt.verify(token, ACCESS_SECRET());
}

/**
 * Verify a refresh token. Throws on invalid/expired.
 * @param {string} token
 * @returns {object} decoded payload
 */
function verifyRefreshToken(token) {
  return jwt.verify(token, REFRESH_SECRET());
}

module.exports = {
  issueAccessToken,
  issueRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  ACCESS_TTL_SECONDS,
  REFRESH_TTL_SECONDS,
};
