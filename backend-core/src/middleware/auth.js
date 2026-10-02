'use strict';

const prisma = require('../utils/prismaClient');
const { verifyAccessToken } = require('../utils/tokenService');
const { isJtiDenylisted } = require('../utils/redisClient');

const ROLES = Object.freeze({
  ADMIN: 'Admin',
  SECURITY_TEAM: 'Security Team',
  DEVELOPER: 'Developer',
  AUDITOR: 'Auditor',
});

/**
 * requireAuth — validates the Bearer access token.
 *
 * Rejects (401) if:
 *   - The token is missing, malformed, or expired.
 *   - The token's jti is in the Redis denylist (logged-out session).
 *
 * On success, sets req.user = { id, email, role }.
 */
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.split(' ')[1];
  if (!token || token === 'null' || token === 'undefined') {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Verify signature and expiry
  let payload;
  try {
    payload = verifyAccessToken(token);
  } catch (err) {
    const msg = err.name === 'TokenExpiredError' ? 'Access token expired' : 'Invalid token';
    return res.status(401).json({ error: msg });
  }

  // Reject if JTI is denylisted (revoked on logout)
  if (payload.jti) {
    const denied = await isJtiDenylisted(payload.jti);
    if (denied) {
      return res.status(401).json({ error: 'Token has been revoked' });
    }
  }

  // Hydrate user from DB; fall back to JWT claims if DB is unavailable
  let user;
  try {
    user = await prisma.user.findUnique({
      where: { id: payload.id },
      select: { id: true, email: true, role: true },
    });
  } catch (dbErr) {
    console.warn('PostgreSQL unavailable during auth verification, using payload fallback:', dbErr.message);
  }

  if (!user) {
    user = { id: payload.id, email: payload.email, role: payload.role || 'Developer' };
  }

  req.user = user;
  return next();
}

/**
 * requireRole — authorization guard that must follow requireAuth.
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => allowedRoles.includes(req.user?.role)
    ? next()
    : res.status(403).json({ error: 'Your role is not permitted to perform this action' });
}

module.exports = { requireAuth, requireRole, ROLES };
