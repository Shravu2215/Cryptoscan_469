const jwt = require('jsonwebtoken');
const prisma = require('../utils/prismaClient');
const { isDev, logStructuredError, sendError, serviceUnavailable } = require('../utils/failClosed');
const ROLES = Object.freeze({ ADMIN: 'Admin', SECURITY_TEAM: 'Security Team', DEVELOPER: 'Developer', AUDITOR: 'Auditor' });

async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: { code: 'UNAUTHENTICATED', message: 'A valid bearer token is required' } });
  }
  const token = authHeader?.slice(7) || '';
  if (!token || ['null', 'undefined', 'demo-token'].includes(token)) {
    if (isDev) {
      req.user = { id: 'usr_demo', email: 'demo@cryptoscan.io', role: 'Developer' };
      return next();
    }
    return res.status(401).json({ error: { code: 'UNAUTHENTICATED', message: 'A valid bearer token is required' } });
  }

  const secret = process.env.JWT_SECRET;
  if (!secret) {
    return sendError(res, serviceUnavailable('auth.jwt_secret_missing', new Error('JWT_SECRET is not configured')),
      'auth.jwt_secret_missing');
  }

  let payload;
  try {
    payload = jwt.verify(token, secret);
  } catch (err) {
    logStructuredError('auth.jwt_verification_failed', err);
    return res.status(401).json({ error: { code: 'INVALID_TOKEN', message: 'Bearer token is invalid' } });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: payload.id },
      select: { id: true, email: true, role: true },
    });
    if (!user) {
      if (isDev) {
        req.user = { id: payload.id, email: payload.email, role: payload.role || 'Developer' };
        return next();
      }
      return res.status(401).json({ error: { code: 'UNKNOWN_USER', message: 'Token user is no longer active' } });
    }
    req.user = user;
    return next();
  } catch (err) {
    if (!isDev) return sendError(res, serviceUnavailable('auth.user_lookup_failed', err), 'auth.user_lookup_failed');
    logStructuredError('auth.user_lookup_failed', err, {}, 'warning');
    req.user = { id: payload.id, email: payload.email, role: payload.role || 'Developer' };
    return next();
  }
}

function requireRole(...allowedRoles) {
  return (req, res, next) => allowedRoles.includes(req.user?.role)
    ? next()
    : res.status(403).json({ error: 'Your role is not permitted to perform this action' });
}

module.exports = { requireAuth, requireRole, ROLES };
