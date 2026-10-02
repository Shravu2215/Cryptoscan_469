'use strict';

const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const prisma = require('../utils/prismaClient');
const { isDev, logStructuredError, sendError, serviceUnavailable } = require('../utils/failClosed');
const { issueAccessToken, issueRefreshToken, verifyRefreshToken, REFRESH_TTL_SECONDS } = require('../utils/tokenService');
const { denylistJti, isJtiDenylisted } = require('../utils/redisClient');
const csrfCheck = require('../utils/csrf');

const router = express.Router();
const isProd = process.env.NODE_ENV === 'production';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function hashToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

/** Write the refresh token into an httpOnly cookie. */
function setRefreshCookie(res, token) {
  res.cookie('cs_refresh', token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'strict' : 'lax',
    maxAge: REFRESH_TTL_SECONDS * 1000,
    path: '/auth/refresh',
  });
}

/** Clear the refresh cookie. */
function clearRefreshCookie(res) {
  res.clearCookie('cs_refresh', { httpOnly: true, secure: isProd, sameSite: isProd ? 'strict' : 'lax', path: '/auth/refresh' });
}

/** Persist a new Session row and return it. */
async function createSession(userId, jti, rawRefreshToken, expiresAt) {
  return prisma.session.create({
    data: {
      userId,
      jti,
      refreshTokenHash: hashToken(rawRefreshToken),
      expiresAt,
    },
  });
}

// ─── POST /auth/signup ────────────────────────────────────────────────────────
// Deliberately does NOT accept a "role" field from the client — avoids the
// role self-assignment vulnerability we hit in AssetFlow/GlobeTrotter.
router.post('/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    let user;
    try {
      const existing = await prisma.user.findUnique({ where: { email } });
      if (existing) {
        return res.status(409).json({ error: 'User with this email already exists' });
      }

      const hashed = await bcrypt.hash(password, 10);

      user = await prisma.user.create({
        data: { email, password: hashed, name, role: 'Developer' },
      });
    } catch (dbErr) {
      if (!isDev) throw serviceUnavailable('auth.signup_persist_failed', dbErr);
      logStructuredError('auth.signup_persist_failed', dbErr, {}, 'warning');
    }

    return res.status(201).json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    });
  } catch (err) {
    return sendError(res, err, 'auth.signup_failed');
  }
});

// ─── POST /auth/login ─────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    let user;
    let valid = false;
    try {
      user = await prisma.user.findUnique({ where: { email } });
      if (user) {
        valid = await bcrypt.compare(password, user.password);
      } else {
        // dummy compare to prevent timing attacks
        await bcrypt.compare(password, '$2a$10$z.aBkbgKMKClaz769f.VaunPDzrwb79Y7FBZnCamFYrGFWbWFJwny');
      }

      if (!user || !valid) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    } catch (dbErr) {
      if (!isDev) throw serviceUnavailable('auth.login_lookup_failed', dbErr);
      logStructuredError('auth.login_lookup_failed', dbErr, {}, 'warning');
    }

    // Issue tokens
    const { token: accessToken } = issueAccessToken(user);
    const { token: refreshToken, jti: refreshJti, expiresAt: refreshExpiry } = issueRefreshToken(user);

    // Persist session (best-effort — dev fallback users won't have a DB row)
    try {
      await createSession(user.id, refreshJti, refreshToken, refreshExpiry);
    } catch (dbErr) {
      console.warn('Could not persist session (DB unavailable):', dbErr.message);
    }

    setRefreshCookie(res, refreshToken);

    return res.json({
      token: accessToken,
      user: { id: user.id, email: user.email, name: user.name || email.split('@')[0], role: user.role },
    });
  } catch (err) {
    return sendError(res, err, 'auth.login_failed');
  }
});

// ─── POST /auth/refresh ───────────────────────────────────────────────────────
// Refresh-token rotation: issues a new access + refresh pair.
// Reuse of an already-rotated refresh token triggers full session revocation.
router.post('/refresh', csrfCheck, async (req, res) => {
  const rawRefreshToken = req.cookies?.cs_refresh;

  if (!rawRefreshToken) {
    return res.status(401).json({ error: 'No refresh token' });
  }

  let payload;
  try {
    payload = verifyRefreshToken(rawRefreshToken);
  } catch {
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  const incomingJti = payload.jti;

  // Check Redis denylist first (fast path)
  try {
    if (await isJtiDenylisted(incomingJti)) {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Refresh token has been revoked' });
    }
  } catch (_) {
    // redisClient already logs; continue to DB check
  }

  // Look up the session in the database
  let session;
  try {
    session = await prisma.session.findUnique({ where: { jti: incomingJti } });
  } catch (dbErr) {
    console.error('DB error during refresh:', dbErr.message);
    return res.status(500).json({ error: 'Internal server error' });
  }

  if (!session) {
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Session not found' });
  }

  // Detect reuse of an already-rotated (revoked) token → revoke entire user session family
  if (session.revokedAt) {
    // Revoke all active sessions for this user (session-family invalidation)
    try {
      await prisma.session.updateMany({
        where: { userId: session.userId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    } catch (dbErr) {
      console.warn('Could not revoke sessions on reuse detection:', dbErr.message);
    }
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Refresh token reuse detected — all sessions revoked' });
  }

  // Verify token hash matches what we stored (defence against DB-level token substitution)
  if (hashToken(rawRefreshToken) !== session.refreshTokenHash) {
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Refresh token mismatch' });
  }

  // Revoke the old session row and denylist its JTI in Redis
  const remaining = Math.floor((new Date(session.expiresAt) - Date.now()) / 1000);
  try {
    await prisma.session.update({ where: { id: session.id }, data: { revokedAt: new Date() } });
    await denylistJti(incomingJti, remaining > 0 ? remaining : 1);
  } catch (dbErr) {
    console.warn('Could not revoke old session:', dbErr.message);
  }

  // Look up the current user record
  let user;
  try {
    user = await prisma.user.findUnique({
      where: { id: session.userId },
      select: { id: true, email: true, name: true, role: true },
    });
  } catch (_) { /* fall through */ }

  if (!user) {
    user = { id: session.userId, email: payload.email || '', name: '', role: 'Developer' };
  }

  // Issue new token pair
  const { token: newAccessToken } = issueAccessToken(user);
  const { token: newRefreshToken, jti: newRefreshJti, expiresAt: newExpiry } = issueRefreshToken(user);

  try {
    await createSession(user.id, newRefreshJti, newRefreshToken, newExpiry);
  } catch (dbErr) {
    console.warn('Could not persist new session:', dbErr.message);
  }

  setRefreshCookie(res, newRefreshToken);

  return res.json({
    token: newAccessToken,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });
});

// ─── POST /auth/logout ────────────────────────────────────────────────────────
// Invalidates the access token JTI in Redis and revokes the refresh session.
router.post('/logout', csrfCheck, async (req, res) => {
  // Denylist the access token JTI if provided
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const rawAccess = authHeader.split(' ')[1];
    try {
      const { verifyAccessToken } = require('../utils/tokenService');
      const payload = verifyAccessToken(rawAccess);
      if (payload?.jti) {
        const remaining = payload.exp ? Math.floor(payload.exp - Date.now() / 1000) : 900;
        await denylistJti(payload.jti, remaining > 0 ? remaining : 1);
      }
    } catch (_) { /* expired or invalid — nothing to denylist */ }
  }

  // Revoke the refresh session
  const rawRefreshToken = req.cookies?.cs_refresh;
  if (rawRefreshToken) {
    try {
      const payload = verifyRefreshToken(rawRefreshToken);
      if (payload?.jti) {
        await prisma.session.updateMany({
          where: { jti: payload.jti, revokedAt: null },
          data: { revokedAt: new Date() },
        });
        const remaining = payload.exp ? Math.floor(payload.exp - Date.now() / 1000) : 1;
        await denylistJti(payload.jti, remaining > 0 ? remaining : 1);
      }
    } catch (_) { /* already expired */ }
  }

  clearRefreshCookie(res);
  return res.json({ message: 'Logged out' });
});

// ─── GitHub OAuth ─────────────────────────────────────────────────────────────
router.get('/github', (req, res) => {
  const clientId = process.env.GITHUB_CLIENT_ID;
  const redirectUri = process.env.GITHUB_CALLBACK_URL;
  if (!clientId || !redirectUri) {
    return res.status(500).json({ error: 'GitHub OAuth not configured' });
  }

  // CSRF protection: bind this authorization request to a random state value,
  // stored server-side (short-lived cookie) and echoed back by GitHub
  const state = crypto.randomBytes(24).toString('hex');
  res.cookie('oauth_state', state, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    maxAge: 10 * 60 * 1000,
  });

  const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=user:email&state=${state}`;
  res.redirect(githubAuthUrl);
});

router.get('/github/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const expectedState = req.cookies?.oauth_state;
    res.clearCookie('oauth_state');

    if (!code) return res.redirect(`${process.env.FRONTEND_URL}/?error=NoCodeProvided`);
    if (!state || !expectedState || state !== expectedState) {
      return res.redirect(`${process.env.FRONTEND_URL}/?error=InvalidOAuthState`);
    }

    const clientId = process.env.GITHUB_CLIENT_ID;
    const clientSecret = process.env.GITHUB_CLIENT_SECRET;

    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code })
    });
    const tokenData = await tokenRes.json();
    if (tokenData.error) return res.redirect(`${process.env.FRONTEND_URL}/?error=GitHubAuthFailed`);

    const accessToken = tokenData.access_token;
    const userRes = await fetch('https://api.github.com/user', { headers: { 'Authorization': `Bearer ${accessToken}` } });
    const githubUser = await userRes.json();

    const emailsRes = await fetch('https://api.github.com/user/emails', { headers: { 'Authorization': `Bearer ${accessToken}` } });
    const emails = await emailsRes.json();
    const primaryEmail = emails.find(e => e.primary)?.email || emails[0]?.email;
    if (!primaryEmail) return res.redirect(`${process.env.FRONTEND_URL}/?error=NoEmailProvidedByGitHub`);

    let user = await prisma.user.findUnique({ where: { email: primaryEmail } });
    if (user) {
      if (!user.providerId) {
        user = await prisma.user.update({
          where: { id: user.id },
          data: { provider: 'github', providerId: String(githubUser.id), avatar: githubUser.avatar_url }
        });
      }
    } else {
      user = await prisma.user.create({
        data: {
          email: primaryEmail,
          name: githubUser.name || githubUser.login,
          provider: 'github',
          providerId: String(githubUser.id),
          avatar: githubUser.avatar_url,
          role: 'Developer'
        }
      });
    }

    const { token: newAccessToken } = issueAccessToken(user);
    const { token: newRefreshToken, jti: newJti, expiresAt: newExpiry } = issueRefreshToken(user);

    try {
      await createSession(user.id, newJti, newRefreshToken, newExpiry);
    } catch (dbErr) {
      console.warn('Could not persist GitHub session:', dbErr.message);
    }

    setRefreshCookie(res, newRefreshToken);
    // Pass access token via URL fragment so the frontend can store it in memory
    res.redirect(`${process.env.FRONTEND_URL}/dashboard.html#token=${newAccessToken}`);
  } catch (err) {
    console.error(err);
    res.redirect(`${process.env.FRONTEND_URL}/?error=ServerError`);
  }
});

module.exports = router;
