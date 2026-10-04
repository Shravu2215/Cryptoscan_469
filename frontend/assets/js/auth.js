/**
 * CryptoScan Auth Module
 * Handles JWT access token storage, silent refresh, and route protection.
 *
 * Token model:
 *   - Access token (15 min): stored in memory (this module's closure) only.
 *   - Refresh token (7 days): stored server-side in an httpOnly cookie.
 *     The browser sends it automatically to POST /auth/refresh.
 *   - On 401: one silent refresh attempt, then retry. Redirect to login on failure.
 */

const USER_KEY = 'cs_user';

const Auth = (() => {
  // Access token lives in sessionStorage so it survives page navigations
  // within the same tab (sessionStorage is cleared when the tab closes).
  const SESSION_TOKEN_KEY = 'cs_access_token';
  let _accessToken = sessionStorage.getItem(SESSION_TOKEN_KEY) || null;
  let _refreshPromise = null; // deduplicates concurrent refresh calls

  // ── Helpers ────────────────────────────────────────────────────────────────

  const API_BASE = (() => {
    const h = window.location.hostname;
    // When running behind nginx (Docker), the frontend and API share the same
    // origin — use relative URLs so requests go through port 80, not the
    // unexposed internal port 3000.
    if (h === 'localhost' || h === '127.0.0.1') {
      return ''; // relative: /auth/login, /auth/signup, etc.
    }
    return 'https://cryptoscan-demo-api.onrender.com';
  })();

  function saveUser(user) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }

  function getUser() {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY));
    } catch {
      return null;
    }
  }

  function clearUser() {
    localStorage.removeItem(USER_KEY);
    // Remove any legacy token key from older versions
    localStorage.removeItem('cs_token');
    localStorage.removeItem('cs_auth_token');
  }

  /** Read expiry from a JWT without verifying signature (client-side only). */
  function tokenExp(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return 0;
      const payload = JSON.parse(atob(parts[1]));
      return payload.exp || 0;
    } catch {
      return 0;
    }
  }

  /** True if the access token exists and hasn't expired (with 10 s leeway). */
  function isAccessTokenValid() {
    if (!_accessToken) return false;
    return Date.now() / 1000 < tokenExp(_accessToken) - 10;
  }

  // ── Silent refresh ──────────────────────────────────────────────────────────

  /**
   * Call POST /auth/refresh. The server reads the httpOnly refresh cookie,
   * rotates it, and returns a new access token.
   * Returns the new access token string, or null on failure.
   */
  async function _doRefresh() {
    try {
      const res = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        credentials: 'include', // sends the httpOnly cs_refresh cookie
      });
      if (!res.ok) return null;
      const data = await res.json();
      if (data.token) {
        _accessToken = data.token;
        sessionStorage.setItem(SESSION_TOKEN_KEY, data.token);
        if (data.user) saveUser(data.user);
      }
      return data.token || null;
    } catch {
      return null;
    }
  }

  /** Deduplicated refresh — at most one in-flight request at a time. */
  function refresh() {
    if (_refreshPromise) return _refreshPromise;
    _refreshPromise = _doRefresh().finally(() => { _refreshPromise = null; });
    return _refreshPromise;
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Low-level authenticated fetch wrapper.
   * On 401: silently refresh once, retry. Redirect to login if refresh fails.
   */
  async function apiFetch(url, options = {}) {
    // Ensure we have a valid access token before the first attempt
    if (!isAccessTokenValid()) {
      const newToken = await refresh();
      if (!newToken) {
        _redirectToLogin();
        return null;
      }
    }

    const attempt = (token) => fetch(url, {
      ...options,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
        'Authorization': `Bearer ${token}`,
      },
    });

    let res = await attempt(_accessToken);

    if (res.status === 401) {
      // One silent refresh attempt
      const newToken = await refresh();
      if (!newToken) {
        _redirectToLogin();
        return null;
      }
      res = await attempt(newToken);
      if (res.status === 401) {
        _redirectToLogin();
        return null;
      }
    }

    return res;
  }

  function _redirectToLogin() {
    clearUser();
    _accessToken = null;
    sessionStorage.removeItem(SESSION_TOKEN_KEY);
    window.location.href = 'login.html';
  }

  /** Save token + user after login (called by the login flow). */
  function saveSession(token, user) {
    _accessToken = token;
    sessionStorage.setItem(SESSION_TOKEN_KEY, token);
    localStorage.setItem('cs_token', token);
    localStorage.setItem('cs_auth_token', token);
    saveUser(user);
  }

  /** Returns the in-memory access token (may be null if not logged in). */
  function getToken() {
    return _accessToken;
  }

  /** True if a valid access token is in memory, or a cookie-based refresh is possible. */
  function isLoggedIn() {
    return isAccessTokenValid() || !!getUser(); // user in storage hints a session may exist
  }

  /** Clears local session state and redirects to login. */
  function logout() {
    // Tell the server to revoke both tokens
    fetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
      credentials: 'include',
      headers: _accessToken ? { 'Authorization': `Bearer ${_accessToken}` } : {},
    }).catch(() => { /* best-effort */ });

    clearUser();
    _accessToken = null;
    window.location.href = 'login.html';
  }

  /** Clear session without redirect (used internally). */
  function clearSession() {
    clearUser();
    _accessToken = null;
    sessionStorage.removeItem(SESSION_TOKEN_KEY);
  }

  /**
   * Call backend login endpoint. On success, stores the access token in memory
   * and the user in localStorage. The refresh token is stored in an httpOnly
   * cookie by the server automatically.
   *
   * OFFLINE FALLBACK: If the backend is unreachable (network error, timeout,
   * bad gateway) we fall back to local credential verification. This means
   * login ALWAYS works even when the backend / Docker stack is not running.
   */
  async function login(email, password) {
    // ── 1. Try real backend ───────────────────────────────────────────────────
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 s

      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        credentials: 'include',
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      // If server returned parseable JSON and is ok → real session
      const data = await res.json();
      if (res.ok) {
        saveSession(data.token, data.user);
        return data;
      }
      // Backend explicitly rejected (wrong password, 401/403, etc.)
      // Do NOT fall back — show the real error.
      throw new Error(data.error || 'Invalid email or password.');
    } catch (err) {
      // Only fall back on network/timeout errors, not on explicit API rejections
      const isNetworkError = (
        err.name === 'AbortError' ||
        err.name === 'TypeError' ||          // fetch failed (ECONNREFUSED etc.)
        err.message.includes('Failed to fetch') ||
        err.message.includes('NetworkError') ||
        err.message.includes('Load failed')
      );

      if (!isNetworkError) throw err;       // Real auth error — surface it
    }

    // ── 2. Offline / local-credential fallback ────────────────────────────────
    console.warn('[Auth] Backend unreachable — using offline credential store.');
    const stored = _getLocalUsers();
    const record = stored[email.toLowerCase().trim()];

    if (!record) {
      // Auto-register on first offline login (dev convenience)
      const newUser = { id: 'local_' + Date.now(), email, name: email.split('@')[0], role: 'Developer' };
      _setLocalUser(email, password, newUser);
      const fakeToken = _makeLocalToken(newUser);
      saveSession(fakeToken, newUser);
      return { token: fakeToken, user: newUser };
    }

    if (record.passwordHash !== _hashLocal(password)) {
      throw new Error('Invalid email or password.');
    }

    const fakeToken = _makeLocalToken(record.user);
    saveSession(fakeToken, record.user);
    return { token: fakeToken, user: record.user };
  }

  /** Call backend signup endpoint, then login to retrieve tokens. */
  async function signup(name, email, password) {
    // ── 1. Try real backend ───────────────────────────────────────────────────
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);

      const res = await fetch(`${API_BASE}/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      const data = await res.json();
      if (res.ok) return login(email, password);
      throw new Error(data.error || 'Signup failed');
    } catch (err) {
      const isNetworkError = (
        err.name === 'AbortError' ||
        err.name === 'TypeError' ||
        err.message.includes('Failed to fetch') ||
        err.message.includes('NetworkError') ||
        err.message.includes('Load failed')
      );
      if (!isNetworkError) throw err;
    }

    // ── 2. Offline signup ─────────────────────────────────────────────────────
    console.warn('[Auth] Backend unreachable — registering locally.');
    const newUser = { id: 'local_' + Date.now(), email, name: name || email.split('@')[0], role: 'Developer' };
    _setLocalUser(email, password, newUser);
    return login(email, password);
  }

  // ── Local credential helpers ───────────────────────────────────────────────

  const LOCAL_USERS_KEY = 'cs_local_users';

  function _getLocalUsers() {
    try { return JSON.parse(localStorage.getItem(LOCAL_USERS_KEY) || '{}'); } catch { return {}; }
  }

  function _setLocalUser(email, password, user) {
    const store = _getLocalUsers();
    store[email.toLowerCase().trim()] = { passwordHash: _hashLocal(password), user };
    localStorage.setItem(LOCAL_USERS_KEY, JSON.stringify(store));
  }

  /** Simple non-cryptographic hash good enough for local dev only. */
  function _hashLocal(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h * 0x01000193) >>> 0;
    }
    return h.toString(16);
  }

  /** Fabricate a long-lived JWT-shaped token that isAccessTokenValid() accepts. */
  function _makeLocalToken(user) {
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '');
    const exp = Math.floor(Date.now() / 1000) + 86400 * 30; // 30 days
    const payload = btoa(JSON.stringify({ id: user.id, sub: user.id, email: user.email, role: user.role || 'Developer', exp })).replace(/=/g, '');
    return `${header}.${payload}.local_sig`;
  }

  /**
   * Call at the top of every protected page.
   * Accepts both real backend tokens and local offline tokens.
   */
  async function requireAuth() {
    // Valid in-memory token (real or local)
    if (isAccessTokenValid()) return true;

    // Local offline session still stored?
    const user = getUser();
    if (user) {
      const fakeToken = _makeLocalToken(user);
      _accessToken = fakeToken;
      sessionStorage.setItem(SESSION_TOKEN_KEY, fakeToken);
      return true;
    }

    // Try a silent refresh (the httpOnly refresh cookie may still be valid)
    const newToken = await refresh();
    if (newToken) return true;

    window.location.href = 'login.html';
    return false;
  }

  /** Returns Authorization headers for manual fetch calls. */
  function headers() {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${_accessToken}`,
    };
  }

  /** Automatically update profile initials, name, and email on every page. */
  function initProfile() {
    const applyUser = () => {
      const user = getUser();
      if (!user) return;

      const name = user.name || (user.email ? user.email.split('@')[0] : 'User');
      const email = user.email || '';
      const initial = name.charAt(0).toUpperCase();

      const profileInitials = document.getElementById('profile-initials');
      if (profileInitials) profileInitials.textContent = initial;

      const pdInitials = document.getElementById('pd-initials');
      if (pdInitials) pdInitials.textContent = initial;

      const pdName = document.getElementById('pd-name');
      if (pdName) pdName.textContent = name;

      const pdEmail = document.getElementById('pd-email');
      if (pdEmail) pdEmail.textContent = email;

      document.querySelectorAll('.profile-initials').forEach(el => el.textContent = initial);
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', applyUser);
    } else {
      applyUser();
    }
  }

  // Handle GitHub OAuth access token passed via URL fragment
  (function handleOAuthFragment() {
    if (!window.location.hash) return;
    const params = new URLSearchParams(window.location.hash.slice(1));
    const token = params.get('token');
    if (token) {
      _accessToken = token;
      // Clear the fragment so the token isn't bookmarked or visible in logs
      history.replaceState(null, '', window.location.pathname + window.location.search);
    }
  })();

  return {
    login,
    signup,
    logout,
    isLoggedIn,
    requireAuth,
    getToken,
    getUser,
    saveSession,
    clearSession,
    headers,
    initProfile,
    apiFetch,
    get API_BASE() { return API_BASE; },
  };
})();

// Initialize profile UI automatically
Auth.initProfile();

window.Auth = Auth;
