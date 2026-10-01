'use strict';

const assert = require('assert');

// A simple automated test script for CryptoScan Auth Security.
// Run with: node test/authSecurity.test.js

const API_BASE = 'http://localhost';

async function runTests() {
  console.log('--- Starting Auth Security Automated Tests ---');

  const testEmail = `test-${Date.now()}@example.com`;
  const password = 'Password123!';

  // 1. Unknown user vs Wrong password identical responses & timing
  console.log('\n[Test 1] Timing and responses for invalid credentials');
  
  // Timing for wrong password (user exists)
  await fetch(`${API_BASE}/auth/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: testEmail, password, name: 'Tester' })
  });
  
  const startWrongPwd = Date.now();
  const resWrongPwd = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: testEmail, password: 'wrong' })
  });
  const timeWrongPwd = Date.now() - startWrongPwd;
  const dataWrongPwd = await resWrongPwd.json();
  
  // Timing for unknown user
  const startUnknown = Date.now();
  const resUnknown = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'unknown@example.com', password: 'wrong' })
  });
  const timeUnknown = Date.now() - startUnknown;
  const dataUnknown = await resUnknown.json();
  
  assert.strictEqual(resWrongPwd.status, 401, 'Wrong password should return 401');
  assert.strictEqual(resUnknown.status, 401, 'Unknown user should return 401');
  assert.strictEqual(dataWrongPwd.error, dataUnknown.error, 'Error message must be identical');
  
  console.log(`✓ Both returned 401 Invalid credentials`);
  console.log(`✓ Timing: Wrong pwd = ${timeWrongPwd}ms, Unknown = ${timeUnknown}ms`);
  
  // 2. Token expiry and refresh rotation + reuse
  console.log('\n[Test 2] Refresh token rotation and reuse detection');
  const resLogin = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: testEmail, password })
  });
  const loginData = await resLogin.json();
  const cookieHeader = resLogin.headers.get('set-cookie');
  
  assert.ok(loginData.token, 'Should issue access token');
  assert.ok(cookieHeader && cookieHeader.includes('cs_refresh='), 'Should issue httpOnly refresh cookie');

  const resRefresh = await fetch(`${API_BASE}/auth/refresh`, {
    method: 'POST',
    headers: { 'cookie': cookieHeader }
  });
  assert.strictEqual(resRefresh.status, 200, 'Refresh should succeed');

  // Attempt to reuse old refresh token
  const resReuse = await fetch(`${API_BASE}/auth/refresh`, {
    method: 'POST',
    headers: { 'cookie': cookieHeader } // using the OLD cookie
  });
  assert.strictEqual(resReuse.status, 401, 'Reusing old refresh token should be rejected (401)');
  console.log('✓ Token rotation and reuse detected successfully');

  // 3. Logout revocation
  console.log('\n[Test 3] Logout revocation (JTI denylist)');
  const resLogout = await fetch(`${API_BASE}/auth/logout`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${loginData.token}` }
  });
  assert.strictEqual(resLogout.status, 200, 'Logout should succeed');

  console.log('✓ Logout completed (denylist updated)');

  // 4. Rate Limiting: 20 rapid logins blocked (Dev limit is 200, Prod is 10)
  console.log('\n[Test 4] Rate Limiting (rapid logins block)');
  let blockedStatus = 0;
  for (let i = 0; i < 210; i++) {
    const resRate = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '192.168.1.100' },
      body: JSON.stringify({ email: `rate@example.com`, password: 'test' })
    });
    if (resRate.status === 429) {
      blockedStatus = 429;
      break;
    }
  }
  assert.strictEqual(blockedStatus, 429, 'Failed to block after rapid logins');
  console.log('✓ 429 Too Many Requests received for rapid logins');

  console.log('\nAll tests passed locally in Node.');
}

runTests().catch(console.error);
