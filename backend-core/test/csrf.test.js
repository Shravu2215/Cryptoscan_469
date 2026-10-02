'use strict';

const assert = require('node:assert/strict');
const express = require('express');
const cookieParser = require('cookie-parser');
const csrfCheck = require('../src/utils/csrf');

async function main() {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());

  app.post('/auth/refresh', csrfCheck, (req, res) => res.json({ status: 'ok' }));
  app.post('/auth/logout', csrfCheck, (req, res) => res.json({ status: 'ok' }));

  const server = app.listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  try {
    // 1. Without header -> 403 CSRF_REJECTED
    const res1 = await fetch(`${base}/auth/refresh`, { method: 'POST' });
    assert.equal(res1.status, 403);
    const body1 = await res1.json();
    assert.equal(body1.error.code, 'CSRF_REJECTED');

    // 2. With invalid header -> 403 CSRF_REJECTED
    const res2 = await fetch(`${base}/auth/refresh`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'InvalidApp' },
    });
    assert.equal(res2.status, 403);

    // 3. With correct header -> 200 OK
    const res3 = await fetch(`${base}/auth/refresh`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'CryptoScan' },
    });
    assert.equal(res3.status, 200);

    // 4. Logout with correct header -> 200 OK
    const res4 = await fetch(`${base}/auth/logout`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'CryptoScan' },
    });
    assert.equal(res4.status, 200);

    console.log('PASS: CSRF header check enforces X-Requested-With: CryptoScan and rejects missing/invalid headers with 403');
  } finally {
    await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
  }
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
