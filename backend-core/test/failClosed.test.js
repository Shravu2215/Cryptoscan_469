'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const jwt = require('jsonwebtoken');
const AdmZip = require('adm-zip');

process.env.NODE_ENV = 'production';
process.env.USE_MOCK = 'false';
process.env.JWT_SECRET = 'fail-closed-test-secret-with-more-than-32-characters';

const prisma = require('../src/utils/prismaClient');
const { auditMiddleware } = require('../src/services/auditLog');
const authRouter = require('../src/routes/auth');
const reposRouter = require('../src/routes/repos');
const anchorScript = require('../../blockchain-module/scripts/anchor');
let failChainAnchor = false;
anchorScript.anchorCBOM = async () => {
  if (failChainAnchor) throw Object.assign(new Error('simulated chain failure'), { code: 'CHAIN_UNAVAILABLE' });
  return {
    merkleRoot: '0x' + '1'.repeat(64),
    txHash: '0x' + '2'.repeat(64),
    signature: 'test-signature',
    network: 'testnet',
    blockNumber: 1,
  };
};
const scansRouter = require('../src/routes/scans');

const USER = { id: 'test-user', email: 'test@example.test', role: 'Developer' };
const REPO = { id: 'repo-prod-test', name: 'prod-test', uploadedBy: USER.id, filePath: '.' };
const SCAN = {
  id: 'scan-prod-test',
  repoId: REPO.id,
  status: 'COMPLETED',
  createdAt: new Date('2026-01-02T00:00:00.000Z'),
  repo: REPO,
};
const dbError = () => Object.assign(new Error('simulated database unavailable'), { code: 'P1001' });

let failAuditWrite = false;
let failScanCreate = true;
prisma.user.findUnique = async ({ where }) => {
  if (where.id) return { ...USER };
  if (where.email === 'signup@example.test') return null;
  throw dbError();
};
prisma.user.create = async () => { throw dbError(); };
prisma.repo.create = async () => { throw dbError(); };
prisma.repo.findFirst = async () => ({ ...REPO });
prisma.scan.create = async ({ data }) => {
  if (failScanCreate) throw dbError();
  return { ...SCAN, ...data };
};
prisma.scan.findFirst = async () => ({ ...SCAN });
prisma.scan.findMany = async () => [];
prisma.scan.update = async ({ data }) => {
  return { ...SCAN, ...data };
};
prisma.finding.findMany = async () => [];
prisma.finding.createMany = async () => ({ count: 0 });
prisma.anchor.upsert = async () => { throw dbError(); };
prisma.anchor.findUnique = async () => { throw dbError(); };
prisma.auditLog.findFirst = async () => {
  if (failAuditWrite) throw dbError();
  return null;
};
prisma.auditLog.create = async ({ data }) => {
  if (failAuditWrite) throw dbError();
  return { ...data, id: 'audit-test', createdAt: new Date() };
};

const token = jwt.sign(USER, process.env.JWT_SECRET);
async function request(base, route, options = {}) {
  const response = await fetch(base + route, options);
  const text = await response.text();
  let body;
  try { body = JSON.parse(text); } catch (_) { body = text; }
  return { status: response.status, body };
}

function assert503(response, label) {
  assert.equal(response.status, 503, `${label} returns 503; received ${JSON.stringify(response.body)}`);
  assert.equal(response.body?.error?.code, 'SERVICE_UNAVAILABLE', `${label} returns structured service error`);
}

async function main() {
  const app = express();
  app.use(express.json());
  app.use(auditMiddleware);
  app.use('/auth', authRouter);
  app.use('/repos', reposRouter);
  app.use('/scan', scansRouter);
  app.post('/test/state-change', (req, res) => res.status(201).json({ ok: true }));

  const server = app.listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const uploadsDir = path.resolve(__dirname, '../uploads');
  const beforeFiles = new Set(fs.readdirSync(uploadsDir));
  const originalFetch = global.fetch;

  try {
    const headers = { Authorization: `Bearer ${token}` };
    const unsignedToken = `x.${Buffer.from(JSON.stringify(USER)).toString('base64url')}.x`;
    const unsignedResponse = await request(base, '/repos', {
      headers: { Authorization: `Bearer ${unsignedToken}` },
    });
    assert.equal(unsignedResponse.status, 401, 'production rejects unsigned JWT payloads');


    const uploadForm = new FormData();
    uploadForm.append('repo', new Blob(['test zip bytes'], { type: 'application/zip' }), 'db-down.zip');
    assert503(await request(base, '/repos/upload', { method: 'POST', headers, body: uploadForm }), 'repo upload');

    const archive = new AdmZip();
    archive.addFile('repo/file.txt', Buffer.from('test repository'));
    const archiveBuffer = archive.toBuffer();
    global.fetch = async (url, options) => {
      if (String(url).startsWith('https://api.github.com/')) {
        return new Response(JSON.stringify({
          archived: false,
          default_branch: 'main',
          full_name: 'owner/repo',
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (String(url).startsWith('https://codeload.github.com/')) {
        return new Response(archiveBuffer, { status: 200 });
      }
      return originalFetch(url, options);
    };
    assert503(await request(base, '/repos/github', {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://github.com/owner/repo' }),
    }), 'repo import');

    assert503(await request(base, `/scan/${REPO.id}`, { method: 'POST', headers }), 'scan start');
    failChainAnchor = true;
    assert503(await request(base, `/scan/${SCAN.id}/anchor`, { method: 'POST', headers }), 'chain anchor failure');
    failChainAnchor = false;
    assert503(await request(base, `/scan/${SCAN.id}/anchor`, { method: 'POST', headers }), 'anchor persistence');
    assert503(await request(base, `/scan/${SCAN.id}/verify`, { headers }), 'verify DB read');

    assert503(await request(base, '/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'signup@example.test', password: 'TestPass123!' }),
    }), 'signup');
    assert503(await request(base, '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'login@example.test', password: 'TestPass123!' }),
    }), 'login');

    // P0-6: scan dispatch now requires Redis (BullMQ queue).
    // With no Redis available in this test environment the endpoint must fail
    // closed rather than accept the request and silently drop the job.
    // The full worker failure path (FAILED persistence when completion write
    // fails) is exercised by scanSecurity.test.js with a live queue.
    failScanCreate = false;
    assert503(
      await request(base, `/scan/${REPO.id}`, { method: 'POST', headers }),
      'scan start with Redis queue unavailable',
    );

    failAuditWrite = true;
    assert503(await request(base, '/test/state-change', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: 'change' }),
    }), 'state-changing request with audit DB failure');
    failAuditWrite = false;

    const startupEnv = {
      ...process.env,
      NODE_ENV: 'production',
      JWT_SECRET: 'production-startup-test-secret-over-32-chars',
      JWT_ACCESS_SECRET: 'production-access-secret-over-32-chars-long',
      JWT_REFRESH_SECRET: 'production-refresh-secret-over-32-chars-long',
      // Deliberately omit REDIS_URL so the server cannot connect
      DATABASE_URL: 'postgresql://test:test@127.0.0.1:5432/test',
      DATA_ENCRYPTION_KEY: Buffer.alloc(32).toString('base64'),
      ALLOWED_ORIGINS: 'http://localhost',
      KMS_PROVIDER: 'aws-kms',
    };
    // Remove REDIS_URL so the startup validation catches it
    delete startupEnv.REDIS_URL;
    const startup = spawnSync(process.execPath, ['src/server.js'], {
      cwd: path.resolve(__dirname, '..'),
      env: startupEnv,
      encoding: 'utf8',
      timeout: 15000,
    });
    assert.equal(startup.status, 1, 'production app refuses to boot with missing required configuration');
    assert.match(
      startup.stderr + startup.stdout,
      /REDIS_URL must be set in production|Refusing to start|FATAL ERROR/,
    );

    console.log('PASS: repo upload/import, scan start, anchor, verify, signup, and login return structured 503');
    console.log('PASS: production rejects unsigned JWTs and chain-anchor failures do not synthesize success');
    console.log('PASS: state-changing requests fail with 503 when audit persistence fails');
    console.log('PASS: production startup refuses incomplete configuration');
  } finally {
    global.fetch = originalFetch;
    failAuditWrite = false;
    for (const entry of fs.readdirSync(uploadsDir)) {
      if (!beforeFiles.has(entry)) fs.rmSync(path.join(uploadsDir, entry), { recursive: true, force: true });
    }
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});