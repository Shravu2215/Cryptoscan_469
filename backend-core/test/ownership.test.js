'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const express = require('express');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = 'ownership-integration-test-secret-32-characters';
process.env.USE_MOCK = 'true';

const prisma = require('../src/utils/prismaClient');
const devStore = require('../src/utils/devStore');
const reposRouter = require('../src/routes/repos');
const scansRouter = require('../src/routes/scans');

const USER_A = { id: 'user-a', email: 'a@example.test', role: 'Developer' };
const USER_B = { id: 'user-b', email: 'b@example.test', role: 'Developer' };
const ADMIN = { id: 'user-admin', email: 'admin@example.test', role: 'Admin' };
const REPO = {
  id: 'repo-a',
  name: 'private-repo',
  filePath: '.',
  uploadedBy: USER_A.id,
  businessCriticality: 'Standard',
  createdAt: new Date('2026-01-01T00:00:00.000Z'),
};
const SCAN = {
  id: 'scan-a',
  repoId: REPO.id,
  status: 'COMPLETED',
  createdAt: new Date('2026-01-02T00:00:00.000Z'),
  completedAt: new Date('2026-01-02T00:01:00.000Z'),
  filesScanned: 1,
};
const FINDING = {
  id: 'finding-a',
  scanId: SCAN.id,
  filePath: 'src/example.js',
  lineNumber: 1,
  algorithm: 'RSA',
  severity: 'HIGH',
  quantumStatus: 'Quantum Vulnerable',
  usage: 'Key exchange',
  description: 'Test finding',
  status: 'ACTIVE',
};
const ANCHOR = {
  scanId: SCAN.id,
  contentHash: '0x1234',
  txHash: '0x5678',
  signature: 'test-signature',
  network: 'testnet',
  blockNumber: 1,
};

const repos = new Map([[REPO.id, { ...REPO }]]);
const scans = new Map([[SCAN.id, { ...SCAN }]]);
const findings = new Map([[FINDING.id, { ...FINDING }]]);
const anchors = new Map([[ANCHOR.scanId, { ...ANCHOR }]]);

function repoMatches(repo, where) {
  if (where.id && repo.id !== where.id) return false;
  if (where.uploadedBy && repo.uploadedBy !== where.uploadedBy) return false;
  if (where.OR && !where.OR.some(condition => repo.name === condition.name)) return false;
  return true;
}

function scanMatches(scan, where) {
  if (where.id && scan.id !== where.id) return false;
  if (where.repoId && scan.repoId !== where.repoId) return false;
  if (where.repo && !repoMatches(repos.get(scan.repoId), where.repo)) return false;
  return true;
}

function findingMatches(finding, where) {
  if (where.id && finding.id !== where.id) return false;
  if (where.scanId && finding.scanId !== where.scanId) return false;
  if (where.scan) {
    const scan = scans.get(finding.scanId);
    if (!scan || !scanMatches(scan, where.scan)) return false;
  }
  return true;
}

prisma.user.findUnique = async () => null;
prisma.repo.findFirst = async ({ where }) => {
  return [...repos.values()].find(repo => repoMatches(repo, where)) || null;
};
prisma.repo.findMany = async ({ where }) => {
  return [...repos.values()].filter(repo => repoMatches(repo, where));
};
prisma.repo.update = async ({ where, data }) => {
  const repo = repos.get(where.id);
  if (!repo) throw new Error('Repo not found');
  Object.assign(repo, data);
  return { ...repo };
};
prisma.repo.create = async ({ data }) => {
  const repo = { ...data, id: `repo-created-${repos.size}`, createdAt: new Date() };
  repos.set(repo.id, repo);
  return { ...repo };
};

prisma.scan.findFirst = async ({ where, include }) => {
  const scan = [...scans.values()].find(item => scanMatches(item, where));
  if (!scan) return null;
  return { ...scan, ...(include?.repo ? { repo: { ...repos.get(scan.repoId) } } : {}) };
};
prisma.scan.findMany = async ({ where }) => {
  return [...scans.values()].filter(scan => scanMatches(scan, where)).map(scan => ({ ...scan }));
};
prisma.scan.create = async ({ data }) => {
  const scan = { ...data, id: `scan-created-${scans.size}`, createdAt: new Date() };
  scans.set(scan.id, scan);
  return { ...scan };
};
prisma.scan.update = async ({ where, data }) => {
  const scan = scans.get(where.id);
  if (!scan) throw new Error('Scan not found');
  Object.assign(scan, data);
  return { ...scan };
};

prisma.finding.findFirst = async ({ where, include }) => {
  const finding = [...findings.values()].find(item => findingMatches(item, where));
  if (!finding) return null;
  if (!include?.scan) return { ...finding };
  const scan = scans.get(finding.scanId);
  return {
    ...finding,
    scan: { ...scan, repo: { ...repos.get(scan.repoId) } },
  };
};
prisma.finding.findMany = async ({ where }) => {
  return [...findings.values()].filter(finding => finding.scanId === where.scanId).map(finding => ({ ...finding }));
};
prisma.finding.update = async ({ where, data }) => {
  const finding = findings.get(where.id);
  if (!finding) throw new Error('Finding not found');
  Object.assign(finding, data);
  return { ...finding };
};

prisma.anchor.findUnique = async ({ where }) => {
  return anchors.has(where.scanId) ? { ...anchors.get(where.scanId) } : null;
};
prisma.anchor.upsert = async ({ where, create, update }) => {
  const anchor = anchors.get(where.scanId);
  if (anchor) Object.assign(anchor, update);
  else anchors.set(where.scanId, { ...create });
  return { ...anchors.get(where.scanId) };
};

for (const store of [devStore.devRepos, devStore.devScans, devStore.devFindings, devStore.devAnchors]) {
  store.clear();
}
devStore.saveRepo({ ...REPO });
devStore.saveScan({ ...SCAN });
devStore.saveFindings(SCAN.id, [{ ...FINDING }]);
devStore.saveAnchor(SCAN.id, { ...ANCHOR });

function token(user) {
  return jwt.sign(user, process.env.JWT_SECRET);
}

async function request(base, user, route, method = 'GET', body) {
  const response = await fetch(base + route, {
    method,
    headers: {
      Authorization: `Bearer ${token(user)}`,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return { status: response.status, body: await response.json() };
}

async function main() {
  const app = express();
  app.use(express.json());
  app.use('/repos', reposRouter);
  app.use('/scan', scansRouter);

  const server = app.listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const originalExec = childProcess.exec;
  childProcess.exec = () => ({});

  try {
    const notFoundRoutes = [
      ['/repos/repo-a'],
      ['/repos/private-repo'],
      ['/repos/repo-a', 'PATCH', { businessCriticality: 'Critical' }],
      ['/repos/private-repo', 'PATCH', { businessCriticality: 'Critical' }],
      ['/scan/repo-a', 'POST'],
      ['/scan/scan-a/findings'],
      ['/scan/scan-a/cbom'],
      ['/scan/scan-a/anchor', 'POST'],
      ['/scan/scan-a/verify'],
      ['/scan/scan-a/migration-assessment'],
      ['/scan/scan-a/findings/finding-a/resolve', 'PUT'],
    ];

    for (const [route, method = 'GET', body] of notFoundRoutes) {
      const response = await request(base, USER_B, route, method, body);
      assert.equal(response.status, 404, `${method} ${route} hides another user's resources`);
    }

    const repoList = await request(base, USER_B, '/repos');
    assert.equal(repoList.status, 200, 'repo list remains a collection endpoint');
    assert.deepEqual(repoList.body, [], 'repo list excludes another user\'s repo');

    const accessibleRoutes = [
      ['/repos'],
      ['/repos/repo-a'],
      ['/repos/private-repo'],
      ['/repos/repo-a', 'PATCH', { businessCriticality: 'Standard' }],
      ['/repos/private-repo', 'PATCH', { businessCriticality: 'Standard' }],
      ['/scan/repo-a', 'POST'],
      ['/scan/scan-a/findings'],
      ['/scan/scan-a/cbom'],
      ['/scan/scan-a/anchor', 'POST'],
      ['/scan/scan-a/verify'],
      ['/scan/scan-a/migration-assessment'],
      ['/scan/scan-a/findings/finding-a/resolve', 'PUT'],
    ];

    for (const [route, method = 'GET', body] of accessibleRoutes) {
      const ownerResponse = await request(base, USER_A, route, method, body);
      assert.ok(ownerResponse.status >= 200 && ownerResponse.status < 400, `${method} ${route} remains accessible to the owner`);
      if (route === '/repos') {
        assert.ok(ownerResponse.body.some(repo => repo.id === REPO.id), 'owner repo list includes the owned repo');
      }
    }

    for (const role of ['Admin', 'Security Team', 'Auditor']) {
      const elevatedUser = { ...ADMIN, role };
      for (const [route, method = 'GET', body] of accessibleRoutes) {
        const response = await request(base, elevatedUser, route, method, body);
        assert.ok(response.status >= 200 && response.status < 400, `${method} ${route} remains accessible to ${role}`);
        if (route === '/repos') {
          assert.ok(response.body.some(repo => repo.id === REPO.id), `${role} repo list includes the owned repo`);
        }
      }
    }

    console.log(`PASS: ${notFoundRoutes.length} non-owner resource routes return 404`);
    console.log(`PASS: owner and ${accessibleRoutes.length} routes for each elevated role remain accessible`);
    console.log('PASS: non-owner repo list excludes the private repo');
  } finally {
    childProcess.exec = originalExec;
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});