'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');

process.env.NODE_ENV = 'test';
process.env.JWT_ACCESS_SECRET = 'quantum-risk-hndl-route-test-secret';

const db = {
  scans: new Map([
    ['owned-scan', { id: 'owned-scan', repo: { uploadedBy: 'owner-id' } }],
    ['empty-scan', { id: 'empty-scan', repo: { uploadedBy: 'owner-id' } }],
    ['persisted-scan', { id: 'persisted-scan', repo: { uploadedBy: 'owner-id' } }],
  ]),
  findings: new Map(),
  scenarios: [],
  assessments: [],
  fields: [],
  exposures: [],
};

db.findings.set('owned-scan', [
  {
    id: 'finding-rsa-1',
    scanId: 'owned-scan',
    filePath: 'services/payments/src/keys.ts',
    lineNumber: 18,
    algorithm: 'RSA-2048',
    keySize: 2048,
    usage: 'key_exchange',
    confidence: 'Likely|ast',
    suppressed: false,
  },
]);

db.findings.set('persisted-scan', [
  {
    id: 'finding-rsa-2',
    scanId: 'persisted-scan',
    filePath: 'services/payments/src/keys.ts',
    lineNumber: 18,
    algorithm: 'RSA-2048',
    keySize: 2048,
    usage: 'key_exchange',
    confidence: 'Likely|ast',
    suppressed: false,
  },
]);

const prisma = {
  scan: {
    findUnique: async ({ where }) => db.scans.get(where.id) || null,
  },
  user: { findUnique: async () => null },
  finding: {
    findMany: async ({ where, take }) => (db.findings.get(where.scanId) || [])
      .filter((finding) => where.suppressed !== false || finding.suppressed === false)
      .slice(0, take || undefined),
  },
  threatScenario: {
    findMany: async ({ where }) => db.scenarios.filter((row) => row.scanId === where.scanId),
    findFirst: async ({ where }) => db.scenarios.find((row) => row.id === where.id && row.scanId === where.scanId) || null,
  },
  sensitiveDataField: {
    findMany: async ({ where }) => db.fields.filter((row) => row.scanId === where.scanId),
    findFirst: async ({ where }) => db.fields.find((row) => row.scanId === where.scanId && (!where.fieldId || row.fieldId === where.fieldId)) || null,
    deleteMany: async ({ where }) => {
      const before = db.fields.length;
      db.fields = db.fields.filter((row) => row.scanId !== where.scanId);
      return { count: before - db.fields.length };
    },
    createMany: async ({ data }) => {
      db.fields.push(...data.map((row) => ({ ...row, id: 'sdf-' + Math.random(), createdAt: new Date() })));
      return { count: data.length };
    },
  },
  dataExposure: {
    findMany: async ({ where }) => db.exposures.filter((row) => row.scanId === where.scanId && (!where.fieldId || row.fieldId === where.fieldId)),
    deleteMany: async ({ where }) => {
      const before = db.exposures.length;
      db.exposures = db.exposures.filter((row) => row.scanId !== where.scanId);
      return { count: before - db.exposures.length };
    },
    createMany: async ({ data }) => {
      db.exposures.push(...data.map((row) => ({ ...row, id: 'de-' + Math.random(), createdAt: new Date() })));
      return { count: data.length };
    },
  },
  $transaction: async (callback) => callback(prisma),
};

const prismaPath = require.resolve('../../src/utils/prismaClient');
require.cache[prismaPath] = { id: prismaPath, filename: prismaPath, loaded: true, exports: prisma };
const redisPath = require.resolve('../../src/utils/redisClient');
require.cache[redisPath] = {
  id: redisPath,
  filename: redisPath,
  loaded: true,
  exports: { isJtiDenylisted: async () => false, denylistJti: async () => {}, getRedisClient: () => ({}) },
};

const router = require('../../src/routes/quantumRisk');
const app = express();
app.use(express.json());
app.use('/scan/:scanId/quantum-risk', router);
app.use((req, res) => res.status(404).json({ error: 'not found' }));

function tokenFor(id) {
  return jwt.sign({ id, email: `${id}@test.invalid`, role: 'Developer', jti: `jti-${id}` }, process.env.JWT_ACCESS_SECRET, { expiresIn: '5m' });
}

async function startServer() {
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

async function call(base, userId, method, route, body) {
  const headers = {};
  if (userId) headers.Authorization = `Bearer ${tokenFor(userId)}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(`${base}${route}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const payload = await response.json();
  return { status: response.status, payload };
}

async function runTests() {
  const { server, base } = await startServer();
  const root = '/scan/owned-scan/quantum-risk/hndl';
  const owner = 'owner-id';
  const other = 'other-id';

  try {
    // 1. 401 unauthenticated
    assert.strictEqual((await call(base, null, 'POST', `${root}/run`, { devSample: true })).status, 401);
    assert.strictEqual((await call(base, null, 'GET', root)).status, 401);

    // 2. 403 non-owner
    assert.strictEqual((await call(base, other, 'POST', `${root}/run`, { devSample: true })).status, 403);
    assert.strictEqual((await call(base, other, 'GET', root)).status, 403);

    // 3. Over-cap rejected
    assert.strictEqual((await call(base, owner, 'POST', `${root}/run`, { devSample: true, iterations: 100001 })).status, 400);
    assert.strictEqual((await call(base, owner, 'POST', `${root}/run`, { devSample: true, scenarioIds: Array(11).fill('s1') })).status, 400);

    // 4. 200 run with devSample
    const runRes = await call(base, owner, 'POST', `${root}/run`, { devSample: true, iterations: 500, seed: 42 });
    assert.strictEqual(runRes.status, 200);
    assert(Array.isArray(runRes.payload.fields) && runRes.payload.fields.length > 0, 'fields should be returned');
    assert(Array.isArray(runRes.payload.exposures), 'exposures should be returned');
    assert(runRes.payload.summary && runRes.payload.summary.byScenario, 'summary should be returned');
    assert(runRes.payload.assumptions && runRes.payload.assumptions.sensitivityWeights, 'assumptions should be returned');

    const firstFieldId = runRes.payload.fields[0].fieldId;
    assert(firstFieldId, 'fieldId should be defined');

    const initialFieldCount = db.fields.length;
    const initialExpCount = db.exposures.length;
    assert(initialFieldCount > 0 && initialExpCount > 0, 'rows should be persisted in db');

    // 5. Persisted rows replaced on re-run (no duplicates)
    const rerunRes = await call(base, owner, 'POST', `${root}/run`, { devSample: true, iterations: 500, seed: 99 });
    assert.strictEqual(rerunRes.status, 200);
    assert.strictEqual(db.fields.length, initialFieldCount, 'fields count should remain constant on re-run');
    assert.strictEqual(db.exposures.length, initialExpCount, 'exposures count should remain constant on re-run');

    // 6. No raw sample value in response or stored row
    const resString = JSON.stringify(runRes.payload);
    const dbString = JSON.stringify({ fields: db.fields, exposures: db.exposures });
    assert(!/\b234567890\d{3}\b/.test(resString), 'no raw 12-digit aadhaar in response');
    assert(!/\b234567890\d{3}\b/.test(dbString), 'no raw 12-digit aadhaar in stored DB rows');

    // 7. GET returns latest
    const getLatest = await call(base, owner, 'GET', root);
    assert.strictEqual(getLatest.status, 200);
    assert.strictEqual(getLatest.payload.fields.length, db.fields.length);
    assert.strictEqual(getLatest.payload.exposures.length, db.exposures.length);
    assert(getLatest.payload.summary.byField, 'rebuilt summary.byField should be present');

    // 8. GET fields/:fieldId
    const getField = await call(base, owner, 'GET', `${root}/fields/${firstFieldId}`);
    assert.strictEqual(getField.status, 200);
    assert.strictEqual(getField.payload.field.fieldId, firstFieldId);
    assert(Array.isArray(getField.payload.exposures));

    const getFieldMissing = await call(base, owner, 'GET', `${root}/fields/non-existent-field-id`);
    assert.strictEqual(getFieldMissing.status, 404);

    // 9. Empty case: non-devSample run without persisted fields returns message
    const emptyRun = await call(base, owner, 'POST', '/scan/empty-scan/quantum-risk/hndl/run', {});
    assert.strictEqual(emptyRun.status, 200);
    assert.deepStrictEqual(emptyRun.payload.fields, []);
    assert.strictEqual(emptyRun.payload.message, 'No HNDL data for this scan; rescan with HNDL_SCAN_HOOK enabled');

    // 10. Run uses persisted rows without needing source files
    db.fields.push({
      scanId: 'persisted-scan',
      fieldId: 'field-persisted-1',
      dataClass: 'AADHAAR',
      location: { filePath: 'services/payments/src/keys.ts', line: 18, lineageStatus: 'linked' },
      retentionYears: 10,
      retentionSource: 'stated',
      protectedBy: ['finding:finding-rsa-2'],
      detectionConfidence: 0.9,
      lineageConfidence: 0.8,
      evidence: ['****1234'],
    });


    const persistedRun = await call(base, owner, 'POST', '/scan/persisted-scan/quantum-risk/hndl/run', { iterations: 200, seed: 42 });
    assert.strictEqual(persistedRun.status, 200);
    assert.strictEqual(persistedRun.payload.fields.length, 1);
    assert.strictEqual(persistedRun.payload.fields[0].fieldId, 'field-persisted-1');
    assert(persistedRun.payload.exposures.length > 0, 'exposures should be computed from persisted rows');

    console.log('Quantum-risk HNDL route tests passed.');
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

runTests().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
