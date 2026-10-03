'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');

process.env.NODE_ENV = 'test';
process.env.JWT_ACCESS_SECRET = 'quantum-risk-route-test-access-secret';

const db = {
  scans: new Map([
    ['owned-scan', { id: 'owned-scan', repo: { uploadedBy: 'owner-id' } }],
    ['empty-scan', { id: 'empty-scan', repo: { uploadedBy: 'owner-id' } }],
    ['large-scan', { id: 'large-scan', repo: { uploadedBy: 'owner-id' } }],
  ]),
  findings: new Map(),
  scenarios: [],
  assessments: [],
  nextScenarioId: 1,
};

db.findings.set('owned-scan', [
  {
    id: 'finding-rsa-1',
    scanId: 'owned-scan',
    filePath: 'services/payments/src/crypto.js',
    lineNumber: 12,
    algorithm: 'RSA-2048',
    keySize: 2048,
    usage: 'key_exchange',
    confidence: 'Likely|ast',
    suppressed: false,
  },
  {
    id: 'finding-hidden',
    scanId: 'owned-scan',
    filePath: 'services/payments/src/hidden.js',
    lineNumber: 9,
    algorithm: 'RSA-2048',
    keySize: 2048,
    usage: 'key_exchange',
    confidence: 'Likely|ast',
    suppressed: true,
  },
]);
db.findings.set('empty-scan', []);
db.findings.set('large-scan', Array.from({ length: 5001 }, (_, index) => ({
  id: `finding-${index}`,
  scanId: 'large-scan',
  filePath: `services/payments/src/file-${index}.js`,
  lineNumber: 1,
  algorithm: 'RSA-2048',
  keySize: 2048,
  usage: 'key_exchange',
  confidence: 'Likely|ast',
  suppressed: false,
})));

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
    create: async ({ data }) => {
      const row = { id: `custom-scenario-${db.nextScenarioId++}`, createdAt: new Date(), ...data };
      db.scenarios.push(row);
      return row;
    },
    update: async ({ where, data }) => {
      const row = db.scenarios.find((scenario) => scenario.id === where.id);
      Object.assign(row, data);
      return row;
    },
    delete: async ({ where }) => {
      const index = db.scenarios.findIndex((scenario) => scenario.id === where.id);
      return db.scenarios.splice(index, 1)[0];
    },
  },
  threatAssessment: {
    findMany: async ({ where }) => db.assessments
      .filter((row) => row.scanId === where.scanId && (!where.scenarioId || where.scenarioId.in.includes(row.scenarioId)))
      .sort((left, right) => new Date(right.createdAt) - new Date(left.createdAt)),
    deleteMany: async ({ where }) => {
      const before = db.assessments.length;
      db.assessments = db.assessments.filter((row) => !(row.scanId === where.scanId && row.scenarioId === where.scenarioId));
      return { count: before - db.assessments.length };
    },
    createMany: async ({ data }) => {
      db.assessments.push(...data.map((row) => ({ ...row, createdAt: new Date() })));
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
  const root = '/scan/owned-scan/quantum-risk';
  const owner = 'owner-id';
  const other = 'other-id';
  const defaults = require('../../src/services/quantumRisk/threatModel/scenarios').loadDefaultScenarios();
  const median = defaults.find((scenario) => scenario.name === 'median');
  const customPatch = {
    name: '<img src=x onerror=alert(1)>',
    familyTimelines: median.familyTimelines,
    source: 'ASSUMPTION - route test',
    citationNote: 'ASSUMPTION - route test citation note',
  };

  try {
    assert.strictEqual((await call(base, null, 'GET', `${root}/scenarios`)).status, 401);
    assert.strictEqual((await call(base, other, 'GET', `${root}/scenarios`)).status, 403);

    const listed = await call(base, owner, 'GET', `${root}/scenarios`);
    assert.strictEqual(listed.status, 200);
    assert.strictEqual(listed.payload.scenarios.length, 3);
    assert(listed.payload.assumptions['scenario-median-v1'].citationNote);
    assert(listed.payload.engineVersion);
    const unfinished = await call(base, owner, 'GET', `${root}/hndl/exposures`);
    assert.strictEqual(unfinished.status, 501);
    assert(unfinished.payload.assumptions && unfinished.payload.engineVersion);

    const badSource = { ...customPatch };
    delete badSource.source;
    assert.strictEqual((await call(base, owner, 'POST', `${root}/scenarios`, { basedOn: median.id, patch: badSource })).status, 400);
    const badCitation = { ...customPatch };
    delete badCitation.citationNote;
    assert.strictEqual((await call(base, owner, 'POST', `${root}/scenarios`, { basedOn: median.id, patch: badCitation })).status, 400);
    assert.strictEqual((await call(base, owner, 'POST', `${root}/scenarios`, { basedOn: median.id, patch: { ...customPatch, name: 'x'.repeat(61) } })).status, 400);

    const create = await call(base, owner, 'POST', `${root}/scenarios`, { basedOn: median.id, patch: customPatch });
    assert.strictEqual(create.status, 201);
    const customId = create.payload.scenario.id;
    assert.strictEqual(create.payload.scenario.displayName, customPatch.name);
    assert.strictEqual(db.scenarios[0].name, customPatch.name, 'XSS-looking text is stored verbatim');
    assert.strictEqual((await call(base, owner, 'PUT', `${root}/scenarios/${median.id}`, { patch: customPatch })).status, 400);
    assert.strictEqual((await call(base, owner, 'DELETE', `${root}/scenarios/${median.id}`)).status, 400);

    const editedPatch = { ...customPatch, name: 'Edited custom', source: 'ASSUMPTION - revised' };
    const edit = await call(base, owner, 'PUT', `${root}/scenarios/${customId}`, { patch: editedPatch });
    assert.strictEqual(edit.status, 200);
    assert.strictEqual(edit.payload.scenario.displayName, 'Edited custom');

    const runPath = `${root}/threat-model/run`;
    assert.strictEqual((await call(base, owner, 'POST', runPath, { scenarioIds: [median.id], iterations: 100001 })).status, 400);
    assert.strictEqual((await call(base, owner, 'POST', runPath, { scenarioIds: Array.from({ length: 11 }, (_, index) => `s-${index}`) })).status, 400);
    assert.strictEqual((await call(base, owner, 'POST', runPath, { scenarioIds: ['missing-scenario'] })).status, 404);

    const runBody = { scenarioIds: [median.id], iterations: 128, seed: 5 };
    const run = await call(base, owner, 'POST', runPath, runBody);
    assert.strictEqual(run.status, 200);
    assert.strictEqual(run.payload.assets.length, 1, 'suppressed findings are excluded');
    assert.strictEqual(run.payload.byScenario[median.id].length, 1);
    assert.strictEqual(run.payload.heatmap.rows[0], 'payments');
    assert(run.payload.assumptions[median.id].source);
    assert(run.payload.engineVersion);
    const persistedCount = db.assessments.length;
    assert.strictEqual(persistedCount, 1);

    const rerun = await call(base, owner, 'POST', runPath, { ...runBody, seed: 6 });
    assert.strictEqual(rerun.status, 200);
    assert.strictEqual(db.assessments.length, persistedCount, 'rerun replaces, rather than duplicates, scan/scenario rows');

    const latest = await call(base, owner, 'GET', `${root}/threat-model`);
    assert.strictEqual(latest.status, 200);
    assert.strictEqual(latest.payload.byScenario[median.id].length, 1);
    assert(latest.payload.meta.generatedAt);
    assert(latest.payload.byScenario[median.id][0].pMoscaViolatedCI95);

    const heatmap = await call(base, owner, 'GET', `${root}/threat-model/heatmap?rows=family&metric=pBreakBeforeMigration&scenarioIds=${median.id}`);
    assert.strictEqual(heatmap.status, 200);
    assert.deepStrictEqual(heatmap.payload.heatmap.columns, [median.id]);
    const heatmapBad = await call(base, owner, 'GET', `${root}/threat-model/heatmap?rows=nope`);
    assert.strictEqual(heatmapBad.status, 400);

    const rowsBeforeSweep = db.assessments.length;
    const sweep = await call(base, owner, 'POST', `${root}/threat-model/sweep`, {
      scenarioId: median.id,
      shifts: [-1, 0, 1],
      metric: 'pMoscaViolated',
      rows: 'service',
      iterations: 128,
      seed: 5,
    });
    assert.strictEqual(sweep.status, 200);
    assert.strictEqual(Object.keys(sweep.payload.byScenario).length, 3);
    assert.strictEqual(db.assessments.length, rowsBeforeSweep, 'sweeps are not persisted');
    assert.strictEqual((await call(base, owner, 'POST', `${root}/threat-model/sweep`, { scenarioId: median.id, shifts: Array(22).fill(0) })).status, 400);

    const empty = await call(base, owner, 'POST', '/scan/empty-scan/quantum-risk/threat-model/run', { scenarioIds: [median.id], iterations: 64 });
    assert.strictEqual(empty.status, 200);
    assert.deepStrictEqual(empty.payload.assets, []);
    assert.strictEqual(empty.payload.byScenario[median.id].length, 0);
    assert.match(empty.payload.message, /No non-suppressed findings/);

    assert.strictEqual((await call(base, owner, 'POST', '/scan/large-scan/quantum-risk/threat-model/run', { scenarioIds: [median.id], iterations: 64 })).status, 400);

    const sample = await call(base, owner, 'POST', '/scan/empty-scan/quantum-risk/threat-model/run', { scenarioIds: [median.id], iterations: 64, seed: 42, devSample: true });
    assert.strictEqual(sample.status, 200);
    assert.strictEqual(sample.payload.assets.length, 12);
    const virtualSample = await call(base, owner, 'POST', '/scan/dev-quantum-sample/quantum-risk/threat-model/run', { scenarioIds: [median.id], iterations: 64, seed: 42, devSample: true });
    assert.strictEqual(virtualSample.status, 200);
    assert.strictEqual(virtualSample.payload.assets.length, 12);

    const editCount = db.assessments.length;
    await call(base, owner, 'POST', runPath, { scenarioIds: [customId], iterations: 64 });
    assert(db.assessments.length > editCount);
    const deleted = await call(base, owner, 'DELETE', `${root}/scenarios/${customId}`);
    assert.strictEqual(deleted.status, 200);
    assert.strictEqual(db.scenarios.length, 0);
    assert(!db.assessments.some((row) => row.scenarioId === customId));

    const frontendScript = fs.readFileSync(path.resolve(__dirname, '../../../frontend/assets/js/quantumThreatModel.js'), 'utf8');
    assert(!/\binnerHTML\b/.test(frontendScript), 'scenario/user text must not be assigned through HTML parsing');
    console.log('Quantum-risk route tests passed.');
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

runTests().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});