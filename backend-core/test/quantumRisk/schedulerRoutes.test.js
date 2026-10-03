'use strict';

const assert = require('assert');
const express = require('express');
const jwt = require('jsonwebtoken');

process.env.NODE_ENV = 'test';
process.env.JWT_ACCESS_SECRET = 'quantum-risk-route-test-access-secret';

const db = {
  scans: new Map([
    ['owned-scan', { id: 'owned-scan', repo: { uploadedBy: 'owner-id' } }],
  ]),
  findings: new Map([
    ['owned-scan', [
      { id: 'f1', scanId: 'owned-scan', assetId: 'a1', migrationMonths: 2, peopleNeeded: 1, suppressed: false }
    ]]
  ]),
  assessments: [],
  schedules: new Map(),
};

const prisma = {
  scan: { findUnique: async ({ where }) => db.scans.get(where.id) || null },
  user: { findUnique: async () => null },
  finding: {
    findMany: async ({ where }) => (db.findings.get(where.scanId) || []).filter(f => !f.suppressed),
  },
  threatAssessment: {
    findMany: async () => db.assessments,
  },
  migrationSchedule: {
    findFirst: async ({ where }) => db.schedules.get(where.scanId) || null,
    deleteMany: async ({ where }) => { db.schedules.delete(where.scanId); return { count: 1 }; },
    create: async ({ data }) => {
      const row = { id: 'sched-1', createdAt: new Date(), ...data };
      db.schedules.set(data.scanId, row);
      return row;
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

// Mock only the solver call
const schedulerPath = require.resolve('../../src/services/quantumRisk/scheduler');
const originalScheduler = require(schedulerPath);
require.cache[schedulerPath] = {
  id: schedulerPath,
  filename: schedulerPath,
  loaded: true,
  exports: {
    ...originalScheduler,
    generateSchedule: async (input) => ({
      waves: [],
      ganttRows: [],
      totalExposure: 100,
      baselineTotalExposure: 150,
      improvementPct: 33,
      solverStatus: 'OPTIMAL',
      message: 'Success',
      baseline: { waves: [], ganttRows: [], deadlineMisses: [] }
    })
  }
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
  const payload = await response.json().catch(() => ({}));
  return { status: response.status, payload };
}

async function runTests() {
  const { server, base } = await startServer();
  const root = '/scan/owned-scan/quantum-risk';
  const owner = 'owner-id';
  const other = 'other-id';

  try {
    // 401 unauthenticated, 403 non-owner
    assert.strictEqual((await call(base, null, 'POST', `${root}/schedule/run`)).status, 401);
    assert.strictEqual((await call(base, other, 'POST', `${root}/schedule/run`)).status, 403);

    // 200 owner for POST /schedule/run
    const runBody = {
      tasks: [{ taskId: 't1', durationMonths: 1, peopleNeeded: 1 }],
      teamCapacity: 5,
      horizonMonths: 36,
      timeLimitSeconds: 5
    };
    const runRes = await call(base, owner, 'POST', `${root}/schedule/run`, runBody);
    assert.strictEqual(runRes.status, 200);
    assert.strictEqual(runRes.payload.solverStatus, 'OPTIMAL');

    // GET /schedule returns the persisted row
    const getRes = await call(base, owner, 'GET', `${root}/schedule`);
    assert.strictEqual(getRes.status, 200);
    assert.strictEqual(getRes.payload.solverStatus, 'OPTIMAL');
    
    // rerun replaces the row (no duplicate)
    await call(base, owner, 'POST', `${root}/schedule/run`, runBody);
    assert.strictEqual(db.schedules.size, 1, 'Only one schedule per scan');

    // POST /schedule/sensitivity (max 9 variations enforced)
    const sensBody = {
      tasks: runBody.tasks,
      teamCapacity: 5,
      horizonMonths: 36,
      variations: Array.from({ length: 10 }, (_, i) => ({ label: `V${i}` }))
    };
    const sensResBad = await call(base, owner, 'POST', `${root}/schedule/sensitivity`, sensBody);
    assert.strictEqual(sensResBad.status, 400);
    assert.match(sensResBad.payload.error, /cannot exceed 9/);
    
    sensBody.variations = [{ label: 'V1' }];
    const sensRes = await call(base, owner, 'POST', `${root}/schedule/sensitivity`, sensBody);
    assert.strictEqual(sensRes.status, 200);
    assert.strictEqual(sensRes.payload.variations.length, 1);

    // caps rejected (tasks > 500, horizon > 120)
    assert.strictEqual((await call(base, owner, 'POST', `${root}/schedule/run`, { ...runBody, tasks: Array(501).fill({ taskId: 't', durationMonths: 1 }) })).status, 400);
    assert.strictEqual((await call(base, owner, 'POST', `${root}/schedule/run`, { ...runBody, horizonMonths: 121 })).status, 400);
    assert.strictEqual((await call(base, owner, 'POST', `${root}/schedule/run`, { ...runBody, teamCapacity: 101 })).status, 400);
    
    console.log('PASS test/quantumRisk/schedulerRoutes.test.js');
  } catch (err) {
    console.error('FAIL test/quantumRisk/schedulerRoutes.test.js');
    console.error(err);
    process.exit(1);
  } finally {
    server.close();
  }
}

if (require.main === module) {
  runTests();
}
