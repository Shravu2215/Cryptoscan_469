'use strict';

const assert = require('assert');
const cryptoTwinEngine = require('../src/services/cryptoTwinEngine');
const cryptoTwinRoutes = require('../src/routes/cryptoTwin');

console.log('--- Testing CryptoTwin Engine & Routes ---');

// 1. Check Route Exports & Endpoints
const routePaths = cryptoTwinRoutes.stack
  .filter(layer => layer.route)
  .map(layer => ({ path: layer.route.path, methods: Object.keys(layer.route.methods) }));

assert(routePaths.some(r => r.path === '/runs' && r.methods.includes('post')), 'POST /runs endpoint should exist');
assert(routePaths.some(r => r.path === '/runs' && r.methods.includes('get')), 'GET /runs endpoint should exist');
assert(routePaths.some(r => r.path === '/runs/:id' && r.methods.includes('get')), 'GET /runs/:id endpoint should exist');
assert(routePaths.some(r => r.path === '/runs/:id/reset' && r.methods.includes('post')), 'POST /runs/:id/reset endpoint should exist');
assert(routePaths.some(r => r.path === '/runs/:id/approval' && r.methods.includes('post')), 'POST /runs/:id/approval endpoint should exist');
assert(routePaths.some(r => r.path === '/runs/:id/report' && r.methods.includes('get')), 'GET /runs/:id/report endpoint should exist');
console.log('✓ All CryptoTwin route paths verified.');

// 2. Check Attack Path Generation
const sampleItems = [
  {
    id: 'f1',
    filePath: 'src/auth.js',
    line: 42,
    currentAlgorithm: 'RSA-2048',
    usageContext: 'jwt',
    severity: 'HIGH',
    quantumVulnerable: true
  },
  {
    id: 'f2',
    filePath: 'src/hash.js',
    line: 12,
    currentAlgorithm: 'MD5',
    usageContext: 'hashing',
    severity: 'CRITICAL',
    quantumVulnerable: false
  }
];

const attackPaths = sampleItems.map(item => cryptoTwinEngine.buildAttackPath(item));
assert.strictEqual(attackPaths.length, 2);
assert(attackPaths[0].steps.some(s => s.toLowerCase().includes('rsa') || s.toLowerCase().includes('jwt')), 'RSA JWT attack path should have relevant steps');
assert(attackPaths[1].steps.some(s => s.toLowerCase().includes('md5') || s.toLowerCase().includes('collision')), 'MD5 attack path should have collision steps');
console.log('✓ Attack path generation verified.');

// 3. Check Verdict Computation
const readyVerdict = cryptoTwinEngine.computeVerdict(
  [{ statusAfter: 'BLOCKED' }],
  [{ status: 'PASSED', severity: 'HIGH' }],
  [{ status: 'PATCHED' }]
);
assert.strictEqual(readyVerdict.verdict, 'PRODUCTION_READY');
assert(readyVerdict.confidence >= 80, 'All passed/blocked should yield high confidence score');

const notReadyVerdict = cryptoTwinEngine.computeVerdict(
  [{ statusAfter: 'STILL_OPEN' }],
  [{ status: 'FAILED', type: 'SECURITY' }],
  [{ status: 'PATCH_GENERATED_NOT_APPLIED' }]
);
assert.strictEqual(notReadyVerdict.verdict, 'PRODUCTION_NOT_READY');
console.log('✓ Verdict derivation and confidence computation verified (Score: ' + readyVerdict.confidence + '%).');

// 4. Check End-to-End Engine Run
(async () => {
  const runRecord = await cryptoTwinEngine.runCryptoTwin({
    scanId: 'scan-123',
    repoName: 'test-repo',
    source: 'direct',
    items: sampleItems
  });
  assert(runRecord.stages.length >= 6, 'Run record should contain stage pipeline');
  assert(runRecord.verdict, 'Verdict should be populated');
  assert(typeof runRecord.confidence === 'number', 'Confidence score should be numeric');
  console.log('✓ End-to-end engine execution verified (Verdict: ' + runRecord.verdict + ', Confidence: ' + runRecord.confidence + '%).');
  console.log('--- CryptoTwin Unit Tests Passed Successfully ---');
})();
