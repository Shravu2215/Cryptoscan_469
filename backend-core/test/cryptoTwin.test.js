'use strict';

const assert = require('assert');
const cryptoTwinEngine = require('../src/services/cryptoTwinEngine');
const cryptoTwinRoutes = require('../src/routes/cryptoTwin');

console.log('--- Testing CryptoTwin Per-Migration Engine & Routes ---');

// 1. Check Route Endpoints
const routePaths = cryptoTwinRoutes.stack
  .filter(layer => layer.route)
  .map(layer => ({ path: layer.route.path, methods: Object.keys(layer.route.methods) }));

assert(routePaths.some(r => r.path === '/runs' && r.methods.includes('post')), 'POST /runs endpoint should exist');
assert(routePaths.some(r => r.path === '/runs' && r.methods.includes('get')), 'GET /runs endpoint should exist');
assert(routePaths.some(r => r.path === '/runs/:id' && r.methods.includes('get')), 'GET /runs/:id endpoint should exist');
assert(routePaths.some(r => r.path === '/runs/:id/approval' && r.methods.includes('post')), 'POST /runs/:id/approval endpoint should exist');
console.log('✓ All CryptoTwin route paths verified.');

// 2. Check Migration Type Classification & Specific Attack Paths
const hardcodedPath = cryptoTwinEngine.buildSpecificAttackPath({ currentAlgorithm: 'Hardcoded secret', usageContext: 'secret' });
assert.strictEqual(hardcodedPath.migrationType, 'secret-handling');
assert(hardcodedPath.proposedReplacement.includes('Environment Variable'), 'Secret handling replacement must suggest Env Var/KMS, never SHA-256');

const rsaPath = cryptoTwinEngine.buildSpecificAttackPath({ currentAlgorithm: 'RSA-2048', usageContext: 'jwt' });
assert.strictEqual(rsaPath.migrationType, 'pqc-replacement');
assert(rsaPath.proposedReplacement.includes('ML-DSA'), 'RSA JWT replacement must suggest ML-DSA');

const md5Path = cryptoTwinEngine.buildSpecificAttackPath({ currentAlgorithm: 'MD5', usageContext: 'hashing' });
assert.strictEqual(md5Path.migrationType, 'hash-upgrade');
assert(md5Path.proposedReplacement.includes('SHA-256'), 'MD5 replacement must suggest SHA-256');
console.log('✓ Migration classification and specific attack paths verified.');

// 3. Check Input Normalization & Safe Item Exclusion
const norm = cryptoTwinEngine.normaliseInput({
  items: [
    { currentAlgorithm: 'RSA-2048', severity: 'HIGH' },
    { currentAlgorithm: 'MD5', severity: 'CRITICAL' },
    { currentAlgorithm: 'AES-256-GCM', severity: 'SAFE' }
  ]
});
assert.strictEqual(norm.inScope.length, 2, '2 items should be in active migration scope');
assert.strictEqual(norm.safeExcluded.length, 1, '1 safe item (AES-256-GCM) should be excluded from scope');
console.log('✓ Input normalization and safe item exclusion verified.');

// 4. Check End-to-End Per-Migration Execution & Readiness Computation
(async () => {
  const result = await cryptoTwinEngine.runCryptoTwin({
    items: [
      { id: 'm1', filePath: 'src/auth.js', line: 42, currentAlgorithm: 'RSA-2048', usageContext: 'jwt', severity: 'HIGH' },
      { id: 'm2', filePath: 'src/digest.js', line: 12, currentAlgorithm: 'MD5', usageContext: 'hashing', severity: 'CRITICAL' },
      { id: 'm3', filePath: 'src/cipher.js', line: 88, currentAlgorithm: 'AES-256-GCM', severity: 'SAFE' }
    ]
  });

  assert.strictEqual(result.summary.inScopeCount, 2);
  assert.strictEqual(result.summary.excludedCount, 1);
  assert(result.migrations.length === 2, 'Should process 2 in-scope migrations');
  assert(typeof result.summary.readinessBefore === 'number', 'Readiness before should be percentage');
  assert(typeof result.summary.readinessAfter === 'number', 'Readiness after should be percentage');

  // Check application generator
  const appBuild = cryptoTwinEngine.generateUpdatedApplication(null, ['m1', 'm2'], result.migrations);
  assert(appBuild.diffText !== undefined, 'Generated application must produce diff text');
  console.log('✓ End-to-end per-migration engine execution verified (Readiness: ' + result.summary.readinessBefore + '% -> ' + result.summary.readinessAfter + '%).');
  console.log('--- CryptoTwin Unit Tests Passed Successfully ---');
})();
