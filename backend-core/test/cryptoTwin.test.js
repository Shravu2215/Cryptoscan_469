'use strict';

const assert = require('assert');
const cryptoTwinEngine = require('../src/services/cryptoTwinEngine');
const cryptoTwinRoutes = require('../src/routes/cryptoTwin');

console.log('--- Testing CryptoTwin Real Code Review & Verification Engine ---');

// 1. Check Route Endpoints
const routePaths = cryptoTwinRoutes.stack
  .filter(layer => layer.route)
  .map(layer => ({ path: layer.route.path, methods: Object.keys(layer.route.methods) }));

assert(routePaths.some(r => r.path === '/runs' && r.methods.includes('post')), 'POST /runs endpoint should exist');
assert(routePaths.some(r => r.path === '/runs' && r.methods.includes('get')), 'GET /runs endpoint should exist');
assert(routePaths.some(r => r.path === '/runs/:id' && r.methods.includes('get')), 'GET /runs/:id endpoint should exist');
assert(routePaths.some(r => r.path === '/runs/:id/approval' && r.methods.includes('post')), 'POST /runs/:id/approval endpoint should exist');
assert(routePaths.some(r => r.path === '/runs/:id/raw-logs/:migrationId' && r.methods.includes('get')), 'GET /runs/:id/raw-logs/:migrationId endpoint should exist');
assert(routePaths.some(r => r.path === '/runs/:id/generate-app' && r.methods.includes('post')), 'POST /runs/:id/generate-app endpoint should exist');
console.log('✓ All CryptoTwin route paths verified.');

// 2. Check AST / Token-level Fake-Diff Guard
const fakeDiffResult = cryptoTwinEngine.checkFakeDiff(
  '// Legacy: RSA-2048 signing',
  '// Upgraded: ML-DSA-65 (FIPS 204)'
);
assert.strictEqual(fakeDiffResult.isFake, true, 'Comment-only/Label-only patch must be caught as fake diff');

const realDiffResult = cryptoTwinEngine.checkFakeDiff(
  'signer = pkcs1_15.new(RSA.import_key(key))',
  'with oqs.Signature("ML-DSA-65") as signer:'
);
assert.strictEqual(realDiffResult.isFake, false, 'Real code change must pass fake-diff guard');
console.log('✓ AST / Token-level Fake-Diff Guard verified.');

// 3. Check Secret Masking (Zero Raw Secrets Enforced)
const rawSecretText = 'API_KEY = "sk_live_99887766554433221100"';
const maskedText = cryptoTwinEngine.maskSecretsInText(rawSecretText);
assert(!maskedText.includes('sk_live_99887766554433221100'), 'Raw secret value must never appear in masked text');
assert(maskedText.includes('•••••••• [sha256:'), 'Masked text must contain bullet placeholder and sha256 hash');
console.log('✓ Secret Masking & Protection verified.');

// 4. Check Context Extraction (±8 lines with line numbers)
const sampleFileContent = Array.from({ length: 50 }, (_, i) => `line_${i + 1} = ${i + 1}`).join('\n');
const context = cryptoTwinEngine.extractRealCodeContext('src/app.py', 25, sampleFileContent);
assert.strictEqual(context.beforeLines.length, 17, 'Context should extract target line ±8 lines (17 lines total)');
assert(context.beforeRaw.includes('  25 | line_25 = 25'), 'Context raw must contain formatted line number');
console.log('✓ Source Code Context Extraction verified.');

// 5. Check Input Normalization & Safe Item Exclusion
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

// 6. Check End-to-End Per-Migration Execution & Quantum Readiness Rescan
(async () => {
  const result = await cryptoTwinEngine.runCryptoTwin({
    items: [
      { id: 'm1', filePath: 'src/auth.py', line: 42, currentAlgorithm: 'RSA-2048', usageContext: 'jwt', severity: 'HIGH' },
      { id: 'm2', filePath: 'src/digest.py', line: 12, currentAlgorithm: 'MD5', usageContext: 'hashing', severity: 'CRITICAL' },
      { id: 'm3', filePath: 'src/cipher.py', line: 88, currentAlgorithm: 'AES-256-GCM', severity: 'SAFE' }
    ]
  });

  assert.strictEqual(result.summary.inScopeCount, 2);
  assert.strictEqual(result.summary.excludedCount, 1);
  assert(result.migrations.length === 2, 'Should process 2 in-scope migrations');
  assert(Array.isArray(result.migrations[0].evidence.rawLogs), 'Evidence must contain rawLogs array');

  // Check Quantum Readiness rescan computation with VERIFIED items
  const testResults = result.migrations.map(m => ({ ...m, verificationStatus: 'VERIFIED' }));
  const readiness = cryptoTwinEngine.computeQuantumReadiness(
    testResults.map(m => m.item),
    result.safeExcluded,
    new Set(['m1']), // Only m1 approved
    testResults
  );
  assert.strictEqual(readiness.currentPct, 33, 'Current readiness should be 33%');
  assert.strictEqual(readiness.afterApprovedPct, 67, 'After approved readiness should be 67% with 1 item approved');
  assert.strictEqual(readiness.projectedPct, 100, 'Projected readiness should be 100% if all approved');

  // Check application generator
  const appBuild = cryptoTwinEngine.generateUpdatedApplication(null, ['m1'], testResults);
  assert(appBuild.diffText !== undefined, 'Generated application must produce diff patch text');
  assert.strictEqual(appBuild.approvedCount, 1);

  console.log('✓ End-to-end per-migration engine execution & readiness rescan verified.');
  console.log('--- CryptoTwin Unit Tests Passed Successfully ---');
})();


