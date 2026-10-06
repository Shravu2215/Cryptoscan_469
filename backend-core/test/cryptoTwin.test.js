'use strict';

const assert = require('assert');
const cryptoTwinEngine = require('../src/services/cryptoTwinEngine');
const cryptoTwinRoutes = require('../src/routes/cryptoTwin');

console.log('--- Testing CryptoTwin Recommendation & Evidence Engine ---');

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
assert(routePaths.some(r => r.path === '/assurance-checks' && r.methods.includes('post')), 'POST /assurance-checks endpoint should exist');
assert(routePaths.some(r => r.path === '/assurance-checks/:id' && r.methods.includes('get')), 'GET /assurance-checks/:id endpoint should exist');
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

// 6. Recommendation classes, purpose-aware targets, secret deduplication, and honest status
assert.strictEqual(cryptoTwinEngine.classifyMigration('Hardcoded key material', 'secret'), 'SECRET_HYGIENE');
assert.strictEqual(cryptoTwinEngine.classifyMigration('RSA-2048', 'jwt signing'), 'PQC_REPLACEMENT');
assert.strictEqual(cryptoTwinEngine.classifyMigration('MD5', 'hashing'), 'SYMMETRIC_HASH_UPGRADE');
assert.match(cryptoTwinEngine.deriveTargetAlgorithm('RSA-2048', 'PQC_REPLACEMENT', 'jwt signing'), /ML-DSA/);
assert.match(cryptoTwinEngine.deriveTargetAlgorithm('ECDH', 'PQC_REPLACEMENT', 'key_exchange'), /ML-KEM/);

const deduped = cryptoTwinEngine.normaliseInput({
  items: [
    { id: 'secret-11', filePath: '.env', line: 11, currentAlgorithm: 'Hardcoded key material', severity: 'CRITICAL', hash: 'a'.repeat(64) },
    { id: 'secret-12', filePath: '.env', line: 12, currentAlgorithm: 'Hardcoded key material', severity: 'HIGH', hash: 'a'.repeat(64) }
  ]
}).inScope;
assert.strictEqual(deduped.length, 1);
assert.deepStrictEqual(deduped[0].lineNumbers, [11, 12]);
assert.strictEqual(deduped[0].secretHashPrefix, 'aaaaaaaa');
assert.strictEqual(Object.prototype.hasOwnProperty.call(deduped[0], 'secretHash'), false);

const secretPanel = cryptoTwinEngine.buildWhyThisChangePanel(deduped[0], {}, {});
assert.strictEqual(secretPanel.impact, 'App fails at startup if env var missing');
assert.deepStrictEqual(secretPanel.checks, ['Build', 'Run-with-env', 'Missing-var-raises', 'Rescan']);
assert(!secretPanel.checks.includes('Tamper'));

const after = cryptoTwinEngine.generateRealAfterCode({ line: 11, migrationType: 'SECRET_HYGIENE', targetAlgorithm: 'secret manager' }, { language: 'Python' }, false);
assert.deepStrictEqual(after.afterLines.map(line => line.lineNum), [11, 12, 13, 14]);

(async () => {
  const secretChecks = await cryptoTwinEngine.runAssuranceChecks({
    algorithm: 'Hardcoded key material',
    purpose: 'secret',
    replacement: 'Environment variable / secret manager'
  });
  assert.deepStrictEqual(secretChecks.checks.map(check => check.name), ['Build', 'Run-with-env', 'Missing-var-raises', 'Rescan']);
  assert(secretChecks.checks.every(check => check.status === 'NOT_VERIFIED'), 'Secret hygiene checks must stay unverified until the target application is migrated and tested');

  const hashChecks = await cryptoTwinEngine.runAssuranceChecks({
    algorithm: 'MD5',
    purpose: 'hashing',
    replacement: 'SHA-256 / SHA-3-256'
  });
  assert.strictEqual(hashChecks.checks[0].name, 'Cryptographic hash known-answer test');
  assert.strictEqual(hashChecks.checks[0].status, 'PASS', 'Hash KAT must pass only when computed standard vectors match');
  assert.strictEqual(hashChecks.checks[1].status, 'NOT_APPLICABLE');
  assert.strictEqual(hashChecks.checks[2].status, 'NOT_APPLICABLE');

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

  assert(result.migrations.every(m => m.verificationStatus === 'NOT_TESTABLE'), 'Suggestions must not be reported as verified or applied');
  assert(result.migrations.every(m => m.evidence.checks.every(check => check.status === 'NOT_VERIFIED')), 'Recommendation checks must remain unverified until actually run');
  assert(result.migrations.every(m => m.evidence.rawLogs.length === 0), 'No synthetic execution log may be displayed');

  const readiness = cryptoTwinEngine.computeQuantumReadiness(
    result.migrations.map(m => m.item),
    result.safeExcluded,
    new Set(['m1']),
    result.migrations
  );
  assert.strictEqual(readiness.currentPct, null, 'Readiness requires CBOM evidence, not finding counts');
  assert.strictEqual(readiness.afterApprovedPct, null);
  assert.strictEqual(readiness.projectedPct, null);

  const appBuild = cryptoTwinEngine.generateUpdatedApplication(null, ['m1'], result.migrations);
  assert(appBuild.diffText !== undefined, 'Generated application must produce diff patch text');
  assert.strictEqual(appBuild.approvedCount, 0, 'Unverified recommendations must not be applied as approved migrations');

  console.log('✓ Per-finding recommendations, unverified evidence, and scan-derived readiness verified.');
  console.log('--- CryptoTwin Unit Tests Passed Successfully ---');
})().catch(error => { console.error(error); process.exitCode = 1; });
