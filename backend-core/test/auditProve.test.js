'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const cryptoTwinEngine = require('../src/services/cryptoTwinEngine');

console.log('================================================================================');
console.log('           CRYPTOTWIN RECOMMENDATION EVIDENCE TEST SUITE                        ');
console.log('================================================================================\n');

// ── PART 1: Truth Table & Code Inspection Verification ────────────────────────
console.log('--- PART 1: EVIDENCE CONTRACT ---');
console.log('Recommendations are not applied. No build, round-trip, tamper, or rescan result is reported unless an actual check ran.');
console.log('Original secret values are omitted; source context is masked before any display.\n');

// ── PART 2: Empirical Verification & Fixture Execution ────────────────────────
(async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptotwin-fixtures-'));

  // Setup Test Fixtures
  const files = {
    'src/auth/jwt_service.py': `def sign_token(payload):\n    signer = pkcs1_15.new(RSA.import_key(key))\n    sig = signer.sign(h)\n    return sig`,
    'src/crypto/cipher.java': `Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");`,
    'src/auth/jwt.js': `const signer = crypto.createSign('RSA-SHA256');\nsigner.update(payload);\nconst sig = signer.sign(privateKey);`,
    'src/config/secrets.py': `API_KEY = "FIXTURE_HARDCODED_KEY_EXAMPLE_DO_NOT_USE"`,
    'src/utils/digest.py': `def get_hash(data):\n    return hashlib.md5(data).hexdigest()`,
    'src/utils/safe.py': `aesgcm = AESGCM(key)\nct = aesgcm.encrypt(nonce, data, None)`,
    'src/broken/syntax_error.py': `def bad_code(\n    return broken syntax`,
    'src/tamper/tamper_fail.py': `def verify_sig(payload, sig):\n    return True  # Weak verifier`,
    'src/comment_only.py': `// Legacy: RSA-2048 signing`
  };

  Object.entries(files).forEach(([relPath, content]) => {
    const absPath = path.join(tmpDir, relPath);
    fs.mkdirSync(path.dirname(absPath), { recursive: true });
    fs.writeFileSync(absPath, content, 'utf8');
  });

  const rawInputFixtureA = {
    repoName: 'Repo A — Primary Security Audit',
    items: [
      { id: 'f1', filePath: 'src/auth/jwt_service.py', line: 2, currentAlgorithm: 'RSA-2048', usageContext: 'jwt signing', severity: 'CRITICAL', language: 'Python' },
      { id: 'f2', filePath: 'src/crypto/cipher.java', line: 1, currentAlgorithm: '3DES', usageContext: 'legacy encryption', severity: 'HIGH', language: 'Java' },
      { id: 'f3', filePath: 'src/auth/jwt.js', line: 2, currentAlgorithm: 'RSA-2048', usageContext: 'jwt', severity: 'HIGH', language: 'JavaScript' },
      { id: 'f4', filePath: 'src/config/secrets.py', line: 1, currentAlgorithm: 'Hardcoded key material', usageContext: 'secret key', severity: 'CRITICAL', language: 'Python' },
      { id: 'f5', filePath: 'src/utils/digest.py', line: 2, currentAlgorithm: 'MD5', usageContext: 'hashing', severity: 'HIGH', language: 'Python' },
      { id: 'f6', filePath: 'src/utils/safe.py', line: 1, currentAlgorithm: 'AES-256-GCM', usageContext: 'encryption', severity: 'SAFE', language: 'Python' },
      { id: 'f7', filePath: 'src/broken/syntax_error.py', line: 2, currentAlgorithm: 'RSA-1024', usageContext: 'signing', severity: 'HIGH', language: 'Python' },
      { id: 'f8', filePath: 'src/tamper/tamper_fail.py', line: 2, currentAlgorithm: 'ECDSA-P256', usageContext: 'signing', severity: 'HIGH', language: 'Python' },
      { id: 'f9', filePath: 'src/comment_only.py', line: 1, currentAlgorithm: 'RSA-2048', usageContext: 'signing', severity: 'HIGH', language: 'Python' }
    ]
  };

  console.log('--- EXECUTING CRYPTOTWIN ENGINE ON FIXTURE REPO A ---');
  const resultA = await cryptoTwinEngine.runCryptoTwin(rawInputFixtureA, { sandboxDir: tmpDir });

  console.log('\n--- PER-ITEM VERIFICATION RESULTS ---');
  resultA.migrations.forEach(m => {
    console.log(`[${m.verificationStatus.padEnd(12)}] ${m.item.filePath}:${m.item.line} | ${m.item.currentAlgorithm} -> ${m.item.targetAlgorithm}`);
    if (m.unavailReason) {
      console.log(`              Reason: ${m.unavailReason}`);
    }
  });

  // Recommendations remain pending until an actual migrated source tree is tested.
  const rsaItem = resultA.migrations.find(m => m.item.filePath === 'src/auth/jwt_service.py');
  assert(rsaItem, 'RSA item must exist in results');
  assert.strictEqual(rsaItem.verificationStatus, 'NOT_TESTABLE');
  assert(rsaItem.evidence.checks.every(check => check.status === 'NOT_VERIFIED'));
  assert.strictEqual(rsaItem.evidence.rawLogs.length, 0);

  // Verify Spread of Statuses
  const counts = resultA.summary;
  console.log('\n--- REALISTIC STATUS SPREAD COUNTS ---');
  console.log(`In Scope Total   : ${counts.inScopeCount}`);
  console.log(`Excluded (Safe)  : ${counts.excludedCount}`);
  console.log(`VERIFIED         : ${counts.verifiedCount}`);
  console.log(`FAILED           : ${counts.failedCount}`);
  console.log(`NOT_TESTABLE     : ${counts.notTestableCount}`);

  assert.strictEqual(counts.verifiedCount, 0, 'A recommendation preview must not be reported as applied or verified');
  assert.strictEqual(counts.failedCount, 0, 'Checks that did not run are not reported as failed');
  assert.strictEqual(counts.notTestableCount, 8, 'All eight actionable findings remain unverified without an applied migration');

  // Verify Negative Tests
  const commentItem = resultA.migrations.find(m => m.item.filePath === 'src/comment_only.py');
  assert.strictEqual(commentItem.verificationStatus, 'NOT_TESTABLE');

  const tamperFailItem = resultA.migrations.find(m => m.item.filePath === 'src/tamper/tamper_fail.py');
  assert.strictEqual(tamperFailItem.verificationStatus, 'NOT_TESTABLE');

  // Verify Secret Protection
  console.log('\n--- ZERO RAW SECRET GREP SCAN ---');
  const jsonReportStr = JSON.stringify(resultA);
  const rawKeyInOutput = jsonReportStr.includes('FIXTURE_HARDCODED_KEY_EXAMPLE_DO_NOT_USE');
  console.log(`Raw fixture secret present in engine output: ${rawKeyInOutput}`);
  assert.strictEqual(rawKeyInOutput, false, 'Raw secret value must not be returned or stored');
  assert(!jsonReportStr.includes('sk_live_'), 'No Stripe-format keys allowed in output');

  // Verify Second Repo Execution (Distinct Fingerprints)
  console.log('\n--- EXECUTING CRYPTOTWIN ENGINE ON FIXTURE REPO B ---');
  const rawInputFixtureB = {
    repoName: 'Repo B — Payment Gateway Service',
    items: [
      { id: 'b1', filePath: 'payments/token.js', line: 15, currentAlgorithm: 'ECDSA-P256', usageContext: 'signing', severity: 'HIGH', language: 'JavaScript' },
      { id: 'b2', filePath: 'config/db.py', line: 5, currentAlgorithm: 'Hardcoded key material', usageContext: 'db secret', severity: 'CRITICAL', language: 'Python' }
    ]
  };
  const resultB = await cryptoTwinEngine.runCryptoTwin(rawInputFixtureB, { sandboxDir: tmpDir });
  console.log(`Repo A unverified recommendations: ${resultA.migrations.length} | Repo B unverified recommendations: ${resultB.migrations.length}`);
  assert(resultB.migrations.every(m => m.evidence.rawLogs.length === 0), 'No synthetic logs may be returned for an unapplied recommendation');

  // Verify Quantum Readiness Rescan Computation
  console.log('\n--- QUANTUM READINESS RESCAN COMPUTATION ---');
  const readiness0 = cryptoTwinEngine.computeQuantumReadiness(resultA.migrations.map(m => m.item), resultA.safeExcluded, new Set(), resultA.migrations);
  console.log(`Readiness score: ${readiness0.currentPct ?? 'Not yet verified'}`);
  assert.strictEqual(readiness0.currentPct, null, 'Finding counts do not establish CBOM readiness.');

  // Verify Updated Application Package Generation
  console.log('\n--- UPDATED APPLICATION PACKAGE GENERATION ---');
  const appBuild = cryptoTwinEngine.generateUpdatedApplication(null, ['f1', 'f2'], resultA.migrations);
  console.log(`Approved Count Applied: ${appBuild.approvedCount}`);
  console.log(`Patch Diff Output snippet:\n${appBuild.diffText.slice(0, 300)}...`);

  assert.strictEqual(appBuild.approvedCount, 0, 'Unverified suggestions must not be applied to an application package');

  // Clean up
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}

  console.log('\n================================================================================');
  console.log('         ALL RECOMMENDATION EVIDENCE TESTS PASSED SUCCESSFULLY!          ');
  console.log('================================================================================');
})();
