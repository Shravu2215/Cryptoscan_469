'use strict';

/**
 * P0-5 Mosca Scoring & Quantum Classification Tests
 * Run: node test/moscaScoring.test.js
 */

const assert = require('assert');
const {
  classifyQuantum,
  computeFindingMosca,
  computeOverallPosture,
  Z_PRESETS,
  DEFAULT_Z_YEARS,
  getZPreset,
} = require('../src/services/vulnScoring');

console.log('Running P0-5 Mosca Scoring & Quantum Classification Tests...\n');

// 1. broken
{
  assert.strictEqual(classifyQuantum({ algorithm: 'RSA-2048' }), 'broken');
  assert.strictEqual(classifyQuantum({ algorithm: 'RSA-4096' }), 'broken');
  assert.strictEqual(classifyQuantum({ algorithm: 'DSA' }), 'broken');
  assert.strictEqual(classifyQuantum({ algorithm: 'ECDSA-P256' }), 'broken');
  assert.strictEqual(classifyQuantum({ algorithm: 'ECDH' }), 'broken');
  assert.strictEqual(classifyQuantum({ algorithm: 'Ed25519' }), 'broken');
  assert.strictEqual(classifyQuantum({ algorithm: 'DH' }), 'broken');
  console.log('✓ Test 1 Passed: RSA, DSA, DH, and ECC family all classified as broken');
}

// 2. weakened
{
  assert.strictEqual(classifyQuantum({ algorithm: 'AES-128' }), 'weakened');
  assert.strictEqual(classifyQuantum({ algorithm: 'AES', keySize: 128 }), 'weakened');
  assert.strictEqual(classifyQuantum({ algorithm: 'SHA-224' }), 'weakened');
  assert.strictEqual(classifyQuantum({ algorithm: 'RIPEMD-160' }), 'weakened');
  console.log('✓ Test 2 Passed: AES-128 and short hashes classified as weakened');
}

// 3. resilient
{
  assert.strictEqual(classifyQuantum({ algorithm: 'AES-256' }), 'resilient');
  assert.strictEqual(classifyQuantum({ algorithm: 'AES', keySize: 256 }), 'resilient');
  assert.strictEqual(classifyQuantum({ algorithm: 'SHA-256' }), 'resilient');
  assert.strictEqual(classifyQuantum({ algorithm: 'SHA256' }), 'resilient');
  assert.strictEqual(classifyQuantum({ algorithm: 'HMAC-SHA256' }), 'resilient');
  assert.strictEqual(classifyQuantum({ algorithm: 'HMAC' }), 'resilient');
  assert.strictEqual(classifyQuantum({ algorithm: 'SHA-384' }), 'resilient');
  assert.strictEqual(classifyQuantum({ algorithm: 'SHA-512' }), 'resilient');
  assert.strictEqual(classifyQuantum({ algorithm: 'ChaCha20-Poly1305' }), 'resilient');
  console.log('✓ Test 3 Passed: AES-256, SHA-256, HMAC, SHA-384+, ChaCha20 classified as resilient');
}

// 4. classical
{
  assert.strictEqual(classifyQuantum({ algorithm: 'MD5' }), 'classical');
  assert.strictEqual(classifyQuantum({ algorithm: 'SHA-1' }), 'classical');
  assert.strictEqual(classifyQuantum({ algorithm: 'DES' }), 'classical');
  assert.strictEqual(classifyQuantum({ algorithm: 'AES-128', mode: 'ECB' }), 'classical');
  assert.strictEqual(classifyQuantum({ algorithm: 'AES-256', description: 'Hardcoded secret key in source' }), 'classical');
  assert.strictEqual(classifyQuantum({ algorithm: 'Math.random' }), 'classical');
  assert.strictEqual(classifyQuantum({ ruleId: 'HARDCODED_API_KEY', algorithm: 'SECRET' }), 'classical');
  console.log('✓ Test 4 Passed: Hardcoded secrets, MD5, weak RNG, ECB mode classified as classical');
}

// 5. SHA-256 with keySize=256 must NOT be broken (guards scans.js line-91 bug)
{
  const sha = { algorithm: 'SHA-256', keySize: 256 };
  assert.strictEqual(classifyQuantum(sha), 'resilient');
  assert.notStrictEqual(classifyQuantum(sha), 'broken');
  console.log('✓ Test 5 Passed: SHA-256 not misclassified as broken even when keySize=256');
}

// 6. Mosca NOT applicable to resilient findings
{
  const moscaAes = computeFindingMosca({ algorithm: 'AES-256', dataLifetime: 30 }, 7);
  const moscaSha = computeFindingMosca({ algorithm: 'SHA-256', dataLifetime: 30 }, 7);
  assert.strictEqual(moscaAes.mosca_applicable, false);
  assert.strictEqual(moscaAes.urgency_tier, null);
  assert.strictEqual(moscaAes.mosca_at_risk, false);
  assert.strictEqual(moscaSha.mosca_applicable, false);
  assert.strictEqual(moscaSha.urgency_tier, null);
  assert.strictEqual(moscaSha.mosca_at_risk, false);
  console.log('✓ Test 6 Passed: AES-256 and SHA-256 never receive Critical Mosca urgency');
}

// 7. Mosca NOT applicable to classical findings
{
  assert.strictEqual(computeFindingMosca({ algorithm: 'MD5', dataLifetime: 20 }, 12).mosca_applicable, false);
  assert.strictEqual(computeFindingMosca({ algorithm: 'SECRET', description: 'Hardcoded password' }, 12).mosca_applicable, false);
  assert.strictEqual(computeFindingMosca({ algorithm: 'HMAC-SHA256' }, 12).mosca_applicable, false);
  console.log('✓ Test 7 Passed: Classical and resilient findings never enter the Mosca heatmap');
}

// 8. Mosca correctly computed for broken (RSA-2048): X=10, Y=2.5, Z=12 => -0.5 => Critical
{
  const m = computeFindingMosca({ algorithm: 'RSA-2048', dataLifetime: 10, isComplex: true }, 12, 'CRITICAL');
  assert.strictEqual(m.mosca_applicable, true);
  assert.strictEqual(m.quantum_class, 'broken');
  assert.strictEqual(m.mosca_at_risk, true);
  assert.strictEqual(m.urgency_tier, 'Critical');
  assert.strictEqual(m.urgency_margin, -0.5);
  console.log('✓ Test 8 Passed: Mosca correctly computed for RSA-2048 (Critical urgency, margin=-0.5)');
}

// 9. Z Presets — labels, years, sources
{
  assert.strictEqual(Z_PRESETS.early.years, 7);
  assert.strictEqual(Z_PRESETS.early.label, 'Early Quantum Computer');
  assert(Z_PRESETS.early.source.includes('backend-core/src/services/vulnScoring.js:134'));
  assert.strictEqual(Z_PRESETS.median.years, 12);
  assert.strictEqual(Z_PRESETS.median.label, 'Median Quantum Computer');
  assert(Z_PRESETS.median.source.includes('source to confirm'));
  assert.strictEqual(Z_PRESETS.late.years, 20);
  assert.strictEqual(Z_PRESETS.late.label, 'Late Quantum Computer');
  assert(Z_PRESETS.late.source.includes('source to confirm'));
  assert.strictEqual(DEFAULT_Z_YEARS, 12);
  assert.strictEqual(getZPreset('early').years, 7);
  assert.strictEqual(getZPreset('median').years, 12);
  assert.strictEqual(getZPreset('late').years, 20);
  console.log('✓ Test 9 Passed: Z presets define early (7y), median (12y), late (20y) correctly');
}

// 10. Changing Z changes urgency for broken/weakened only
//     RSA: X=6, migrationTime=1.0 => X+Y=7
//     Z=7  => margin=0.0  => High (0 <= 2)
//     Z=12 => margin=5.0  => Medium (2 < m <= 5)
//     Z=20 => margin=13.0 => Low
{
  const rsa = { algorithm: 'RSA-2048', dataLifetime: 6, migrationTime: 1.0 };
  assert.strictEqual(computeFindingMosca(rsa, 7).urgency_tier,  'High');
  assert.strictEqual(computeFindingMosca(rsa, 12).urgency_tier, 'Medium');
  assert.strictEqual(computeFindingMosca(rsa, 20).urgency_tier, 'Low');
  assert.strictEqual(computeFindingMosca({ algorithm: 'AES-256' }, 7).urgency_tier,  null);
  assert.strictEqual(computeFindingMosca({ algorithm: 'AES-256' }, 20).urgency_tier, null);
  assert.strictEqual(computeFindingMosca({ algorithm: 'MD5' }, 7).urgency_tier,  null);
  assert.strictEqual(computeFindingMosca({ algorithm: 'MD5' }, 20).urgency_tier, null);
  console.log('✓ Test 10 Passed: Z preset changes urgency for broken/weakened only; resilient/classical unchanged');
}

// 11. computeOverallPosture — count breakdown
{
  const findings = [
    { algorithm: 'RSA-2048' }, { algorithm: 'ECDSA' },
    { algorithm: 'AES-128' },
    { algorithm: 'AES-256' }, { algorithm: 'SHA-256' }, { algorithm: 'HMAC-SHA256' },
    { algorithm: 'MD5' }, { algorithm: 'SECRET' },
  ];
  const p = computeOverallPosture(findings, 12);
  assert.strictEqual(p.totalFindings, 8);
  assert.strictEqual(p.brokenCount, 2);
  assert.strictEqual(p.weakenedCount, 1);
  assert.strictEqual(p.resilientCount, 3);
  assert.strictEqual(p.classicalCount, 2);
  assert.strictEqual(p.quantumVulnerableCount, 3);
  assert.strictEqual(p.quantumVulnerableCount, p.brokenCount + p.weakenedCount);
  console.log('✓ Test 11 Passed: Heatmap total = broken + weakened (3 of 8, not 46 of 46)');
}

// 12. computeOverallPosture — verdict
{
  const safePosture = computeOverallPosture(
    [{ algorithm: 'AES-256' }, { algorithm: 'SHA-256' }, { algorithm: 'HMAC' }], 12
  );
  assert.strictEqual(safePosture.verdict, 'LOW');

  const urgentPosture = computeOverallPosture(
    [{ algorithm: 'RSA-2048', dataLifetime: 15 }], 12
  );
  assert.strictEqual(urgentPosture.verdict, 'CRITICAL');
  console.log('✓ Test 12 Passed: Posture verdict correct (LOW for safe findings, CRITICAL for urgent broken)');
}

console.log('\nAll 12 Mosca Scoring tests passed successfully!');