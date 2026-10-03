/**
 * Unit Tests for PQC Simulator — Findings Filter, User-Entered Limits, Verdict
 *
 * Usage (Node.js):
 *   node frontend/tests/pqcFindingsAndLimitsTests.js
 */

if (typeof window === 'undefined') {
  const { JSDOM } = require('jsdom');
  const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
  global.window = dom.window;
  global.document = dom.window.document;
  const fs = require('fs');
  const path = require('path');
  eval(fs.readFileSync(path.resolve(__dirname, '..', 'assets', 'js', 'pqcSizes.js'), 'utf-8'));
}

const PQCSizes = window.PQCSizes;

let passed = 0;
let failed = 0;

function assert(condition, testName) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${testName}`);
  } else {
    failed++;
    console.error(`  ✗ FAIL: ${testName}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Test 1: Default limits → Estimated risk, Review verdict ===');

(function testDefaultLimits() {
  // No user limits, no scanned evidence → should be Estimated risk, Review
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', {}, {});
  const jwt = res.matrix.find(r => r.id === 'jwt');
  const tls = res.matrix.find(r => r.id === 'tls');

  assert(jwt.status === 'Estimated risk', 'JWT row: Estimated risk with no user limits');
  assert(jwt.evidence.includes('Default protocol limit'), 'JWT evidence: mentions default protocol limit');
  assert(jwt.evidence.includes('4,096'), 'JWT evidence: shows 4,096 B');
  assert(jwt.evidence.includes('may break'), 'JWT evidence: says may break');

  assert(tls.status === 'Estimated risk', 'TLS row: Estimated risk with no user limits');
  assert(tls.evidence.includes('Default protocol limit'), 'TLS evidence: mentions default protocol limit');

  assert(res.kpis.verdict === 'Review', 'Verdict is Review (only Estimated risks)');
  assert(!res.matrix.some(r => r.status === 'Confirmed issue'), 'No row is Confirmed issue');
})();

// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Test 2: User enters cookie limit 4096 → Confirmed issue, Breaking ===');

(function testUserEnteredCookieLimit() {
  // User typed 4096 in the cookie limit field → this is NOT the same as the
  // default because onLimitChanged now only includes changed keys.
  // However, in the data engine, if userLimits.cookieLimit is provided, it
  // triggers Confirmed issue.
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure',
    { cookieLimit: 4096 }, {});
  const jwt = res.matrix.find(r => r.id === 'jwt');

  assert(jwt.status === 'Confirmed issue', 'JWT row: Confirmed issue with user-entered limit');
  assert(jwt.evidence.includes('User-entered limit'), 'JWT evidence: says user-entered');
  assert(jwt.evidence.includes('4,096'), 'JWT evidence: shows 4,096 B');

  assert(res.kpis.verdict === 'Breaking', 'Verdict is Breaking (has Confirmed issue)');
})();

// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Test 3: User enters cookie limit 5000 → JWT fits, No issue ===');

(function testUserEnteredHighCookieLimit() {
  // 5000 B > 4729 B JWT → fits, so No issue even though user entered it
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure',
    { cookieLimit: 5000 }, {});
  const jwt = res.matrix.find(r => r.id === 'jwt');

  assert(jwt.status === 'No issue', 'JWT row: No issue when user limit is higher than after-size');
  assert(jwt.evidence.includes('Fits comfortably'), 'JWT evidence: fits comfortably');
})();

// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Test 4: Reset to defaults → back to Estimated risk, Review ===');

(function testResetToDefaults() {
  // After reset, userCustomLimits = {} → should be back to Estimated risk
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', {}, {});
  const jwt = res.matrix.find(r => r.id === 'jwt');

  assert(jwt.status === 'Estimated risk', 'JWT row: Estimated risk after reset');
  assert(res.kpis.verdict === 'Review', 'Verdict: Review after reset');
})();

// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Test 5: User enters TLS limit → TLS becomes Confirmed ===');

(function testUserEnteredTlsLimit() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure',
    { tlsInitCwnd: 14600 }, {});
  const tls = res.matrix.find(r => r.id === 'tls');

  assert(tls.status === 'Confirmed issue', 'TLS row: Confirmed issue with user-entered limit');
  assert(tls.evidence.includes('User-entered limit'), 'TLS evidence: says user-entered');
  assert(res.kpis.verdict === 'Breaking', 'Verdict: Breaking');
})();

// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Test 6: No scanned evidence → never Confirmed from scan ===');

(function testNoFakeConfirmed() {
  // Even with evidence that doesn't have parsedLimit → should not be Confirmed
  const fakeEvidence = {
    jwt: { file: 'nginx.conf', line: 13, source: 'scanned finding' },
    tls: { file: 'nginx.conf', line: 13, source: 'scanned finding' }
    // Note: no parsedLimit field!
  };
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', {}, fakeEvidence);
  const jwt = res.matrix.find(r => r.id === 'jwt');
  const tls = res.matrix.find(r => r.id === 'tls');

  assert(jwt.status === 'Estimated risk', 'JWT: NOT Confirmed with evidence lacking parsedLimit');
  assert(tls.status === 'Estimated risk', 'TLS: NOT Confirmed with evidence lacking parsedLimit');
  assert(!jwt.evidence.includes('Scanned config'), 'JWT: no Scanned config text');
})();

// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Test 7: Real parsedLimit evidence → Confirmed from scan ===');

(function testRealParsedLimit() {
  const realEvidence = {
    jwt: {
      file: 'nginx.conf', line: 5,
      parsedLimit: { directive: 'large_client_header_buffers', value: 4096 }
    }
  };
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', {}, realEvidence);
  const jwt = res.matrix.find(r => r.id === 'jwt');

  assert(jwt.status === 'Confirmed issue', 'JWT: Confirmed with real parsedLimit');
  assert(jwt.evidence.includes('nginx.conf'), 'JWT evidence: mentions nginx.conf');
  assert(jwt.evidence.includes('large_client_header_buffers'), 'JWT evidence: mentions directive');
})();

// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Test 8: Certificate chain row is Informational ===');

(function testCertChainInformational() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', {}, {});
  const cert = res.matrix.find(r => r.id === 'cert');

  assert(cert.status === 'Informational', 'Cert: Informational status');
  assert(cert.isInformational === true, 'Cert: isInformational flag is true');
  assert(cert.limit === null, 'Cert: limit is null');
  assert(cert.limitDisplay === 'N/A', 'Cert: limitDisplay is N/A');
  assert(cert.evidence.includes('grew'), 'Cert evidence: mentions chain grew');
})();

// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Test 9: TLS flight key share is 32 B for signature-only replacement ===');

(function testTlsKeyShare() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', {}, {});
  const tls = res.matrix.find(r => r.id === 'tls');

  // ML-DSA-65 is a signature algo, so key share stays X25519 = 32 B
  // Chain = 3 * (1952 + 3309 + 300) = 16683 B
  // Flight = 16683 + 32 = 16715 B
  assert(tls.afterSize === 16715, `TLS after = 16715 (got ${tls.afterSize})`);
  assert(tls.breakdown.includes('Key Share (32 B)'), 'TLS breakdown shows Key Share (32 B)');
})();

// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Test 10: Components at risk count matches matrix ===');

(function testComponentsCount() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', {}, {});
  const matrixAffected = res.matrix.filter(r => r.status === 'Confirmed issue' || r.status === 'Estimated risk').length;

  assert(res.kpis.affectedScenariosCount === matrixAffected,
    `KPI count (${res.kpis.affectedScenariosCount}) matches matrix count (${matrixAffected})`);
})();

// ─────────────────────────────────────────────────────────────────────────────
console.log('\n\n' + '='.repeat(50));
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.error('SOME TESTS FAILED');
  if (typeof process !== 'undefined') process.exit(1);
} else {
  console.log('ALL TESTS PASSED ✓');
}
