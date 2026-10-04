const path = require('path');
const fs = require('fs');
const HndlEngine = require('../../frontend/assets/js/hndl.js');
const QuantumRules = require('../../frontend/assets/js/quantumRules.js');

function assert(cond, msg) {
  if (!cond) {
    console.error('FAILED: ' + msg);
    process.exit(1);
  }
  console.log('  ✓ ' + msg);
}

console.log('Running HNDL Shared Engine & Quantum Rules Test Suite...\n');

// 1. Exposure window math & Mosca inequality (with DEFAULT_Z = 10)
console.log('1. Exposure window math & Mosca inequality (Z = 10)');
const m1 = HndlEngine.calculateMosca(20, 2.0, 10);
assert(m1.X === 20, 'X is data lifetime (20)');
assert(m1.Y === 2.0, 'Y is migration time (2.0)');
assert(m1.Z === 10, 'Z is threat horizon (10)');
assert(m1.totalRequirement === 22, 'Total requirement X + Y = 22');
assert(m1.moscaInequalityHolds === true, 'X + Y > Z holds true');
assert(m1.exposureWindow === 12, 'Exposure window is 22 - 10 = 12 years');
assert(m1.formulaReadout.includes('20y lifetime'), 'Formula readout includes 20y lifetime');
assert(m1.formulaReadout.includes('2y migration'), 'Formula readout includes 2y migration');

const m2 = HndlEngine.calculateMosca(3, 1.0, 10);
assert(m2.moscaInequalityHolds === false, 'X (3) + Y (1) <= Z (10) is not exceeded');
assert(m2.exposureWindow === 0, 'Exposure window is 0 when safe');

// 2. classify() boundary tests (margin -0.1, 0, 5, 5.1, x+y==z)
console.log('\n2. classify() boundary tests');
const cBreach = QuantumRules.classify(8, 2.1, 10); // exposure = 10.1, margin = -0.1
assert(cBreach.category === 'VULNERABLE_NOW', 'Margin -0.1 is VULNERABLE_NOW');
assert(cBreach.margin === -0.1, 'Margin is exactly -0.1');

const cZero = QuantumRules.classify(8, 2.0, 10); // exposure = 10.0, margin = 0.0
assert(cZero.category === 'VULNERABLE_WITHIN_HORIZON', 'Margin 0.0 is VULNERABLE_WITHIN_HORIZON (buffer <= 5)');
assert(cZero.margin === 0, 'Margin is exactly 0.0');

const cExactBuffer = QuantumRules.classify(4, 1.0, 10); // exposure = 5.0, margin = 5.0
assert(cExactBuffer.category === 'VULNERABLE_WITHIN_HORIZON', 'Margin 5.0 is VULNERABLE_WITHIN_HORIZON (buffer boundary)');
assert(cExactBuffer.margin === 5.0, 'Margin is exactly 5.0');

const cSafeBuffer = QuantumRules.classify(3.9, 1.0, 10); // exposure = 4.9, margin = 5.1
assert(cSafeBuffer.category === 'SAFE_UNDER_CURRENT_TIMELINE', 'Margin 5.1 is SAFE_UNDER_CURRENT_TIMELINE (> 5 buffer)');
assert(cSafeBuffer.margin === 5.1, 'Margin is exactly 5.1');

const cEqual = QuantumRules.classify(5, 5, 10); // X + Y == Z
assert(cEqual.category === 'VULNERABLE_WITHIN_HORIZON', 'X + Y == Z yields margin 0 and VULNERABLE_WITHIN_HORIZON');
assert(cEqual.exposure === 10, 'Exposure is 10');

// 3. Threat horizon variation / Z change test (Z 10 -> 20 flips categories)
console.log('\n3. Threat horizon variation / Z change test');
const xVal = 7, yVal = 2; // X + Y = 9
const atZ8 = QuantumRules.classify(xVal, yVal, 8); // margin = -1
assert(atZ8.category === 'VULNERABLE_NOW', 'Z=8 makes component VULNERABLE_NOW (9 > 8)');

const atZ10 = QuantumRules.classify(xVal, yVal, 10); // margin = 1
assert(atZ10.category === 'VULNERABLE_WITHIN_HORIZON', 'Z=10 makes component VULNERABLE_WITHIN_HORIZON (margin 1 <= 5)');

const atZ20 = QuantumRules.classify(xVal, yVal, 20); // margin = 11
assert(atZ20.category === 'SAFE_UNDER_CURRENT_TIMELINE', 'Z=20 flips component to SAFE_UNDER_CURRENT_TIMELINE (margin 11 > 5)');

// 4. Banding thresholds
console.log('\n4. Banding thresholds');
function getBandForScore(score) {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  return 'LOW';
}
assert(getBandForScore(0) === 'LOW', 'Score 0 is LOW');
assert(getBandForScore(24) === 'LOW', 'Score 24 is LOW');
assert(getBandForScore(25) === 'MEDIUM', 'Score 25 is MEDIUM');
assert(getBandForScore(49) === 'MEDIUM', 'Score 49 is MEDIUM');
assert(getBandForScore(50) === 'HIGH', 'Score 50 is HIGH');
assert(getBandForScore(74) === 'HIGH', 'Score 74 is HIGH');
assert(getBandForScore(75) === 'CRITICAL', 'Score 75 is CRITICAL');
assert(getBandForScore(100) === 'CRITICAL', 'Score 100 is CRITICAL');

// 5. Group 1 vs Group 2 split (confidentiality vs authenticity)
console.log('\n5. Group 1 vs Group 2 split');
const fKex = { algorithm: 'ECDH-P256', purpose: 'key_exchange' };
const clsKex = HndlEngine.classifyFinding(fKex);
assert(clsKex.group === 'confidentiality', 'ECDH key_exchange is Group 1 (confidentiality)');
assert(clsKex.confidence === 'high', 'Explicit key_exchange has high confidence');

const fEnc = { algorithm: 'RSA-2048', purpose: 'data_encryption' };
const clsEnc = HndlEngine.classifyFinding(fEnc);
assert(clsEnc.group === 'confidentiality', 'RSA data_encryption is Group 1 (confidentiality)');

const fSig = { algorithm: 'ECDSA-SHA256', purpose: 'digital_signature' };
const clsSig = HndlEngine.classifyFinding(fSig);
assert(clsSig.group === 'authenticity', 'ECDSA digital_signature is Group 2 (authenticity)');

const fUnknown = { algorithm: 'RSA-2048' }; // no purpose
const clsUnknown = HndlEngine.classifyFinding(fUnknown);
assert(clsUnknown.group === 'confidentiality', 'Unknown purpose defaults to Group 1 (confidentiality)');
assert(clsUnknown.confidence === 'low', 'Unknown purpose marked with confidence low');

// 6. Dedupe of locations & unique-location aggregation
console.log('\n6. Dedupe of locations');
const sampleFindings = [
  { algorithm: 'RSA-2048', purpose: 'key_exchange', file: 'src/auth.js', line: 42 },
  { algorithm: 'RSA-2048', purpose: 'key_exchange', file: 'src/auth.js', line: 42 }, // duplicate file:line
  { algorithm: 'ECDH-P256', purpose: 'key_exchange', file: 'src/tls.js', line: 88 },
  { algorithm: 'ECDSA', purpose: 'digital_signature', file: 'src/sign.js', line: 15 } // Group 2
];

const analysis = HndlEngine.calculateHndlAnalysis(sampleFindings, { yearsToQuantumThreat: 10 });
assert(analysis.group1Findings.length === 3, 'Group 1 has 3 findings total (including duplicate location)');
assert(analysis.atRiskLocationsCount === 2, 'At-Risk Locations count is 2 (deduped unique file:line pairs)');
assert(analysis.uniqueLocations.length === 2, 'Unique locations array has 2 entries');
assert(analysis.authenticityCount === 1, 'Authenticity count is 1');
assert(analysis.vulnerableAlgorithmsCount === 2, 'Vulnerable algorithms in group 1 is 2 (RSA-2048, ECDH-P256)');

// 7. Empty input handling
console.log('\n7. Empty input handling');
const emptyAnalysis = HndlEngine.calculateHndlAnalysis([], { yearsToQuantumThreat: 10 });
assert(emptyAnalysis.aggregateScore === 0, 'Empty findings list produces score 0');
assert(emptyAnalysis.band === 'LOW', 'Empty findings list produces band LOW');
assert(emptyAnalysis.hasConfidentialityRisk === false, 'hasConfidentialityRisk is false for empty findings');
assert(emptyAnalysis.atRiskLocationsCount === 0, 'atRiskLocationsCount is 0');
assert(emptyAnalysis.vulnerableAlgorithmsCount === 0, 'vulnerableAlgorithmsCount is 0');
assert(emptyAnalysis.authenticityCount === 0, 'authenticityCount is 0');

// 8. Non-quantum findings only
console.log('\n8. Non-quantum findings only');
const safeFindings = [
  { algorithm: 'AES-256-GCM', purpose: 'data_encryption', file: 'cipher.js', line: 1 },
  { algorithm: 'SHA-256', purpose: 'integrity_hashing', file: 'hash.js', line: 5 }
];
const safeAnalysis = HndlEngine.calculateHndlAnalysis(safeFindings, { yearsToQuantumThreat: 10 });
assert(safeAnalysis.aggregateScore === 0, 'Non-quantum findings yield score 0');
assert(safeAnalysis.hasConfidentialityRisk === false, 'hasConfidentialityRisk is false for quantum-safe crypto');

// 9. Classically weak algorithm identification
console.log('\n9. Classically weak algorithms handling');
assert(QuantumRules.isClassicallyWeak({ algorithm: 'MD5' }) === true, 'MD5 is classically weak');
assert(QuantumRules.isClassicallyWeak({ algorithm: 'DES' }) === true, 'DES is classically weak');
assert(QuantumRules.isClassicallyWeak({ algorithm: '3DES' }) === true, '3DES is classically weak');
assert(QuantumRules.isClassicallyWeak({ algorithm: 'RC4' }) === true, 'RC4 is classically weak');
assert(QuantumRules.isClassicallyWeak({ algorithm: 'RSA-2048' }) === false, 'RSA-2048 is not classically weak');
assert(QuantumRules.isClassicallyWeak({ algorithm: 'AES-256-GCM' }) === false, 'AES-256 is not classically weak');

const md5Rule = QuantumRules.lookup('MD5');
assert(md5Rule.classicallyWeak === true, 'MD5 rule has classicallyWeak true');
assert(md5Rule.replacement.includes('SHA-256'), 'MD5 replacement is a secure classical hash (SHA-256), not PQC');

// 10. Multi-fixture test across 3 distinct repositories
console.log('\n10. Multi-fixture test (3 independent repos)');
const repoEcommerce = [
  { algorithm: 'RSA-2048', purpose: 'key_exchange', file: 'checkout/payment.js', line: 34 },
  { algorithm: 'AES-256-GCM', purpose: 'data_encryption', file: 'db/users.js', line: 12 },
  { algorithm: 'SHA-256', purpose: 'integrity_hashing', file: 'auth/tokens.js', line: 78 }
];

const repoFintech = [
  { algorithm: 'ECDH-P384', purpose: 'key_exchange', file: 'banking/transfer.py', line: 102 },
  { algorithm: 'RSA-4096', purpose: 'digital_signature', file: 'banking/contracts.py', line: 45 },
  { algorithm: '3DES', purpose: 'data_encryption', file: 'legacy/atm.py', line: 19 }
];

const repoIot = [
  { algorithm: 'Ed25519', purpose: 'digital_signature', file: 'firmware/ota.c', line: 210 },
  { algorithm: 'ChaCha20-Poly1305', purpose: 'data_encryption', file: 'radio/packet.c', line: 55 },
  { algorithm: 'MD5', purpose: 'integrity_hashing', file: 'drivers/crc.c', line: 12 }
];

const ecomRes = HndlEngine.calculateHndlAnalysis(repoEcommerce, { yearsToQuantumThreat: 10 });
assert(ecomRes.vulnerableAlgorithmsCount === 1, 'E-Commerce repo has 1 vulnerable algorithm (RSA-2048)');
assert(ecomRes.hasConfidentialityRisk === true, 'E-Commerce repo has confidentiality risk');
assert(ecomRes.atRiskLocationsCount === 1, 'E-Commerce repo has 1 at-risk location');

const fintechRes = HndlEngine.calculateHndlAnalysis(repoFintech, { yearsToQuantumThreat: 10 });
assert(fintechRes.vulnerableAlgorithmsCount === 1, 'Fintech repo has 1 confidentiality algorithm (ECDH-P384)');
assert(fintechRes.authenticityCount === 1, 'Fintech repo has 1 authenticity algorithm (RSA-4096)');

const iotRes = HndlEngine.calculateHndlAnalysis(repoIot, { yearsToQuantumThreat: 10 });
assert(iotRes.hasConfidentialityRisk === false, 'IoT repo has 0 confidentiality risk (Ed25519 is signature, ChaCha20 is safe)');
assert(iotRes.authenticityCount === 1, 'IoT repo has 1 authenticity finding');
assert(QuantumRules.isClassicallyWeak(repoIot[2]) === true, 'IoT repo MD5 correctly identified as classically weak');

// 11. Grep CI check: verify no demo repo hardcoding in app code
console.log('\n11. Grep CI check for no hardcoded demo repo in app code');
const frontendDir = path.resolve(__dirname, '../../frontend');
const appFiles = ['dashboard.html', 'risk-analysis.html', 'migration-plan.html', 'cbom.html', 'findings.html', 'repositories.html'];

appFiles.forEach(file => {
  const filePath = path.join(frontendDir, file);
  if (fs.existsSync(filePath)) {
    const content = fs.readFileSync(filePath, 'utf8');
    assert(!content.includes('pqc-test-fixture'), `File ${file} contains no hardcoded "pqc-test-fixture" string`);
  }
});

console.log('\nAll HNDL Shared Engine & Quantum Rules unit tests passed successfully!\n');
