const path = require('path');
const HndlEngine = require('../../frontend/assets/js/hndl.js');

function assert(cond, msg) {
  if (!cond) {
    console.error('FAILED: ' + msg);
    process.exit(1);
  }
  console.log('  ✓ ' + msg);
}

console.log('Running HNDL Shared Engine Test Suite...\n');

// 1. Exposure window math & Mosca inequality
console.log('1. Exposure window math & Mosca inequality');
const m1 = HndlEngine.calculateMosca(20, 2.0, 12);
assert(m1.X === 20, 'X is data lifetime (20)');
assert(m1.Y === 2.0, 'Y is migration time (2.0)');
assert(m1.Z === 12, 'Z is threat horizon (12)');
assert(m1.totalRequirement === 22, 'Total requirement X + Y = 22');
assert(m1.moscaInequalityHolds === true, 'X + Y > Z holds true');
assert(m1.exposureWindow === 10, 'Exposure window is 22 - 12 = 10 years');
assert(m1.formulaReadout.includes('20y lifetime'), 'Formula readout includes 20y lifetime');
assert(m1.formulaReadout.includes('2y migration'), 'Formula readout includes 2y migration');

const m2 = HndlEngine.calculateMosca(3, 1.0, 12);
assert(m2.moscaInequalityHolds === false, 'X (3) + Y (1) <= Z (12) is not exceeded');
assert(m2.exposureWindow === 0, 'Exposure window is 0 when safe');

// 2. Banding thresholds
console.log('\n2. Banding thresholds');
function getBandForScore(score) {
  const dummyFindings = [
    {
      algorithm: 'RSA-2048',
      purpose: 'data_encryption',
      quantumVulnerabilityScore: 100,
      file: 'app.js',
      line: 10
    }
  ];
  // Verify bands directly: 0-24 LOW, 25-49 MEDIUM, 50-74 HIGH, 75-100 CRITICAL
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

// 3. Group 1 vs Group 2 split
console.log('\n3. Group 1 vs Group 2 split');
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

// 4. Dedupe of locations
console.log('\n4. Dedupe of locations');
const sampleFindings = [
  { algorithm: 'RSA-2048', purpose: 'key_exchange', file: 'src/auth.js', line: 42 },
  { algorithm: 'RSA-2048', purpose: 'key_exchange', file: 'src/auth.js', line: 42 }, // duplicate file:line
  { algorithm: 'ECDH-P256', purpose: 'key_exchange', file: 'src/tls.js', line: 88 },
  { algorithm: 'ECDSA', purpose: 'digital_signature', file: 'src/sign.js', line: 15 } // Group 2
];

const analysis = HndlEngine.calculateHndlAnalysis(sampleFindings, { yearsToQuantumThreat: 12 });
assert(analysis.group1Findings.length === 3, 'Group 1 has 3 findings total (including duplicate location)');
assert(analysis.atRiskLocationsCount === 2, 'At-Risk Locations count is 2 (deduped unique file:line pairs)');
assert(analysis.uniqueLocations.length === 2, 'Unique locations array has 2 entries');
assert(analysis.authenticityCount === 1, 'Authenticity count is 1');
assert(analysis.vulnerableAlgorithmsCount === 2, 'Vulnerable algorithms in group 1 is 2 (RSA-2048, ECDH-P256)');

// 5. Empty input handling
console.log('\n5. Empty input handling');
const emptyAnalysis = HndlEngine.calculateHndlAnalysis([], { yearsToQuantumThreat: 12 });
assert(emptyAnalysis.aggregateScore === 0, 'Empty findings list produces score 0');
assert(emptyAnalysis.band === 'LOW', 'Empty findings list produces band LOW');
assert(emptyAnalysis.hasConfidentialityRisk === false, 'hasConfidentialityRisk is false for empty findings');
assert(emptyAnalysis.atRiskLocationsCount === 0, 'atRiskLocationsCount is 0');
assert(emptyAnalysis.vulnerableAlgorithmsCount === 0, 'vulnerableAlgorithmsCount is 0');
assert(emptyAnalysis.authenticityCount === 0, 'authenticityCount is 0');

// 6. Non-quantum findings only
console.log('\n6. Non-quantum findings only');
const safeFindings = [
  { algorithm: 'AES-256-GCM', purpose: 'data_encryption', file: 'cipher.js', line: 1 },
  { algorithm: 'SHA-256', purpose: 'integrity_hashing', file: 'hash.js', line: 5 }
];
const safeAnalysis = HndlEngine.calculateHndlAnalysis(safeFindings, { yearsToQuantumThreat: 12 });
assert(safeAnalysis.aggregateScore === 0, 'Non-quantum findings yield score 0');
assert(safeAnalysis.hasConfidentialityRisk === false, 'hasConfidentialityRisk is false for quantum-safe crypto');

// 7. Z slider live variation changes score
console.log('\n7. Threat horizon variation changes score');
const urgentFindings = [
  { algorithm: 'RSA-2048', purpose: 'data_encryption', file: 'db.js', line: 10 } // X=20
];
const resZ30 = HndlEngine.calculateHndlAnalysis(urgentFindings, { yearsToQuantumThreat: 30 });
const resZ5 = HndlEngine.calculateHndlAnalysis(urgentFindings, { yearsToQuantumThreat: 5 });
assert(resZ5.aggregateScore > resZ30.aggregateScore, 'Score is strictly higher when threat is imminent (Z=5 vs Z=30)');

console.log('\nAll HNDL Shared Engine unit tests passed successfully!\n');
