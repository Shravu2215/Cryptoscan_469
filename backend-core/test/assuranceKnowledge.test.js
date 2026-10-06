const path = require('path');
const AssuranceKnowledge = require('../../frontend/assets/js/assuranceKnowledge.js');

function assert(cond, msg) {
  if (!cond) {
    console.error('FAILED: ' + msg);
    process.exit(1);
  }
  console.log('  ✓ ' + msg);
}

console.log('Running PQC Assurance Knowledge & Resolver Test Suite...\n');

// 1. Resolver for standard Migration Plan algorithms
console.log('1. Resolving standard Migration Plan algorithms:');

const rsa2048 = AssuranceKnowledge.resolve('RSA-2048', 'ML-KEM (Kyber-768/1024) + Hybrid X25519/ML-KEM');
assert(rsa2048.id === 'ML-KEM', 'RSA-2048 resolves to ML-KEM');
assert(rsa2048.standards.includes('FIPS 203'), 'ML-KEM includes FIPS 203 citation');
assert(rsa2048.statusBadges.oldBadge === 'Quantum-Broken', 'RSA-2048 old badge is Quantum-Broken');
assert(rsa2048.statusBadges.newBadge === 'Quantum-Safe', 'RSA-2048 new badge is Quantum-Safe');
assert(rsa2048.whyQuantumSafe.length >= 2, 'ML-KEM provides >= 2 technical points');

const ecdsa = AssuranceKnowledge.resolve('ECDSA', 'ML-DSA (Dilithium-3/5) or SLH-DSA (SPHINCS+)');
assert(ecdsa.id === 'ML-DSA', 'ECDSA resolves to ML-DSA');
assert(ecdsa.standards.includes('FIPS 204'), 'ML-DSA includes FIPS 204 citation');
assert(ecdsa.statusBadges.newBadge === 'Quantum-Safe', 'ECDSA new badge is Quantum-Safe');

const md5 = AssuranceKnowledge.resolve('MD5', 'SHA-256 / SHA-3-256 / BLAKE3');
assert(md5.id === 'SHA-256', 'MD5 resolves to SHA-256');
assert(md5.standards.includes('FIPS 180-4 (SHA-2)'), 'MD5 replacement cites FIPS 180-4');
assert(md5.statusBadges.oldBadge === 'Legacy-Broken', 'MD5 old badge is Legacy-Broken');

const des = AssuranceKnowledge.resolve('DES', 'AES-256-GCM / ChaCha20-Poly1305');
assert(des.id === 'AES-256-GCM', 'DES resolves to AES-256-GCM');
assert(des.standards.includes('NIST SP 800-38D (AES-GCM)'), 'AES-256-GCM cites NIST SP 800-38D');
assert(des.standards.includes('RFC 8439 (ChaCha20-Poly1305)'), 'Cites RFC 8439');

const hardcoded = AssuranceKnowledge.resolve('Hardcoded key material', 'Secrets Manager / KMS / HashiCorp Vault');
assert(hardcoded.id === 'SECRETS-MANAGER', 'Hardcoded secret resolves to SECRETS-MANAGER');
assert(hardcoded.statusBadges.oldBadge === 'Harmful', 'Hardcoded secret old badge is Harmful');

const ecb = AssuranceKnowledge.resolve('AES-ECB', 'AES-256-GCM / AES-256-CBC with HMAC');
assert(ecb.id === 'AES-256-GCM', 'AES-ECB resolves to AES-256-GCM');
assert(ecb.statusBadges.oldBadge === 'Harmful', 'AES-ECB old badge is Harmful');

// 2. Safe / compliant algorithms
console.log('\n2. Safe / modern compliant algorithms:');
const sha256 = AssuranceKnowledge.resolve('SHA-256', 'None specified');
assert(sha256.id === 'SAFE-MODERN', 'SHA-256 resolves to SAFE-MODERN');
assert(sha256.isAlreadySafe === true, 'SHA-256 marked as already safe');

// 3. Fallback verification
console.log('\n3. Safe generic fallback verification:');
const unknown = AssuranceKnowledge.resolve('CustomNonStandardAlgoX99', 'Unknown Future Spec');
assert(unknown !== null && typeof unknown === 'object', 'Fallback returns an object');
assert(unknown.id === 'GENERIC-FALLBACK', 'Unknown resolves to GENERIC-FALLBACK');
assert(unknown.algorithm === 'CustomNonStandardAlgoX99', 'Fallback preserves input algorithm name');
assert(unknown.recommendedReplacement === 'Unknown Future Spec', 'Fallback preserves replacement');
assert(unknown.whyQuantumSafe.length > 0, 'Fallback provides general PQC migration points');
assert(unknown.standards.includes('NIST IR 8547 (PQC Migration)'), 'Fallback cites NIST IR 8547');

// 4. Null / empty input protection
console.log('\n4. Null / empty / corrupted input handling:');
const empty = AssuranceKnowledge.resolve(null, undefined);
assert(empty !== null && typeof empty === 'object', 'Null input returns an object');
assert(empty.id === 'GENERIC-FALLBACK', 'Null input resolves safely to fallback without crashing');
assert(empty.algorithm === 'Unknown Algorithm', 'Null input gets human-readable label');

console.log('\nAll PQC Assurance Knowledge tests passed successfully! ✓');
