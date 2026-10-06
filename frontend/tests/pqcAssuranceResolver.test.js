'use strict';

const assert = require('node:assert/strict');
const { resolveAssuranceEntry, ENTRIES } = require('../assets/js/pqcAssuranceKnowledge');
const MigrationPlanData = require('../assets/js/migrationPlanData');
const QuantumRules = require('../assets/js/quantumRules');

const sha = resolveAssuranceEntry('SHA-256 / SHA-3-256 / BLAKE3', 'MD5');
assert.equal(sha.isFallback, false);
assert.equal(sha.category, 'Cryptographic hash');
assert.match(sha.standard, /FIPS 180-4/);
assert.match(sha.oldClassical, /classically collision-broken/i);

const kem = resolveAssuranceEntry('ML-KEM (Kyber-768/1024) or Hybrid X25519+ML-KEM', 'RSA-2048');
assert.equal(kem.isFallback, false);
assert.match(kem.standard, /FIPS 203/);
assert.match(kem.sizes, /1,184 bytes/);

const unknown = resolveAssuranceEntry('A replacement not in the map', 'CustomPrimitive');
assert.equal(unknown.isFallback, true);
assert.equal(unknown.replacement, 'FALLBACK');
assert.ok(unknown.points.length > 0);
assert.ok(unknown.safeStatus);

assert.ok(Object.keys(ENTRIES).length >= 10);
QuantumRules.RULES.filter(rule => rule.replacement).forEach(rule => {
	const assurance = resolveAssuranceEntry(rule.replacement, rule.families[0]);
	assert.ok(assurance.safeStatus, `Resolver returns non-empty knowledge for ${rule.replacement}`);
	assert.ok(assurance.points.length > 0, `Resolver returns rationale for ${rule.replacement}`);
});

const scoped = MigrationPlanData.collectFindings({
	scans: [
	  { id: 'scan-a', repoName: 'first', findings: [{ id: 'finding-a', algorithm: 'RSA-2048', severity: 'HIGH' }] },
	  { id: 'scan-b', repoName: 'second', findings: [{ id: 'finding-b', algorithm: 'MD5', severity: 'HIGH' }] },
	],
}, 'scan-b');
assert.equal(scoped.scans.length, 1);
assert.equal(scoped.scans[0].id, 'scan-b');
assert.deepEqual(scoped.findings.map(finding => finding.id), ['finding-b']);
console.log('PQC assurance replacement resolver tests passed.');
