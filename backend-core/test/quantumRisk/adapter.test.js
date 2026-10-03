'use strict';

const assert = require('assert');
const { findingsToCryptoAssets, componentsToCryptoAssets } = require('../../src/services/quantumRisk/adapter');

const finding = {
  id: 'finding-001',
  algorithm: 'RSA-2048',
  keySize: 2048,
  usage: 'key_wrap',
  filePath: 'services/payments/src/crypto.js',
  lineNumber: 31,
  confidence: 'Likely|ast',
};

const [asset] = findingsToCryptoAssets([finding]);
assert.strictEqual(asset.assetId, 'finding:finding-001');
assert.strictEqual(asset.findingId, finding.id);
assert.strictEqual(asset.algorithm, finding.algorithm);
assert.strictEqual(asset.family, 'RSA');
assert.strictEqual(asset.keySize, 2048);
assert.strictEqual(asset.usage, 'key_wrap');
assert.strictEqual(asset.filePath, finding.filePath);
assert.strictEqual(asset.lineNumber, 31);
assert.strictEqual(asset.service, 'payments');
assert.strictEqual(asset.confidence, 0.7);
assert.deepStrictEqual(asset.sources, ['static']);

assert.strictEqual(findingsToCryptoAssets([{ ...finding, algorithm: 'ML-KEM-768' }])[0].family, 'PQC');
assert.strictEqual(findingsToCryptoAssets([{ ...finding, algorithm: 'SHA-256' }])[0].family, 'HASH');
assert.strictEqual(findingsToCryptoAssets([{ ...finding, confidence: '82%|regex' }])[0].confidence, 0.82);
assert.strictEqual(findingsToCryptoAssets([{ ...finding, confidence: 'unmapped' }])[0].confidence, 0.5);
assert.deepStrictEqual(finding, {
  id: 'finding-001',
  algorithm: 'RSA-2048',
  keySize: 2048,
  usage: 'key_wrap',
  filePath: 'services/payments/src/crypto.js',
  lineNumber: 31,
  confidence: 'Likely|ast',
});
assert.throws(() => findingsToCryptoAssets([{}]), /stable id/);
assert.throws(() => findingsToCryptoAssets({}), /array/);

const [fromComponent] = componentsToCryptoAssets([{
  name: 'ECDSA P-256 JWT',
  service: 'identity',
  cryptoProperties: { algorithmProperties: { primitive: 'ECDSA', parameterSetIdentifier: 'P-256' } },
  occurrences: [{ findingId: 'cbom-finding-1', file: 'services/identity/src/jwt.js', line: 9, usage: 'digital_signature' }],
}]);
assert.strictEqual(fromComponent.assetId, 'finding:cbom-finding-1');
assert.strictEqual(fromComponent.family, 'ECC');
assert.strictEqual(fromComponent.keySize, 256);
assert.strictEqual(fromComponent.service, 'identity');

console.log('Quantum-risk adapter tests passed.');