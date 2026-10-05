'use strict';

const assert = require('assert');
const { classifyRuntimeEvent, runtimeEventToFinding } = require('../src/services/runtimeFinding');

function event(algorithm, keyInfo = {}, operation = 'digest') {
  return { algorithm, keyInfo, operation, callSite: 'https://example.test/app.js:42', count: 3, scanId: 'scan-test' };
}

assert.strictEqual(classifyRuntimeEvent(event('Math.random')).severity, 'WARNING');
assert.strictEqual(classifyRuntimeEvent(event('crypto.getRandomValues', {}, 'random')).severity, 'INFO');
assert.strictEqual(classifyRuntimeEvent(event('uuid.uuid4', {}, 'random')).severity, 'INFO');
assert.strictEqual(classifyRuntimeEvent(event('MD5')).severity, 'HIGH');
assert.strictEqual(classifyRuntimeEvent(event('HMAC', { hash: 'SHA-1' }, 'hmac')).severity, 'HIGH');
assert.strictEqual(classifyRuntimeEvent(event('HMAC', { hash: 'SHA-256' }, 'hmac')).quantumStatus, 'Quantum Weakened');
assert.strictEqual(classifyRuntimeEvent(event('SHA-256')).quantumStatus, 'Quantum Weakened');
assert.strictEqual(classifyRuntimeEvent(event('RSA', { keySize: 1024 }, 'sign')).severity, 'HIGH');
assert.strictEqual(classifyRuntimeEvent(event('RSA', { keySize: 2048 }, 'sign')).quantumStatus, 'Quantum Vulnerable');
assert.strictEqual(classifyRuntimeEvent(event('RSA-OAEP', { keySize: 2048 }, 'encrypt')).quantumStatus, 'Quantum Vulnerable');
assert.strictEqual(classifyRuntimeEvent(event('eth_signTypedData_v4', {}, 'wallet')).quantumStatus, 'Quantum Vulnerable');
assert.strictEqual(classifyRuntimeEvent(event('AES-GCM', { keySize: 256, mode: 'GCM' }, 'encrypt')).severity, 'LOW');
assert.strictEqual(classifyRuntimeEvent(event('AES-CBC', { keySize: 128, mode: 'CBC' }, 'encrypt')).severity, 'WARNING');
assert.strictEqual(classifyRuntimeEvent(event('AES-CBC', { keySize: 128, mode: 'ECB' }, 'encrypt')).severity, 'HIGH');

const finding = runtimeEventToFinding('session-test', event('ECDSA', { curve: 'P-256' }, 'sign'));
assert.strictEqual(finding.source, 'runtime');
assert.strictEqual(finding.count, 3);
assert.strictEqual(finding.filePath, 'https://example.test/app.js');
assert.strictEqual(finding.lineNumber, 42);
assert.strictEqual(finding.callSite, 'https://example.test/app.js:42');
assert.strictEqual(Object.hasOwn(finding, 'key'), false);
assert.strictEqual(Object.hasOwn(finding, 'plaintext'), false);
assert.strictEqual(Object.hasOwn(finding, 'arguments'), false);

console.log('Runtime finding mapping tests passed.');
