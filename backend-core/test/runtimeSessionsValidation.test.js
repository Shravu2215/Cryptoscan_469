'use strict';

const assert = require('assert');
const runtimeSessions = require('../src/routes/runtimeSessions');
const { isPublicAddress } = require('../src/services/runtimeAnalysis');
const { normalizeEvent } = runtimeSessions.validation;

const cryptoEvent = {
  source: 'crypto',
  algorithm: 'AES-GCM',
  operation: 'encrypt',
  keyInfo: { keySize: 256, mode: 'GCM', hash: 'SHA-256' },
  callerScript: 'https://site.example/assets/app.js:18:4',
  count: 9,
  timestamp: '2026-10-05T12:00:00.000Z',
};

const normalized = normalizeEvent(cryptoEvent);
assert.strictEqual(normalized.callerScript, 'https://site.example/assets/app.js:18');
assert.deepStrictEqual(normalized.keyInfo, { keySize: 256, mode: 'GCM', hash: 'SHA-256' });
assert.strictEqual(normalized.count, 9);
assert.strictEqual(normalizeEvent({ ...cryptoEvent, key: 'secret-key' }), null);
assert.strictEqual(normalizeEvent({ ...cryptoEvent, plaintext: 'private text' }), null);
assert.strictEqual(normalizeEvent({ ...cryptoEvent, headers: { Cookie: 'private-cookie' } }), null);
assert.strictEqual(normalizeEvent({ ...cryptoEvent, keyInfo: { ...cryptoEvent.keyInfo, token: 'secret-token' } }), null);
assert.strictEqual(normalizeEvent({ ...cryptoEvent, callerScript: 'https://user:password@site.example/app.js:18' }), null);

const networkEvent = normalizeEvent({
  source: 'network', algorithm: 'NETWORK', operation: 'network', keyInfo: {},
  callerScript: 'unknown:0', hostOrigin: 'http://127.0.0.1:8000/path?private=yes',
  scheme: 'http', port: 8000, crossOrigin: true,
});
assert.strictEqual(networkEvent.hostOrigin, 'http://127.0.0.1:8000');
assert.strictEqual(networkEvent.scheme, 'http');
assert.strictEqual(normalizeEvent({ ...cryptoEvent, callerScript: 'password=hidden:5' }), null);
assert.strictEqual(normalizeEvent({ ...cryptoEvent, count: -1 }), null);
assert.strictEqual(normalizeEvent({ ...cryptoEvent, extra: 'not allowed' }), null);

const pythonCallsite = normalizeEvent({
  ...cryptoEvent,
  callerScript: 'app/main.py:27',
});
assert.strictEqual(pythonCallsite.callerScript, 'python://app/main.py:27');
assert.strictEqual(isPublicAddress('93.184.216.34'), true);
assert.strictEqual(isPublicAddress('127.0.0.1'), false);
assert.strictEqual(isPublicAddress('10.0.0.2'), false);
assert.strictEqual(isPublicAddress('::1'), false);

console.log('Runtime session validation and public-address tests passed.');
