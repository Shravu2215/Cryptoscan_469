'use strict';

const assert = require('assert');
const runtimeSessions = require('../src/routes/runtimeSessions');
const { normalizeEvent } = runtimeSessions;

const validEvent = {
  algorithm: 'AES-GCM',
  operation: 'encrypt',
  keyInfo: { keySize: 256, mode: 'GCM', hash: 'SHA-256' },
  callSite: 'https://example.test/app.js:17',
  language: 'JavaScript',
  count: 8,
  timestamp: '2026-10-05T12:00:00.000Z',
};

const normalized = normalizeEvent(validEvent);
assert.deepStrictEqual(normalized.keyInfo, { keySize: 256, mode: 'GCM', hash: 'SHA-256' });
assert.strictEqual(normalized.callSite, 'https://example.test/app.js:17');
assert.strictEqual(normalized.count, 8);
assert.strictEqual(normalizeEvent({ ...validEvent, algorithm: 'Python random.gauss', operation: 'random', language: 'Python' }).algorithm, 'Python random.gauss');
assert.strictEqual(normalizeEvent({ ...validEvent, callSite: 'backend/main.py:22', language: 'Python' }).callSite, 'backend/main.py:22');
assert.strictEqual(normalizeEvent({ ...validEvent, key: 'private-key-material' }), null);
assert.strictEqual(normalizeEvent({ ...validEvent, plaintext: 'secret message' }), null);
assert.strictEqual(normalizeEvent({ ...validEvent, arguments: ['password'] }), null);
assert.strictEqual(normalizeEvent({ ...validEvent, keyInfo: { ...validEvent.keyInfo, token: 'secret-token' } }), null);
assert.strictEqual(normalizeEvent({ ...validEvent, algorithm: 'AES-GCM secret-token' }), null);
assert.strictEqual(normalizeEvent({ ...validEvent, callSite: 'secret-token:17' }), null);

console.log('Runtime event metadata validation tests passed.');
