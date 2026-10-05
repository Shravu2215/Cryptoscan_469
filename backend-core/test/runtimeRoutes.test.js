'use strict';

const assert = require('assert');
const runtimeRoutes = require('../src/routes/runtime');

const routePaths = runtimeRoutes.stack
  .filter(layer => layer.route)
  .map(layer => ({ path: layer.route.path, methods: Object.keys(layer.route.methods) }));

assert(routePaths.some(route => route.path === '/sessions' && route.methods.includes('post')));
assert(routePaths.some(route => route.path === '/sessions/:id/events' && route.methods.includes('post')));
assert(routePaths.some(route => route.path === '/sessions/:id' && route.methods.includes('get')));
assert(routePaths.some(route => route.path === '/sessions/:id/stop' && route.methods.includes('post')));
assert(!routePaths.some(route => String(route.path).startsWith('/runs')));

const validEvent = {
  source: 'crypto',
  algorithm: 'SHA-256',
  operation: 'digest',
  keyInfo: { hash: 'SHA-256' },
  callerScript: 'https://app.example/assets/main.js:12:3',
  hostOrigin: '',
  scheme: '',
  port: 0,
  crossOrigin: false,
  count: 4,
  timestamp: new Date().toISOString(),
};
const normalized = runtimeRoutes.validation.normalizeEvent(validEvent);
assert.strictEqual(normalized.callerScript, 'https://app.example/assets/main.js:12');
assert.strictEqual(normalized.count, 4);
assert.strictEqual(runtimeRoutes.validation.normalizeEvent({ ...validEvent, plaintext: 'must reject' }), null);
assert.strictEqual(runtimeRoutes.validation.normalizeEvent({ ...validEvent, keyInfo: { key: 'must reject' } }), null);

console.log('Runtime session route and metadata validation tests passed.');