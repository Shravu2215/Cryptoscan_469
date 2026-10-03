'use strict';

const Redis = require('ioredis');

let _client = null;

function getRedisClient() {
  if (_client) return _client;

  const url = process.env.REDIS_URL;
  if (!url) {
    _client = {
      set: async () => {},
      get: async () => null,
      call: async () => {},
      on: () => {},
      ping: async () => 'PONG'
    };
    return _client;
  }

  _client = new Redis(url, {
    // Do not crash the process on connection errors — log and let callers
    // handle graceful degradation (denylist falls back to strict-reject).
    lazyConnect: false,
    maxRetriesPerRequest: 2,
    enableOfflineQueue: true,
  });

  _client.on('error', (err) => {
    console.error('[Redis] connection error:', err.message);
  });

  return _client;
}

/**
 * Add a JTI to the denylist with an expiry matching the token's remaining lifetime.
 * @param {string} jti
 * @param {number} ttlSeconds
 */
async function denylistJti(jti, ttlSeconds) {
  if (ttlSeconds <= 0) return; // already expired — nothing to denylist
  await getRedisClient().set(`denylist:jti:${jti}`, '1', 'EX', ttlSeconds);
}

/**
 * Returns true if the JTI is in the denylist (i.e. the token has been revoked).
 * On Redis failure, returns true (fail-closed: deny the request).
 * @param {string} jti
 * @returns {Promise<boolean>}
 */
async function isJtiDenylisted(jti) {
  try {
    const result = await getRedisClient().get(`denylist:jti:${jti}`);
    return result !== null;
  } catch (err) {
    console.error('[Redis] denylist check failed — failing closed:', err.message);
    return true; // fail-closed
  }
}

module.exports = { getRedisClient, denylistJti, isJtiDenylisted };
