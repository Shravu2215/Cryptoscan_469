'use strict';

/**
 * Node.js Runtime Cryptographic Instrumentation Preload Module for CryptoScan.
 * Loaded via `node --require ./runtime/node_agent/preload.js`.
 * Intercepts crypto operations and logs metadata-only execution events.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const tls = require('tls');
const { v4: uuidv4 } = require('crypto');

const OUT_PATH = process.env.CRYPTOSCAN_RUNTIME_OUT || path.join(process.cwd(), 'runtime_events.jsonl');
const RUN_ID = process.env.CRYPTOSCAN_RUN_ID || (crypto.randomUUID ? crypto.randomUUID() : 'run-' + Date.now());

const EVENT_BUFFER = [];

// ── Algorithm Normalizer ──────────────────────────────────────────────────
function normalizeAlgorithm(rawName) {
  if (!rawName) return 'UNKNOWN';
  const cleaned = String(rawName).trim().toLowerCase();
  
  if (cleaned.includes('sha256') || cleaned.includes('sha-256')) return 'SHA-256';
  if (cleaned.includes('sha512') || cleaned.includes('sha-512')) return 'SHA-512';
  if (cleaned.includes('sha1') || cleaned.includes('sha-1')) return 'SHA-1';
  if (cleaned.includes('md5')) return 'MD5';
  if (cleaned.startsWith('aes')) return 'AES';
  if (cleaned.startsWith('rsa')) return 'RSA';
  if (cleaned.includes('ecdsa') || cleaned.includes('secp256r1') || cleaned === 'ec') return 'ECDSA';
  if (cleaned.includes('hmac')) return 'HMAC';
  
  return String(rawName).toUpperCase();
}

// ── Stack Trace Caller Parser ─────────────────────────────────────────────
function getCallerInfo() {
  try {
    const err = new Error();
    const stackLines = (err.stack || '').split('\n');
    
    for (let i = 2; i < stackLines.length; i++) {
      const line = stackLines[i];
      if (!line) continue;
      
      // Skip internal preload/node core lines
      if (line.includes('runtime/node_agent') || line.includes('node:internal') || line.includes('node:crypto')) {
        continue;
      }
      
      // Parse "at FunctionName (file:line:col)" or "at file:line:col"
      const match = line.match(/at (?:(.+?)\s+\()?(.+?):(\d+):(\d+)\)?$/);
      if (match) {
        let fnName = match[1] || '<anonymous>';
        let filePath = match[2];
        let lineNo = parseInt(match[3], 10) || 0;
        
        try {
          filePath = path.relative(process.cwd(), filePath);
        } catch (_) {}

        return {
          call_file: filePath,
          call_line: lineNo,
          call_function: fnName,
        };
      }
    }
  } catch (_) {}
  return { call_file: 'unknown', call_line: 0, call_function: 'unknown' };
}

// ── Event Collector & Output Writer ───────────────────────────────────────
function emitEvent(details) {
  try {
    const caller = getCallerInfo();
    const event = {
      event_id: crypto.randomUUID ? crypto.randomUUID() : 'evt-' + Math.random().toString(36).substring(2),
      run_id: RUN_ID,
      timestamp: new Date().toISOString(),
      language: 'node',
      library: details.library || 'node:crypto',
      operation: details.operation,
      algorithm: normalizeAlgorithm(details.algorithm),
      key_size: details.key_size || null,
      mode: details.mode || null,
      padding: details.padding || null,
      curve: details.curve || null,
      call_file: caller.call_file,
      call_line: caller.call_line,
      call_function: caller.call_function,
      matched_finding_id: null,
    };

    EVENT_BUFFER.push(event);
    flushEvents();
  } catch (_) {
    // Fail-safe: swallow all errors
  }
}

function flushEvents() {
  if (EVENT_BUFFER.length === 0) return;
  try {
    const dir = path.dirname(OUT_PATH);
    if (dir && !fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const lines = EVENT_BUFFER.map(e => JSON.stringify(e)).join('\n') + '\n';
    fs.appendFileSync(OUT_PATH, lines, 'utf8');
    EVENT_BUFFER.length = 0;
  } catch (_) {}
}

process.on('exit', () => flushEvents());

// ── Instrumentation Hooks ─────────────────────────────────────────────────

// 1. crypto.createHash
const origCreateHash = crypto.createHash;
crypto.createHash = function (algorithm, options) {
  try {
    emitEvent({ library: 'node:crypto', operation: 'hash', algorithm });
  } catch (_) {}
  return origCreateHash.apply(this, arguments);
};

// 2. crypto.createHmac
const origCreateHmac = crypto.createHmac;
crypto.createHmac = function (algorithm, key, options) {
  try {
    emitEvent({ library: 'node:crypto', operation: 'hmac', algorithm: 'HMAC-' + algorithm });
  } catch (_) {}
  return origCreateHmac.apply(this, arguments);
};

// 3. crypto.createCipheriv
const origCreateCipheriv = crypto.createCipheriv;
crypto.createCipheriv = function (algorithm, key, iv, options) {
  try {
    let keySize = null;
    if (key && key.length) keySize = key.length * 8;
    let mode = null;
    if (typeof algorithm === 'string') {
      const parts = algorithm.split('-');
      if (parts.length >= 3) mode = parts[2].toUpperCase();
    }
    emitEvent({ library: 'node:crypto', operation: 'encrypt', algorithm, key_size: keySize, mode });
  } catch (_) {}
  return origCreateCipheriv.apply(this, arguments);
};

// 4. crypto.createDecipheriv
const origCreateDecipheriv = crypto.createDecipheriv;
crypto.createDecipheriv = function (algorithm, key, iv, options) {
  try {
    let keySize = null;
    if (key && key.length) keySize = key.length * 8;
    let mode = null;
    if (typeof algorithm === 'string') {
      const parts = algorithm.split('-');
      if (parts.length >= 3) mode = parts[2].toUpperCase();
    }
    emitEvent({ library: 'node:crypto', operation: 'decrypt', algorithm, key_size: keySize, mode });
  } catch (_) {}
  return origCreateDecipheriv.apply(this, arguments);
};

// 5. crypto.generateKeyPair / generateKeyPairSync
if (crypto.generateKeyPairSync) {
  const origGenKeyPairSync = crypto.generateKeyPairSync;
  crypto.generateKeyPairSync = function (type, options) {
    try {
      let keySize = options ? options.modulusLength : null;
      let curve = options ? options.namedCurve : null;
      emitEvent({ library: 'node:crypto', operation: 'keygen', algorithm: type, key_size: keySize, curve });
    } catch (_) {}
    return origGenKeyPairSync.apply(this, arguments);
  };
}

// 6. crypto.createSign / createVerify
if (crypto.createSign) {
  const origCreateSign = crypto.createSign;
  crypto.createSign = function (algorithm, options) {
    try {
      emitEvent({ library: 'node:crypto', operation: 'sign', algorithm });
    } catch (_) {}
    return origCreateSign.apply(this, arguments);
  };
}

if (crypto.createVerify) {
  const origCreateVerify = crypto.createVerify;
  crypto.createVerify = function (algorithm, options) {
    try {
      emitEvent({ library: 'node:crypto', operation: 'verify', algorithm });
    } catch (_) {}
    return origCreateVerify.apply(this, arguments);
  };
}

// 7. crypto.pbkdf2 / pbkdf2Sync / scrypt / scryptSync
if (crypto.pbkdf2Sync) {
  const origPbkdf2Sync = crypto.pbkdf2Sync;
  crypto.pbkdf2Sync = function (password, salt, iterations, keylen, digest) {
    try {
      emitEvent({ library: 'node:crypto', operation: 'kdf', algorithm: 'PBKDF2-' + (digest || 'sha1') });
    } catch (_) {}
    return origPbkdf2Sync.apply(this, arguments);
  };
}

// 8. TLS Hook
const origTlsConnect = tls.connect;
tls.connect = function (...args) {
  const socket = origTlsConnect.apply(this, args);
  try {
    socket.on('secureConnect', () => {
      try {
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        const algo = (protocol || 'TLS') + ':' + (cipher ? cipher.name : 'UNKNOWN');
        emitEvent({ library: 'tls', operation: 'tls', algorithm: algo });
      } catch (_) {}
    });
  } catch (_) {}
  return socket;
};

// 9. Module require hook for optional packages (jsonwebtoken)
const Module = require('module');
const origRequire = Module.prototype.require;

Module.prototype.require = function (moduleName) {
  const res = origRequire.apply(this, arguments);
  if (moduleName === 'jsonwebtoken' && res && !res._cryptoscan_hooked) {
    try {
      res._cryptoscan_hooked = true;
      const origSign = res.sign;
      const origVerify = res.verify;
      
      res.sign = function (payload, secretOrPrivateKey, options, callback) {
        try {
          const algo = (options && options.algorithm) || 'HS256';
          emitEvent({ library: 'jsonwebtoken', operation: 'sign', algorithm: algo });
        } catch (_) {}
        return origSign.apply(this, arguments);
      };

      res.verify = function (token, secretOrPublicKey, options, callback) {
        try {
          const algo = (options && options.algorithms && options.algorithms[0]) || 'JWT';
          emitEvent({ library: 'jsonwebtoken', operation: 'verify', algorithm: algo });
        } catch (_) {}
        return origVerify.apply(this, arguments);
      };
    } catch (_) {}
  }
  return res;
};
