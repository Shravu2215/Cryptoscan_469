(() => {
  try {
    const script = document.currentScript;
    const sessionId = script && script.dataset.session;
    const ingestUrl = script && script.dataset.ingest;
    const token = script && script.dataset.token;
    if (!sessionId || !ingestUrl || !token) return;

    const queue = new Map();
    let sending = false;
    const allowedAlgorithms = /^(?:CSPRNG|Math\.random|MD5|SHA-1|SHA-256|SHA-384|SHA-512|SHA3(?:-256|-384|-512)?|SHA-3(?:-256|-384|-512)?|Keccak-256|AES(?:-(?:GCM|CBC|CTR|ECB))?|RSA(?:-(?:OAEP|PSS))?|RSASSA-PKCS1-v1_5|ECDSA|ECDH|Ed25519|Ed448|HMAC|HKDF|PBKDF2|eth_sendTransaction|personal_sign|eth_signTypedData(?:_v\d+)?|eth_requestAccounts)$/;

    function callSite() {
      try {
        const lines = String(new Error().stack || '').split('\n').slice(1);
        for (const line of lines) {
          if (line.includes('cryptoscan-agent.js')) continue;
          const match = line.match(/((?:https?:\/\/|file:\/\/|[A-Za-z]:[\\/]|\/)[^\s)]*?):(\d+)(?::\d+)?\)?\s*$/);
          if (match) return `${match[1].replace(/[?#].*$/, '')}:${match[2]}`.slice(0, 500);
        }
      } catch (_) {}
      return 'unknown:0';
    }

    function metadata(algorithm) {
      const info = {};
      let name = typeof algorithm === 'string' ? algorithm : '';
      try {
        if (algorithm && typeof algorithm === 'object') {
          name = typeof algorithm.name === 'string' ? algorithm.name : name;
          if (Number.isSafeInteger(algorithm.length) && algorithm.length > 0) info.keySize = algorithm.length;
          if (Number.isSafeInteger(algorithm.modulusLength) && algorithm.modulusLength > 0) info.keySize = algorithm.modulusLength;
          if (typeof algorithm.namedCurve === 'string') info.curve = algorithm.namedCurve;
          if (algorithm.hash && typeof algorithm.hash.name === 'string') info.hash = algorithm.hash.name;
          else if (typeof algorithm.hash === 'string') info.hash = algorithm.hash;
        }
      } catch (_) {}
      const upper = name.toUpperCase();
      if (upper.startsWith('AES-')) info.mode = upper.slice(4);
      return { algorithm: name ? name.slice(0, 100) : 'WebCrypto', keyInfo: info };
    }

    function record(algorithm, operation, site) {
      try {
        const eventInfo = metadata(algorithm);
        if (!allowedAlgorithms.test(eventInfo.algorithm)) return;
        const key = JSON.stringify([eventInfo.algorithm, operation, eventInfo.keyInfo, site]);
        const existing = queue.get(key);
        if (existing) existing.count += 1;
        else queue.set(key, {
          algorithm: eventInfo.algorithm,
          operation,
          keyInfo: eventInfo.keyInfo,
          callSite: site || 'unknown:0',
          language: 'JavaScript',
          count: 1,
          timestamp: new Date().toISOString(),
        });
      } catch (_) {}
    }

    function recordSuccessful(result, algorithm, operation, site) {
      try {
        if (result && typeof result.then === 'function') {
          result.then(() => record(algorithm, operation, site), () => {});
        } else {
          record(algorithm, operation, site);
        }
      } catch (_) {}
      return result;
    }

    async function flush() {
      if (sending || queue.size === 0) return;
      sending = true;
      const entries = Array.from(queue.entries()).slice(0, 50);
      const batch = entries.map(([, event]) => event);
      entries.forEach(([key]) => queue.delete(key));
      try {
        await fetch(ingestUrl, {
          method: 'POST',
          mode: 'cors',
          credentials: 'omit',
          keepalive: true,
          headers: { 'Content-Type': 'application/json', 'X-CryptoScan-Token': token },
          body: JSON.stringify({ events: batch }),
        });
      } catch (_) {
        for (const item of batch) {
          const key = JSON.stringify([item.algorithm, item.operation, item.keyInfo, item.callSite]);
          const existing = queue.get(key);
          if (existing) existing.count += item.count;
          else queue.set(key, item);
        }
      } finally {
        sending = false;
      }
    }

    try {
      const subtle = window.crypto && window.crypto.subtle;
      if (subtle) {
        const methods = {
          digest: 0, generateKey: 0, importKey: 2, encrypt: 0, decrypt: 0,
          sign: 0, verify: 0, deriveKey: 0, deriveBits: 0,
        };
        for (const [method, algorithmIndex] of Object.entries(methods)) {
          try {
            const original = subtle[method];
            if (typeof original !== 'function') continue;
            subtle[method] = function (...args) {
              const result = Reflect.apply(original, this, args);
              return recordSuccessful(result, args[algorithmIndex], method, callSite());
            };
          } catch (_) {}
        }
      }
    } catch (_) {}

    try {
      const originalRandomValues = window.crypto && window.crypto.getRandomValues;
      if (typeof originalRandomValues === 'function') {
        window.crypto.getRandomValues = function (...args) {
          const result = Reflect.apply(originalRandomValues, this, args);
          record('CSPRNG', 'random', callSite());
          return result;
        };
      }
    } catch (_) {}

    try {
      const originalRandom = Math.random;
      Math.random = function (...args) {
        const result = Reflect.apply(originalRandom, this, args);
        record('Math.random', 'random', callSite());
        return result;
      };
    } catch (_) {}

    try {
      const ethereum = window.ethereum;
      const originalRequest = ethereum && ethereum.request;
      if (typeof originalRequest === 'function') {
        ethereum.request = function (...args) {
          const method = args[0] && typeof args[0].method === 'string' ? args[0].method : '';
          const result = Reflect.apply(originalRequest, this, args);
          if (/^(eth_sendTransaction|personal_sign|eth_signTypedData(?:_v\d+)?|eth_requestAccounts)$/.test(method)) {
            return recordSuccessful(result, method, 'wallet', callSite());
          }
          return result;
        };
      }
    } catch (_) {}

    setInterval(() => { flush().catch(() => {}); }, 1000);
    window.addEventListener('pagehide', () => { flush().catch(() => {}); });
  } catch (_) {}
})();
