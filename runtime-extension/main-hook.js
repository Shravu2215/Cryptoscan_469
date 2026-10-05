(() => {
  try {
    const pending = new Map();
    const detectedLibraries = new Set();
    let active = false;
    let firstEventLogged = false;
    let initialOriginLogged = false;

    function safeOrigin(value) {
      try {
        const parsed = new URL(value, location.href);
        if (!['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) return null;
        return parsed;
      } catch (_) { return null; }
    }

    function callerScript() {
      try {
        const lines = String(new Error().stack || '').split('\n').slice(1);
        for (const line of lines) {
          if (line.includes('main-hook.js')) continue;
          const match = line.match(/((?:https?:\/\/|file:\/\/)[^\s)]*?):(\d+)(?::\d+)?\)?\s*$/);
          if (!match) continue;
          const parsed = safeOrigin(match[1]);
          if (parsed) return `${parsed.origin}${parsed.pathname}:${match[2]}`.slice(0, 700);
        }
      } catch (_) {}
      return 'unknown:0';
    }

    function normalizeScheme(protocol) {
      return String(protocol || '').replace(/:$/, '').toLowerCase();
    }

    function record(source, algorithm, operation, keyInfo = {}, site = callerScript(), network = null) {
      try {
        if (!active) return;
        let caller = null;
        try {
          const sourceUrl = String(site || '').replace(/:\d+$/, '');
          if (/^https?:\/\//i.test(sourceUrl)) caller = safeOrigin(sourceUrl);
        } catch (_) {}
        const callerScheme = caller ? normalizeScheme(caller.protocol) : '';
        const callerDefaultPort = callerScheme === 'https' ? 443 : 80;
        const event = {
          source,
          algorithm: String(algorithm || 'UNKNOWN').slice(0, 100),
          operation,
          keyInfo: keyInfo || {},
          callerScript: site || 'unknown:0',
          hostOrigin: network ? network.origin : (caller ? caller.origin : ''),
          scheme: network ? network.scheme : callerScheme,
          port: network ? network.port : (caller ? Number(caller.port || callerDefaultPort) : 0),
          crossOrigin: network ? network.crossOrigin : Boolean(caller && caller.hostname.toLowerCase() !== location.hostname.toLowerCase()),
          count: 1,
          timestamp: new Date().toISOString(),
        };
        const key = JSON.stringify([
          event.source, event.algorithm, event.operation, event.keyInfo, event.callerScript,
          event.hostOrigin, event.scheme, event.port, event.crossOrigin,
        ]);
        const old = pending.get(key);
        if (old) old.count += 1;
        else pending.set(key, event);
        if (!firstEventLogged) {
          firstEventLogged = true;
          console.log('[CryptoScan] first event', event.source, event.algorithm);
        }
      } catch (_) {}
    }

    function keyMetadata(algorithm) {
      const info = {};
      let name = typeof algorithm === 'string' ? algorithm : '';
      try {
        if (algorithm && typeof algorithm === 'object') {
          if (typeof algorithm.name === 'string') name = algorithm.name;
          if (Number.isSafeInteger(algorithm.length) && algorithm.length > 0) info.keySize = algorithm.length;
          if (Number.isSafeInteger(algorithm.modulusLength) && algorithm.modulusLength > 0) info.modulusLength = algorithm.modulusLength;
          if (typeof algorithm.namedCurve === 'string') info.curve = algorithm.namedCurve;
          const hash = algorithm.hash;
          if (typeof hash === 'string') info.hash = hash;
          else if (hash && typeof hash.name === 'string') info.hash = hash.name;
        }
      } catch (_) {}
      const upper = name.toUpperCase();
      const mode = upper.match(/^AES-(GCM|CBC|CTR|ECB)$/);
      if (mode) info.mode = mode[1];
      return { name: name || 'WebCrypto', info };
    }

    function recordSuccessful(result, source, algorithm, operation, keyInfo, site) {
      try {
        if (result && typeof result.then === 'function') result.then(() => record(source, algorithm, operation, keyInfo, site), () => {});
        else record(source, algorithm, operation, keyInfo, site);
      } catch (_) {}
      return result;
    }

    function networkMetadata(value) {
      let raw = '';
      try {
        if (typeof value === 'string' || value instanceof URL) raw = String(value);
        else if (value && typeof value.url === 'string') raw = value.url;
      } catch (_) {}
      const parsed = safeOrigin(raw);
      if (!parsed) return null;
      const scheme = normalizeScheme(parsed.protocol);
      const isSocketScheme = scheme === 'ws' || scheme === 'wss';
      const pageProtocol = location.protocol === 'https:' ? 'https' : 'http';
      const comparableProtocol = isSocketScheme ? (scheme === 'wss' ? 'https' : 'http') : scheme;
      const pageHost = location.host.toLowerCase();
      const eventHost = parsed.host.toLowerCase();
      const defaultPort = scheme === 'https' || scheme === 'wss' ? 443 : 80;
      return {
        origin: `${scheme}://${parsed.host}`,
        scheme,
        port: Number(parsed.port || defaultPort),
        crossOrigin: comparableProtocol !== pageProtocol || eventHost !== pageHost,
      };
    }

    function wrapCryptoSubtle() {
      try {
        const subtle = window.crypto && window.crypto.subtle;
        if (!subtle) return;
        const specs = {
          digest: args => args[0],
          generateKey: args => args[0],
          importKey: args => args[2],
          exportKey: args => args[1] && args[1].algorithm,
          encrypt: args => args[0],
          decrypt: args => args[0],
          sign: args => args[0],
          verify: args => args[0],
          deriveKey: args => args[0],
          deriveBits: args => args[0],
          wrapKey: args => args[3],
          unwrapKey: args => args[3],
        };
        const keyIndexes = {
          encrypt: 2, decrypt: 2, sign: 2, verify: 2, deriveKey: 1,
          deriveBits: 1, wrapKey: 2, unwrapKey: -1, exportKey: 1,
        };
        for (const [method, getAlgorithm] of Object.entries(specs)) {
          try {
            const original = subtle[method];
            if (typeof original !== 'function') continue;
            Object.defineProperty(subtle, method, {
              configurable: true,
              writable: true,
              value: function (...args) {
                const result = Reflect.apply(original, this, args);
                if (!active) return result;
                try {
                  const metadata = keyMetadata(getAlgorithm(args));
                  if (method === 'exportKey' || method === 'importKey' || method === 'unwrapKey') {
                    if (typeof args[0] === 'string') metadata.info.format = args[0];
                  }
                  const keyIndex = keyIndexes[method];
                  const cryptoKey = keyIndex === -1 && result && typeof result.then === 'function'
                    ? null
                    : (keyIndex === undefined ? null : args[keyIndex]);
                  if (cryptoKey && cryptoKey.algorithm) {
                    const keyDetails = keyMetadata(cryptoKey.algorithm);
                    metadata.info = { ...keyDetails.info, ...metadata.info };
                    if (!metadata.name || metadata.name === 'WebCrypto') metadata.name = keyDetails.name;
                  }
                  if ((method === 'unwrapKey' || method === 'importKey') && result && typeof result.then === 'function') {
                    result.then(key => {
                      try {
                        const keyDetails = keyMetadata(key && key.algorithm);
                        record('crypto', keyDetails.name, method, {
                          ...keyDetails.info,
                          ...metadata.info,
                          format: String(args[0] || ''),
                        }, callerScript());
                      } catch (_) {}
                    }, () => {});
                  } else recordSuccessful(result, 'crypto', metadata.name, method, metadata.info, callerScript());
                } catch (_) {}
                return result;
              },
            });
          } catch (_) {}
        }
      } catch (_) {}
    }

    function wrapSyncApi(target, name, algorithm, operation, metadata = () => ({})) {
      try {
        const original = target && target[name];
        if (typeof original !== 'function') return;
        Object.defineProperty(target, name, {
          configurable: true,
          writable: true,
          value: function (...args) {
            const result = Reflect.apply(original, this, args);
            if (active) {
              try { record('crypto', algorithm, operation, metadata(args), callerScript()); } catch (_) {}
            }
            return result;
          },
        });
      } catch (_) {}
    }

    function wrapNetwork() {
      try {
        const originalFetch = window.fetch;
        if (typeof originalFetch === 'function') {
          window.fetch = function (...args) {
            if (!active) return Reflect.apply(originalFetch, this, args);
            try {
              const info = networkMetadata(args[0]);
              if (info) record('network', 'NETWORK', 'network', {}, callerScript(), info);
            } catch (_) {}
            return Reflect.apply(originalFetch, this, args);
          };
        }
      } catch (_) {}
      try {
        const prototype = window.XMLHttpRequest && XMLHttpRequest.prototype;
        const originalOpen = prototype && prototype.open;
        const originalSend = prototype && prototype.send;
        const xhrTargets = new WeakMap();
        if (typeof originalOpen === 'function') {
          prototype.open = function (...args) {
            const result = Reflect.apply(originalOpen, this, args);
            try {
              if (active) xhrTargets.set(this, networkMetadata(args[1]));
            } catch (_) {}
            return result;
          };
        }
        if (typeof originalSend === 'function') {
          prototype.send = function (...args) {
            const result = Reflect.apply(originalSend, this, args);
            try {
              if (!active) return result;
              const info = xhrTargets.get(this);
              if (info) record('network', 'NETWORK', 'network', {}, callerScript(), info);
            } catch (_) {}
            return result;
          };
        }
      } catch (_) {}
      for (const name of ['WebSocket', 'EventSource']) {
        try {
          const Original = window[name];
          if (typeof Original !== 'function') continue;
          const Wrapped = new Proxy(Original, {
            construct(target, args, newTarget) {
              const instance = Reflect.construct(target, args, newTarget);
              try {
                if (active) {
                  const info = networkMetadata(args[0]);
                  if (info) record('network', 'NETWORK', 'network', {}, callerScript(), info);
                }
              } catch (_) {}
              return instance;
            },
          });
          Object.setPrototypeOf(Wrapped, Original);
          window[name] = Wrapped;
        } catch (_) {}
      }
    }

    function wrapWallet() {
      try {
        const ethereum = window.ethereum;
        const original = ethereum && ethereum.request;
        if (typeof original !== 'function') return;
        ethereum.request = function (...args) {
          const result = Reflect.apply(original, this, args);
          if (!active) return result;
          let method = '';
          try {
            method = args[0] && typeof args[0].method === 'string' ? args[0].method : '';
          } catch (_) {}
          if (/^(eth_sendTransaction|personal_sign|eth_signTypedData(?:_v\d+)?|eth_requestAccounts)$/.test(method)) {
            return recordSuccessful(result, 'crypto', method, 'wallet', {}, callerScript());
          }
          return result;
        };
      } catch (_) {}
    }

    function wrapWasm() {
      try {
        const wasm = window.WebAssembly;
        for (const name of ['instantiate', 'instantiateStreaming']) {
          try {
            const original = wasm && wasm[name];
            if (typeof original !== 'function') continue;
            wasm[name] = function (...args) {
              const result = Reflect.apply(original, this, args);
              return active ? recordSuccessful(result, 'wasm', 'WASM', 'wasm', {}, callerScript()) : result;
            };
          } catch (_) {}
        }
      } catch (_) {}
    }

    function checkLibraries() {
      if (!active) return;
      const globals = [
        ['CryptoJS', globalThis.CryptoJS], ['forge', globalThis.forge], ['sjcl', globalThis.sjcl],
        ['jsrsasign', globalThis.KJUR], ['elliptic', globalThis.elliptic], ['tweetnacl', globalThis.nacl],
        ['ethers', globalThis.ethers], ['web3', globalThis.web3],
      ];
      for (const [name, value] of globals) {
        if (value && !detectedLibraries.has(name)) {
          detectedLibraries.add(name);
          record('library', name, 'library', {}, callerScript());
        }
      }
      try {
        for (const script of document.scripts) {
          const parsed = safeOrigin(script.src);
          if (!parsed) continue;
          const url = `${parsed.origin}${parsed.pathname}`.toLowerCase();
          const match = [
            ['crypto-js', 'CryptoJS'], ['cryptojs', 'CryptoJS'], ['forge', 'forge'], ['sjcl', 'sjcl'],
            ['jsrsasign', 'jsrsasign'], ['elliptic', 'elliptic'], ['tweetnacl', 'tweetnacl'],
            ['/nacl', 'tweetnacl'], ['ethers', 'ethers'], ['web3', 'web3'],
          ].find(([needle]) => url.includes(needle));
          if (!match || detectedLibraries.has(match[1])) continue;
          detectedLibraries.add(match[1]);
          record('library', match[1], 'library', {}, `${parsed.origin}${parsed.pathname}:0`, {
            origin: parsed.origin,
            scheme: normalizeScheme(parsed.protocol),
            port: Number(parsed.port || (parsed.protocol === 'https:' ? 443 : 80)),
            crossOrigin: parsed.host !== location.host,
          });
        }
      } catch (_) {}
    }

    function flush(force = false) {
      try {
        if (!active && !force) return;
        if (!pending.size) return;
        const events = Array.from(pending.values()).slice(0, 100);
        for (const event of events) {
          const key = JSON.stringify([
            event.source, event.algorithm, event.operation, event.keyInfo, event.callerScript,
            event.hostOrigin, event.scheme, event.port, event.crossOrigin,
          ]);
          const queued = pending.get(key);
          if (queued && queued.count <= event.count) pending.delete(key);
          else if (queued) queued.count -= event.count;
        }
        window.postMessage({ source: 'CryptoScanMainHook', type: 'CS_EVENTS', events }, location.origin);
      } catch (_) {}
    }

    window.addEventListener('message', event => {
      try {
        if (event.source !== window || event.origin !== location.origin) return;
        const data = event.data;
        if (!data || data.source !== 'CryptoScanExtension') return;
        if (data.type === 'CS_HOOK_STATE') {
          const wasActive = active;
          active = Boolean(data.recording);
          if (active && !wasActive && !initialOriginLogged) {
            initialOriginLogged = true;
            try {
              const currentOrigin = networkMetadata(location.href);
              if (currentOrigin) record('network', 'NETWORK', 'network', {}, 'unknown:0', currentOrigin);
            } catch (_) {}
          }
          if (!active) flush(true);
        }
        if (data.type === 'CS_HOOK_FLUSH') flush(true);
      } catch (_) {}
    });

    wrapCryptoSubtle();
    try {
      wrapSyncApi(window.crypto, 'getRandomValues', 'crypto.getRandomValues', 'random');
      wrapSyncApi(window.crypto, 'randomUUID', 'crypto.randomUUID', 'random');
    } catch (_) {}
    try {
      const originalRandom = Math.random;
      Math.random = function (...args) {
        const result = Reflect.apply(originalRandom, this, args);
        if (active) {
          try { record('crypto', 'Math.random', 'random', {}, callerScript()); } catch (_) {}
        }
        return result;
      };
    } catch (_) {}
    wrapNetwork();
    wrapWallet();
    wrapWasm();
    setInterval(() => flush(false), 1000);
    setInterval(checkLibraries, 1500);
    window.addEventListener('pagehide', () => flush(true));
    console.log('[CryptoScan] hooks installed', { origin: location.origin });
  } catch (_) {}
})();
