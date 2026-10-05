/**
 * CryptoScan Real-Time Scanner & IndexedDB Storage Engine
 */

const CryptoEngine = {
  STORAGE_KEY: 'CRYPTOSCAN_PLATFORM_DATA', // base key — actual key is namespaced per user
  DB_NAME: 'CryptoScanDB',
  STORE_NAME: 'uploads',

  // Resolve the storage key for the currently logged-in user.
  // Each user gets their own isolated data namespace so scan data
  // is NEVER shared across different accounts.
  getStorageKey: function() {
    try {
      const userRaw = localStorage.getItem('cs_user');
      if (userRaw) {
        const user = JSON.parse(userRaw);
        const identifier = (user.email || user.id || user.username || '').toLowerCase().trim();
        if (identifier) {
          // Sanitize so it's safe as a localStorage key
          const safe = identifier.replace(/[^a-z0-9@._-]/g, '_');
          return this.STORAGE_KEY + '__' + safe;
        }
      }
    } catch(e) {}
    // Fallback: not logged in — return a session-scoped key that won't persist usefully
    return this.STORAGE_KEY + '__guest';
  },

  // Open IndexedDB to store actual File / ArrayBuffer across page navigations
  openDB: function() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.DB_NAME, 1);
      request.onupgradeneeded = function(e) {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('uploads')) {
          db.createObjectStore('uploads', { keyPath: 'id' });
        }
      };
      request.onsuccess = function(e) { resolve(e.target.result); };
      request.onerror = function(e) { reject(e); };
    });
  },

  storeUploadedFile: async function(file) {
    const db = await this.openDB();
    const arrayBuffer = await file.arrayBuffer();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('uploads', 'readwrite');
      const store = tx.objectStore('uploads');
      store.put({
        id: 'pending_file',
        name: file.name,
        size: file.size,
        data: arrayBuffer,
        timestamp: Date.now()
      });
      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e);
    });
  },

  getPendingFile: async function() {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('uploads', 'readonly');
      const store = tx.objectStore('uploads');
      const req = store.get('pending_file');
      req.onsuccess = () => resolve(req.result);
      req.onerror = (e) => reject(e);
    });
  },

  getInitialState: function() {
    return {
      repositories: [],
      scans: [],
      activeScan: null,
      totalScans: 0,
      totalFindings: 0,
      criticalFindings: 0,
      quantumVulnerable: 0
    };
  },

  getData: function() {
    try {
      const raw = localStorage.getItem(this.getStorageKey());
      if (!raw) return this.getInitialState();
      return JSON.parse(raw);
    } catch(e) {
      return this.getInitialState();
    }
  },

  saveData: function(data) {
    localStorage.setItem(this.getStorageKey(), JSON.stringify(data));
    window.dispatchEvent(new Event('cryptoscan_data_updated'));
  },

  clearAllData: function() {
    localStorage.removeItem(this.getStorageKey());
    window.dispatchEvent(new Event('cryptoscan_data_updated'));
  },


  RULES: [
    {
      id: 'CRYPTO-RULE-RSA-SHORT',
      name: 'RSA Short Key Usage (< 2048-bit)',
      category: 'Asymmetric Key Length',
      severity: 'critical',
      quantum: 'yes',
      regex: /(?:RSA\.generate\(\s*(?:512|1024)|key_size\s*=\s*(?:512|1024)|generate_private_key\([^)]*1024|RSA-?1024|rsa1024)/i,
      remediation: 'Migrate to NIST ML-DSA or minimum RSA-3072 bit key.'
    },
    {
      id: 'CRYPTO-RULE-RSA-CLASSIC',
      name: 'Classical RSA Asymmetric Key Pair (Quantum-Vulnerable)',
      category: 'Post-Quantum Risk',
      severity: 'medium',
      quantum: 'yes',
      regex: /(?:RSA\.generate\(\s*(?:2048|3072|4096)|key_size\s*=\s*(?:2048|3072|4096)|generate_private_key\([^)]*(?:2048|3072|4096)|RSA-?2048|RSA-?3072|RSA-?4096|rsa\.generate_keypair|RSAPublicKey|RSAPrivateKey)/i,
      remediation: 'Migrate to NIST ML-DSA or ML-KEM post-quantum standards.'
    },
    {
      id: 'CRYPTO-RULE-MD5-BROKEN',
      name: 'MD5 Cryptographically Broken Hash',
      category: 'Broken Hash Function',
      severity: 'critical',
      quantum: 'no',
      regex: /(?:createHash\(\s*['"]md5['"]|hashlib\.md5|MessageDigest\.getInstance\(\s*["']MD5["']|MD5_Init|crypto\.md5|MD5\(|md5_hex|md5_bytes)/i,
      remediation: 'Replace MD5 with collision-resistant SHA-256 or SHA-3.'
    },
    {
      id: 'CRYPTO-RULE-SHA1-DEP',
      name: 'SHA-1 Deprecated Hash Function',
      category: 'Deprecated Hash',
      severity: 'high',
      quantum: 'no',
      regex: /(?:createHash\(\s*['"]sha1['"]|hashlib\.sha1|MessageDigest\.getInstance\(\s*["']SHA-?1["']|SHA1_Init|SHA1\(|sha1_hex|sha1_bytes)/i,
      remediation: 'Upgrade to SHA-256 or SHA-512.'
    },
    {
      id: 'CRYPTO-RULE-SHA256-SAFE',
      name: 'SHA-256 Secure Hash Function',
      category: 'Secure Hash',
      severity: 'info',
      quantum: 'safe',
      regex: /(?:createHash\(\s*['"]sha256['"]|hashlib\.sha256|MessageDigest\.getInstance\(\s*["']SHA-?256["']|SHA256_Init|SHA256\(|sha256_hex)/i,
      remediation: 'Compliant with NIST FIPS 180-4 standard.'
    },
    {
      id: 'CRYPTO-RULE-DES-WEAK',
      name: 'DES / 3DES Deprecated Cipher',
      category: 'Weak Block Cipher',
      severity: 'critical',
      quantum: 'no',
      regex: /(?:DES3?\.new\(|des\.NewCipher\(|DES_ecb_encrypt\(|Cipher\.getInstance\(\s*['"](?:3?DES|TripleDES)|CryptoJS\.(?:3?DES|TripleDES)|DES3?_Init|DES_ecb)/i,
      remediation: 'Migrate to AES-256-GCM.'
    },
    {
      id: 'CRYPTO-RULE-RC4-BLOWFISH',
      name: 'RC4 / Blowfish Legacy Cipher',
      category: 'Weak Block Cipher',
      severity: 'critical',
      quantum: 'no',
      regex: /(?:Cipher\.getInstance\(\s*["'](?:RC4|ARC4|Blowfish)|CryptoJS\.RC4|CryptoJS\.Blowfish|RC4_Init|Blowfish_Init)/i,
      remediation: 'Replace with AES-256-GCM or ChaCha20-Poly1305.'
    },
    {
      id: 'CRYPTO-RULE-ECDSA-CLASSIC',
      name: 'Classical ECDSA / ECDH (Quantum-Vulnerable)',
      category: 'Post-Quantum Risk',
      severity: 'high',
      quantum: 'yes',
      regex: /(?:secp256k1|secp256r1|prime256v1|SECP256R1|crypto\.createECDH|EC_KEY_new_by_curve_name|ECDSA|ECDH|curve25519|ed25519)/i,
      remediation: 'Implement NIST PQC hybrid key exchange (ML-KEM-768).'
    },
    {
      id: 'CRYPTO-RULE-AES-ECB',
      name: 'AES Electronic Codebook (ECB) Mode',
      category: 'Insecure Cipher Mode',
      severity: 'critical',
      quantum: 'no',
      regex: /(?:AES\/ECB|Cipher\.AES_ECB|modes\.ECB|AES-128-ECB|AES-256-ECB)/i,
      remediation: 'Switch to Authenticated Encryption (AES-256-GCM).'
    },
    {
      id: 'CRYPTO-RULE-AES-CBC-PADDING',
      name: 'AES in CBC Mode',
      category: 'Padding Oracle Risk',
      severity: 'medium',
      quantum: 'no',
      regex: /(?:AES\/CBC\/PKCS5Padding|AES\/CBC\/PKCS7Padding|modes\.CBC|Cipher\.AES_CBC|AES-128-CBC|AES-256-CBC)/i,
      remediation: 'Switch to Authenticated Encryption (AES-GCM).'
    },
    {
      id: 'CRYPTO-ASSET-AES-GCM',
      name: 'AES-256-GCM Authenticated Encryption',
      category: 'Modern Symmetric Cipher',
      severity: 'info',
      quantum: 'safe',
      regex: /(?:AES-256-GCM|AES\/GCM\/NoPadding|modes\.GCM|aes-256-gcm|createCipheriv\(\s*['"]aes-256-gcm['"])/i,
      remediation: 'Compliant with FIPS 140-3.'
    },
    {
      id: 'CRYPTO-RULE-HARDCODED-SECRET',
      name: 'Hardcoded Private Key / Secret',
      category: 'Secret Management',
      severity: 'critical',
      quantum: 'no',
      regex: /(?:-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|api[_-]?key\s*=\s*['"][a-zA-Z0-9_\-]{16,}['"]|secret[_-]?key\s*=\s*['"][a-zA-Z0-9_\-]{16,}['"]|private[_-]?key\s*=\s*['"][a-zA-Z0-9_\-]{16,}['"])/i,
      remediation: 'Inject secrets dynamically via KMS or environment variables.'
    },
    {
      id: 'CRYPTO-RULE-NON-CSPRNG',
      name: 'Non-Cryptographic PRNG Usage',
      category: 'Insecure Randomness',
      severity: 'high',
      quantum: 'no',
      regex: /(?:Math\.random\(\)|random\.random\(\)|rand\(\)\s*%)/i,
      remediation: 'Use cryptographically secure PRNG (crypto.getRandomValues / os.urandom).'
    },
    {
      id: 'CRYPTO-RULE-TLS-DISABLED',
      name: 'TLS Certificate Verification Disabled',
      category: 'Transport Layer Security',
      severity: 'critical',
      quantum: 'no',
      regex: /(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|--insecure|-k\b)/i,
      remediation: 'Re-enable TLS certificate verification to prevent MitM attacks.'
    }
  ],

  // ─── PART 1 & 2: TYPE, LIFETIME, CRITICALITY, MIGRATION (Y) & MOSCA (X+Y vs Z) ENGINES ───
  classifyType: function(finding) {
    const rawType = (finding.type || '').toLowerCase().replace(/[-\s]/g, '_');
    if (rawType === 'hardware_module' || rawType === 'hardware') return 'hardware_module';
    if (rawType === 'cloud_service' || rawType === 'cloud') return 'cloud_service';
    if (rawType === 'certificate' || rawType === 'cert') return 'certificate';
    if (rawType === 'protocol') return 'protocol';
    if (rawType === 'library') return 'library';
    if (rawType === 'key') return 'key';
    if (rawType === 'algorithm' || rawType === 'algo') return 'algorithm';

    const title = (finding.title || finding.name || '').toLowerCase();
    const cat = (finding.category || '').toLowerCase();
    const lib = (finding.library || '').toLowerCase();
    const algo = (finding.algorithm || '').toLowerCase();
    const file = (finding.file || finding.filePath || '').toLowerCase();
    const usage = (finding.usage || finding.description || '').toLowerCase();
    const snippet = (finding.snippet || finding.code || '').toLowerCase();
    const tags = Array.isArray(finding.tags) ? finding.tags.map(t => String(t).toLowerCase()) : [];

    // Hardware Module check FIRST before cloud_service
    if (
      cat.includes('hardware') ||
      cat.includes('hsm') ||
      cat.includes('pkcs11') ||
      cat.includes('tpm') ||
      tags.includes('hardware-module') ||
      tags.includes('hsm') ||
      tags.includes('pkcs11') ||
      tags.includes('tpm2') ||
      tags.includes('hardware-custody') ||
      usage.includes('hsm') ||
      usage.includes('pkcs11') ||
      usage.includes('tpm') ||
      usage.includes('smart card') ||
      usage.includes('hardware token') ||
      usage.includes('nitrokey') ||
      usage.includes('yubikey') ||
      algo.includes('hsm') ||
      algo.includes('pkcs11') ||
      algo.includes('tpm') ||
      lib.includes('pkcs11') ||
      lib.includes('tpm') ||
      lib.includes('pyscard') ||
      lib.includes('yubikey') ||
      snippet.includes('pkcs11') ||
      snippet.includes('tpm2') ||
      snippet.includes('softhsm') ||
      snippet.includes('yubikey') ||
      snippet.includes('pyscard') ||
      snippet.includes('libcryptoki')
    ) {
      return 'hardware_module';
    }

    if (file.includes('boto3') || file.includes('kms') || cat.includes('cloud') || usage.includes('kms') || usage.includes('vault') || usage.includes('key vault') || usage.includes('aws') || usage.includes('azure')) {
      return 'cloud_service';
    }
    if (file.endsWith('.pem') || file.endsWith('.crt') || file.endsWith('.cer') || file.endsWith('.der') || file.endsWith('.p12') || file.endsWith('.pfx') || cat.includes('cert') || title.includes('cert') || title.includes('x509')) {
      return 'certificate';
    }
    if (cat.includes('protocol') || title.includes('tls') || title.includes('ssl') || title.includes('ssh') || title.includes('ipsec') || usage.includes('transport') || usage.includes('handshake')) {
      return 'protocol';
    }
    if (cat.includes('key') || title.includes('key') || algo.includes('rsa') || algo.includes('ecdsa') || algo.includes('ecdh') || algo.includes('ecc') || algo.includes('dsa') || usage.includes('secret') || usage.includes('private key') || usage.includes('key pair')) {
      return 'key';
    }
    if (cat.includes('library') || lib.includes('cryptojs') || lib.includes('bouncycastle') || lib.includes('pycryptodome') || lib.includes('openssl') || lib.includes('boringssl')) {
      return 'library';
    }
    return 'algorithm';
  },

  estimateLifetime: function(finding) {
    const title = (finding.title || finding.name || '').toLowerCase();
    const file = (finding.file || finding.filePath || '').toLowerCase();
    const usage = (finding.usage || finding.description || '').toLowerCase();
    const type = finding.type || this.classifyType(finding);
    const cat = (finding.category || '').toLowerCase();
    const snippet = (finding.snippet || finding.code || '').toLowerCase();
    const text = (file + ' ' + title + ' ' + usage + ' ' + cat + ' ' + snippet).toLowerCase();

    let suggested = 5;
    let rationale = 'Standard application cryptographic asset (5y baseline retention)';

    if (text.includes('session') || text.includes('token') || text.includes('ephemeral') || text.includes('jwt') || text.includes('nonce') || file.includes('session') || file.includes('cookie') || text.includes('otp')) {
      suggested = 1;
      rationale = 'Ephemeral token / session material (1y short-term lifetime)';
    } else if (type === 'certificate' || file.endsWith('.crt') || file.endsWith('.pem') || text.includes('tls') || text.includes('ssl') || text.includes('cert')) {
      suggested = 2;
      rationale = 'TLS / X.509 Certificate validity window (2y standard lifecycle)';
    } else if (text.includes('health') || text.includes('medical') || text.includes('hipaa') || text.includes('root ca') || text.includes('sovereign') || text.includes('master key')) {
      suggested = 30;
      rationale = 'Permanent compliance / healthcare / root master key (30y archival retention)';
    } else if (text.includes('archive') || text.includes('at-rest') || text.includes('database') || text.includes('backup') || text.includes('s3') || type === 'cloud_service') {
      suggested = 20;
      rationale = 'Long-term storage / Database data at-rest (20y retention)';
    } else if (type === 'key' || algoIsAsymmetric(finding) || file.includes('.env') || text.includes('private key') || text.includes('credential')) {
      suggested = 10;
      rationale = 'Asymmetric key / Persistent secret credential (10y protection window)';
    }

    function algoIsAsymmetric(f) {
      const a = (f.algorithm || f.title || '').toLowerCase();
      return a.includes('rsa') || a.includes('ecdsa') || a.includes('ecdh') || a.includes('dsa') || a.includes('ecc');
    }

    const confirmed = (finding.user_confirmed_lifetime !== undefined && finding.user_confirmed_lifetime !== null && finding.user_confirmed_lifetime !== '')
      ? Number(finding.user_confirmed_lifetime)
      : null;

    return {
      suggested_lifetime: suggested,
      user_confirmed_lifetime: confirmed,
      effective_lifetime: confirmed !== null ? confirmed : suggested,
      rationale: rationale
    };
  },

  classifyExposure: function(finding, repoContext) {
    const file = (finding.file || finding.filePath || '').toLowerCase();
    const repo = (finding.repoName || finding.repository || '').toLowerCase();
    const snippet = (finding.snippet || finding.code || finding.description || '').toLowerCase();
    const title = (finding.title || finding.algorithm || '').toLowerCase();
    const text = (file + ' ' + repo + ' ' + title + ' ' + snippet).toLowerCase();

    // 0. Respect backend scan classification if explicit
    const rawExp = (finding.exposure || '').toLowerCase();
    if (rawExp === 'internal' || (finding.exposure_label && finding.exposure_label.toLowerCase() === 'internal')) {
      return {
        exposure_label: 'Internal',
        exposure_score: 1.0,
        exposure_confidence: finding.exposure_confidence || 'High',
        triggered_signals: (finding.exposure_signals && finding.exposure_signals.length > 0) ? finding.exposure_signals : ['Scanner verified internal exposure']
      };
    }
    if (rawExp === 'external-facing' || rawExp === 'external' || (finding.exposure_label && finding.exposure_label.toLowerCase() === 'external')) {
      return {
        exposure_label: 'External',
        exposure_score: 5.0,
        exposure_confidence: finding.exposure_confidence || 'High',
        triggered_signals: (finding.exposure_signals && finding.exposure_signals.length > 0) ? finding.exposure_signals : ['Scanner verified external exposure']
      };
    }

    // Protection for internal file types: database files, env, test files, scripts
    const isInternalFileType = file.endsWith('.db') || file.endsWith('.sqlite') || file.endsWith('.sqlite3') ||
      file.includes('/tests/') || file.includes('/test/') || file.includes('/fixtures/') || file.includes('/mocks/') ||
      file.includes('/scripts/') || file.includes('/tools/') || file.includes('/migrations/') || file.includes('/internal/');
    const hasExplicitExternalKeyword = file.includes('edge') || file.includes('gateway') || file.includes('dmz') || file.includes('webhook');
    if (isInternalFileType && !hasExplicitExternalKeyword) {
      return {
        exposure_label: 'Internal',
        exposure_score: 1.0,
        exposure_confidence: 'High',
        triggered_signals: ['Internal file type / internal directory context']
      };
    }

    const triggeredSignals = [];
    let maxSignalScore = 0;
    let confidence = 'Low';

    // 1. ROUTE / ENDPOINT DEFINITION (Strongest Signal)
    const routeSignatures = [
      { pattern: /app\.(get|post|put|delete|patch|use)\s*\(/i, name: 'Express/Node Route Signature (app.get/post)' },
      { pattern: /router\.(get|post|put|delete|use)\s*\(/i, name: 'Express Router Handler' },
      { pattern: /express\.router\b/i, name: 'Express Router Definition' },
      { pattern: /@app\.route\b/i, name: 'Python Flask Route (@app.route)' },
      { pattern: /@api_view\b/i, name: 'Django REST Framework (@api_view)' },
      { pattern: /urlpatterns\s*=/i, name: 'Django URL Routing (urlpatterns)' },
      { pattern: /\bre_path\s*\(/i, name: 'Django Path Mapping' },
      { pattern: /@restcontroller\b/i, name: 'Spring Boot Controller (@RestController)' },
      { pattern: /@(requestmapping|getmapping|postmapping|putmapping|deletemapping)\b/i, name: 'Spring Mapping Annotation' },
      { pattern: /\[http(get|post|put|delete|patch)\]/i, name: '.NET Controller Route ([HttpGet/Post])' },
      { pattern: /\[route\s*\(/i, name: '.NET Route Attribute' },
      { pattern: /controllerbase\b/i, name: '.NET Controller Base' },
      { pattern: /http\.handlefunc\b/i, name: 'Go Standard HTTP Handler' },
      { pattern: /gin\.(default|new|engine)\b|\.(get|post)\("/i, name: 'Go Gin Framework Route' },
      { pattern: /echo\.(get|post)\b/i, name: 'Go Echo Web Router' }
    ];

    let matchedRouteSignal = null;
    for (const sig of routeSignatures) {
      if (sig.pattern.test(snippet) || sig.pattern.test(text)) {
        matchedRouteSignal = sig.name;
        break;
      }
    }

    if (matchedRouteSignal) {
      triggeredSignals.push(`Signal 1: ${matchedRouteSignal}`);
      maxSignalScore = Math.max(maxSignalScore, 5.0);
      confidence = 'High';
    }

    // 2. CONFIG / DEPLOYMENT SIGNALS
    let matchedConfigSignal = null;
    const isDeployConfig = text.includes('dockerfile') || text.includes('docker-compose') || text.includes('compose.y') || text.includes('ingress') || text.includes('nginx') || text.includes('k8s') || text.includes('service.yaml') || text.includes('haproxy') || text.includes('caddy') || text.includes('traefik') || text.includes('envoy') || text.includes('apache');
    if (isDeployConfig) {
      if (/expose\s+[0-9]+/i.test(text) || text.includes('loadbalancer') || text.includes('nodeport') || text.includes('ingress') || /listen\s+[0-9]+/i.test(text) || /bind\s+[0-9.:]+/i.test(text) || text.includes('reverse_proxy') || text.includes('proxy_pass')) {
        matchedConfigSignal = 'Public Deployment / Server Config (EXPOSE / LoadBalancer / Ingress / Proxy)';
        maxSignalScore = Math.max(maxSignalScore, 5.0);
        confidence = 'High';
      } else if (text.includes('clusterip') || text.includes('internal-only') || text.includes('private-net')) {
        matchedConfigSignal = 'Internal-only Deployment Manifest (ClusterIP / Private Network)';
        maxSignalScore = Math.max(maxSignalScore, 1.0);
        confidence = 'High';
      }
    }
    if (matchedConfigSignal) {
      triggeredSignals.push(`Signal 2: ${matchedConfigSignal}`);
    }

    // 3. TRANSITIVE IMPORT / DEPENDENCY CONTEXT
    let matchedImportSignal = null;
    if (repoContext && Array.isArray(repoContext.allFiles)) {
      const isImportedByPublic = repoContext.allFiles.some(f => {
        const path = (f.path || f.name || '').toLowerCase();
        const content = (f.content || '').toLowerCase();
        const isPublicController = path.includes('controller') || path.includes('route') || path.includes('api') || content.includes('@restcontroller') || content.includes('app.post');
        const importsTarget = file && content.includes(file.split('/').pop().replace(/\.[^/.]+$/, ''));
        return isPublicController && importsTarget;
      });
      if (isImportedByPublic) {
        matchedImportSignal = 'Transitive Call from Confirmed Public Controller';
        maxSignalScore = Math.max(maxSignalScore, 4.5);
        if (confidence !== 'High') confidence = 'Medium';
      }
    }
    if (matchedImportSignal) {
      triggeredSignals.push(`Signal 3: ${matchedImportSignal}`);
    }

    // 4. NETWORK BINDING PATTERNS
    if (text.includes('0.0.0.0') || text.includes('*:8080') || text.includes('http.listenandserve(":8080"') || text.includes('server.listen(8080')) {
      triggeredSignals.push('Signal 4: Public Interface Network Binding (0.0.0.0)');
      if (maxSignalScore === 0) maxSignalScore = 4.0;
      else maxSignalScore = Math.min(5.0, maxSignalScore + 0.5);
      if (confidence !== 'High') confidence = 'Medium';
    } else if (text.includes('127.0.0.1') || text.includes('localhost') || text.includes('unix:')) {
      triggeredSignals.push('Signal 4: Loopback Interface Binding (127.0.0.1 / localhost)');
      if (maxSignalScore === 0) maxSignalScore = 1.0;
      else maxSignalScore = Math.max(1.0, maxSignalScore - 1.0);
      if (confidence !== 'High') confidence = 'Medium';
    }

    // 5. FOLDER / NAMING CONVENTIONS (Fallback / Heuristic adjustment)
    const extKeywords = ['external', 'internet-facing', 'edge', 'dmz', 'webhook', 'gateway'];
    const intFolderPatterns = ['/internal/', '/test/', '/tests/', '/spec/', '/dev/', '/scripts/', '/tools/', '/migrations/', '/admin-cli/', '/jobs/', '/cron/', '/batch/'];

    const matchedExtKeyword = extKeywords.find(k => file.includes(k) || (finding.rule_id || '').toLowerCase().includes(k));
    const matchedIntPath = intFolderPatterns.find(p => file.includes(p));

    if (matchedExtKeyword) {
      triggeredSignals.push(`Signal 5: External-facing Keyword (${matchedExtKeyword})`);
      if (maxSignalScore === 0) {
        maxSignalScore = 4.0;
        confidence = 'Medium';
      }
    } else if (matchedIntPath) {
      triggeredSignals.push(`Signal 5: Internal Directory Keyword (${matchedIntPath})`);
      if (maxSignalScore === 0) {
        maxSignalScore = 1.0;
        confidence = 'Low';
      }
    }

    // FINAL DECISION LOGIC & VERDICT (Strictly Default to Internal)
    let finalLabel;
    let finalScore;

    if (triggeredSignals.length === 0) {
      finalLabel = 'Internal';
      finalScore = 1.0;
      triggeredSignals.push('Heuristic: No public route/infra signals — defaulting to Internal');
      confidence = 'Low';
    } else if (maxSignalScore >= 4.0) {
      finalLabel = 'External';
      finalScore = maxSignalScore;
    } else {
      finalLabel = 'Internal';
      finalScore = Math.max(1.0, maxSignalScore);
    }

    return {
      exposure_label: finalLabel,
      exposure_score: Math.round(finalScore * 10) / 10,
      exposure_confidence: confidence,
      triggered_signals: triggeredSignals
    };
  },

  computeCriticality: function(finding, repoContext) {
    const file = (finding.file || finding.filePath || '').toLowerCase();
    const repo = (finding.repoName || finding.repository || '').toLowerCase();
    const text = (file + ' ' + repo + ' ' + (finding.title || '') + ' ' + (finding.snippet || '') + ' ' + (finding.library || '')).toLowerCase();

    // 1. Data Sensitivity (0.30) — keyword density & classification
    // Exclude generic 'crypto' and 'cipher' which are present in all crypto findings
    let sens = 1.0;
    const sensKeywords = ['payment', 'auth', 'pii', 'health', 'secret', 'token', 'password', 'key', 'cred', 'credential', 'card', 'ssn', 'bank', 'account', 'wallet'];
    const sensMatches = sensKeywords.filter(k => text.includes(k)).length;
    if (sensMatches >= 3 || text.includes('payment') || text.includes('card') || text.includes('pii') || text.includes('wallet')) {
      sens = 5.0;
    } else if (sensMatches >= 2 || text.includes('auth') || text.includes('secret') || text.includes('token') || text.includes('password')) {
      sens = 4.0;
    } else if (sensMatches >= 1 || text.includes('user') || text.includes('db') || text.includes('session')) {
      sens = 2.5;
    } else {
      sens = 1.0;
    }

    // 2. Exposure (0.25) — Generic Multi-Signal Classifier (default internal = 1.0)
    const expResult = this.classifyExposure(finding, repoContext);
    let exp = expResult.exposure_score;

    // 3. System Role (0.25) — production vs staging vs dev
    let sys = 2.0;
    if (/\bproduction\b|\bprod\b/.test(file) || /\bproduction\b|\bprod\b/.test(repo) || file.includes('/prod/') || file.includes('/core/') || file.includes('/sys/')) {
      sys = 5.0;
    } else if (text.includes('staging') || text.includes('stage') || text.includes('qa') || text.includes('beta')) {
      sys = 3.0;
    } else if (text.includes('test') || text.includes('dev') || text.includes('sandbox') || text.includes('scratch') || text.includes('demo')) {
      sys = 1.0;
    }

    // 4. Regulatory Impact (0.20) — compliance frameworks & security standards
    let reg = 1.0;
    if (text.includes('gdpr') || text.includes('pci') || text.includes('hipaa') || text.includes('rbi') || text.includes('compliance') || text.includes('billing') || text.includes('financial') || text.includes('sox') || text.includes('fips') || text.includes('iso27001')) {
      reg = 5.0;
    } else if (text.includes('auth') || text.includes('cert') || text.includes('tls') || text.includes('ssl') || text.includes('kms') || text.includes('audit')) {
      reg = 3.0;
    } else {
      reg = 1.0;
    }

    // Preserve user override of subfactors if manually edited
    if (finding.subfactors) {
      sens = finding.subfactors.data_sensitivity !== undefined ? Number(finding.subfactors.data_sensitivity) : sens;
      exp = finding.subfactors.exposure !== undefined ? Number(finding.subfactors.exposure) : exp;
      sys = finding.subfactors.system_role !== undefined ? Number(finding.subfactors.system_role) : sys;
      reg = finding.subfactors.regulatory_impact !== undefined ? Number(finding.subfactors.regulatory_impact) : reg;
    }

    const rawScore = (sens * 0.30) + (exp * 0.25) + (sys * 0.25) + (reg * 0.20);
    const score = Math.round(rawScore * 10) / 10;

    // Calibrated thresholds: all 4 bands (Critical, High, Medium, Low) are naturally reachable
    let label = 'Low';
    if (score >= 3.8) label = 'Critical';
    else if (score >= 2.8) label = 'High';
    else if (score >= 1.8) label = 'Medium';

    return {
      criticality_score: score,
      criticality_label: label,
      exposure_label: expResult.exposure_label,
      exposure_confidence: expResult.exposure_confidence,
      exposure_signals: expResult.triggered_signals,
      subfactors: {
        data_sensitivity: sens,
        exposure: exp,
        system_role: sys,
        regulatory_impact: reg
      },
      last_modified_by: finding.last_modified_by || null,
      modification_reason: finding.modification_reason || null,
      modified_at: finding.modified_at || null
    };
  },

  MIGRATION_LOOKUP: {
    algorithm: { simple: 0.25, complex: 1.5 },
    key: { simple: 0.5, complex: 2.0 },
    certificate: { simple: 0.1, complex: 0.5 },
    protocol: { simple: 0.5, complex: 2.0 },
    library: { simple: 0.5, complex: 1.5 },
    hardware_module: { simple: 1.0, complex: 3.0 },
    cloud_service: { simple: 0.25, complex: 1.0 }
  },

  getMigrationLookup: function() {
    try {
      const stored = localStorage.getItem('cs_migration_lookup');
      if (stored) return JSON.parse(stored);
    } catch(e) {}
    return this.MIGRATION_LOOKUP;
  },

  saveMigrationLookup: function(lookup) {
    try {
      localStorage.setItem('cs_migration_lookup', JSON.stringify(lookup));
      window.dispatchEvent(new Event('cryptoscan_data_updated'));
    } catch(e) {}
  },

  estimateMigrationTime: function(finding) {
    const type = finding.type || this.classifyType(finding);
    const lookup = this.getMigrationLookup();
    const entry = lookup[type] || { simple: 0.5, complex: 1.5 };
    const isComplex = finding.isComplex ||
      (finding.severity === 'critical' || finding.quantum === 'yes' || (finding.file && (finding.file.includes('core') || finding.file.includes('crypto'))));
    const complexityKey = isComplex ? 'complex' : 'simple';
    return Number(entry[complexityKey] || 1.0);
  },

  getGlobalZ: function() {
    const saved = localStorage.getItem('cs_global_z');
    if (saved !== null && saved !== '') {
      const n = Number(saved);
      if (!isNaN(n) && n >= 1 && n <= 30) return n;
    }
    return 10; // DEFAULT_Z = 10 years (NIST CNSA 2.0 baseline)
  },

  // Alias: pages can call CryptoEngine.getZ() or QuantumRules.getZ() interchangeably
  getZ: function() { return this.getGlobalZ(); },

  setGlobalZ: function(val) {
    const n = Number(val);
    if (isNaN(n) || n < 1 || n > 30) return;
    localStorage.setItem('cs_global_z', String(n));
    // Fire both events so all pages (risk-analysis, migration-plan, dashboard) update
    try { window.dispatchEvent(new CustomEvent('zchange', { detail: { z: n } })); } catch(e) {}
    window.dispatchEvent(new Event('cryptoscan_data_updated'));
  },

  // Alias for QuantumRules compatibility
  setZ: function(val) { this.setGlobalZ(val); },

  computeMoscaRisk: function(finding, globalZ) {
    const Z = globalZ !== undefined ? Number(globalZ) : this.getGlobalZ();
    const X = (finding.user_confirmed_lifetime !== undefined && finding.user_confirmed_lifetime !== null && finding.user_confirmed_lifetime !== '')
      ? Number(finding.user_confirmed_lifetime)
      : Number(finding.suggested_lifetime || this.estimateLifetime(finding).suggested_lifetime);

    const Y = this.estimateMigrationTime(finding);
    const urgency_margin = Math.round((Z - (X + Y)) * 10) / 10;
    const mosca_at_risk = (X + Y) > Z;

    let urgency_tier = 'Low';
    if (urgency_margin < 0) {
      urgency_tier = 'Critical';
    } else if (urgency_margin <= 2) {
      urgency_tier = 'High';
    } else if (urgency_margin <= 5) {
      urgency_tier = 'Medium';
    }

    const tierWeights = { Critical: 4, High: 3, Medium: 2, Low: 1 };
    const critScore = finding.criticality_score !== undefined ? Number(finding.criticality_score) : 3.0;
    const priority_score = Math.round((tierWeights[urgency_tier] * critScore) * 10) / 10;

    return {
      X,
      Y,
      Z,
      urgency_margin,
      mosca_at_risk,
      urgency_tier,
      priority_score
    };
  },

  extractMode: function(finding) {
    if (finding.mode && finding.mode !== '-' && finding.mode !== '—') {
      return finding.mode;
    }
    const cat = (finding.category || '').toLowerCase();
    const algo = (finding.algorithm || '').toUpperCase();
    const isCipher = cat.includes('cipher') || cat.includes('symmetric') || algo.includes('AES') || algo.includes('DES') || algo.includes('BLOWFISH') || algo.includes('CHACHA');
    if (!isCipher) {
      return '-';
    }

    const title = (finding.title || '').toUpperCase();
    const snippet = (finding.snippet || finding.code || '').toUpperCase();
    const ruleId = (finding.ruleId || finding.rule_id || '').toUpperCase();
    const textToSearch = algo + ' ' + title + ' ' + snippet + ' ' + ruleId;

    if (textToSearch.includes('CHACHA20') && textToSearch.includes('POLY1305')) {
      return 'Poly1305';
    }

    const modes = ['GCM', 'CBC', 'ECB', 'CTR', 'CFB', 'OFB', 'CCM', 'OCB', 'POLY1305'];
    for (const m of modes) {
      const regex = new RegExp(`\\b${m}\\b`, 'i');
      if (regex.test(textToSearch)) {
        return m.toUpperCase();
      }
    }
    
    return '-';
  },

  enrichFinding: function(f, globalZ) {
    const type = f.type || this.classifyType(f);
    const lt = this.estimateLifetime(f);
    const crit = this.computeCriticality(f);

    f.type = type;
    f.mode = f.mode || this.extractMode(f);
    f.suggested_lifetime = lt.suggested_lifetime;
    f.user_confirmed_lifetime = (f.user_confirmed_lifetime !== undefined && f.user_confirmed_lifetime !== null && f.user_confirmed_lifetime !== '')
      ? Number(f.user_confirmed_lifetime)
      : lt.user_confirmed_lifetime;

    f.exposure_label = f.exposure_label || crit.exposure_label || 'Internal';
    f.exposure_confidence = f.exposure_confidence || crit.exposure_confidence || 'Low';
    f.exposure_signals = f.exposure_signals || crit.exposure_signals || [];
    f.exposure = f.exposure_label.toLowerCase() === 'external' ? 'external-facing' : 'internal';

    f.criticality_score = (f.criticality_score !== undefined && f.criticality_score !== null)
      ? Number(f.criticality_score)
      : crit.criticality_score;

    f.criticality_label = f.criticality_label || crit.criticality_label;
    f.subfactors = f.subfactors || crit.subfactors;
    f.last_modified_by = f.last_modified_by || crit.last_modified_by;
    f.modification_reason = f.modification_reason || crit.modification_reason;
    f.modified_at = f.modified_at || crit.modified_at;

    const mosca = this.computeMoscaRisk(f, globalZ);
    f.risk = mosca;
    f.X = mosca.X;
    f.Y = mosca.Y;
    f.Z = mosca.Z;
    f.urgency_margin = mosca.urgency_margin;
    f.mosca_at_risk = mosca.mosca_at_risk;
    f.urgency_tier = mosca.urgency_tier;
    f.priority_score = mosca.priority_score;

    if (f.latencyImpactMs === undefined || f.latencyImpactMs === null) {
      const algo = (f.algorithm || f.title || '').toUpperCase();
      if (algo.includes('RSA') || algo.includes('DH') || algo.includes('ECDH') || algo.includes('KYBER') || algo.includes('ML-KEM')) {
        f.latencyImpactMs = 1.8;
      } else if (algo.includes('DSA') || algo.includes('ECDSA') || algo.includes('DILITHIUM') || algo.includes('ML-DSA')) {
        f.latencyImpactMs = 3.5;
      } else if (algo.includes('SPHINCS') || algo.includes('SLH-DSA')) {
        f.latencyImpactMs = 12.0;
      } else if (algo.includes('AES') || algo.includes('GCM')) {
        f.latencyImpactMs = 0.1;
      } else {
        f.latencyImpactMs = 2.0;
      }
    }

    return f;
  },

  calculateDynamicRiskScore: function(findings, filesScanned) {
    const list = findings || [];
    if (list.length === 0) {
      return { score: 0, level: 'Low Risk', text: '0 / 100 (Low Risk)', color: '#10b981' };
    }

    let c = 0, h = 0, m = 0, l = 0, q = 0;
    list.forEach(f => {
      const sev = (f.severity || '').toLowerCase();
      if (sev === 'critical') c++;
      else if (sev === 'high') h++;
      else if (sev === 'medium') m++;
      else if (sev === 'low') l++;
      if (f.quantum === 'yes' || f.isQuantumVulnerable || (f.quantumStatus && f.quantumStatus.toLowerCase().includes('vulnerable'))) q++;
    });

    const severityPoints = (c * 8) + (h * 4) + (m * 2) + (l * 0.5) + (q * 3.5);
    const dynamicScore = Math.min(99, Math.round(100 * (1 - Math.exp(-severityPoints / 32))));
    const finalScore = Math.max(8, dynamicScore);

    let level = 'Low Risk';
    let color = '#10b981';
    if (finalScore >= 75) {
      level = 'Critical Risk';
      color = '#ef4444';
    } else if (finalScore >= 50) {
      level = 'High Risk';
      color = '#f97316';
    } else if (finalScore >= 25) {
      level = 'Moderate';
      color = '#f59e0b';
    }

    return {
      score: finalScore,
      level: level,
      text: `${finalScore} / 100 (${level})`,
      color: color,
      breakdown: { c, h, m, l, q, severityPoints }
    };
  },

  processRealBackendFindings: function(repo, scanId, dbFindings) {
    const globalZ = this.getGlobalZ();

    const allMappedFindings = dbFindings.map(f => {
      const baseFinding = {
        id: f.id,
        title: f.algorithm + ' ' + (f.usage || ''),
        category: f.library || 'Standard API',
        library: f.library || 'Standard API',
        version: f.version || f.libraryVersion || '',
        exposure: f.exposure || 'internal',
        dataSensitivity: f.dataSensitivity || 'GENERAL',
        severity: (f.severity || 'medium').toLowerCase(),
        quantum: (f.quantumStatus || '').toLowerCase().includes('vulnerable') ? 'yes' : 'safe',
        file: f.filePath,
        line: f.lineNumber,
        snippet: f.description || '',
        remediation: f.recommendation || '',
        algorithm: f.algorithm,
        usage: f.usage,
        operation: f.operation || f.usage,
        callSite: f.callSite || `${f.filePath || 'unknown'}:${f.lineNumber || 0}`,
        count: f.count || 1,
        source: f.source || 'static',
        sessionId: f.sessionId || null,
        mode: f.mode || null,
        curve: f.curve || null,
        hash: f.hash || null,
        observedAt: f.observedAt || null,
        keySize: f.keySize ? `${f.keySize}-bit` : 'N/A',
        quantumStatus: f.quantumStatus,
        confidence: (f.confidence || 'Likely|ast').split('|')[0],
        detection_method: f.detection_method || (f.confidence || 'Likely|ast').split('|')[1] || 'ast',
        detection: f.detection || (f.detection_method ? f.detection_method.toUpperCase() : ((f.confidence || '').split('|')[1] ? (f.confidence || '').split('|')[1].toUpperCase() : 'AST')),
        // ── Language fields — both names forwarded so findings.html f.language || f.language_name works ──
        language: f.language || 'Unknown',
        language_name: f.language || f.language_name || 'Unknown',
        suppressed: Boolean(f.suppressed),
        suppressionReason: f.suppressionReason || null,
        status: f.status || 'ACTIVE',
        user_confirmed_lifetime: f.user_confirmed_lifetime !== undefined ? f.user_confirmed_lifetime : null,
        criticality_score: f.criticality_score,
        criticality_label: f.criticality_label,
        subfactors: f.subfactors,
        last_modified_by: f.last_modified_by,
        modification_reason: f.modification_reason,
        modified_at: f.modified_at
      };
      return this.enrichFinding(baseFinding, globalZ);
    });

    const activeDbFindings = dbFindings.filter(f => !f.suppressed && f.status !== 'RESOLVED');
    const activeFindings = allMappedFindings.filter(f => !f.suppressed && f.status !== 'RESOLVED');
    const suppressedFindings = allMappedFindings.filter(f => f.suppressed);
    const resolvedFindings = allMappedFindings.filter(f => f.status === 'RESOLVED');

    const componentMap = {};
    for (const f of activeDbFindings) {
      const algo = f.algorithm || 'Unknown Component';
      if (!componentMap[algo]) {
        componentMap[algo] = {
          name: algo,
          operations: new Set(),
          libraries: new Set(),
          versions: new Set(),
          locations: [],
          keySizes: new Set(),
          quantumRisk: (f.quantumStatus || '').toLowerCase().includes('vulnerable') ? 'Vulnerable' : 'Quantum-Ready',
          severities: new Set(),
          recommendation: f.recommendation || ''
        };
      }
      
      const comp = componentMap[algo];
      if (f.usage) comp.operations.add(f.usage);
      if (f.library) comp.libraries.add(f.library);
      if (f.version) comp.versions.add(f.version);
      
      const locStr = f.filePath + ':' + (f.lineNumber || '?');
      comp.locations.push(locStr);
      
      if (f.keySize) comp.keySizes.add(`${f.keySize}-bit`);
      comp.severities.add(f.severity ? f.severity.toUpperCase() : 'LOW');
    }

    const cbomAssets = Object.values(componentMap).map(c => ({
      name: c.name,
      operations: Array.from(c.operations),
      library: Array.from(c.libraries).filter(l => l && l !== 'Standard API').join(', ') || (Array.from(c.libraries)[0] || 'Standard Crypto API'),
      version: Array.from(c.versions).filter(Boolean).join(', ') || '—',
      locations: c.locations,
      keySize: Array.from(c.keySizes).join(', ') || 'N/A',
      quantumRisk: c.quantumRisk,
      severity: Array.from(c.severities).includes('CRITICAL') ? 'Critical' : 
               Array.from(c.severities).includes('HIGH') ? 'High' : 
               Array.from(c.severities).includes('MEDIUM') ? 'Medium' : 'Low',
      recommendation: c.recommendation
    }));

    const cbomMetrics = {
      totalComponents: cbomAssets.length,
      totalUsages: activeDbFindings.length,
      quantumVulnerable: cbomAssets.filter(c => c.quantumRisk === 'Vulnerable').length,
      quantumReady: cbomAssets.filter(c => c.quantumRisk === 'Quantum-Ready').length,
      unknownPotential: cbomAssets.filter(c => c.name.toLowerCase().includes('unknown') || c.name.toLowerCase().includes('potential')).length,
      highRisk: cbomAssets.filter(c => c.severity === 'Critical' || c.severity === 'High').length
    };

    const criticalCount = activeFindings.filter(f => f.severity === 'critical').length;
    const quantumCount = activeFindings.filter(f => f.quantum === 'yes').length;

    const repoName = repo.name || 'Scanned Repository';
    const uniqueFilesCount = new Set(activeFindings.map(f => f.file)).size || activeFindings.length;
    const riskObj = this.calculateDynamicRiskScore(activeFindings, uniqueFilesCount);

    const scanResult = {
      scanId: scanId,
      repoId: repo.id || 'repo-1',
      repoName: repoName,
      systems: repo.systems || [],
      fileSize: 0,
      timestamp: new Date().toLocaleString(),
      scanDate: new Date().toISOString(),
      durationSeconds: 1,
      filesDiscovered: uniqueFilesCount,
      filesScanned: uniqueFilesCount,
      assetsFound: cbomAssets.length,
      criticalCount: criticalCount,
      quantumCount: quantumCount,
      riskScore: riskObj.score,
      riskLevel: riskObj.level,
      riskText: riskObj.text,
      riskColor: riskObj.color,
      findings: activeFindings,
      suppressedFindings: suppressedFindings,
      resolvedFindings: resolvedFindings,
      suppressedCount: suppressedFindings.length,
      resolvedCount: resolvedFindings.length,
      cbom: cbomAssets,
      cbomMetrics: cbomMetrics,
      status: 'complete'
    };

    const currentData = this.getData();
    const existingRepoIdx = currentData.repositories.findIndex(r => r.name === repoName || r.id === scanResult.repoId || (r.name && r.name.replace(/\.zip$/i, '') === repoName.replace(/\.zip$/i, '')));
    const repoSummary = {
      id: scanResult.repoId,
      name: repoName,
      size: 0,
      lastScan: 'Just now',
      status: 'completed',
      filesCount: uniqueFilesCount,
      findingsCount: activeFindings.length,
      criticalCount: criticalCount,
      quantumCount: quantumCount,
      riskScore: riskObj.score,
      riskLevel: riskObj.level,
      riskText: riskObj.text,
      riskColor: riskObj.color
    };

    if (existingRepoIdx >= 0) {
      currentData.repositories[existingRepoIdx] = repoSummary;
    } else {
      currentData.repositories.unshift(repoSummary);
    }

    // Clear previous scan entries for this repository so stale findings are not accumulated
    currentData.scans = (currentData.scans || []).filter(s => s.repoName !== repoName && s.repoId !== scanResult.repoId);
    currentData.scans.unshift(scanResult);
    currentData.activeScan = scanResult;
    
    // Group scans by repo to calculate global metrics based ONLY on the latest scan of each repo
    const latestScansByRepo = {};
    currentData.scans.forEach(s => {
      if (!latestScansByRepo[s.repoId]) {
        latestScansByRepo[s.repoId] = s;
      }
    });
    const latestScans = Object.values(latestScansByRepo);

    currentData.totalScans = currentData.scans.length;
    currentData.totalFindings = latestScans.reduce((acc, s) => acc + (s.findings ? s.findings.length : 0), 0);
    currentData.criticalFindings = latestScans.reduce((acc, s) => acc + (s.criticalCount || 0), 0);
    currentData.quantumVulnerable = latestScans.reduce((acc, s) => acc + (s.quantumCount || 0), 0);

    this.saveData(currentData);
    return scanResult;
  }
};

if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
  const pBtn = document.getElementById('profile-btn');
  const pDrop = document.getElementById('profile-dropdown');
  if (pBtn && pDrop) {
    pBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      pDrop.classList.toggle('open');
    });
    document.addEventListener('click', (e) => {
      if (!pDrop.contains(e.target)) pDrop.classList.remove('open');
    });
  }

  // Also sync user data if available in localStorage
  try {
    const user = JSON.parse(localStorage.getItem('cs_user'));
    if (user) {
      const name = user.name || (user.email ? user.email.split('@')[0] : 'User');
      const email = user.email || '';
      const initial = name.charAt(0).toUpperCase();

      const pdInitials = document.getElementById('pd-initials');
      if (pdInitials) pdInitials.textContent = initial;

      const pdName = document.getElementById('pd-name');
      if (pdName) pdName.textContent = name;

      const pdEmail = document.getElementById('pd-email');
      if (pdEmail) pdEmail.textContent = email;

      document.querySelectorAll('.profile-initials').forEach(el => el.textContent = initial);
    }
  } catch(e) {}
});




// Theme Toggle Logic
window.addEventListener('DOMContentLoaded', () => {
  const tBtn = document.getElementById('theme-btn');
  const iconMoon = document.getElementById('theme-icon-moon');
  const iconSun = document.getElementById('theme-icon-sun');
  
  function updateThemeUI() {
    const isLight = document.documentElement.classList.contains('light-mode');
    if (iconMoon && iconSun) {
      iconMoon.style.display = isLight ? 'none' : 'block';
      iconSun.style.display = isLight ? 'block' : 'none';
    }
  }

  if (tBtn) {
    updateThemeUI();
    tBtn.addEventListener('click', () => {
      const isLight = document.documentElement.classList.contains('light-mode');
      if (isLight) {
        document.documentElement.classList.remove('light-mode');
        document.documentElement.classList.add('dark', 'dark-mode');
        localStorage.setItem('cs_theme', 'dark');
      } else {
        document.documentElement.classList.remove('dark', 'dark-mode');
        document.documentElement.classList.add('light-mode');
        localStorage.setItem('cs_theme', 'light');
      }
      updateThemeUI();
    });
  }
});
}

if (typeof window !== 'undefined') window.CryptoEngine = CryptoEngine;
if (typeof module !== 'undefined' && module.exports) module.exports = CryptoEngine;
