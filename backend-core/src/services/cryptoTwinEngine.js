'use strict';

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

// ── Attack-path template library ──────────────────────────────────────────────
const ATTACK_PATH_TEMPLATES = {
  'rsa|jwt':          ['Weak RSA key', 'Offline key-factor attack (CRQC)', 'Private key recovered', 'Forged JWT', 'Auth bypass', 'Full API access', 'Sensitive data exposed'],
  'rsa|signing':      ['Weak RSA signing key', 'Quantum key factorisation', 'Private key recovered', 'Forged signatures', 'Integrity bypass', 'Code/data forgery'],
  'rsa|tls':          ['RSA key-transport in TLS', 'Record traffic (harvest-now)', 'CRQC decrypts session key', 'Session plaintext exposed', 'Credentials / session tokens stolen'],
  'rsa|key-exchange': ['RSA key exchange', 'Harvested ciphertexts', 'Quantum decryption', 'Symmetric session key recovered', 'Plaintext traffic exposed'],
  'rsa|encryption':   ['RSA-encrypted data', 'Recorded ciphertext', 'CRQC factors key', 'Plaintext recovered', 'Data confidentiality lost'],
  'rsa|other':        ['RSA usage detected', 'Quantum factorisation threat', 'Private key recoverable by CRQC', 'Downstream compromise possible'],
  'ecdh|tls':         ['ECDH key agreement', 'Forward secrecy depends on discrete-log hardness', 'CRQC solves ECDLP', 'Session key recovered from recorded traffic', 'Historical sessions decryptable'],
  'ecdh|key-exchange':['ECDH ephemeral exchange', 'CRQC solves ECDLP offline', 'Session key recovered', 'Encrypted data exposed'],
  'ecdsa|signing':    ['ECDSA signature', 'CRQC recovers private key via ECDLP', 'Forged signatures', 'Software / data integrity bypass'],
  'ecdsa|jwt':        ['ECDSA JWT signing', 'CRQC recovers signing key', 'Forged JWT tokens', 'Authentication completely bypassed'],
  'ec|other':         ['EC operation detected', 'ECDLP vulnerable to Shors algorithm', 'Private key recoverable', 'Downstream operations compromised'],
  'ec|signing':       ['EC signing key', 'CRQC ECDLP attack', 'Signing key recovered', 'Forged signatures'],
  'md5|hashing':      ['MD5 hash used', 'Classical collision attack available today', 'Hash collision generated', 'Forged data accepted as authentic', 'Integrity guarantee broken'],
  'md5|signing':      ['MD5-signed artifact', 'Collision created (Chosen-prefix)', 'Forged signature accepted', 'Malicious payload deployed'],
  'sha-1|hashing':    ['SHA-1 hash', 'SHAttered / birthday attack (classical)', 'Collision found', 'Forged document / artifact', 'Integrity bypass'],
  'sha-1|signing':    ['SHA-1-based signature', 'Classical collision (SHAttered)', 'Forged signature', 'Supply-chain or code-signing bypass'],
  'dsa|signing':      ['DSA signature (1024-bit typical)', 'Quantum discrete-log', 'Private key recovered', 'All future signatures forgeable'],
  'des|encryption':   ['DES/3DES encrypted data', 'Known plaintext / brute force (classical)', 'Key recovered', 'All data decrypted'],
  '3des|encryption':  ['3DES cipher', 'Sweet32 birthday attack (classical)', 'Block collisions - plaintext leakage', 'Data confidentiality broken'],
  'rc4|encryption':   ['RC4 stream cipher', 'Statistical bias attack (classical)', 'Keystream recovered', 'Plaintext exposed'],
};

function algoFamily(algo) {
  if (!algo) return 'unknown';
  const a = algo.toLowerCase().replace(/[-_\s]/g, '');
  if (a.startsWith('rsa')) return 'rsa';
  if (a.startsWith('ecdh')) return 'ecdh';
  if (a.startsWith('ecdsa')) return 'ecdsa';
  if (a.startsWith('ec')) return 'ec';
  if (a.startsWith('dsa')) return 'dsa';
  if (a.startsWith('md5')) return 'md5';
  if (a === 'sha1' || a === 'sha-1') return 'sha-1';
  if (a.startsWith('sha1') || a.startsWith('sha-1')) return 'sha-1';
  if (a.startsWith('3des') || a === 'tripledes') return '3des';
  if (a.startsWith('des')) return 'des';
  if (a.startsWith('rc4') || a.startsWith('arc4')) return 'rc4';
  return a.slice(0, 8);
}

function normaliseContext(ctx) {
  if (!ctx) return 'other';
  const c = ctx.toLowerCase().replace(/[-_\s]/g, '');
  if (c.includes('jwt') || c.includes('token')) return 'jwt';
  if (c.includes('tls') || c.includes('ssl') || c.includes('https')) return 'tls';
  if (c.includes('sign')) return 'signing';
  if (c.includes('key') && (c.includes('exchange') || c.includes('agreement') || c.includes('encap'))) return 'key-exchange';
  if (c.includes('enc') || c.includes('cipher') || c.includes('crypt')) return 'encryption';
  if (c.includes('hash') || c.includes('digest') || c.includes('checksum')) return 'hashing';
  return 'other';
}

function deriveTarget(algo) {
  const a = (algo || '').toLowerCase();
  if (a.includes('rsa') || a.includes('dh') || a.includes('ecdh')) return 'ML-KEM-768 (FIPS 203) / Hybrid X25519+ML-KEM';
  if (a.includes('ecdsa') || a.includes('dsa') || a.includes('ed25519')) return 'ML-DSA-65 (FIPS 204) / SLH-DSA';
  if (a === 'md5' || a === 'sha1' || a === 'sha-1') return 'SHA-256 / SHA-3-256';
  if (a.includes('des') || a.includes('rc4')) return 'AES-256-GCM / ChaCha20-Poly1305';
  return 'NIST PQC Standard (FIPS 203/204/205)';
}

function buildAttackPath(item) {
  const family = algoFamily(item.currentAlgorithm || item.algorithm || '');
  const ctx    = normaliseContext(item.usageContext || item.usage || '');
  const key    = family + '|' + ctx;
  const steps  = ATTACK_PATH_TEMPLATES[key] || ATTACK_PATH_TEMPLATES[family + '|other'] || [
    (item.currentAlgorithm || 'Algorithm') + ' usage detected',
    'Quantum / classical vulnerability present',
    'Attacker exploits weakness',
    'Protected data or operation compromised',
  ];
  const isQuantum = ['rsa','ecdh','ecdsa','ec','dsa'].includes(family);
  const isClassical = ['md5','sha-1','des','3des','rc4'].includes(family);
  let whyItMatters = (item.currentAlgorithm || 'Algorithm') + ' is vulnerable.';
  if (isQuantum) whyItMatters = (item.currentAlgorithm || 'Algorithm') + ': Shors algorithm on a CRQC can factor/solve the underlying hard problem in polynomial time.';
  if (isClassical) whyItMatters = (item.currentAlgorithm || 'Algorithm') + ': Classical collision/brute-force attacks are already practical today.';
  return {
    id:                  crypto.randomUUID(),
    findingId:           item.id || null,
    filePath:            item.filePath || item.file || 'unknown',
    lineNumber:          item.line || item.lineNumber || null,
    algorithm:           item.currentAlgorithm || item.algorithm || 'Unknown',
    context:             item.usageContext || item.usage || 'other',
    severity:            item.severity || 'MEDIUM',
    steps,
    statusBefore:        'OPEN',
    statusAfter:         'NOT_VERIFIED',
    whyItMatters,
    proposedReplacement: item.targetAlgorithm || deriveTarget(item.currentAlgorithm || ''),
    note:                'Simulated attack path (model-based), not a live exploit.',
  };
}

// ── Patch application ─────────────────────────────────────────────────────────
function applySandboxPatches(sandboxDir, items) {
  const log = [];
  for (const item of items) {
    const algo    = (item.currentAlgorithm || item.algorithm || '').toLowerCase();
    const lang    = (item.language || '').toLowerCase();
    const relPath = item.filePath || item.file || '';
    if (!relPath) continue;
    const absPath = path.join(sandboxDir, relPath);
    if (!fs.existsSync(absPath)) {
      log.push({ filePath: relPath, status: 'PATCH_FILE_NOT_FOUND', tag: 'N/A', before: null, after: null });
      continue;
    }
    let src;
    try { src = fs.readFileSync(absPath, 'utf8'); } catch (e) {
      log.push({ filePath: relPath, status: 'PATCH_READ_ERROR', tag: 'N/A', error: e.message });
      continue;
    }
    const ext = path.extname(relPath).replace('.', '').toLowerCase();
    const isPy = lang === 'python' || ext === 'py';
    const isJs = lang === 'javascript' || lang === 'js' || ext === 'js' || ext === 'ts';
    let matched = false;

    const tryApply = (searchStr, replaceStr, tag) => {
      if (matched) return;
      if (src.includes(searchStr)) {
        const patched = src.replace(searchStr, replaceStr);
        if (patched !== src) {
          try {
            fs.writeFileSync(absPath, patched, 'utf8');
            log.push({ filePath: relPath, status: 'PATCHED', tag, before: searchStr, after: replaceStr });
            matched = true;
            src = patched;
          } catch (we) {
            log.push({ filePath: relPath, status: 'PATCH_WRITE_ERROR', tag, error: we.message });
          }
        }
      }
    };

    if (isPy && algo.includes('md5'))                      tryApply('hashlib.md5(',  'hashlib.sha256(  # PQC MIGRATION: MD5->SHA-256', 'MD5->SHA-256');
    if (isPy && (algo.includes('sha1') || algo === 'sha-1')) tryApply('hashlib.sha1(', 'hashlib.sha256(  # PQC MIGRATION: SHA-1->SHA-256', 'SHA-1->SHA-256');
    if (isJs && algo.includes('md5'))                      tryApply("createHash('md5')",  "createHash('sha256') // PQC MIGRATION: MD5->SHA-256", 'MD5->SHA-256');
    if (isJs && (algo.includes('sha1') || algo === 'sha-1')) tryApply("createHash('sha1')", "createHash('sha256') // PQC MIGRATION: SHA-1->SHA-256", 'SHA-1->SHA-256');

    if (!matched) {
      const target = deriveTarget(algo);
      log.push({
        filePath:  relPath,
        status:    'PATCH_GENERATED_NOT_APPLIED',
        tag:       (item.currentAlgorithm || algo) + '->' + target,
        before:    'Current: ' + (item.currentAlgorithm || algo),
        after:     'Target: ' + target + ' (manual migration required; no auto-template for this language/algorithm pair)',
      });
    }
  }
  return log;
}

// ── Test runner (static analysis) ─────────────────────────────────────────────
function runTests(sandboxDir, items, patchLog, phase) {
  const results     = [];
  const phaseLabel  = phase === 'before' ? 'Baseline (before migration)' : 'Post-migration';
  const filesInScope = [...new Set(items.map(i => i.filePath || i.file || '').filter(Boolean))];

  for (const item of items) {
    const algo     = (item.currentAlgorithm || item.algorithm || '').toUpperCase();
    const ctx      = normaliseContext(item.usageContext || item.usage || '');
    const relPath  = item.filePath || item.file || 'unknown';
    const absPath  = path.join(sandboxDir, relPath);
    let src = '';
    let canRead = false;
    if (fs.existsSync(absPath)) { try { src = fs.readFileSync(absPath, 'utf8'); canRead = true; } catch (_) {} }
    const patchEntry = patchLog.find(p => p.filePath === relPath);
    const wasPatched = patchEntry && patchEntry.status === 'PATCHED';

    // Functional: key-exchange / encryption
    if (ctx === 'key-exchange' || ctx === 'encryption') {
      const testName = algo + ' ' + ctx + ' - vulnerable algorithm absent from patched file';
      if (phase === 'after' && canRead) {
        const stillPresent = /rsa\.generate_private_key|createCipheriv\('des|createCipheriv\('rc4/i.test(src);
        results.push({
          id: crypto.randomUUID(), suite: 'Functional', name: testName, file: relPath, phase: phaseLabel,
          status: wasPatched && !stillPresent ? 'PASSED' : (wasPatched ? 'FAILED' : 'NOT_EXECUTED'),
          reason: wasPatched && !stillPresent ? 'Vulnerable algorithm pattern not found after patch'
            : wasPatched ? 'Pattern still present after patch - manual migration needed'
            : 'File was not patched (no auto-template available)',
          log: 'File size: ' + src.length + ' bytes | Pattern: ' + (stillPresent ? 'FOUND (fail)' : 'NOT FOUND (pass)'),
        });
      } else {
        results.push({ id: crypto.randomUUID(), suite: 'Functional', name: testName, file: relPath, phase: phaseLabel, status: 'NOT_EXECUTED', reason: 'Baseline phase - no patch applied yet' });
      }
    }

    // Security: weak pattern removed
    const WEAK_PATTERNS = {
      'MD5':   /hashlib\.md5|createHash\('md5'\)/i,
      'SHA-1': /hashlib\.sha1|createHash\('sha1'\)/i,
      'SHA1':  /hashlib\.sha1|createHash\('sha1'\)/i,
      'DES':   /createCipheriv\('des|new\sDES\b/i,
      '3DES':  /createCipheriv\('des-ede|createCipheriv\('3des/i,
      'RC4':   /createCipheriv\('rc4|createCipheriv\('arcfour/i,
    };
    const pattern = WEAK_PATTERNS[algo];
    if (pattern && canRead) {
      const found = pattern.test(src);
      results.push({
        id: crypto.randomUUID(), suite: 'Security',
        name: algo + ' - classically-weak pattern removed from ' + relPath,
        file: relPath, phase: phaseLabel,
        status: phase === 'after' ? (wasPatched ? (found ? 'FAILED' : 'PASSED') : 'NOT_EXECUTED') : 'NOT_EXECUTED',
        reason: phase === 'after'
          ? (wasPatched ? (found ? 'Weak pattern still present in file after patching' : 'Weak pattern successfully removed') : 'File not auto-patched; pattern check skipped')
          : 'Baseline: weak pattern present (expected)',
        log: 'Pattern match: ' + (found ? 'YES (weak algo present)' : 'NO (cleared)'),
      });
    }

    // Security: no TLS downgrade
    if (ctx === 'tls' && canRead && phase === 'after') {
      const noDowngrade = !/TLSv1\.0|TLSv1\.1|PROTOCOL_TLS[^v]/.test(src);
      results.push({
        id: crypto.randomUUID(), suite: 'Security',
        name: 'No TLS downgrade path in ' + relPath,
        file: relPath, phase: phaseLabel,
        status: noDowngrade ? 'PASSED' : 'FAILED',
        reason: noDowngrade ? 'No TLSv1.0/1.1 downgrade configuration detected' : 'TLSv1.0/1.1 still configured - possible downgrade path',
      });
    }

    // Compatibility: RSA key size
    if (algo.startsWith('RSA') && canRead) {
      const hasSmallKey = /key_size=(512|768|1024)/.test(src);
      results.push({
        id: crypto.randomUUID(), suite: 'Compatibility',
        name: algo + ' key size adequate in ' + relPath,
        file: relPath, phase: phaseLabel,
        status: wasPatched ? 'PASSED' : (hasSmallKey ? 'FAILED' : 'PASSED'),
        reason: hasSmallKey ? 'Key size < 2048 bits detected' : 'Key size appears adequate',
      });
    }
  }

  // Global: no hardcoded key material
  for (const relPath of filesInScope) {
    const absPath = path.join(sandboxDir, relPath);
    let src = '';
    try { src = fs.readFileSync(absPath, 'utf8'); } catch (_) { continue; }
    const hardcoded = /(?:private_key|secret_key|api_key)\s*=\s*['"][A-Za-z0-9+/]{20,}['"]/i.test(src)
                   || /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/.test(src);
    results.push({
      id: crypto.randomUUID(), suite: 'Security',
      name: 'No hardcoded key material in ' + relPath,
      file: relPath, phase: phaseLabel,
      status: hardcoded ? 'FAILED' : 'PASSED',
      reason: hardcoded ? 'Hardcoded private key or secret detected in source file' : 'No hardcoded key material detected',
    });
  }

  if (results.length === 0) {
    results.push({ id: crypto.randomUUID(), suite: 'Functional', name: 'General crypto usage audit', file: 'project-wide', phase: phaseLabel, status: 'NOT_EXECUTED', reason: 'No source files from migration items were readable in sandbox' });
  }
  return results;
}

// ── AI diagnosis prompt builder ────────────────────────────────────────────────
function buildAiDiagnosisPrompt(failedTest, patchLog, item) {
  return 'You are a post-quantum cryptography migration expert.\n\n'
    + 'A security test FAILED after attempting to migrate cryptographic code.\n\n'
    + '## Failing Test\n'
    + '- Name: ' + failedTest.name + '\n'
    + '- Suite: ' + failedTest.suite + '\n'
    + '- File: ' + failedTest.file + '\n'
    + '- Reason: ' + failedTest.reason + '\n'
    + '- Log: ' + (failedTest.log || 'N/A') + '\n\n'
    + '## Migration Context\n'
    + '- Algorithm: ' + (item ? (item.currentAlgorithm || item.algorithm || 'Unknown') : 'Unknown') + '\n'
    + '- Context: ' + (item ? (item.usageContext || item.usage || 'Unknown') : 'Unknown') + '\n'
    + '- Target: ' + (item ? (item.targetAlgorithm || deriveTarget(item.currentAlgorithm || '')) : 'Unknown') + '\n\n'
    + '## Patch Log\n' + JSON.stringify(patchLog.slice(0, 5), null, 2) + '\n\n'
    + '## Task\nRespond ONLY with valid JSON:\n'
    + '{"rootCause":"<1-2 sentence root cause>","patch":{"file":"<relative path>","before":"<code to replace>","after":"<replacement code>"},"confidence":<0-100>}';
}

// ── Verdict + confidence computation ──────────────────────────────────────────
function computeVerdict(attackPaths, tests, patchLog) {
  const totalPaths   = attackPaths.length;
  const blockedPaths = attackPaths.filter(p => p.statusAfter === 'BLOCKED').length;
  const openPaths    = attackPaths.filter(p => p.statusAfter === 'STILL_OPEN').length;

  const bySuite = {
    Functional:    { pass: 0, fail: 0, ne: 0, total: 0 },
    Security:      { pass: 0, fail: 0, ne: 0, total: 0 },
    Compatibility: { pass: 0, fail: 0, ne: 0, total: 0 },
  };
  for (const t of tests) {
    const s = bySuite[t.suite] || bySuite.Functional;
    s.total++;
    if (t.status === 'PASSED') s.pass++;
    else if (t.status === 'FAILED') s.fail++;
    else s.ne++;
  }

  const pctPath   = totalPaths > 0 ? blockedPaths / totalPaths : 0;
  const pctSec    = bySuite.Security.total > 0 ? bySuite.Security.pass / bySuite.Security.total : 1;
  const pctFunc   = bySuite.Functional.total > 0 ? bySuite.Functional.pass / bySuite.Functional.total : 1;
  const pctCompat = bySuite.Compatibility.total > 0 ? bySuite.Compatibility.pass / bySuite.Compatibility.total : 1;
  const unapplied = patchLog.filter(p => p.status === 'PATCH_GENERATED_NOT_APPLIED').length;
  const notExec   = tests.filter(t => t.status === 'NOT_EXECUTED').length;

  let confidence = 40 * pctPath + 30 * pctSec + 20 * pctFunc + 10 * pctCompat
    - 5 * Math.min(unapplied, 6)
    - 2 * Math.min(notExec, 10);
  confidence = Math.max(0, Math.min(100, confidence));

  const blockers  = [];
  let verdict;
  const critFailed = bySuite.Security.fail > 0 || bySuite.Functional.fail > 0;

  if (critFailed || openPaths > 0) {
    verdict = 'PRODUCTION_NOT_READY';
    if (bySuite.Security.fail > 0)   blockers.push(bySuite.Security.fail + ' security test(s) failed');
    if (bySuite.Functional.fail > 0) blockers.push(bySuite.Functional.fail + ' functional test(s) failed');
    if (openPaths > 0)               blockers.push(openPaths + ' attack path(s) still open');
    if (unapplied > 0)               blockers.push(unapplied + ' patch(es) require manual application');
  } else if (confidence >= 75 && blockedPaths === totalPaths && bySuite.Security.fail === 0) {
    verdict = 'PRODUCTION_READY';
  } else {
    verdict = 'INCONCLUSIVE';
    if (notExec > 0)  blockers.push(notExec + ' test(s) could not be executed (source not readable in sandbox)');
    if (unapplied > 0) blockers.push(unapplied + ' patch(es) require manual application');
    const unverified = attackPaths.filter(p => p.statusAfter === 'NOT_VERIFIED').length;
    if (unverified > 0) blockers.push(unverified + ' attack path(s) not verified by test');
  }

  return { verdict, confidence: Math.round(confidence * 10) / 10, blockers };
}

// ── Update attack-path statusAfter ────────────────────────────────────────────
function resolveAttackPathStatuses(attackPaths, tests, patchLog) {
  return attackPaths.map(ap => {
    const relPath    = ap.filePath;
    const patchEntry = patchLog.find(p => p.filePath === relPath);
    const wasPatched = patchEntry && patchEntry.status === 'PATCHED';
    const secFailed  = tests.filter(t => t.file === relPath && t.suite === 'Security' && t.status === 'FAILED');
    const secPassed  = tests.filter(t => t.file === relPath && t.suite === 'Security' && t.status === 'PASSED');
    let statusAfter;
    if (wasPatched && secFailed.length === 0 && secPassed.length > 0) statusAfter = 'BLOCKED';
    else if (wasPatched && secFailed.length > 0)                       statusAfter = 'STILL_OPEN';
    else                                                                statusAfter = 'NOT_VERIFIED';
    return Object.assign({}, ap, { statusAfter });
  });
}

// ── Sandbox creation / cleanup ─────────────────────────────────────────────────
function createSandbox(items, repoFilePath) {
  const sandboxDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptotwin-'));
  const repoBase   = repoFilePath ? path.dirname(repoFilePath) : null;
  for (const item of items) {
    const relPath = item.filePath || item.file || '';
    if (!relPath) continue;
    const destFile = path.join(sandboxDir, relPath);
    const destDir  = path.dirname(destFile);
    if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
    let copied = false;
    if (repoBase) {
      const srcFile = path.join(repoBase, relPath);
      if (fs.existsSync(srcFile)) { try { fs.copyFileSync(srcFile, destFile); copied = true; } catch (_) {} }
    }
    if (!copied) {
      const algo = item.currentAlgorithm || item.algorithm || 'UnknownAlgo';
      const lang = (item.language || '').toLowerCase();
      const stub = (lang === 'python' || relPath.endsWith('.py'))
        ? '# CryptoTwin sandbox stub\n# Algorithm: ' + algo + '\n# Line: ' + (item.line || item.lineNumber || '?') + '\n'
        : '// CryptoTwin sandbox stub\n// Algorithm: ' + algo + '\n// Line: ' + (item.line || item.lineNumber || '?') + '\n';
      fs.writeFileSync(destFile, stub, 'utf8');
    }
  }
  return sandboxDir;
}

function cleanupSandbox(sandboxDir) {
  if (!sandboxDir) return;
  try { fs.rmSync(sandboxDir, { recursive: true, force: true }); } catch (_) {}
}

// ── Public pipeline ────────────────────────────────────────────────────────────
async function runCryptoTwin(input, opts) {
  if (!opts) opts = {};
  const repoFilePath    = opts.repoFilePath || null;
  const llmFn           = opts.llmFn || null;
  const maxFixIterations = opts.maxFixIterations || 3;
  const items = (input.items || []).filter(Boolean);

  const stages = [
    { name: 'Twin Created',     status: 'running' },
    { name: 'Breach Simulation', status: 'pending' },
    { name: 'Migration Applied', status: 'pending' },
    { name: 'Tests (baseline)',  status: 'pending' },
    { name: 'AI Diagnose & Fix', status: 'pending' },
    { name: 'Retest',            status: 'pending' },
    { name: 'Verdict',           status: 'pending' },
  ];
  const setStage = (i, s) => { stages[i].status = s; };

  let sandboxDir   = null;
  let attackPaths  = [];
  let baselineTests = [];
  let postTests    = [];
  let patchLog     = [];
  let aiIterations = [];
  let allTests     = [];

  try {
    sandboxDir = createSandbox(items, repoFilePath);
    setStage(0, 'passed');

    setStage(1, 'running');
    attackPaths = items.map(buildAttackPath);
    setStage(1, 'passed');

    setStage(2, 'running');
    patchLog = applySandboxPatches(sandboxDir, items);
    setStage(2, patchLog.some(p => p.status === 'PATCHED') ? 'passed' : 'skipped');

    setStage(3, 'running');
    baselineTests = runTests(sandboxDir, items, [], 'before');
    setStage(3, 'passed');

    setStage(4, 'running');
    postTests    = runTests(sandboxDir, items, patchLog, 'after');
    attackPaths  = resolveAttackPathStatuses(attackPaths, postTests, patchLog);

    const failedTests   = postTests.filter(t => t.status === 'FAILED');
    let   currentTests  = postTests.slice();
    let   iteration     = 0;

    for (let i = 0; i < Math.min(failedTests.length, 3); i++) {
      if (iteration >= maxFixIterations) break;
      iteration++;
      const ft      = failedTests[i];
      const relItem = items.find(it => (it.filePath || it.file) === ft.file);
      const prompt  = buildAiDiagnosisPrompt(ft, patchLog, relItem);
      const attempt = { iteration, testName: ft.name, file: ft.file, status: 'ATTEMPTED' };

      if (typeof llmFn === 'function') {
        try {
          const aiRaw = await llmFn(prompt);
          let parsed = null;
          try { parsed = JSON.parse(aiRaw); } catch (_) {}
          if (parsed && parsed.patch && parsed.patch.file) {
            const pf = path.join(sandboxDir, parsed.patch.file);
            if (fs.existsSync(pf)) {
              try {
                let src = fs.readFileSync(pf, 'utf8');
                if (parsed.patch.before && src.includes(parsed.patch.before)) {
                  src = src.replace(parsed.patch.before, parsed.patch.after);
                  fs.writeFileSync(pf, src, 'utf8');
                  attempt.status     = 'FIXED';
                  attempt.rootCause  = parsed.rootCause;
                  attempt.before     = parsed.patch.before;
                  attempt.after      = parsed.patch.after;
                  attempt.confidence = parsed.confidence;
                } else {
                  attempt.status    = 'PATCH_NOT_APPLIED';
                  attempt.reason    = '"before" text not found in file';
                  attempt.rootCause = parsed.rootCause;
                }
              } catch (we) { attempt.status = 'WRITE_ERROR'; attempt.error = we.message; }
            } else { attempt.status = 'FILE_NOT_FOUND'; }
          } else {
            attempt.status      = 'PARSE_ERROR';
            attempt.rawResponse = (aiRaw || '').slice(0, 500);
          }
        } catch (le) { attempt.status = 'LLM_ERROR'; attempt.error = le.message; }
      } else {
        attempt.status = 'LLM_UNAVAILABLE';
        attempt.reason = 'No LLM integration configured; attach an llmFn to enable AI diagnosis.';
      }
      aiIterations.push(attempt);
    }

    if (aiIterations.some(a => a.status === 'FIXED')) {
      const retestResults = runTests(sandboxDir, items, patchLog, 'after');
      const fixedFiles    = new Set(aiIterations.filter(a => a.status === 'FIXED').map(a => a.file));
      currentTests = [
        ...postTests.filter(t => !fixedFiles.has(t.file)),
        ...retestResults.filter(t => fixedFiles.has(t.file)),
      ];
      attackPaths = resolveAttackPathStatuses(attackPaths, currentTests, patchLog);
    }
    setStage(4, 'passed');
    setStage(5, 'passed');
    setStage(6, 'running');
    allTests = baselineTests.concat(currentTests);
    const result = computeVerdict(attackPaths, currentTests, patchLog);
    setStage(6, 'passed');
    cleanupSandbox(sandboxDir);

    return {
      status:       'DONE',
      stages,
      attackPaths,
      tests:        allTests,
      patchLog,
      aiIterations,
      verdict:      result.verdict,
      confidence:   result.confidence,
      blockers:     result.blockers,
    };
  } catch (err) {
    cleanupSandbox(sandboxDir);
    return {
      status:       'FAILED',
      stages,
      attackPaths,
      tests:        allTests,
      patchLog,
      aiIterations,
      verdict:      null,
      confidence:   null,
      blockers:     [],
      errorMessage: err.message,
    };
  }
}

module.exports = { runCryptoTwin, buildAttackPath, computeVerdict, buildAiDiagnosisPrompt, deriveTarget, algoFamily, normaliseContext };
