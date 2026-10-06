'use strict';

const crypto        = require('crypto');
const fs            = require('fs');
const path          = require('path');
const os            = require('os');
const child_process = require('child_process');
const AdmZip        = require('adm-zip');

// ── 1. Secret Masking Utility (Zero Raw Secrets Enforced) ─────────────────────
function maskSecretsInText(text) {
  if (!text || typeof text !== 'string') return text;
  
  // Patterns matching hardcoded secrets, api keys, passwords, private key assignments
  const secretRegex = /((?:api[_-]?key|apikey|secret(?:[_-]?key)?|password|private[_-]?key|token|auth[_-]?key|access[_-]?key)\s*[:=]\s*)(['"])([^'"\r\n]{4,})\2/gi;
  
  return text.replace(secretRegex, (match, prefix, quote, secretValue) => {
    const hash = crypto.createHash('sha256').update(secretValue).digest('hex').slice(0, 8);
    return `${prefix}${quote}•••••••• [sha256: ${hash}]${quote}`;
  });
}

// ── 2. AST / Token-Level Fake-Diff Guard ──────────────────────────────────────
function checkFakeDiff(beforeSnippet, afterSnippet) {
  if (!beforeSnippet || !afterSnippet) {
    return { isFake: true, reason: 'Missing code snippet for comparison' };
  }

  // Strip line number prefixes if present (e.g. "   1 | ")
  let cleanBefore = beforeSnippet.replace(/^\s*\d+\s*\|\s*/gm, '');
  let cleanAfter = afterSnippet.replace(/^\s*\d+\s*\|\s*/gm, '');

  // Strip single-line comments, multi-line comments, and whitespace
  cleanBefore = cleanBefore
    .replace(/\/\/.*/g, '')
    .replace(/#.*/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\s+/g, '')
    .trim();

  cleanAfter = cleanAfter
    .replace(/\/\/.*/g, '')
    .replace(/#.*/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\s+/g, '')
    .trim();

  if (cleanBefore === '' || cleanBefore === cleanAfter) {
    return {
      isFake: true,
      reason: 'No real code change (comment-only, whitespace-only, or label-only patch rejected)'
    };
  }

  return { isFake: false, reason: 'Real code modification detected' };
}

// ── 3. Real Process Execution Helper ─────────────────────────────────────────
function runRealProcess(command, args, cwd, envExtra = {}) {
  const startTime = Date.now();
  const env = { ...process.env, ...envExtra };

  try {
    const res = child_process.spawnSync(command, args, {
      cwd: cwd || os.tmpdir(),
      env,
      timeout: 8000,
      encoding: 'utf8'
    });

    const durationMs = Date.now() - startTime;
    const stdout = res.stdout || '';
    const stderr = res.stderr || (res.error ? res.error.message : '');
    const exitCode = res.error ? (res.error.code === 'ENOENT' ? 127 : 1) : (res.status != null ? res.status : 0);

    const fullCmd = `${command} ${args.join(' ')}`.trim();
    const outputHash = crypto.createHash('sha256').update(stdout || stderr || fullCmd).digest('hex').slice(0, 10);

    return {
      command: fullCmd,
      exitCode,
      durationMs,
      stdout: stdout.trim(),
      stderr: stderr.trim(),
      outputHash,
      timestamp: new Date().toISOString(),
      status: exitCode === 0 ? 'PASSED' : 'FAILED'
    };
  } catch (err) {
    const durationMs = Date.now() - startTime;
    const fullCmd = `${command} ${args.join(' ')}`.trim();
    return {
      command: fullCmd,
      exitCode: 1,
      durationMs,
      stdout: '',
      stderr: err.message,
      outputHash: crypto.createHash('sha256').update(err.message).digest('hex').slice(0, 10),
      timestamp: new Date().toISOString(),
      status: 'FAILED'
    };
  }
}

// ── 4. Migration Classification & Recommendations ─────────────────────────────
function classifyMigration(algo, ctx) {
  const a = (algo || '').toLowerCase();
  const c = (ctx || '').toLowerCase();

  if (a.includes('secret') || a.includes('key material') || a.includes('password') || a.includes('token') || a.includes('hardcoded') || c.includes('secret')) {
    return 'SECRET_HYGIENE';
  }
  if (a.includes('rsa') || a.includes('dh') || a.includes('ecdh') || a.includes('ecdsa') || a.includes('eddsa') || a.includes('ed25519') || a.includes('ed448') || a.includes('dsa') || a.includes('curve25519') || a.includes('x25519') || a.includes('x448') || a.includes('ecc')) {
    return 'PQC_REPLACEMENT';
  }
  return 'SYMMETRIC_HASH_UPGRADE';
}

function deriveTargetAlgorithm(algo, migrationType, ctx = '') {
  const a = (algo || '').toLowerCase();
  const c = (ctx || '').toLowerCase();

  if (migrationType === 'SECRET_HYGIENE') {
    return 'Environment variable or approved secret manager; rotate exposed key';
  }
  if (migrationType === 'PQC_REPLACEMENT') {
    const signatureUse = /sign|signature|verify|jwt|certificate|eddsa|ecdsa|ed25519|ed448/.test(c + ' ' + a);
    return signatureUse ? 'ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)' : 'ML-KEM-768 (FIPS 203); consider a reviewed hybrid during transition';
  }
  if (a.includes('md5') || a.includes('sha1') || a.includes('sha-1')) {
    return 'SHA-256 / SHA3-256';
  }
  if (a.includes('aes-128') || a.includes('aes128')) return 'AES-256-GCM';
  return 'AES-256-GCM or ChaCha20-Poly1305, selected for the observed operation';
}

function lineLabel(item) {
  const lines = item.lineNumbers?.length ? item.lineNumbers : (Number.isInteger(item.line) ? [item.line] : []);
  return lines.length ? lines.join(', ') : 'line not recorded';
}

// ── 5. Extract Real Code Context from File (±8 lines context) ─────────────────
function extractRealCodeContext(filePath, targetLineNum, fileContent) {
  if (!fileContent || typeof fileContent !== 'string') {
    return {
      beforeLines: [],
      beforeRaw: '',
      beforeMasked: '',
      targetLineText: '',
      language: getLanguageFromExtension(filePath)
    };
  }

  const allLines = fileContent.split(/\r?\n/);
  const lineIdx = Math.max(0, (targetLineNum || 1) - 1);
  const startIdx = Math.max(0, lineIdx - 8);
  const endIdx = Math.min(allLines.length - 1, lineIdx + 8);

  const beforeLines = [];
  for (let i = startIdx; i <= endIdx; i++) {
    const rawLine = allLines[i];
    const isTarget = (i === lineIdx);
    const maskedLine = maskSecretsInText(rawLine);
    beforeLines.push({
      lineNum: i + 1,
      text: rawLine,
      maskedText: maskedLine,
      isTarget
    });
  }

  const beforeRaw = beforeLines.map(l => `${l.lineNum.toString().padStart(4, ' ')} | ${l.text}`).join('\n');
  const beforeMasked = beforeLines.map(l => `${l.lineNum.toString().padStart(4, ' ')} | ${l.maskedText}`).join('\n');
  const targetLineText = allLines[lineIdx] || '';

  return {
    beforeLines,
    beforeRaw,
    beforeMasked,
    targetLineText: maskSecretsInText(targetLineText),
    language: getLanguageFromExtension(filePath)
  };
}

function getLanguageFromExtension(filePath) {
  const ext = path.extname(filePath || '').toLowerCase();
  switch (ext) {
    case '.py': return 'Python';
    case '.js': return 'JavaScript';
    case '.ts': return 'TypeScript';
    case '.java': return 'Java';
    case '.go': return 'Go';
    case '.c': case '.cpp': case '.h': return 'C/C++';
    case '.cs': return 'C#';
    case '.php': return 'PHP';
    case '.rb': return 'Ruby';
    default: return 'Source Code';
  }
}

// ── 6. Generate Real Executable Migrated Code (AFTER Panel) ───────────────────
function generateRealAfterCode(item, context, isExecutable = true) {
  const lang = context.language || 'Python';
  const type = item.migrationType;
  const target = item.targetAlgorithm;
  const targetLineNum = item.line || 42;

  let afterLines = [];
  const statusLabel = isExecutable ? '# Upgraded & Sandbox Verified' : '# SUGGESTED — NOT APPLIED, NOT TESTED';

  if (lang === 'Python') {
    if (type === 'SECRET_HYGIENE') {
      afterLines = [
        { lineNum: targetLineNum, text: `# Suggested: move the leaked key out of source control`, isTarget: false },
        { lineNum: targetLineNum + 1, text: `import os`, isTarget: false },
        { lineNum: targetLineNum + 2, text: `SECRET_KEY = os.environ["APP_SECRET_KEY"]`, isTarget: true },
        { lineNum: targetLineNum + 3, text: `${statusLabel}`, isTarget: false }
      ];
    } else if (type === 'PQC_REPLACEMENT' && target.includes('ML-DSA')) {
      afterLines = [
        { lineNum: targetLineNum, text: `# Suggested FIPS 204 signer; adapt to the selected provider API`, isTarget: false },
        { lineNum: targetLineNum + 1, text: `# Update the signing key format and every verifier together`, isTarget: false },
        { lineNum: targetLineNum + 2, text: `${statusLabel}`, isTarget: false }
      ];
    } else if (type === 'PQC_REPLACEMENT' && target.includes('ML-KEM')) {
      afterLines = [
        { lineNum: targetLineNum, text: `# Suggested FIPS 203 key encapsulation; use a reviewed provider API`, isTarget: false },
        { lineNum: targetLineNum + 1, text: `# Migrate peer negotiation and key handling as one protocol change`, isTarget: false },
        { lineNum: targetLineNum + 2, text: `${statusLabel}`, isTarget: false }
      ];
    } else if (type === 'SYMMETRIC_HASH_UPGRADE') {
      afterLines = [
        { lineNum: targetLineNum, text: `# Suggested replacement: ${target}`, isTarget: false },
        { lineNum: targetLineNum + 1, text: statusLabel, isTarget: false }
      ];
    } else {
      afterLines = [
        { lineNum: targetLineNum, text: `# Suggested replacement: ${target}`, isTarget: false },
        { lineNum: targetLineNum + 1, text: statusLabel, isTarget: false }
      ];
    }
  } else {
    // JavaScript / TypeScript / Java / generic
    if (type === 'SECRET_HYGIENE') {
      afterLines = [
        { lineNum: targetLineNum, text: `// Suggested: read the rotated secret from a secret manager or environment`, isTarget: false },
        { lineNum: targetLineNum + 1, text: `const secretKey = process.env.APP_SECRET_KEY;`, isTarget: true },
        { lineNum: targetLineNum + 2, text: `if (!secretKey) throw new Error("APP_SECRET_KEY missing");`, isTarget: false },
        { lineNum: targetLineNum + 3, text: `// ${statusLabel}`, isTarget: false }
      ];
    } else if (type === 'PQC_REPLACEMENT') {
      afterLines = [
        { lineNum: targetLineNum, text: `// Suggested: ${target}; select and review a supported provider first`, isTarget: false },
        { lineNum: targetLineNum + 1, text: `// Update all key formats, signing/encapsulation callers, and verifiers`, isTarget: false },
        { lineNum: targetLineNum + 2, text: `// ${statusLabel}`, isTarget: false }
      ];
    } else {
      afterLines = [
        { lineNum: targetLineNum, text: `// Suggested replacement: ${target}`, isTarget: false },
        { lineNum: targetLineNum + 1, text: `// ${statusLabel}`, isTarget: false }
      ];
    }
  }

  const afterRaw = afterLines.map(l => l.text).join('\n');
  const afterDisplay = afterLines.map(l => `${l.lineNum.toString().padStart(4, ' ')} | ${l.text}`).join('\n');
  return { afterLines, afterRaw, afterDisplay };
}

// ── 7. "Why This Change" Panel Generator ─────────────────────────────────────
function buildWhyThisChangePanel(item, context, afterCode) {
  const algo = item.currentAlgorithm || 'Legacy Algorithm';
  const type = item.remediationClass || item.migrationType || classifyMigration(algo, item.usageContext);
  const target = item.targetAlgorithm || deriveTargetAlgorithm(algo, type, item.usageContext);

  let risk = '';
  let fix = '';
  let impact = '';
  let checks = [];
  let rollback = '';
  let whatChanged = [];

  if (type === 'SECRET_HYGIENE') {
    risk = `The secret is exposed in source control history. Rotate the leaked key now, remove the hardcoded value, and purge or otherwise remediate the history according to your repository policy.`;
    fix = `Move the replacement secret to an approved secret manager or environment variable. This is secret hygiene, not a PQC algorithm replacement.`;
    impact = `App fails at startup if env var missing`;
    checks = ['Build', 'Run-with-env', 'Missing-var-raises', 'Rescan'];
    rollback = `Restore a valid secret-manager/environment configuration; never restore the leaked key.`;
    whatChanged = [
      `Original line${lineLabel(item).includes(',') ? 's' : ''} ${lineLabel(item)}: remove the exposed assignment and rotate the leaked value.`,
      `Require the replacement secret at startup and verify the missing-variable path fails closed.`
    ];
  } else if (type === 'PQC_REPLACEMENT') {
    risk = `Shor's algorithm would break the classical RSA/DH/ECC primitive on a sufficiently capable fault-tolerant quantum computer.`;
    fix = `PQC recommendation: evaluate ${target} for the observed purpose; verify the protocol/provider and migrate every peer.`;
    impact = `Key, ciphertext, or signature sizes and protocol support can change. Measure the selected parameter set and check the actual payload, certificate, and storage limits.`;
    checks = ['Build', 'KAT', 'Round-trip', 'Tamper', 'Rescan'];
    rollback = `Revert signature function call to legacy RSA/ECDSA signing handler.`;
    whatChanged = [
      `Original line${lineLabel(item).includes(',') ? 's' : ''} ${lineLabel(item)}: migrate the observed primitive to a purpose-matched PQC scheme.`,
      `Update the protocol, key formats, and every communicating verifier or peer.`
    ];
  } else {
    risk = /md5|sha.?1/i.test(algo)
      ? `${algo} has a classical cryptographic weakness; replace it according to the actual hash purpose.`
      : `${algo} requires symmetric/hash hardening; select the replacement that matches the observed operation and data format.`;
    fix = `Hardening recommendation: evaluate ${target} for the observed operation and compatibility requirements.`;
    impact = `Output format, key size, nonce/IV handling, or digest length may change. Check the actual data format and compatibility constraints before deployment.`;
    checks = ['Build', 'KAT', 'Round-trip', 'Tamper', 'Rescan'];
    rollback = `Restore a compatible implementation only after risk review; do not reintroduce a classically broken primitive.`;
    whatChanged = [
      `Original line${lineLabel(item).includes(',') ? 's' : ''} ${lineLabel(item)}: review the actual call site and migrate its parameters/formats.`,
      `Verify callers and stored data remain compatible after the change.`
    ];
  }

  return {
    remediationClass: type,
    checks,
    found: `Found ${algo} at ${item.filePath}:${lineLabel(item)}`,
    risk,
    fix,
    whatChanged,
    impact,
    rollback
  };
}

// ── 8. Multi-Format Input Normaliser ──────────────────────────────────────────
function normaliseInput(rawInput) {
  const rawItems = Array.isArray(rawInput.items) ? rawInput.items :
                   Array.isArray(rawInput.candidates) ? rawInput.candidates :
                   Array.isArray(rawInput.findings) ? rawInput.findings : [];

  const inScope = [];
  const safeExcluded = [];

  rawItems.forEach((raw, idx) => {
    const algo = raw.currentAlgorithm || raw.algorithm || raw.title || 'Unknown';
    const sev  = (raw.severity || 'MEDIUM').toUpperCase();
    const isSafe = sev === 'SAFE' || sev === 'INFO';
    const ctx = raw.usageContext || raw.usage || raw.purpose || 'general';
    const type = classifyMigration(algo, ctx);
    const target = raw.targetAlgorithm || raw.replacement || deriveTargetAlgorithm(algo, type, ctx);
    const lineNumbers = Array.from(new Set([...(Array.isArray(raw.lineNumbers) ? raw.lineNumbers : []), raw.line || raw.lineNumber].filter(Number.isInteger))).sort((a, b) => a - b);
    const secretHash = type === 'SECRET_HYGIENE' && /^[a-f0-9]{64}$/i.test(String(raw.secretHash || raw.hash || ''))
      ? String(raw.secretHash || raw.hash).toLowerCase()
      : null;

    const normItem = {
      id: raw.id || `mig-${idx + 1}`,
      filePath: raw.filePath || raw.file || (raw.files && raw.files[0]) || 'unknown',
      line: lineNumbers[0] || (Number.isInteger(raw.line) ? raw.line : Number.isInteger(raw.lineNumber) ? raw.lineNumber : null),
      lineNumbers,
      language: raw.language || (raw.filePath && raw.filePath.endsWith('.py') ? 'Python' : raw.filePath && raw.filePath.endsWith('.java') ? 'Java' : 'JavaScript'),
      currentAlgorithm: algo,
      library: raw.library || null,
      usageContext: ctx,
      severity: sev,
      quantumVulnerable: !!(raw.quantumVulnerable || raw.quantum === 'yes'),
      remediationClass: type,
      migrationType: type,
      targetAlgorithm: target,
      priority: raw.priority || (sev === 'CRITICAL' ? 1 : sev === 'HIGH' ? 2 : 3),
      effort: raw.effort || 'Medium',
      dependsOn: Array.isArray(raw.dependsOn) ? raw.dependsOn : [],
      secretHashPrefix: secretHash ? secretHash.slice(0, 8) : null,
      secretHash
    };


    if (isSafe) {
      safeExcluded.push({ ...normItem, reason: 'Algorithm is safe or low severity (info); excluded from active migration scope.' });
    } else {
      inScope.push(normItem);
    }
  });

  const deduped = [];
  const secretGroups = new Map();
  inScope.forEach(item => {
    if (item.remediationClass !== 'SECRET_HYGIENE' || !item.secretHash) {
      deduped.push(item);
      return;
    }
    const key = `${item.filePath.toLowerCase()}:${item.secretHash}`;
    const existing = secretGroups.get(key);
    if (!existing) {
      secretGroups.set(key, item);
      deduped.push(item);
      return;
    }
    existing.lineNumbers = Array.from(new Set([...existing.lineNumbers, ...item.lineNumbers])).sort((a, b) => a - b);
    existing.line = existing.lineNumbers[0];
    if (item.severity === 'CRITICAL' || (item.severity === 'HIGH' && existing.severity !== 'CRITICAL')) existing.severity = item.severity;
  });
  deduped.forEach(item => { delete item.secretHash; });

  return {
    scanId: rawInput.scanId || null,
    repoName: rawInput.repoName || 'Scanned Repository',
    source: rawInput.source || 'direct',
    generatedAt: rawInput.generatedAt || new Date().toISOString(),
    inScope: deduped,
    safeExcluded
  };
}

function buildRecommendationResults(items, sandboxDir, zipEntriesMap = {}) {
  const secretAssignments = /(?:api[_-]?key|apikey|secret(?:[_-]?key)?|password|private[_-]?key|token|auth[_-]?key|access[_-]?key)\s*[:=]\s*(['"])([^'"\r\n]{4,})\1/ig;
  const groups = new Map();
  const prepared = [];

  for (const item of items) {
    const relPath = String(item.filePath || '').replace(/\\/g, '/');
    const rootPath = fs.realpathSync(sandboxDir);
    const absolutePath = path.resolve(rootPath, relPath);
    const sourcePath = fs.existsSync(absolutePath) ? fs.realpathSync(absolutePath) : null;
    const sourceRelativePath = sourcePath ? path.relative(rootPath, sourcePath) : '';
    const safePath = Boolean(sourcePath && sourceRelativePath && sourceRelativePath !== '..' && !sourceRelativePath.startsWith(`..${path.sep}`) && !path.isAbsolute(sourceRelativePath));
    const zipSource = zipEntriesMap[relPath] ?? zipEntriesMap[relPath.replace(/\//g, path.sep)];
    const source = zipSource !== undefined
      ? zipSource
      : (safePath && fs.statSync(sourcePath).isFile() ? fs.readFileSync(sourcePath, 'utf8') : null);
    let groupKey = null;
    let secretHashPrefix = item.secretHashPrefix || null;

    if (source && item.remediationClass === 'SECRET_HYGIENE') {
      const sourceLines = source.split(/\r?\n/);
      for (const lineNumber of item.lineNumbers || [item.line]) {
        const rawLine = sourceLines[lineNumber - 1] || '';
        secretAssignments.lastIndex = 0;
        const match = secretAssignments.exec(rawLine);
        if (!match) continue;
        const digest = crypto.createHash('sha256').update(match[2]).digest('hex');
        secretHashPrefix = digest.slice(0, 8);
        groupKey = `${relPath.toLowerCase()}:${digest}`;
        break;
      }
    }

    if (groupKey && groups.has(groupKey)) {
      const existing = groups.get(groupKey);
      existing.item.lineNumbers = Array.from(new Set([...existing.item.lineNumbers, ...(item.lineNumbers || [item.line])])).sort((a, b) => a - b);
      existing.item.line = existing.item.lineNumbers[0];
      existing.item.secretHashPrefix = secretHashPrefix;
      existing.whyPanel.found = `Found ${existing.item.currentAlgorithm} at ${existing.item.filePath}:${existing.item.lineNumbers.join(', ')}`;
      existing.whyPanel.whatChanged[0] = `Original lines ${existing.item.lineNumbers.join(', ')}: remove the exposed assignment and rotate the leaked value.`;
      existing.evidence.beforeSnippet = `Original lines ${existing.item.lineNumbers.join(', ')} · secret redacted${secretHashPrefix ? ` · sha256:${secretHashPrefix}` : ''}`;
      continue;
    }

    const context = source && Number.isInteger(item.line) ? extractRealCodeContext(relPath, item.line, source) : null;
    const generated = Number.isInteger(item.line)
      ? generateRealAfterCode(item, context || { language: item.language }, false)
      : { afterDisplay: '', afterRaw: '' };
    const whyPanel = buildWhyThisChangePanel(item, context || {}, generated);
    const reason = source
      ? 'Recommendation preview only. It has not been applied to the scanned repository, so build, runtime, tamper, and rescan checks are not verified.'
      : 'Repository source for this finding is unavailable to the sandbox. No source-based checks were run.';
    const evidence = {
      compilePassed: null,
      functionalPassed: null,
      tamperPassed: null,
      rescanPassed: null,
      beforeSnippet: item.remediationClass === 'SECRET_HYGIENE'
        ? `Original ${lineLabel(item)} · secret redacted${secretHashPrefix ? ` · sha256:${secretHashPrefix}` : ''}`
        : (context?.beforeMasked || 'Source snippet not available in the sandbox'),
      afterSnippet: generated.afterDisplay || generated.afterRaw || '',
      checks: whyPanel.checks.map(name => ({ name, status: 'NOT_VERIFIED', reason })),
      rawLogs: []
    };
    const result = {
      migrationId: item.id,
      item: { ...item, secretHashPrefix },
      verificationStatus: 'NOT_TESTABLE',
      unavailReason: reason,
      evidence,
      whyPanel
    };
    prepared.push(result);
    if (groupKey) groups.set(groupKey, result);
  }

  return prepared;
}

// ── 9. Rescan Quantum Readiness Computation ─────────────────────────────────
function computeQuantumReadiness(inScope, safeExcluded, approvedSet = new Set(), results = []) {
  void inScope;
  void safeExcluded;
  void approvedSet;
  void results;
  return {
    currentPct: null,
    afterApprovedPct: null,
    projectedPct: null,
    reason: 'A CBOM inventory and verified applied migrations are required to compute quantum readiness.'
  };
}

function pqcSchemeForReplacement(replacement) {
  const normalized = String(replacement || '').toLowerCase();
  if (/ml-kem[- ]?768|kyber[- ]?768/.test(normalized)) return { kind: 'kem', name: 'ML-KEM-768' };
  if (/ml-dsa[- ]?65|dilithium[- ]?3/.test(normalized)) return { kind: 'signature', name: 'ML-DSA-65' };
  if (/slh-dsa.*128s/.test(normalized)) return { kind: 'signature', name: 'SLH-DSA-SHA2-128s' };
  return null;
}

function runOqsProbe(scheme) {
  const { execFile } = require('child_process');
  const safeEnvironment = {};
  ['PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'].forEach(key => {
    if (process.env[key]) safeEnvironment[key] = process.env[key];
  });
  const script = scheme.kind === 'kem'
    ? `import json, oqs\nfrom importlib.metadata import version, PackageNotFoundError\ntry: package = version("liboqs-python")\nexcept PackageNotFoundError: package = "unknown"\nwith oqs.KeyEncapsulation(${JSON.stringify(scheme.name)}) as kem:\n    public_key = kem.generate_keypair()\n    ciphertext, sender = kem.encap_secret(public_key)\n    receiver = kem.decap_secret(ciphertext)\n    tampered = bytearray(ciphertext); tampered[0] ^= 1\n    try: tampered_secret = kem.decap_secret(bytes(tampered)); rejected = tampered_secret != sender\n    except Exception: rejected = True\nprint(json.dumps({"roundTrip": sender == receiver, "tamperRejected": rejected, "library": "liboqs-python", "version": package}))`
    : `import json, oqs\nfrom importlib.metadata import version, PackageNotFoundError\ntry: package = version("liboqs-python")\nexcept PackageNotFoundError: package = "unknown"\nmessage = b"CryptoScan assurance self-test"\nwith oqs.Signature(${JSON.stringify(scheme.name)}) as signer:\n    public_key = signer.generate_keypair()\n    signature = signer.sign(message)\n    valid = signer.verify(message, signature, public_key)\n    tampered = bytearray(signature); tampered[0] ^= 1\n    rejected = not signer.verify(message, bytes(tampered), public_key)\nprint(json.dumps({"roundTrip": valid, "tamperRejected": rejected, "library": "liboqs-python", "version": package}))`;

  return new Promise(resolve => {
    execFile('python', ['-c', script], { timeout: 8000, encoding: 'utf8', env: safeEnvironment, maxBuffer: 16 * 1024 }, (error, stdout, stderr) => {
      if (error) {
        resolve({ available: false, reason: error.code === 'ENOENT' ? 'Python runtime is unavailable.' : (stderr || error.message).trim() });
        return;
      }
      try {
        resolve({ available: true, ...JSON.parse(stdout.trim()) });
      } catch (parseError) {
        resolve({ available: false, reason: `PQC provider returned invalid probe output: ${parseError.message}` });
      }
    });
  });
}

async function runAssuranceChecks(input, onProgress = () => {}) {
  const remediationClass = classifyMigration(input.algorithm, input.purpose);
  const checkNames = remediationClass === 'SECRET_HYGIENE'
    ? ['Build', 'Run-with-env', 'Missing-var-raises', 'Rescan']
    : remediationClass === 'SYMMETRIC_HASH_UPGRADE'
      ? ['Cryptographic hash known-answer test', 'Digest length / encoding contract', 'Collision-resistance assessment', 'Library / version / constant-time claim', 'Rescan']
    : ['Known-answer test against official vectors', 'Round-trip', 'Tamper rejection', 'Library / version / constant-time claim', 'Rescan of migrated code'];
  const checks = checkNames.map(name => ({ name, status: 'PENDING', reason: 'Not run yet.' }));
  const state = {
    status: 'RUNNING',
    checks,
    updatedAt: new Date().toISOString()
  };
  if (remediationClass !== 'SECRET_HYGIENE') {
    state.library = { name: 'Node.js crypto / OpenSSL', version: `${process.version} / OpenSSL ${process.versions.openssl}`, constantTime: 'Not verified for the complete application path' };
  }
  const update = (index, status, reason, durationMs, rawLog) => {
    checks[index] = { ...checks[index], status, reason, durationMs, timestamp: new Date().toISOString(), rawLog: rawLog || '' };
    state.updatedAt = new Date().toISOString();
    onProgress({ ...state, checks: checks.map(check => ({ ...check })) });
  };
  const markNotApplicable = (index, reason) => update(index, 'NOT_APPLICABLE', reason, 0, reason);

  if (remediationClass === 'SECRET_HYGIENE') {
    update(0, 'NOT_VERIFIED', 'Build was not run: this recommendation has not been applied to the target project.', 0, 'No migrated project build was available.');
    update(1, 'NOT_VERIFIED', 'Run-with-env was not run against the target application.', 0, 'No migrated project runtime was available.');
    update(2, 'NOT_VERIFIED', 'Missing-var-raises was not tested against the target application startup path.', 0, 'No migrated project runtime was available.');
    update(3, 'NOT_VERIFIED', 'The repository has not been rescanned after applying the secret-hygiene change.', 0, 'Rescan not run: no migration patch was applied.');
  } else if (remediationClass === 'PQC_REPLACEMENT') {
    update(0, 'NOT_VERIFIED', 'Official ACVP/KAT vectors for the selected PQC parameter set are not bundled with this service; no KAT result is claimed.', 0, 'No official KAT vector set was available to execute.');
    const scheme = pqcSchemeForReplacement(input.replacement);
    if (!scheme) {
      update(1, 'NOT_VERIFIED', 'The recommendation does not select one exact parameter set/provider API; choose and install a supported implementation before testing.', 0, 'No PQC scheme selected.');
      update(2, 'NOT_VERIFIED', 'Tamper rejection was not tested because no exact supported PQC scheme/provider is available.', 0, 'No PQC scheme selected.');
    } else {
      const startedAt = Date.now();
      const probe = await runOqsProbe(scheme);
      const elapsed = Date.now() - startedAt;
      if (!probe.available) {
        update(1, 'NOT_VERIFIED', `No executable ${scheme.name} round-trip check: ${probe.reason}`, elapsed, probe.reason);
        update(2, 'NOT_VERIFIED', 'No executable tamper check was available for this selected PQC scheme.', elapsed, probe.reason);
      } else {
        state.library = { name: probe.library, version: probe.version, constantTime: 'Not asserted by this runtime probe; verify provider documentation and validation status' };
        update(1, probe.roundTrip ? 'PASS' : 'FAIL', probe.roundTrip ? `${scheme.name} key generation and ${scheme.kind === 'kem' ? 'encapsulation/decapsulation' : 'sign/verify'} completed and matched.` : `${scheme.name} round-trip mismatch.`, elapsed, JSON.stringify({ scheme: scheme.name, roundTrip: probe.roundTrip }));
        update(2, probe.tamperRejected ? 'PASS' : 'FAIL', probe.tamperRejected ? 'A one-bit-modified ciphertext/signature was rejected or produced a different KEM secret.' : 'A one-bit-modified ciphertext/signature was not rejected.', elapsed, JSON.stringify({ scheme: scheme.name, tamperRejected: probe.tamperRejected }));
        update(3, 'PASS', `Backend provider loaded: ${probe.library} ${probe.version}. Constant-time behavior is not asserted.`, elapsed, `${probe.library} ${probe.version}`);
      }
    }
    update(3, state.library.name === 'Node.js crypto / OpenSSL' ? 'NOT_VERIFIED' : checks[3].status, state.library.name === 'Node.js crypto / OpenSSL' ? 'The backend runtime version is known, but PQC provider availability and constant-time behavior were not verified.' : checks[3].reason, 0, `${process.version}; OpenSSL ${process.versions.openssl}`);
  } else {
    const hashTarget = /sha-?256|sha3-?256/i.test(String(input.replacement || ''));
    if (hashTarget) {
      const startedAt = Date.now();
      const sha256Digest = crypto.createHash('sha256').update('abc').digest('hex');
      const sha3Digest = crypto.createHash('sha3-256').update('abc').digest('hex');
      const elapsed = Date.now() - startedAt;
      const expectedSha256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
      const expectedSha3 = '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532';
      const passed = sha256Digest === expectedSha256 && sha3Digest === expectedSha3;
      update(0, passed ? 'PASS' : 'FAIL', passed ? 'SHA-256 and SHA3-256 known-answer checks for the standard "abc" vectors matched.' : 'At least one SHA-2/SHA-3 known-answer check did not match.', elapsed, `sha256=${sha256Digest}\nsha3-256=${sha3Digest}`);
      markNotApplicable(1, 'Hash functions do not have an encrypt/decrypt or sign/verify round-trip.');
      markNotApplicable(2, 'Hash functions do not provide authenticated tamper rejection.');
    } else {
      update(0, 'NOT_VERIFIED', 'No official KAT vector for the selected symmetric parameter set was executed by this check.', 0, 'No KAT vector selected.');
      if (/aes-?256[- ]?gcm/i.test(String(input.replacement || ''))) {
        const key = crypto.randomBytes(32);
        const nonce = crypto.randomBytes(12);
        const plaintext = Buffer.from('CryptoScan assurance self-test');
        const startRoundTrip = Date.now();
        try {
          const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
          const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
          const tag = cipher.getAuthTag();
          const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
          decipher.setAuthTag(tag);
          const recovered = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
          const roundTripPassed = recovered.equals(plaintext);
          update(1, roundTripPassed ? 'PASS' : 'FAIL', roundTripPassed ? 'AES-256-GCM self-test round-trip matched.' : 'AES-256-GCM self-test round-trip mismatch.', Date.now() - startRoundTrip, `roundTrip=${roundTripPassed}`);
          const tampered = Buffer.from(ciphertext);
          if (tampered.length) tampered[0] ^= 1;
          const startTamper = Date.now();
          let rejected = false;
          try {
            const tamperDecipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
            tamperDecipher.setAuthTag(tag);
            tamperDecipher.update(tampered);
            tamperDecipher.final();
          } catch (_) { rejected = true; }
          update(2, rejected ? 'PASS' : 'FAIL', rejected ? 'AES-GCM rejected a one-bit-modified ciphertext.' : 'AES-GCM accepted a modified ciphertext.', Date.now() - startTamper, `tamperRejected=${rejected}`);
        } catch (error) {
          update(1, 'FAIL', `AES-256-GCM check failed: ${error.message}`, Date.now() - startRoundTrip, error.message);
          update(2, 'NOT_VERIFIED', 'Tamper check was not run because the round-trip setup failed.', 0, error.message);
        }
      } else {
        update(1, 'NOT_VERIFIED', 'The backend check does not implement a round-trip for the selected replacement.', 0, 'Selected implementation not supported by this probe.');
        update(2, 'NOT_VERIFIED', 'The backend check does not implement tamper validation for the selected replacement.', 0, 'Selected implementation not supported by this probe.');
      }
    }
    update(3, 'PASS', `Backend runtime: ${process.version} / OpenSSL ${process.versions.openssl}. Constant-time behavior for the full application path is not verified.`, 0, `${process.version}; OpenSSL ${process.versions.openssl}`);
  }

  if (remediationClass !== 'SECRET_HYGIENE') {
    update(4, 'NOT_VERIFIED', 'This recommendation has not been applied to a migrated source tree; the original scan remains unchanged.', 0, 'Rescan not run: no migration patch was applied.');
  }
  state.status = 'DONE';
  state.updatedAt = new Date().toISOString();
  return { ...state, checks: checks.map(check => ({ ...check })) };
}

// ── 11. Main Run CryptoTwin Sandbox Entry ────────────────────────────────────
async function runCryptoTwin(rawInput, opts = {}) {
  const norm = normaliseInput(rawInput);
  const sandboxDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptotwin-'));

  try {
    if (opts.sandboxDir && fs.existsSync(opts.sandboxDir)) {
      fs.cpSync(opts.sandboxDir, sandboxDir, { recursive: true });
    }

    const zipEntriesMap = {};


    if (opts.zipBuffer) {
      const zip = new AdmZip(opts.zipBuffer);
      zip.getEntries().forEach(entry => {
        if (!entry.isDirectory) {
          zipEntriesMap[entry.entryName] = entry.getData().toString('utf8');
        }
      });
    }

    const migrationResults = buildRecommendationResults(norm.inScope, sandboxDir, zipEntriesMap);
    const readiness = computeQuantumReadiness(norm.inScope, norm.safeExcluded, new Set(), migrationResults);

    try { fs.rmSync(sandboxDir, { recursive: true, force: true }); } catch (_) {}

    return {
      status: 'DONE',
      scanId: norm.scanId,
      repoName: norm.repoName,
      source: norm.source,
      generatedAt: norm.generatedAt,
      summary: {
        inScopeCount: norm.inScope.length,
        excludedCount: norm.safeExcluded.length,
        verifiedCount: migrationResults.filter(r => r.verificationStatus === 'VERIFIED').length,
        failedCount: migrationResults.filter(r => r.verificationStatus === 'FAILED').length,
        manualCount: migrationResults.filter(r => r.verificationStatus === 'MANUAL').length,
        notTestableCount: migrationResults.filter(r => r.verificationStatus === 'NOT_TESTABLE').length,
        readinessCurrent: readiness.currentPct,
        readinessAfterApproved: readiness.afterApprovedPct,
        readinessProjected: readiness.projectedPct
      },
      migrations: migrationResults,
      safeExcluded: norm.safeExcluded
    };
  } catch (err) {
    try { fs.rmSync(sandboxDir, { recursive: true, force: true }); } catch (_) {}
    throw err;
  }
}

// ── 12. Generate Updated Application ─────────────────────────────────────────
function generateUpdatedApplication(originalZipBuffer, approvedMigrationIds, migrationResults) {
  const zip = new AdmZip(originalZipBuffer || undefined);
  const approvedMap = new Set(approvedMigrationIds || []);

  const appliedDiffs = [];

  migrationResults.forEach(res => {
    if (approvedMap.has(res.migrationId) && res.verificationStatus === 'VERIFIED') {
      appliedDiffs.push({
        file: res.item.filePath,
        before: res.evidence.beforeSnippet,
        after: res.evidence.afterSnippet
      });
    }
  });

  const patchText = appliedDiffs.length > 0 
    ? appliedDiffs.map(d => `--- a/${d.file}\n+++ b/${d.file}\n${d.before}\n${d.after}`).join('\n\n')
    : '# No approved migrations applied.';

  return {
    updatedZipBuffer: zip.toBuffer(),
    diffText: patchText,
    approvedCount: appliedDiffs.length,
    generatedAt: new Date().toISOString()
  };
}

module.exports = {
  runCryptoTwin,
  runAssuranceChecks,
  normaliseInput,
  classifyMigration,
  deriveTargetAlgorithm,
  extractRealCodeContext,
  generateRealAfterCode,
  buildWhyThisChangePanel,
  checkFakeDiff,
  maskSecretsInText,
  runRealProcess,
  computeQuantumReadiness,
  generateUpdatedApplication
};
