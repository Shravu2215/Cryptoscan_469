/**
 * Vulnerability scoring — deterministic, explainable, 0-100.
 *
 * score = 0.40 * quantumVulnerability
 *       + 0.30 * keyStrength
 *       + 0.20 * classicalDeprecation
 *       + 0.10 * usageCriticality
 *
 * Every sub-score is a documented lookup/formula below — nothing here is
 * Math.random(). Weights are tunable in WEIGHTS if the team wants to
 * re-balance during the hackathon; keep them summing to 1.0.
 */

const WEIGHTS = {
  quantumVulnerability: 0.4,
  keyStrength: 0.3,
  classicalDeprecation: 0.2,
  usageCriticality: 0.1,
};

// --- 1. Quantum vulnerability -------------------------------------------
// Asymmetric primitives broken outright by Shor's algorithm score highest.
// Symmetric/hash primitives are only weakened by Grover's algorithm
// (quadratic speed-up => effective security roughly halved), so their
// score depends on whether the *remaining* effective strength is still
// adequate.
function quantumVulnerabilityScore(primitive, keySize) {
  const p = primitive.toUpperCase();

  if (['RSA', 'ECC', 'ECDSA', 'ECDH', 'DSA', 'DH', 'EDDSA'].includes(p)) {
    return 100; // fully broken given a cryptographically relevant quantum computer
  }
  if (p === 'AES') {
    if (!keySize || keySize < 192) return 60; // effective ~64-bit under Grover: weak
    if (keySize < 256) return 40; // effective ~96-bit: marginal
    return 20; // AES-256 -> effective ~128-bit: adequate
  }
  if (p === 'CHACHA20') return 20; // 256-bit key, same margin as AES-256
  if (['DES', '3DES', 'RC4'].includes(p)) return 100; // broken classically; quantum is moot
  if (['SHA-256', 'SHA256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-512'].includes(p)) return 15;
  if (['MD5', 'SHA1', 'SHA-1'].includes(p)) return 100; // classically broken already
  return 50; // unrecognized primitive: assume moderate risk pending manual review
}

// --- 2. Key strength ------------------------------------------------------
// How far below current NIST-recommended minimums the observed key/curve
// size is. 0 = meets or exceeds long-term recommendation.
function keyStrengthScore(primitive, keySize) {
  const p = primitive.toUpperCase();
  if (!keySize) return 50; // unknown key size can't be verified as safe

  if (p === 'RSA' || p === 'DSA' || p === 'DH') {
    if (keySize < 2048) return 90;
    if (keySize < 3072) return 55;
    if (keySize < 4096) return 35;
    return 20;
  }
  if (['ECC', 'ECDSA', 'ECDH', 'EDDSA'].includes(p)) {
    if (keySize < 256) return 80;
    if (keySize < 384) return 45;
    return 25;
  }
  if (p === 'AES') {
    if (keySize < 128) return 100;
    if (keySize < 192) return 50;
    if (keySize < 256) return 30;
    return 10;
  }
  if (['DES', '3DES', 'RC4', 'RC2'].includes(p)) return 100; // any key size here is already inadequate
  return 30; // primitive without a defined key-size policy here
}

// --- 3. Classical deprecation ---------------------------------------------
// Algorithms/modes that are unsafe today, independent of quantum computing.
const DEPRECATED_TABLE = {
  MD5: 100,
  SHA1: 90,
  'SHA-1': 90,
  DES: 100,
  '3DES': 80,
  RC4: 100,
  RC2: 90,
  ECB: 70, // mode, not primitive; scanner may report mode separately
};

function classicalDeprecationScore(primitive, mode) {
  const p = primitive.toUpperCase();
  let score = DEPRECATED_TABLE[p] || 0;
  if (mode && DEPRECATED_TABLE[mode.toUpperCase()] !== undefined) {
    score = Math.max(score, DEPRECATED_TABLE[mode.toUpperCase()]);
  }
  return score;
}

// --- 4. Usage criticality --------------------------------------------------
// The same weak algorithm is worse if it protects authentication/signing
// than if it's used somewhere low-stakes.
const USAGE_CRITICALITY = {
  key_exchange: 90,
  digital_signature: 90,
  password_hashing: 85,
  data_encryption: 80,
  mac: 60,
  random_generation: 70,
  integrity_hashing: 55,
  unknown: 50,
};

function usageCriticalityScore(purpose) {
  return USAGE_CRITICALITY[purpose] ?? USAGE_CRITICALITY.unknown;
}

function severityLabel(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'info';
}

// --- 5. HNDL ("Harvest Now, Decrypt Later") exposure model ----------------
// A finding protecting long-lived data is riskier than the same finding
// protecting ephemeral data: an attacker can record ciphertext today and
// decrypt it once a cryptographically-relevant quantum computer exists.
//
// - MIGRATION_TIME_YEARS: realistic time to plan + execute a migration once
//   started (audit, dual-run, cutover).
// - QUANTUM_THREAT_HORIZON_YEARS: conservative industry estimate of when a
//   cryptographically-relevant quantum computer could arrive.
// If (dataLifetime + migrationTime) still exceeds the threat horizon, the
// data is exposed for that many years after the threat materializes.
const DEFAULT_DATA_LIFETIME_YEARS = 10;
const MIGRATION_TIME_YEARS = 3;
const QUANTUM_THREAT_HORIZON_YEARS = 7;

/**
 * Normalizes a caller-supplied data lifetime (years) to a safe numeric value.
 * Missing/invalid input falls back to a conservative default so risk is
 * never silently underestimated.
 *
 * @param {number|undefined} years
 * @returns {{ value: number, isDefault: boolean }}
 */
function normalizeDataLifetime(years) {
  if (typeof years !== 'number' || Number.isNaN(years) || years < 0) {
    return { value: DEFAULT_DATA_LIFETIME_YEARS, isDefault: true };
  }
  return { value: years, isDefault: false };
}

/**
 * How many years past the projected quantum-threat horizon this data
 * remains exposed, given how long it lives and how long migration takes.
 * Clamped to 0 — data that's rotated/expired well before the threat
 * horizon has no HNDL exposure window.
 *
 * @param {{value:number}|number} normalizedLifetime - result of normalizeDataLifetime(), or a raw year count
 * @returns {number} exposure window in years (>= 0)
 */
function calculateQuantumExposureWindow(normalizedLifetime) {
  const years = (normalizedLifetime && typeof normalizedLifetime === 'object')
    ? normalizedLifetime.value
    : normalizedLifetime;
  const window = (years ?? DEFAULT_DATA_LIFETIME_YEARS) + MIGRATION_TIME_YEARS - QUANTUM_THREAT_HORIZON_YEARS;
  return Math.max(0, window);
}

/**
 * Scales a primitive's base quantum-vulnerability score by how long its
 * exposure window is, so two equally-broken primitives are differentiated
 * by how much HNDL risk they actually carry.
 *
 * @param {number} baseQuantumVulnerability - 0-100, from quantumVulnerabilityScore()
 * @param {number} exposureWindowYears - from calculateQuantumExposureWindow()
 * @returns {number} 0-100 HNDL exposure score
 */
function quantumExposureScore(baseQuantumVulnerability, exposureWindowYears) {
  if (!baseQuantumVulnerability || baseQuantumVulnerability <= 0) return 0;
  const scaled = Math.min(100, Math.max(0, exposureWindowYears) * 10);
  return Math.round((scaled * baseQuantumVulnerability) / 100);
}

// --- 6. Business-context multiplier ----------------------------------------
// The same technical risk matters more against critical business assets.
const BUSINESS_IMPORTANCE_MULTIPLIERS = {
  Critical: 1.25,
  High: 1.15,
  Medium: 1.0,
  Low: 0.9,
};
const DEFAULT_BUSINESS_MULTIPLIER = 1.0;

/**
 * @param {{primitive:string, keySize?:number, mode?:string}} finding
 * @param {string} purpose - output of purposeDetection.detectPurpose(...).purpose
 * @param {object} [options={}]
 * @param {number} [options.dataLifetime] - expected data lifetime in years (HNDL)
 * @param {string} [options.businessImportance] - e.g. 'Critical' | 'High' | 'Medium' | 'Low'
 */
function scoreFinding(finding, purpose, options = {}) {
  const quantumVulnerability = quantumVulnerabilityScore(finding.primitive, finding.keySize);
  const keyStrength = keyStrengthScore(finding.primitive, finding.keySize);
  const classicalDeprecation = classicalDeprecationScore(finding.primitive, finding.mode);
  const usageCriticality = usageCriticalityScore(purpose);

  const raw =
    quantumVulnerability * WEIGHTS.quantumVulnerability +
    keyStrength * WEIGHTS.keyStrength +
    classicalDeprecation * WEIGHTS.classicalDeprecation +
    usageCriticality * WEIGHTS.usageCriticality;

  const score = Math.round(Math.min(100, Math.max(0, raw)));

  // HNDL exposure folded into a pre-business-context risk score.
  let normLifetime = normalizeDataLifetime(options.dataLifetime);
  if (normLifetime.isDefault && finding) {
    const { detectDataSensitivity } = require('./purposeDetection');
    if (detectDataSensitivity) {
      const { recommendedLifetimeYears } = detectDataSensitivity(finding);
      if (recommendedLifetimeYears) {
        normLifetime.value = recommendedLifetimeYears;
        normLifetime.isDefault = false;
      }
    }
  }
  const exposureWindow = calculateQuantumExposureWindow(normLifetime);
  const exposureBonus = quantumExposureScore(quantumVulnerability, exposureWindow);
  const preBusinessRiskScore = Math.round(Math.min(100, Math.max(0, score * 0.7 + exposureBonus * 0.3)));

  const appliedMultiplier = BUSINESS_IMPORTANCE_MULTIPLIERS[options.businessImportance] ?? DEFAULT_BUSINESS_MULTIPLIER;
  const businessAdjustedRiskScore = Math.round(Math.min(100, preBusinessRiskScore * appliedMultiplier));

  return {
    score,
    severity: severityLabel(score),
    breakdown: { quantumVulnerability, keyStrength, classicalDeprecation, usageCriticality },
    weights: WEIGHTS,
    preBusinessRiskScore,
    businessAdjustedRiskScore,
    appliedMultiplier,
  };
}

// --- 7. Quantum Classification & Mosca Model (P0-5) --------------------------

/**
 * Z Presets: Years until Cryptographically Relevant Quantum Computer (CRQC).
 * Presets named by arrival timeline meaning.
 */
const Z_PRESETS = {
  early: {
    years: 7,
    label: 'Early Quantum Computer',
    // Source in repo: backend-core/src/services/vulnScoring.js:134 and cbom-service HNDL_CONFIG.crqcHorizonYears (conservative industry estimate of when a cryptographically-relevant quantum computer could arrive)
    source: 'source in repo: backend-core/src/services/vulnScoring.js:134 and cbom-service HNDL_CONFIG.crqcHorizonYears (conservative industry estimate of when a cryptographically-relevant quantum computer could arrive)',
  },
  median: {
    years: 12,
    label: 'Median Quantum Computer',
    // Source: Global Risk Institute consensus estimate / default in CryptoEngine
    source: 'source to confirm',
  },
  late: {
    years: 20,
    label: 'Late Quantum Computer',
    // Source: Conservative timeline for fault-tolerant scaled quantum computer
    source: 'source to confirm',
  },
};

const DEFAULT_Z_YEARS = 12;

function getZPreset(presetName) {
  if (!presetName) return Z_PRESETS.median;
  const key = String(presetName).toLowerCase().trim();
  return Z_PRESETS[key] || Z_PRESETS.median;
}

/**
 * Extracts algorithm key size safely WITHOUT relying on scans.js line 91
 * which misidentified hashes (e.g. SHA-256) as 256-bit keys.
 */
function extractAlgorithmKeySize(finding) {
  const algo = (finding.algorithm || finding.primitive || '').toUpperCase();
  // Never treat hash outputs as key sizes
  if (algo.includes('SHA') || algo.includes('MD5') || algo.includes('RIPEMD') || algo.includes('BLAKE')) {
    return null;
  }
  if (typeof finding.keySize === 'number' && finding.keySize > 0) {
    return finding.keySize;
  }
  if (typeof finding.key_size === 'number' && finding.key_size > 0) {
    return finding.key_size;
  }
  const text = `${algo} ${finding.description || ''} ${finding.title || ''}`;
  const match = text.match(/\b(128|192|256|512|1024|2048|3072|4096|8192)\b/);
  if (match) {
    return parseInt(match[1], 10);
  }
  return null;
}

/**
 * Classifies a finding into one of four quantum risk classes:
 * - 'broken': RSA, DSA, DH, ECC family (ECDSA, ECDH, EdDSA)
 * - 'weakened': AES-128, short hashes
 * - 'resilient': AES-256, SHA-384 and above, ChaCha20, SHA-256, HMAC
 * - 'classical': hardcoded secrets, MD5, weak RNG, ECB mode, DES, 3DES, RC4
 */
function classifyQuantum(finding) {
  if (!finding) return 'classical';

  const algo = (finding.algorithm || finding.primitive || '').toUpperCase().trim();
  const title = (finding.title || '').toUpperCase();
  const desc = (finding.description || finding.message || '').toUpperCase();
  const rule = (finding.ruleId || finding.rule_id || '').toUpperCase();
  const mode = (finding.mode || '').toUpperCase();
  const fullText = `${algo} ${title} ${desc} ${rule} ${mode}`;

  // 1. Classical vulnerabilities (hardcoded secrets, weak RNG, ECB mode, classically broken algorithms)
  if (
    fullText.includes('SECRET') ||
    fullText.includes('HARDCODED') ||
    fullText.includes('PASSWORD') ||
    fullText.includes('API_KEY') ||
    fullText.includes('PRIVATE_KEY') ||
    fullText.includes('MATH.RANDOM') ||
    fullText.includes('WEAK RNG') ||
    rule.includes('SECRET') ||
    rule.includes('RANDOM')
  ) {
    return 'classical';
  }

  if (mode === 'ECB' || fullText.includes('ECB MODE') || algo.includes('ECB')) {
    return 'classical';
  }

  if (
    algo.includes('MD5') ||
    algo.includes('SHA1') ||
    algo.includes('SHA-1') ||
    algo.includes('DES') ||
    algo.includes('3DES') ||
    algo.includes('TRIPLE-DES') ||
    algo.includes('RC4') ||
    algo.includes('RC2') ||
    algo.includes('BLOWFISH')
  ) {
    return 'classical';
  }

  // 2. Broken by Shor's algorithm (asymmetric cryptography)
  if (
    algo.includes('RSA') ||
    algo.includes('DSA') ||
    algo === 'DH' ||
    algo.includes('DIFFIE-HELLMAN') ||
    algo.includes('ECDSA') ||
    algo.includes('ECDH') ||
    algo.includes('EDDSA') ||
    algo.includes('ED25519') ||
    algo.includes('CURVE25519') ||
    algo.includes('SECP256') ||
    algo.includes('SECP384') ||
    algo.includes('SECP521') ||
    algo.includes('ECIES') ||
    algo === 'ECC' ||
    (algo.includes('ECC') && !algo.includes('AES'))
  ) {
    return 'broken';
  }

  // 3. Resilient primitives (NIST post-quantum standards, 256-bit symmetric, SHA-256, HMAC, SHA-384+, ChaCha20)
  // Post-quantum primitives
  if (
    algo.includes('ML-KEM') || algo.includes('MLKEM') || algo.includes('KYBER') ||
    algo.includes('ML-DSA') || algo.includes('MLDSA') || algo.includes('DILITHIUM') ||
    algo.includes('SLH-DSA') || algo.includes('SLHDSA') || algo.includes('SPHINCS') ||
    algo.includes('FALCON') || algo.includes('XMSS') || algo.includes('LMS')
  ) {
    return 'resilient';
  }

  // SHA-256 and HMAC: confirmed resilient
  if (
    algo === 'SHA-256' || algo === 'SHA256' ||
    algo === 'SHA3-256' ||
    algo.startsWith('HMAC') || algo.includes('HMAC')
  ) {
    return 'resilient';
  }

  // SHA-384, SHA-512, SHA3-384, SHA3-512, SHAKE
  if (
    algo.includes('SHA-384') || algo.includes('SHA384') ||
    algo.includes('SHA-512') || algo.includes('SHA512') ||
    algo.includes('SHA3-384') || algo.includes('SHA3-512') ||
    algo.includes('SHAKE')
  ) {
    return 'resilient';
  }

  // ChaCha20
  if (algo.includes('CHACHA20') || algo.includes('CHACHA')) {
    return 'resilient';
  }

  // AES: check key size safely
  if (algo.includes('AES')) {
    const ks = extractAlgorithmKeySize(finding);
    if (ks === 256 || algo.includes('256')) {
      return 'resilient';
    }
    // AES-128 or AES-192 or unspecified key length: weakened under Grover
    return 'weakened';
  }

  // 4. Weakened primitives (short hashes, RIPEMD, SHA-224)
  if (algo.includes('SHA-224') || algo.includes('SHA224') || algo.includes('RIPEMD')) {
    return 'weakened';
  }

  // Default fallback based on quantumStatus if available
  const qStatus = (finding.quantumStatus || '').toLowerCase();
  if (qStatus.includes('broken')) return 'broken';
  if (qStatus.includes('weakened')) return 'weakened';
  if (qStatus.includes('safe') || qStatus.includes('resilient')) return 'resilient';

  return 'classical';
}

function estimateFindingLifetime(finding) {
  if (finding.user_confirmed_lifetime !== undefined && finding.user_confirmed_lifetime !== null && finding.user_confirmed_lifetime !== '') {
    const num = Number(finding.user_confirmed_lifetime);
    if (!isNaN(num) && num >= 0) return num;
  }
  if (finding.dataLifetime !== undefined && finding.dataLifetime !== null && finding.dataLifetime !== '') {
    const num = Number(finding.dataLifetime);
    if (!isNaN(num) && num >= 0) return num;
  }
  return 5.0; // default 5 years data retention
}

function estimateMigrationTime(finding) {
  if (finding.migrationTime !== undefined && finding.migrationTime !== null && finding.migrationTime !== '') {
    const num = Number(finding.migrationTime);
    if (!isNaN(num) && num > 0) return num;
  }
  const algo = (finding.algorithm || finding.primitive || '').toUpperCase();
  const file = (finding.filePath || finding.file || '').toLowerCase();
  const isComplex = finding.isComplex || file.includes('core') || file.includes('crypto') || algo.includes('RSA') || algo.includes('ECC') || algo.includes('DH');
  return isComplex ? 2.5 : 1.0;
}

/**
 * Computes Mosca inequality (X + Y > Z) and urgency metrics.
 * REQUIREMENT: Applied ONLY to broken and weakened findings.
 * Classical and resilient findings are NEVER run through Mosca.
 */
function computeFindingMosca(finding, zYears = DEFAULT_Z_YEARS, businessCriticality = 'MEDIUM') {
  const qClass = finding.quantum_class || classifyQuantum(finding);

  if (qClass !== 'broken' && qClass !== 'weakened') {
    return {
      quantum_class: qClass,
      mosca_applicable: false,
      X: null,
      Y: null,
      Z: Number(zYears) || DEFAULT_Z_YEARS,
      urgency_margin: null,
      mosca_at_risk: false,
      urgency_tier: null,
      priority_score: null,
    };
  }

  const Z = Number(zYears) || DEFAULT_Z_YEARS;
  const X = estimateFindingLifetime(finding);
  const Y = estimateMigrationTime(finding);
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
  const critMap = { CRITICAL: 4.0, HIGH: 3.0, MEDIUM: 2.0, LOW: 1.0 };
  const critWeight = critMap[(businessCriticality || finding.businessCriticality || 'MEDIUM').toUpperCase()] || 2.0;
  const priority_score = Math.round((tierWeights[urgency_tier] * critWeight) * 10) / 10;

  return {
    quantum_class: qClass,
    mosca_applicable: true,
    X,
    Y,
    Z,
    urgency_margin,
    mosca_at_risk,
    urgency_tier,
    priority_score,
  };
}

/**
 * Computes a single overall security posture verdict across findings.
 * Single source of truth from backend-core.
 */
function computeOverallPosture(findings, zYears = DEFAULT_Z_YEARS) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) {
    return {
      verdict: 'LOW',
      totalFindings: 0,
      brokenCount: 0,
      weakenedCount: 0,
      resilientCount: 0,
      classicalCount: 0,
      quantumVulnerableCount: 0,
    };
  }

  let brokenCount = 0;
  let weakenedCount = 0;
  let resilientCount = 0;
  let classicalCount = 0;
  let hasCriticalUrgency = false;
  let hasHighUrgency = false;
  let hasMediumUrgency = false;
  let hasClassicalCritical = false;
  let hasClassicalHigh = false;

  list.forEach(f => {
    const qClass = f.quantum_class || classifyQuantum(f);
    if (qClass === 'broken') brokenCount++;
    else if (qClass === 'weakened') weakenedCount++;
    else if (qClass === 'resilient') resilientCount++;
    else if (qClass === 'classical') classicalCount++;

    const m = (f.mosca && f.mosca.mosca_applicable !== undefined) ? f.mosca : computeFindingMosca(f, zYears, f.businessCriticality);
    if (m.mosca_applicable) {
      if (m.urgency_tier === 'Critical') hasCriticalUrgency = true;
      else if (m.urgency_tier === 'High') hasHighUrgency = true;
      else if (m.urgency_tier === 'Medium') hasMediumUrgency = true;
    } else if (qClass === 'classical') {
      const sev = (f.severity || '').toUpperCase();
      if (sev === 'CRITICAL') hasClassicalCritical = true;
      else if (sev === 'HIGH') hasClassicalHigh = true;
    }
  });

  const quantumVulnerableCount = brokenCount + weakenedCount;

  let verdict = 'LOW';
  if (hasCriticalUrgency || hasClassicalCritical) {
    verdict = 'CRITICAL';
  } else if (hasHighUrgency || hasClassicalHigh) {
    verdict = 'HIGH';
  } else if (hasMediumUrgency || quantumVulnerableCount > 0) {
    verdict = 'MEDIUM';
  }

  return {
    verdict,
    totalFindings: list.length,
    brokenCount,
    weakenedCount,
    resilientCount,
    classicalCount,
    quantumVulnerableCount,
  };
}

module.exports = {
  scoreFinding,
  severityLabel,
  normalizeDataLifetime,
  calculateQuantumExposureWindow,
  quantumExposureScore,
  classifyQuantum,
  computeFindingMosca,
  computeOverallPosture,
  Z_PRESETS,
  DEFAULT_Z_YEARS,
  getZPreset,
};

