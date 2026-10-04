/**
 * quantumRules.js - Single Source of Truth for Quantum Risk Classification
 *
 * Maps algorithm family to properties used across ALL CryptoScan pages.
 * Load this before engine.js, hndl.js, or any page script.
 *
 * DEFAULT_Z = 10 (years until CRQC, stored in localStorage key 'cs_global_z')
 * BUFFER_YEARS = 5 (safety margin for VULNERABLE_WITHIN_HORIZON category)
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.QuantumRules = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var DEFAULT_Z = 10;
  var BUFFER_YEARS = 5;
  var LS_KEY = 'cs_global_z';

  function getZ() {
    try {
      var saved = localStorage.getItem(LS_KEY);
      if (saved !== null && saved !== '') {
        var n = Number(saved);
        if (!isNaN(n) && n >= 1 && n <= 30) return n;
      }
    } catch (e) {}
    return DEFAULT_Z;
  }

  function setZ(val) {
    var n = Number(val);
    if (isNaN(n) || n < 1 || n > 30) return false;
    try { localStorage.setItem(LS_KEY, String(n)); } catch (e) {}
    try { window.dispatchEvent(new CustomEvent('zchange', { detail: { z: n } })); } catch (e) {}
    return true;
  }

  var PURPOSE_LIFETIME = {
    data_encryption: 20,
    key_exchange: 10,
    key_wrap: 10,
    tls: 10,
    password_hashing: 15,
    digital_signature: 5,
    code_signing: 5,
    certificate: 5,
    mac: 5,
    hmac: 5,
    integrity_hashing: 3,
    random_generation: 5,
    unknown: 10
  };

  // Algorithm rules: each entry covers one or more algorithm name prefixes.
  // quantumStatus: 'quantum-broken' | 'quantum-weakened' | 'quantum-safe' | 'classically-weak' | 'unclassified'
  // hndlApplies: 'confidentiality' (HNDL risk) | 'authenticity' (migrate before Z) | 'none'
  // shorBreakable: true = Shor's algorithm can break it (MUST migrate before CRQC)
  // classicallyWeak: true = broken by classical computers today (fix immediately, NOT a PQC migration)
  var RULES = [
    {
      families: ['RSA'],
      quantumStatus: 'quantum-broken',
      hndlApplies: 'confidentiality',
      shorBreakable: true,
      groverWeakened: false,
      classicallyWeak: false,
      replacement: 'ML-KEM (Kyber-768/1024) + Hybrid X25519/ML-KEM',
      defaultMigrationYears: 2.0,
      defaultDataLifetimeYears: 10
    },
    {
      families: ['ECDH', 'X25519', 'X448', 'DH', 'DIFFIE-HELLMAN', 'ELGAMAL'],
      quantumStatus: 'quantum-broken',
      hndlApplies: 'confidentiality',
      shorBreakable: true,
      groverWeakened: false,
      classicallyWeak: false,
      replacement: 'ML-KEM (Kyber-768/1024) or Hybrid X25519+ML-KEM',
      defaultMigrationYears: 1.5,
      defaultDataLifetimeYears: 10
    },
    {
      families: ['ECDSA', 'ED25519', 'ED448', 'DSA'],
      quantumStatus: 'quantum-broken',
      hndlApplies: 'authenticity',
      shorBreakable: true,
      groverWeakened: false,
      classicallyWeak: false,
      replacement: 'ML-DSA (Dilithium-3/5) or SLH-DSA (SPHINCS+)',
      defaultMigrationYears: 1.5,
      defaultDataLifetimeYears: 5
    },
    {
      families: ['ECC', 'EC'],
      quantumStatus: 'quantum-broken',
      hndlApplies: 'confidentiality',
      shorBreakable: true,
      groverWeakened: false,
      classicallyWeak: false,
      replacement: 'ML-KEM (Kyber-768/1024) or ML-DSA (Dilithium-3/5)',
      defaultMigrationYears: 2.0,
      defaultDataLifetimeYears: 10
    },
    {
      families: ['AES-128', 'AES128'],
      quantumStatus: 'quantum-weakened',
      hndlApplies: 'confidentiality',
      shorBreakable: false,
      groverWeakened: true,
      classicallyWeak: false,
      replacement: 'AES-256-GCM',
      defaultMigrationYears: 1.0,
      defaultDataLifetimeYears: 10
    },
    {
      families: ['SHA-1', 'SHA1'],
      quantumStatus: 'quantum-weakened',
      hndlApplies: 'authenticity',
      shorBreakable: false,
      groverWeakened: true,
      classicallyWeak: true,
      replacement: 'SHA-256 / SHA-3-256',
      defaultMigrationYears: 0.5,
      defaultDataLifetimeYears: 3
    },
    {
      families: ['MD5', 'MD4', 'MD2'],
      quantumStatus: 'classically-weak',
      hndlApplies: 'none',
      shorBreakable: false,
      groverWeakened: false,
      classicallyWeak: true,
      replacement: 'SHA-256 / SHA-3-256 / BLAKE3',
      defaultMigrationYears: 0.25,
      defaultDataLifetimeYears: 3
    },
    {
      families: ['DES', '3DES', 'TRIPLE-DES', 'TDES'],
      quantumStatus: 'classically-weak',
      hndlApplies: 'none',
      shorBreakable: false,
      groverWeakened: false,
      classicallyWeak: true,
      replacement: 'AES-256-GCM / ChaCha20-Poly1305',
      defaultMigrationYears: 0.5,
      defaultDataLifetimeYears: 5
    },
    {
      families: ['RC4', 'RC2', 'RC5', 'BLOWFISH', 'SKIPJACK'],
      quantumStatus: 'classically-weak',
      hndlApplies: 'none',
      shorBreakable: false,
      groverWeakened: false,
      classicallyWeak: true,
      replacement: 'AES-256-GCM / ChaCha20-Poly1305',
      defaultMigrationYears: 0.5,
      defaultDataLifetimeYears: 5
    },
    {
      families: ['HARDCODED-KEY', 'HARDCODED-SECRET', 'PLAINTEXT-KEY'],
      quantumStatus: 'classically-weak',
      hndlApplies: 'none',
      shorBreakable: false,
      groverWeakened: false,
      classicallyWeak: true,
      replacement: 'Secrets Manager / KMS / HashiCorp Vault',
      defaultMigrationYears: 0.25,
      defaultDataLifetimeYears: 1
    },
    {
      families: ['AES-ECB', 'ECB'],
      quantumStatus: 'classically-weak',
      hndlApplies: 'none',
      shorBreakable: false,
      groverWeakened: false,
      classicallyWeak: true,
      replacement: 'AES-256-GCM / AES-256-CBC with HMAC',
      defaultMigrationYears: 0.5,
      defaultDataLifetimeYears: 5
    },
    {
      families: ['AES-256', 'AES-192', 'AES256', 'AES192', 'AES-256-GCM', 'AES-256-CBC', 'CHACHA20', 'XCHACHA20'],
      quantumStatus: 'quantum-safe',
      hndlApplies: 'none',
      shorBreakable: false,
      groverWeakened: false,
      classicallyWeak: false,
      replacement: null,
      defaultMigrationYears: 0,
      defaultDataLifetimeYears: 10
    },
    {
      families: ['SHA-256', 'SHA-384', 'SHA-512', 'SHA256', 'SHA384', 'SHA512', 'SHA3-256', 'SHA3-512', 'SHA3', 'BLAKE2', 'BLAKE3'],
      quantumStatus: 'quantum-safe',
      hndlApplies: 'none',
      shorBreakable: false,
      groverWeakened: false,
      classicallyWeak: false,
      replacement: null,
      defaultMigrationYears: 0,
      defaultDataLifetimeYears: 5
    },
    {
      families: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'LMS', 'XMSS', 'FALCON', 'KYBER', 'DILITHIUM', 'SPHINCS'],
      quantumStatus: 'quantum-safe',
      hndlApplies: 'none',
      shorBreakable: false,
      groverWeakened: false,
      classicallyWeak: false,
      replacement: null,
      defaultMigrationYears: 0,
      defaultDataLifetimeYears: 10
    },
    {
      families: ['HMAC', 'ARGON2', 'BCRYPT', 'SCRYPT', 'PBKDF2'],
      quantumStatus: 'quantum-safe',
      hndlApplies: 'none',
      shorBreakable: false,
      groverWeakened: false,
      classicallyWeak: false,
      replacement: null,
      defaultMigrationYears: 0,
      defaultDataLifetimeYears: 10
    }
  ];

  function _unclassified() {
    return {
      matchedFamily: 'UNKNOWN',
      quantumStatus: 'unclassified',
      hndlApplies: 'confidentiality',
      shorBreakable: false,
      groverWeakened: false,
      classicallyWeak: false,
      replacement: 'Review algorithm classification',
      defaultMigrationYears: 1.5,
      defaultDataLifetimeYears: 10,
      confidence: 'low'
    };
  }

  function _clone(r, matchedFamily) {
    return {
      matchedFamily: matchedFamily,
      quantumStatus: r.quantumStatus,
      hndlApplies: r.hndlApplies,
      shorBreakable: !!r.shorBreakable,
      groverWeakened: !!r.groverWeakened,
      classicallyWeak: !!r.classicallyWeak,
      replacement: r.replacement,
      defaultMigrationYears: r.defaultMigrationYears,
      defaultDataLifetimeYears: r.defaultDataLifetimeYears,
      confidence: 'high'
    };
  }

  function lookup(algoName) {
    if (!algoName) return _unclassified();
    var upper = String(algoName).toUpperCase().replace(/\s+/g, '-');
    var i, j, r;
    // Exact match
    for (i = 0; i < RULES.length; i++) {
      r = RULES[i];
      for (j = 0; j < r.families.length; j++) {
        if (upper === r.families[j]) return _clone(r, r.families[j]);
      }
    }
    // Prefix / contains match
    for (i = 0; i < RULES.length; i++) {
      r = RULES[i];
      for (j = 0; j < r.families.length; j++) {
        if (upper.indexOf(r.families[j]) === 0 || upper.indexOf(r.families[j]) !== -1) {
          return _clone(r, r.families[j]);
        }
      }
    }
    if (upper.indexOf('HARDCODED') !== -1) {
      for (i = 0; i < RULES.length; i++) {
        if (RULES[i].families[0] === 'HARDCODED-KEY') return _clone(RULES[i], 'HARDCODED-KEY');
      }
    }
    return _unclassified();
  }

  function isQuantumVulnerable(finding) {
    if (!finding) return false;
    if (finding.quantum === 'yes' || finding.quantum === true) return true;
    if (finding.quantumVulnerable === true || finding.is_quantum_vulnerable === true) return true;
    var qs = (finding.quantumStatus || finding.quantum_status || '').toLowerCase();
    if (qs.indexOf('vulnerable') !== -1 || qs.indexOf('broken') !== -1) return true;
    var rule = lookup(finding.algorithm || finding.title || '');
    return rule.shorBreakable === true;
  }

  function isClassicallyWeak(finding) {
    if (!finding) return false;
    var rule = lookup(finding.algorithm || finding.title || '');
    return rule.classicallyWeak === true;
  }

  /**
   * classify(x, y, z) - Mosca's Inequality
   * X = data lifetime years, Y = migration time years, Z = years to CRQC
   * Returns { X, Y, Z, exposure, margin, category, label, message }
   *
   * VULNERABLE_NOW             : margin < 0   (X + Y > Z)
   * VULNERABLE_WITHIN_HORIZON  : 0 <= margin <= BUFFER_YEARS
   * SAFE_UNDER_CURRENT_TIMELINE: margin > BUFFER_YEARS
   */
  function classify(x, y, z) {
    var X = Math.max(0, Number(x) || 0);
    var Y = Math.max(0, Number(y) || 0);
    var Z = Math.max(1, Number(z) || getZ());
    var exposure = parseFloat((X + Y).toFixed(2));
    var margin = parseFloat((Z - exposure).toFixed(2));
    var category, label, message;
    if (margin < 0) {
      category = 'VULNERABLE_NOW';
      label = 'Vulnerable Now';
      message = 'X + Y (' + exposure.toFixed(1) + 'y) > Z (' + Z + 'y) \u2014 data will be at risk when CRQC arrives.';
    } else if (margin <= BUFFER_YEARS) {
      category = 'VULNERABLE_WITHIN_HORIZON';
      label = 'Vulnerable Within Horizon';
      message = 'Margin is only ' + margin.toFixed(1) + 'y \u2014 less than the ' + BUFFER_YEARS + 'y safety buffer. Start migration planning now.';
    } else {
      category = 'SAFE_UNDER_CURRENT_TIMELINE';
      label = 'Safe Under Current Timeline';
      message = 'Margin of ' + margin.toFixed(1) + 'y exceeds the ' + BUFFER_YEARS + 'y buffer. Monitor and plan lifecycle replacement.';
    }
    return { X: X, Y: Y, Z: Z, exposure: exposure, margin: margin, category: category, label: label, message: message };
  }

  function deriveX(finding) {
    if (!finding) return PURPOSE_LIFETIME.unknown;
    if (finding.user_confirmed_lifetime !== undefined && finding.user_confirmed_lifetime !== null && finding.user_confirmed_lifetime !== '') {
      return Math.max(0.5, Number(finding.user_confirmed_lifetime));
    }
    if (finding.lifetime != null) return Math.max(0.5, Number(finding.lifetime));
    if (finding.dataLifetime != null) return Math.max(0.5, Number(finding.dataLifetime));
    if (finding.risk && finding.risk.X != null) return Math.max(0.5, Number(finding.risk.X));
    if (finding.dataSensitivity) {
      var sensMap = { HEALTH: 20, PII: 15, FINANCIAL: 12, AUTH: 5 };
      if (sensMap[finding.dataSensitivity]) return sensMap[finding.dataSensitivity];
    }
    var purp = (finding.purpose || finding.usage || finding.category || '').toLowerCase().replace(/[^a-z_]/g, '_');
    if (PURPOSE_LIFETIME[purp] !== undefined) return PURPOSE_LIFETIME[purp];
    var rule = lookup(finding.algorithm || finding.title || '');
    return rule.defaultDataLifetimeYears || PURPOSE_LIFETIME.unknown;
  }

  function deriveY(finding, locationCount) {
    if (!finding) return 1.5;
    if (finding.risk && finding.risk.Y != null) return Math.max(0.5, Number(finding.risk.Y));
    var locCount = locationCount != null ? Number(locationCount) : 1;
    if (finding.affectedFiles) {
      locCount = (finding.affectedFiles.size != null ? finding.affectedFiles.size : finding.affectedFiles.length) || locCount;
    }
    var rule = lookup(finding.algorithm || finding.title || '');
    var baseY = rule.defaultMigrationYears || 1.0;
    var locBonus = Math.min(3.0, Math.max(0, (locCount - 1) * 0.5));
    var isHardcoded = ((finding.snippet || finding.title || '').toLowerCase().indexOf('hardcoded') !== -1) ||
      ((finding.category || '').toLowerCase().indexOf('hardcoded-secret') !== -1);
    var hardcodedPenalty = isHardcoded ? 1.5 : 0;
    return parseFloat((baseY + locBonus + hardcodedPenalty).toFixed(1));
  }

  return {
    DEFAULT_Z: DEFAULT_Z,
    BUFFER_YEARS: BUFFER_YEARS,
    PURPOSE_LIFETIME: PURPOSE_LIFETIME,
    RULES: RULES,
    getZ: getZ,
    setZ: setZ,
    lookup: lookup,
    isQuantumVulnerable: isQuantumVulnerable,
    isClassicallyWeak: isClassicallyWeak,
    classify: classify,
    deriveX: deriveX,
    deriveY: deriveY
  };
}));
