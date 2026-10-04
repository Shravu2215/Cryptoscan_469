/**
 * HNDL (Harvest-Now-Decrypt-Later) Shared Analysis Engine
 * 
 * Provides unified, explainable quantum exposure calculation across
 * CryptoScan frontend pages (Risk Analysis, Dashboard, Migration Plan).
 * 
 * Formal Definition:
 *   Mosca's Inequality:
 *     X = Data Secrecy Lifetime Requirement (years)
 *     Y = Migration / Rekeying Time (years)
 *     Z = Estimated Horizon to Cryptographically Relevant Quantum Computer (CRQC) (years)
 *   If (X + Y) > Z, data harvested today will remain secret-sensitive when a CRQC emerges
 *   and will be retrospectively decrypted.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.HndlEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Standard secrecy lifetime baselines in years based on cryptographic purpose
  var PURPOSE_DATA_LIFETIME = {
    data_encryption: 20,
    password_hashing: 15,
    key_exchange: 10,
    digital_signature: 5,
    mac: 5,
    random_generation: 5,
    integrity_hashing: 3,
    unknown: 10
  };

  var DEFAULT_YEARS_TO_QUANTUM_THREAT = 10; // DEFAULT_Z = 10 years (NIST CNSA 2.0 baseline)
  var BUFFER_YEARS = 5;

  /**
   * Determine if a finding utilizes quantum-vulnerable (Shor-breakable) cryptography.
   * Uses QuantumRules config if available, otherwise falls back to family list.
   */
  function isQuantumVulnerable(f) {
    if (!f) return false;
    // Delegate to QuantumRules if loaded
    if (typeof QuantumRules !== 'undefined' && QuantumRules.isQuantumVulnerable) {
      return QuantumRules.isQuantumVulnerable(f);
    }
    if (f.quantum === 'yes' || f.quantum === true) return true;
    if (f.quantumVulnerable !== undefined) return Boolean(f.quantumVulnerable);
    if (f.is_quantum_vulnerable !== undefined) return Boolean(f.is_quantum_vulnerable);
    var qs = (f.quantumStatus || f.quantum_status || '').toLowerCase();
    if (qs.indexOf('vulnerable') !== -1 || qs.indexOf('broken') !== -1) return true;
    // Shor-breakable algorithm families
    var SHOR_FAMILIES = ['RSA', 'ECC', 'ECDSA', 'ECDH', 'DH', 'DIFFIE-HELLMAN', 'DSA', 'ELGAMAL', 'ED25519', 'ED448', 'X25519', 'X448'];
    var name = (f.algorithm || f.title || f.name || '').toUpperCase();
    for (var i = 0; i < SHOR_FAMILIES.length; i++) {
      if (name.indexOf(SHOR_FAMILIES[i]) !== -1) return true;
    }
    return false;
  }


  /**
   * Classify finding into Group 1 (Confidentiality / HNDL applies)
   * or Group 2 (Authenticity / migrate before Z, but not HNDL)
   */
  function classifyFinding(f) {
    var rawPurpose = (f.purpose || f.usage || f.category || '').toLowerCase();
    var algo = (f.algorithm || f.title || '').toUpperCase();
    var snippet = (f.snippet || '').toLowerCase();

    // Check Group 2: Authenticity (Digital signatures, Certificates, MACs, Code signing)
    var isAuthenticity =
      rawPurpose.indexOf('signature') !== -1 ||
      rawPurpose.indexOf('signing') !== -1 ||
      rawPurpose.indexOf('sign') !== -1 ||
      rawPurpose.indexOf('verify') !== -1 ||
      rawPurpose.indexOf('certificate') !== -1 ||
      rawPurpose.indexOf('cert') !== -1 ||
      rawPurpose.indexOf('code_sign') !== -1 ||
      rawPurpose.indexOf('mac') !== -1 ||
      rawPurpose.indexOf('hmac') !== -1 ||
      rawPurpose.indexOf('integrity') !== -1;

    // Check signature-only algorithms when purpose is ambiguous
    var isSigOnlyAlgo = (algo.indexOf('ECDSA') !== -1 || algo.indexOf('DSA') !== -1 || algo.indexOf('ED25519') !== -1 || algo.indexOf('ED448') !== -1) &&
      rawPurpose.indexOf('encrypt') === -1 && rawPurpose.indexOf('exchange') === -1 && rawPurpose.indexOf('wrap') === -1 && rawPurpose.indexOf('kex') === -1;

    if (isAuthenticity || isSigOnlyAlgo) {
      return {
        group: 'authenticity', // Group 2
        confidence: (rawPurpose.indexOf('signature') !== -1 || rawPurpose.indexOf('signing') !== -1 || isSigOnlyAlgo) ? 'high' : 'medium',
        reason: 'Signature/MAC ensures authenticity & integrity; retrospective decryption cannot compromise past messages.',
        purposeCategory: 'digital_signature',
        displayPurpose: 'Digital Signature / Verification'
      };
    }

    // Check Group 1: Confidentiality at risk (HNDL applies)
    var isConfidentiality =
      rawPurpose.indexOf('key_exchange') !== -1 ||
      rawPurpose.indexOf('kex') !== -1 ||
      rawPurpose.indexOf('key_wrap') !== -1 ||
      rawPurpose.indexOf('wrap') !== -1 ||
      rawPurpose.indexOf('encrypt') !== -1 ||
      rawPurpose.indexOf('cipher') !== -1 ||
      rawPurpose.indexOf('tls') !== -1 ||
      rawPurpose.indexOf('agreement') !== -1 ||
      rawPurpose.indexOf('data_encryption') !== -1 ||
      algo.indexOf('ECDH') !== -1 ||
      algo.indexOf('DH') !== -1 ||
      algo.indexOf('X25519') !== -1 ||
      algo.indexOf('X448') !== -1;

    if (isConfidentiality) {
      var purp = 'key_exchange';
      var display = 'Key Exchange / Agreement';
      if (rawPurpose.indexOf('encrypt') !== -1 || rawPurpose.indexOf('cipher') !== -1 || rawPurpose.indexOf('data_encryption') !== -1) {
        purp = 'data_encryption';
        display = 'Data Encryption';
      } else if (rawPurpose.indexOf('wrap') !== -1) {
        purp = 'key_exchange';
        display = 'Key Encapsulation / Wrap';
      }
      return {
        group: 'confidentiality', // Group 1
        confidence: 'high',
        reason: 'Protects confidential payload; adversary can harvest ciphertext now and decrypt with future quantum computer.',
        purposeCategory: purp,
        displayPurpose: display
      };
    }

    // If purpose is unknown or unspecified, requirement states:
    // "If purpose is unknown, put it in group 1 and mark confidence 'low'."
    return {
      group: 'confidentiality', // Group 1
      confidence: 'low',
      reason: 'Cryptographic usage context unspecified; conservatively classified as confidentiality risk (HNDL).',
      purposeCategory: 'unknown',
      displayPurpose: 'Unspecified Usage (Assumed Confidentiality)'
    };
  }

  /**
   * Calculates Mosca's Inequality:
   * X = Data Lifetime (years data must stay secret)
   * Y = Migration Time (years to complete migration)
   * Z = Years to Quantum Threat (CRQC)
   * exposure = X + Y
   * margin = Z - (X + Y)
   */
  function calculateMosca(dataLifetimeYears, migrationTimeYears, yearsToQuantumThreat) {
    var X = Math.max(0.5, parseFloat(Number(dataLifetimeYears || 10).toFixed(1)));   // X = data lifetime
    var Y = Math.max(0.5, parseFloat(Number(migrationTimeYears || 1.5).toFixed(1))); // Y = migration time
    var Z = Math.max(1, parseFloat(Number(yearsToQuantumThreat || DEFAULT_YEARS_TO_QUANTUM_THREAT).toFixed(1)));

    var totalRequirement = parseFloat((X + Y).toFixed(1));
    var moscaInequalityHolds = totalRequirement > Z;
    var exposureWindow = Math.max(0, parseFloat((totalRequirement - Z).toFixed(1)));

    var moscaRisk = 'LOW';
    if (totalRequirement > Z) {
      moscaRisk = 'HIGH';
    } else if (totalRequirement > (Z - BUFFER_YEARS)) {
      moscaRisk = 'MEDIUM'; // within BUFFER_YEARS=5 of threat horizon
    }

    var formulaReadout = 'X (' + X + 'y lifetime) + Y (' + Y + 'y migration) ' + (moscaInequalityHolds ? '>' : '≤') + ' Z (' + Z + 'y threat)';

    return {
      X: X,
      Y: Y,
      Z: Z,
      totalRequirement: totalRequirement,
      moscaInequalityHolds: moscaInequalityHolds,
      moscaRisk: moscaRisk,
      exposureWindow: exposureWindow,
      formulaReadout: formulaReadout
    };
  }

  /**
   * classify(x, y, z) — Canonical Mosca classifier
   * Delegates to QuantumRules.classify() if available.
   * Returns { X, Y, Z, exposure, margin, category, label, message }
   *
   * VULNERABLE_NOW             : margin < 0   (X + Y > Z)
   * VULNERABLE_WITHIN_HORIZON  : 0 <= margin <= BUFFER_YEARS
   * SAFE_UNDER_CURRENT_TIMELINE: margin > BUFFER_YEARS
   */
  function classify(x, y, z) {
    if (typeof QuantumRules !== 'undefined' && QuantumRules.classify) {
      return QuantumRules.classify(x, y, z);
    }
    var X = Math.max(0, Number(x) || 0);
    var Y = Math.max(0, Number(y) || 0);
    var Z = Math.max(1, Number(z) || DEFAULT_YEARS_TO_QUANTUM_THREAT);
    var exposure = parseFloat((X + Y).toFixed(2));
    var margin = parseFloat((Z - exposure).toFixed(2));
    var category, label, message;
    if (margin < 0) {
      category = 'VULNERABLE_NOW'; label = 'Vulnerable Now';
      message = 'X + Y (' + exposure.toFixed(1) + 'y) > Z (' + Z + 'y) — data will be at risk when CRQC arrives.';
    } else if (margin <= BUFFER_YEARS) {
      category = 'VULNERABLE_WITHIN_HORIZON'; label = 'Vulnerable Within Horizon';
      message = 'Margin is only ' + margin.toFixed(1) + 'y — less than the ' + BUFFER_YEARS + 'y safety buffer.';
    } else {
      category = 'SAFE_UNDER_CURRENT_TIMELINE'; label = 'Safe Under Current Timeline';
      message = 'Margin of ' + margin.toFixed(1) + 'y exceeds the ' + BUFFER_YEARS + 'y buffer.';
    }
    return { X: X, Y: Y, Z: Z, exposure: exposure, margin: margin, category: category, label: label, message: message };
  }

  /**
   * Calculates numeric HNDL risk score (0-100) per finding
   * Matches cbom-service hndlEngine.js logic
   */
  function calculateFindingScore(finding, options) {
    options = options || {};
    var classification = classifyFinding(finding);
    var purp = classification.purposeCategory;

    // 1. Data Lifetime (X)
    var X = options.dataLifetimeYears;
    if (X == null && finding.lifetime != null) X = Number(finding.lifetime);
    if (X == null && finding.dataLifetime != null) X = Number(finding.dataLifetime);
    if (X == null && (finding.risk && finding.risk.X != null)) X = Number(finding.risk.X);
    if (X == null && finding.dataSensitivity) {
      var sensMap = { HEALTH: 20, PII: 15, FINANCIAL: 12, AUTH: 5 };
      X = sensMap[finding.dataSensitivity];
    }
    if (X == null) {
      X = PURPOSE_DATA_LIFETIME[purp] || PURPOSE_DATA_LIFETIME.unknown;
    }

    // 2. Migration Time (Y)
    var Y = options.migrationTimeYears;
    if (Y == null && (finding.risk && finding.risk.Y != null)) Y = Number(finding.risk.Y);
    if (Y == null) {
      var locCount = options.affectedFilesCount || (finding.affectedFiles ? (finding.affectedFiles.size || finding.affectedFiles.length || 1) : 1);
      var locMultiplier = Math.min(3.0, (locCount - 1) * 0.5);
      var isHardcoded = (finding.snippet || finding.title || '').toLowerCase().indexOf('hardcoded') !== -1;
      var agilityPenalty = isHardcoded ? 1.5 : 0.5;
      Y = parseFloat((1.0 + locMultiplier + agilityPenalty).toFixed(1));
    }

    // 3. Threat Horizon (Z)
    var Z = options.yearsToQuantumThreat != null ? Number(options.yearsToQuantumThreat) : DEFAULT_YEARS_TO_QUANTUM_THREAT;

    var mosca = calculateMosca(X, Y, Z);

    // 4. Quantum vulnerability base (quantum-broken = 100 / 80+)
    var qScore = finding.quantumVulnerabilityScore || finding.quantum_score;
    if (qScore == null) {
      var algo = (finding.algorithm || finding.title || '').toUpperCase();
      if (algo.indexOf('RSA') !== -1 || algo.indexOf('ECC') !== -1 || algo.indexOf('ECDH') !== -1 || algo.indexOf('DH') !== -1) {
        qScore = 100;
      } else if (isQuantumVulnerable(finding)) {
        qScore = 90;
      } else {
        qScore = 20;
      }
    }

    var hndlRisk = 0;
    if (qScore >= 80) {
      if (mosca.moscaInequalityHolds) {
        hndlRisk = Math.min(100, Math.round(80 + (mosca.exposureWindow / 15) * 20));
      } else {
        hndlRisk = 60; // Imminent CRQC threat retains high baseline
      }
    } else if (qScore >= 40) {
      hndlRisk = Math.min(100, Math.round(qScore * (0.4 + (mosca.exposureWindow / 20) * 0.6)));
    } else {
      hndlRisk = Math.round(qScore * 0.5);
    }

    return {
      X: mosca.X,
      Y: mosca.Y,
      Z: mosca.Z,
      exposureWindow: mosca.exposureWindow,
      moscaInequalityHolds: mosca.moscaInequalityHolds,
      moscaRisk: mosca.moscaRisk,
      formulaReadout: mosca.formulaReadout,
      score: hndlRisk,
      classification: classification
    };
  }

  /**
   * Determine Recommended PQC Replacement
   */
  function determineReplacement(algo) {
    if (!algo) return 'ML-KEM / ML-DSA';
    var al = algo.toLowerCase();
    if (al.indexOf('rsa') !== -1 || al.indexOf('dh') !== -1 || al.indexOf('ecdh') !== -1 || al.indexOf('x25519') !== -1) {
      return 'ML-KEM (Kyber-768/1024) or Hybrid X25519+ML-KEM';
    }
    if (al.indexOf('dsa') !== -1 || al.indexOf('ecdsa') !== -1 || al.indexOf('ed25519') !== -1) {
      return 'ML-DSA (Dilithium-3/5) or SLH-DSA (SPHINCS+)';
    }
    if (al.indexOf('md5') !== -1 || al.indexOf('sha1') !== -1) {
      return 'SHA-256 / SHA-3 / BLAKE3';
    }
    if (al.indexOf('des') !== -1 || al.indexOf('3des') !== -1 || al.indexOf('rc4') !== -1) {
      return 'AES-256-GCM / ChaCha20-Poly1305';
    }
    return 'NIST Post-Quantum Standard (FIPS 203/204/205)';
  }

  /**
   * Perform comprehensive HNDL Analysis across all findings
   * 
   * Aggregate Score Formula:
   *   round(0.5 * max(group1) + 0.5 * mean(group1))
   * Bands:
   *   0-24 LOW, 25-49 MEDIUM, 50-74 HIGH, 75-100 CRITICAL
   */
  function calculateHndlAnalysis(findings, options) {
    findings = findings || [];
    options = options || {};
    var currentZ = options.yearsToQuantumThreat != null ? Number(options.yearsToQuantumThreat) : DEFAULT_YEARS_TO_QUANTUM_THREAT;

    // Filter to quantum broken findings
    var quantumBroken = [];
    for (var i = 0; i < findings.length; i++) {
      if (isQuantumVulnerable(findings[i])) {
        quantumBroken.push(findings[i]);
      }
    }

    var group1 = []; // Confidentiality (HNDL applies)
    var group2 = []; // Authenticity (signatures/MACs)
    var uniqueLocationMap = {}; // Dedupe file:line for group 1
    var algoMap = {}; // Rollup by algorithm for group 1

    for (var j = 0; j < quantumBroken.length; j++) {
      var f = quantumBroken[j];
      var cls = classifyFinding(f);
      var scored = calculateFindingScore(f, {
        yearsToQuantumThreat: currentZ,
        dataLifetimeYears: options.dataLifetimeYears,
        migrationTimeYears: options.migrationTimeYears
      });

      var file = f.file || f.filePath || f.file_path || f.location || f.path || 'unknown';
      var line = f.line != null ? f.line : (f.startLine != null ? f.startLine : (f.lineNumber != null ? f.lineNumber : 1));
      var locKey = file + ':' + line;
      var algo = f.algorithm || f.title || 'Unknown Algorithm';

      var item = {
        finding: f,
        algorithm: algo,
        file: file,
        line: line,
        locationKey: locKey,
        purpose: cls.displayPurpose,
        purposeCategory: cls.purposeCategory,
        confidence: cls.confidence,
        reason: cls.reason,
        X: scored.X,
        Y: scored.Y,
        Z: scored.Z,
        exposureWindow: scored.exposureWindow,
        moscaInequalityHolds: scored.moscaInequalityHolds,
        score: scored.score,
        replacement: determineReplacement(algo)
      };

      if (cls.group === 'confidentiality') {
        group1.push(item);
        if (!uniqueLocationMap[locKey]) {
          uniqueLocationMap[locKey] = item;
        }
        if (!algoMap[algo]) {
          algoMap[algo] = {
            algorithm: algo,
            findings: [],
            locations: {},
            totalX: 0,
            maxY: 0,
            maxScore: 0,
            replacement: item.replacement
          };
        }
        algoMap[algo].findings.push(item);
        algoMap[algo].locations[locKey] = true;
        algoMap[algo].totalX += item.X;
        if (item.Y > algoMap[algo].maxY) algoMap[algo].maxY = item.Y;
        if (item.score > algoMap[algo].maxScore) algoMap[algo].maxScore = item.score;
      } else {
        // Authenticity group: Target deadline is year = CurrentYear + Z
        var currentYear = new Date().getFullYear();
        item.migrateByYear = currentYear + Math.round(currentZ);
        group2.push(item);
      }
    }

    // Sort group1 by score descending
    group1.sort(function (a, b) {
      return b.score - a.score;
    });

    // Compute Aggregate Score
    var aggregateScore = 0;
    var minScore = 0;
    var maxScore = 0;
    var meanScore = 0;
    var histogram = { '0-24': 0, '25-49': 0, '50-74': 0, '75-100': 0 };

    if (group1.length > 0) {
      var scores = group1.map(function (item) { return item.score; });
      maxScore = Math.max.apply(null, scores);
      minScore = Math.min.apply(null, scores);
      var sum = scores.reduce(function (acc, val) { return acc + val; }, 0);
      meanScore = Math.round((sum / scores.length) * 10) / 10;

      aggregateScore = Math.round((0.5 * maxScore) + (0.5 * meanScore));
      if (aggregateScore > 100) aggregateScore = 100;
      if (aggregateScore < 0) aggregateScore = 0;

      for (var k = 0; k < scores.length; k++) {
        var sc = scores[k];
        if (sc < 25) histogram['0-24']++;
        else if (sc < 50) histogram['25-49']++;
        else if (sc < 75) histogram['50-74']++;
        else histogram['75-100']++;
      }
    }

    // Band assignment
    var band = 'LOW';
    var bandColor = 'var(--green, #10b981)';
    if (aggregateScore >= 75) {
      band = 'CRITICAL';
      bandColor = 'var(--red, #ef4444)';
    } else if (aggregateScore >= 50) {
      band = 'HIGH';
      bandColor = 'var(--amber, #f59e0b)';
    } else if (aggregateScore >= 25) {
      band = 'MEDIUM';
      bandColor = 'var(--yellow, #eab308)';
    }

    // Algorithm rollup table
    var algorithmRollup = Object.keys(algoMap).map(function (algoName) {
      var data = algoMap[algoName];
      var locCount = Object.keys(data.locations).length;
      var avgX = parseFloat((data.totalX / data.findings.length).toFixed(1));
      var Y = data.maxY;
      var expWin = Math.max(0, parseFloat(((avgX + Y) - currentZ).toFixed(1)));
      return {
        algorithm: algoName,
        findingsCount: data.findings.length,
        locationsCount: locCount,
        avgX: avgX,
        Y: Y,
        Z: currentZ,
        exposureWindow: expWin,
        score: data.maxScore,
        replacement: data.replacement
      };
    });
    algorithmRollup.sort(function (a, b) { return b.score - a.score; });

    // Deduplicated Unique Locations
    var uniqueLocations = Object.keys(uniqueLocationMap).map(function (k) {
      return uniqueLocationMap[k];
    });
    uniqueLocations.sort(function (a, b) { return b.score - a.score; });

    return {
      currentZ: currentZ,
      group1Findings: group1,
      group2Findings: group2,
      aggregateScore: aggregateScore,
      band: band,
      bandColor: bandColor,
      hasConfidentialityRisk: group1.length > 0,
      vulnerableAlgorithmsCount: Object.keys(algoMap).length,
      atRiskLocationsCount: uniqueLocations.length,
      authenticityCount: group2.length,
      minScore: minScore,
      maxScore: maxScore,
      meanScore: meanScore,
      histogram: histogram,
      algorithmRollup: algorithmRollup,
      uniqueLocations: uniqueLocations
    };
  }

  /**
   * Helper to export locations to CSV
   */
  function exportLocationsToCsv(uniqueLocations, filename) {
    filename = filename || 'hndl_at_risk_locations.csv';
    var headers = ['Location', 'Algorithm', 'Purpose', 'Data Lifetime X (Years)', 'Exposure Window (Years)', 'HNDL Score (0-100)', 'Confidence'];
    var rows = [headers.join(',')];

    for (var i = 0; i < uniqueLocations.length; i++) {
      var item = uniqueLocations[i];
      var locStr = '"' + (item.file + ':' + item.line).replace(/"/g, '""') + '"';
      var algoStr = '"' + (item.algorithm || '').replace(/"/g, '""') + '"';
      var purpStr = '"' + (item.purpose || '').replace(/"/g, '""') + '"';
      var confStr = '"' + (item.confidence || 'medium').toUpperCase() + '"';
      rows.push([
        locStr,
        algoStr,
        purpStr,
        item.X,
        item.exposureWindow,
        item.score,
        confStr
      ].join(','));
    }

    var csvContent = 'data:text/csv;charset=utf-8,' + encodeURIComponent(rows.join('\n'));
    var link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  return {
    PURPOSE_DATA_LIFETIME: PURPOSE_DATA_LIFETIME,
    DEFAULT_YEARS_TO_QUANTUM_THREAT: DEFAULT_YEARS_TO_QUANTUM_THREAT,
    BUFFER_YEARS: BUFFER_YEARS,
    isQuantumVulnerable: isQuantumVulnerable,
    classifyFinding: classifyFinding,
    calculateMosca: calculateMosca,
    classify: classify,
    calculateFindingScore: calculateFindingScore,
    calculateHndlAnalysis: calculateHndlAnalysis,
    determineReplacement: determineReplacement,
    exportLocationsToCsv: exportLocationsToCsv
  };
}));
