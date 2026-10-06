(function (root, factory) {
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.MigrationPlanData = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
  'use strict';

  function getSeverity(finding) {
    if (!finding) return 'MEDIUM';
    const value = String(finding.severity || finding.severity_level || finding.details?.severity || 'MEDIUM').toUpperCase();
    if (value.includes('CRIT')) return 'CRITICAL';
    if (value.includes('HIGH')) return 'HIGH';
    if (value.includes('MED')) return 'MEDIUM';
    if (value.includes('LOW')) return 'LOW';
    if (value.includes('INFO') || value.includes('SAFE')) return 'SAFE';
    return 'MEDIUM';
  }

  function isQuantum(finding) {
    if (!finding) return false;
    if (root.QuantumRules?.isQuantumVulnerable) return root.QuantumRules.isQuantumVulnerable(finding);
    return finding.quantum === 'yes' || finding.quantum === true || Boolean(finding.quantumVulnerable || finding.is_quantum_vulnerable);
  }

  function isClassicallyWeak(finding) {
    return Boolean(finding && root.QuantumRules?.isClassicallyWeak && root.QuantumRules.isClassicallyWeak(finding));
  }

  function determineReplacement(algorithm) {
    if (root.QuantumRules?.lookup) {
      const rule = root.QuantumRules.lookup(algorithm);
      if (rule && rule.replacement) return rule.replacement;
    }
    if (!algorithm) return 'ML-KEM / ML-DSA';
    const normalized = String(algorithm).toLowerCase();
    if (normalized.includes('rsa') || normalized.includes('dh') || normalized.includes('ecdh')) return 'ML-KEM (Kyber-768/1024) or Hybrid X25519+ML-KEM';
    if (normalized.includes('dsa') || normalized.includes('ecdsa') || normalized.includes('ed25519')) return 'ML-DSA (Dilithium-3/5) or SLH-DSA (SPHINCS+)';
    if (normalized.includes('md5') || normalized.includes('sha1')) return 'SHA-256 / SHA-3-256';
    if (normalized.includes('des') || normalized.includes('rc4')) return 'AES-256-GCM / ChaCha20-Poly1305';
    return 'NIST Post-Quantum Standard (FIPS 203/204/205)';
  }

  function computeMosca(finding, fileCount) {
    const rules = root.QuantumRules;
    const x = rules?.deriveX ? rules.deriveX(finding) : (finding?.risk?.X ?? 5);
    const y = rules?.deriveY ? rules.deriveY(finding, fileCount) : (finding?.risk?.Y ?? 1.5);
    const z = root.CryptoEngine?.getGlobalZ ? root.CryptoEngine.getGlobalZ() : (rules?.getZ ? rules.getZ() : 10);
    const classification = rules?.classify ? rules.classify(x, y, z) : {
      X: x, Y: y, Z: z, margin: z - (x + y), category: x + y > z ? 'VULNERABLE_NOW' : (z - (x + y) <= 5 ? 'VULNERABLE_WITHIN_HORIZON' : 'SAFE_UNDER_CURRENT_TIMELINE'),
      label: x + y > z ? 'Vulnerable Now' : (z - (x + y) <= 5 ? 'Vulnerable Within Horizon' : 'Safe Under Current Timeline'),
      message: x + y > z ? 'X + Y > Z — data will be at risk when CRQC arrives.' : 'Safe under current timeline.'
    };
    const category = classification.category === 'VULNERABLE_WITHIN_HORIZON' ? 'WITHIN_HORIZON'
      : classification.category === 'SAFE_UNDER_CURRENT_TIMELINE' ? 'SAFE_TIMELINE' : classification.category;
    return {
      X: classification.X, Y: classification.Y, Z: classification.Z,
      moscaX: `${classification.X}y`, moscaY: `${classification.Y}y`, moscaZ: `${classification.Z}y`,
      diff: classification.margin, urgency_margin: classification.margin,
      isMet: classification.margin < 0, category,
      rawCategory: classification.category, categoryLabel: classification.label, message: classification.message
    };
  }

  function collectFindings(data, selectedScanId) {
    const source = data || (root.CryptoEngine?.getData ? root.CryptoEngine.getData() : {});
    const allScans = (source.scans && source.scans.length)
      ? source.scans
      : (source.activeScan?.findings ? [source.activeScan] : (source.repositories || []));
    const scans = selectedScanId
      ? allScans.filter(scan => [scan.id, scan.scanId, scan.repoId].some(id => id != null && String(id) === String(selectedScanId)))
      : allScans;
    const repoCriticality = {};
    (source.repositories || []).forEach(repo => {
      const value = repo.businessCriticality || repo.criticality_tier;
      if (repo.id && value) repoCriticality[repo.id] = value;
      if (repo.name && value) repoCriticality[repo.name] = value;
    });
    scans.forEach(scan => {
      if (scan.repoId && scan.businessCriticality) repoCriticality[scan.repoId] = scan.businessCriticality;
      if (scan.repoName && scan.businessCriticality) repoCriticality[scan.repoName] = scan.businessCriticality;
    });
    const findings = scans.flatMap(scan => (scan.findings || []).filter(Boolean).map(finding => {
      if (!finding.severity) finding.severity = 'medium';
      let enriched = finding;
      try { if (root.CryptoEngine?.enrichFinding) enriched = root.CryptoEngine.enrichFinding(finding); } catch (_) {}
      return {
        ...enriched,
        scanId: scan.id || scan.scanId || null,
        repoId: scan.repoId,
        repoName: scan.repoName || scan.name,
        businessCriticality: finding.businessCriticality || scan.businessCriticality || repoCriticality[scan.repoId] || repoCriticality[scan.repoName] || 'MEDIUM'
      };
    }));
    return { scans, findings };
  }

  function buildCandidates(findings) {
    const atRisk = (findings || []).filter(finding => getSeverity(finding) !== 'SAFE' || isQuantum(finding));
    const candidateMap = {};
    const criticalityWeights = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    atRisk.forEach(finding => {
      const algorithm = finding.algorithm || (finding.title && finding.title.split(' ')[0]) || 'Unknown';
      if (!candidateMap[algorithm]) {
        candidateMap[algorithm] = {
          algorithm,
          purpose: finding.usage || finding.category || 'Data Protection',
          severity: getSeverity(finding),
          quantumVulnerable: isQuantum(finding),
          isClassicallyWeak: isClassicallyWeak(finding),
          affectedFiles: new Set(),
          findings: [],
          findingIds: [],
          maxCriticality: 'MEDIUM',
          maxCritWeight: 2,
          rationale: finding.remediation || finding.snippet || 'Component is considered insecure or vulnerable to quantum attacks.',
          replacement: determineReplacement(algorithm)
        };
      }
      const candidate = candidateMap[algorithm];
      candidate.findings.push(finding);
      if (finding.id && !candidate.findingIds.includes(String(finding.id))) candidate.findingIds.push(String(finding.id));
      candidate.affectedFiles.add(finding.file || finding.filePath || 'unknown');
      const criticality = String(finding.businessCriticality || 'MEDIUM').toUpperCase();
      const weight = criticalityWeights[criticality] || 2;
      if (weight > candidate.maxCritWeight) {
        candidate.maxCritWeight = weight;
        candidate.maxCriticality = criticality;
      }
      if (!candidate.rawFinding) candidate.rawFinding = finding;
      const severity = getSeverity(finding);
      if (severity === 'CRITICAL' || (severity === 'HIGH' && candidate.severity !== 'CRITICAL')) candidate.severity = severity;
      candidate.quantumVulnerable = candidate.quantumVulnerable || isQuantum(finding);
      candidate.isClassicallyWeak = candidate.isClassicallyWeak || isClassicallyWeak(finding);
    });
    const severityWeights = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, SAFE: 5 };
    return Object.values(candidateMap).map(candidate => {
      const priority = candidate.isClassicallyWeak || candidate.maxCriticality === 'CRITICAL' || candidate.severity === 'CRITICAL' || candidate.severity === 'HIGH' || candidate.quantumVulnerable
        ? 1 : (candidate.maxCriticality === 'HIGH' || candidate.severity === 'MEDIUM' ? 2 : 3);
      const fileCount = candidate.affectedFiles.size;
      return { ...candidate, fileCount, priority, mosca: computeMosca(candidate.rawFinding, fileCount) };
    }).sort((a, b) => {
      if (b.maxCritWeight !== a.maxCritWeight) return b.maxCritWeight - a.maxCritWeight;
      if (a.priority !== b.priority) return a.priority - b.priority;
      if (severityWeights[a.severity] !== severityWeights[b.severity]) return severityWeights[a.severity] - severityWeights[b.severity];
      return b.fileCount - a.fileCount;
    });
  }

  return { getSeverity, isQuantum, isClassicallyWeak, determineReplacement, computeMosca, collectFindings, buildCandidates };
}));
