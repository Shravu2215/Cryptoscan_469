'use strict';

/**
 * CryptoTwin Data Contract & Normalizer
 * Single source of truth for CryptoTwin inputs, derived from either
 * direct scan findings / CBOM / Migration Plan, or an uploaded Migration Plan JSON file.
 */

const prisma = require('../utils/prismaClient');
const { getScan, getFindings } = require('../utils/devStore');

/**
 * Infer usage context from algorithm name, description, or file path
 */
function inferUsageContext(algo, filePath, description) {
  const text = `${algo || ''} ${filePath || ''} ${description || ''}`.toLowerCase();

  if (text.includes('jwt') || text.includes('token') || text.includes('auth') || text.includes('session')) {
    return 'jwt';
  }
  if (text.includes('tls') || text.includes('ssl') || text.includes('https') || text.includes('handshake')) {
    return 'tls';
  }
  if (text.includes('sign') || text.includes('dsa') || text.includes('signature') || text.includes('rsa') || text.includes('ecdsa')) {
    return 'signing';
  }
  if (text.includes('ecdh') || text.includes('key-exchange') || text.includes('dh') || text.includes('kem')) {
    return 'key-exchange';
  }
  if (text.includes('aes') || text.includes('cipher') || text.includes('encrypt') || text.includes('decrypt') || text.includes('des')) {
    return 'encryption';
  }
  if (text.includes('md5') || text.includes('sha1') || text.includes('sha-1') || text.includes('hash') || text.includes('digest')) {
    return 'hashing';
  }

  return 'other';
}

/**
 * Infer target PQC replacement algorithm based on classical algorithm & usage
 */
function inferTargetAlgorithm(algo, usageContext) {
  const normalized = (algo || '').toUpperCase();

  if (normalized.includes('RSA')) {
    return usageContext === 'signing' || usageContext === 'jwt' ? 'ML-DSA-65 (Dilithium)' : 'ML-KEM-768 (Kyber)';
  }
  if (normalized.includes('ECDH') || normalized.includes('DH') || normalized.includes('ECC')) {
    return 'ML-KEM-768 (Kyber) Hybrid';
  }
  if (normalized.includes('ECDSA') || normalized.includes('DSA')) {
    return 'ML-DSA-65 (Dilithium)';
  }
  if (normalized.includes('MD5') || normalized.includes('SHA1') || normalized.includes('SHA-1')) {
    return 'SHA-256 / SHA-3';
  }
  if (normalized.includes('DES') || normalized.includes('3DES') || normalized.includes('RC4')) {
    return 'AES-256-GCM';
  }

  return 'ML-KEM-768 / ML-DSA-65 Hybrid';
}

/**
 * Infer primary programming language from file extension
 */
function inferLanguage(filePath) {
  if (!filePath) return 'javascript';
  const ext = filePath.split('.').pop().toLowerCase();
  switch (ext) {
    case 'js': case 'jsx': case 'ts': case 'tsx': case 'mjs': return 'javascript';
    case 'py': case 'pyw': return 'python';
    case 'go': return 'go';
    case 'java': return 'java';
    case 'c': case 'cpp': case 'h': case 'hpp': return 'cpp';
    case 'rs': return 'rust';
    case 'php': return 'php';
    case 'rb': return 'ruby';
    default: return 'javascript';
  }
}

/**
 * Build normalized CryptoTwinInput from direct scan ID
 */
async function buildDirectInput(scanId) {
  let scan = null;
  let findings = [];

  try {
    scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { repo: true }
    });
    if (scan) {
      findings = await prisma.finding.findMany({ where: { scanId } });
    }
  } catch (_) {}

  if (!scan) {
    const devScan = getScan(scanId);
    if (devScan) {
      scan = devScan;
      findings = getFindings(scanId) || devScan.findings || [];
    }
  }

  if (!scan) {
    throw new Error(`Target scan with ID "${scanId}" not found in system.`);
  }

  const repoName = scan.repo?.name || scan.repoName || scan.name || scanId;

  const items = findings.map((f, idx) => {
    const algo = f.algorithm || 'RSA-2048';
    const filePath = f.filePath || 'src/security/crypto.js';
    const usage = f.usageContext || inferUsageContext(algo, filePath, f.description);

    return {
      id: f.id || `item-${idx + 1}`,
      filePath: filePath,
      line: f.lineNumber || (idx + 1) * 15,
      language: f.language || inferLanguage(filePath),
      currentAlgorithm: algo,
      usageContext: usage,
      severity: (f.severity || 'HIGH').toUpperCase(),
      quantumVulnerable: f.quantumStatus ? f.quantumStatus.toLowerCase().includes('vulnerable') : true,
      targetAlgorithm: f.recommendation || inferTargetAlgorithm(algo, usage),
      priority: f.priority || (f.severity === 'CRITICAL' ? 'P1' : (f.severity === 'HIGH' ? 'P2' : 'P3')),
      effort: f.effort || 'MEDIUM',
      dependencies: f.dependencies || []
    };
  });

  const algorithmsFound = Array.from(new Set(items.map(i => i.currentAlgorithm)));

  return {
    scanId,
    repoName,
    source: 'DIRECT_SCAN',
    generatedAt: new Date().toISOString(),
    itemCount: items.length,
    algorithmsFound,
    items
  };
}

/**
 * Validate and normalize an uploaded Migration Plan JSON file
 */
function validateAndParseUploadInput(jsonString) {
  let rawData;
  try {
    rawData = JSON.parse(jsonString);
  } catch (err) {
    throw new Error('Invalid JSON file format. Failed to parse Migration Plan JSON.');
  }

  if (!rawData || typeof rawData !== 'object') {
    throw new Error('Migration Plan JSON file must be a non-empty object.');
  }

  const itemsRaw = rawData.items || rawData.recommendations || rawData.findings || rawData.plan;
  if (!Array.isArray(itemsRaw) || itemsRaw.length === 0) {
    throw new Error('Migration Plan file contains no valid items or recommendations array.');
  }

  const items = itemsRaw.map((item, idx) => {
    const algo = item.currentAlgorithm || item.algorithm || item.algo || 'RSA-2048';
    const filePath = item.filePath || item.file || 'src/app.js';
    const usage = item.usageContext || inferUsageContext(algo, filePath, item.description);

    return {
      id: item.id || `upload-item-${idx + 1}`,
      filePath,
      line: Number(item.line || item.lineNumber || 1),
      language: item.language || inferLanguage(filePath),
      currentAlgorithm: algo,
      usageContext: usage,
      severity: (item.severity || 'HIGH').toUpperCase(),
      quantumVulnerable: item.quantumVulnerable !== undefined ? Boolean(item.quantumVulnerable) : true,
      targetAlgorithm: item.targetAlgorithm || item.recommendation || inferTargetAlgorithm(algo, usage),
      priority: item.priority || 'P2',
      effort: item.effort || 'MEDIUM',
      dependencies: Array.isArray(item.dependencies) ? item.dependencies : []
    };
  });

  const algorithmsFound = Array.from(new Set(items.map(i => i.currentAlgorithm)));

  return {
    scanId: rawData.scanId || `uploaded-${Date.now()}`,
    repoName: rawData.repoName || rawData.repo || 'Uploaded Migration Plan',
    source: 'UPLOADED_FILE',
    generatedAt: rawData.generatedAt || new Date().toISOString(),
    itemCount: items.length,
    algorithmsFound,
    items
  };
}

module.exports = {
  buildDirectInput,
  validateAndParseUploadInput,
  inferUsageContext,
  inferTargetAlgorithm
};
