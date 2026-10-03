'use strict';

/**
 * Read-only adapter from persisted scanner findings to the quantum-risk
 * CryptoAsset contract. This module does not query or mutate persistence.
 *
 * @typedef {Object} CryptoAsset
 * @property {string} assetId Stable identifier derived from findingId.
 * @property {string} findingId Persisted finding identifier.
 * @property {string} algorithm Scanner algorithm label.
 * @property {'RSA'|'ECC'|'DH'|'AES'|'HASH'|'OTHER'|'PQC'} family Normalized family.
 * @property {number|null} keySize Key size in bits when known.
 * @property {string} usage Usage label, or "unknown" when absent.
 * @property {string} filePath Finding source path.
 * @property {number|null} lineNumber Source line when known.
 * @property {string|null} service Service/package derived from path or library metadata.
 * @property {number} confidence Normalized confidence in the range 0-1.
 * @property {Array<'static'|'runtime'|'network'>} sources Evidence sources.
 */

const CONFIDENCE_VALUES = Object.freeze({
  confirmed: 1,
  high: 0.9,
  likely: 0.7,
  medium: 0.65,
  possible: 0.4,
  low: 0.4,
});

const GENERIC_PATH_ROOTS = new Set(['src', 'app', 'lib']);
const PACKAGE_PATH_ROOTS = new Set(['apps', 'packages', 'services']);

function normalizeConfidence(value) {
  const label = String(value ?? '').split('|', 1)[0].trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(CONFIDENCE_VALUES, label)) {
    return CONFIDENCE_VALUES[label];
  }
  if (/^\d+(?:\.\d+)?%$/.test(label)) {
    return Math.max(0, Math.min(1, Number(label.slice(0, -1)) / 100));
  }
  const numeric = Number(label);
  return label && Number.isFinite(numeric)
    ? Math.max(0, Math.min(1, numeric))
    : 0.5;
}

function normalizeFamily(algorithm) {
  const normalized = String(algorithm || '').toUpperCase().replace(/[ _]/g, '-');
  if (/^(ML-?KEM|ML-?DSA|SLH-?DSA|KYBER|DILITHIUM|SPHINCS|FALCON|BIKE|HQC|NTRU|XMSS|LMS)/.test(normalized)) {
    return 'PQC';
  }
  if (/^(RSA)(?:-|$)/.test(normalized)) return 'RSA';
  if (/^(ECC|ECDSA|ECDH|EDDSA|ED25519|X25519|SECP|P-\d)/.test(normalized)) return 'ECC';
  if (/^(DH|DIFFIE|DSA)(?:-|$)/.test(normalized)) return 'DH';
  if (/^(AES|CHACHA|DES|3DES|TDES|RC[24]|BLOWFISH|FERNET)(?:-|$)/.test(normalized)) return 'AES';
  if (/^(SHA|SHA\d|MD[245]|HMAC|BLAKE|RIPEMD)(?:-|$)/.test(normalized)) return 'HASH';
  return 'OTHER';
}

function deriveService(filePath, finding) {
  const parts = String(filePath || '')
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .split('/')
    .filter(Boolean);
  if (parts.length > 1 && PACKAGE_PATH_ROOTS.has(parts[0].toLowerCase())) return parts[1];
  if (parts.length > 1 && !GENERIC_PATH_ROOTS.has(parts[0].toLowerCase())) return parts[0];
  const packageName = finding.packageName || finding.package || finding.library;
  return packageName ? String(packageName) : null;
}

/**
 * Map database/scanner finding objects without modifying them or accessing storage.
 * @param {Array<Object>} findings
 * @returns {CryptoAsset[]}
 */
function findingsToCryptoAssets(findings) {
  if (!Array.isArray(findings)) throw new TypeError('findings must be an array');

  return findings.map((finding) => {
    if (!finding || typeof finding !== 'object' || Array.isArray(finding)) {
      throw new TypeError('each finding must be an object');
    }
    if (finding.id === undefined || finding.id === null || String(finding.id).trim() === '') {
      throw new TypeError('each finding must have a stable id');
    }

    const findingId = String(finding.id);
    const filePath = String(finding.filePath || finding.file || '');
    const keySize = Number.isFinite(Number(finding.keySize)) && finding.keySize !== null
      ? Number(finding.keySize)
      : null;
    const line = finding.lineNumber ?? finding.line;

    return {
      assetId: `finding:${findingId}`,
      findingId,
      algorithm: String(finding.algorithm || 'UNKNOWN'),
      family: normalizeFamily(finding.algorithm),
      keySize,
      usage: String(finding.usage || 'unknown'),
      filePath,
      lineNumber: Number.isInteger(Number(line)) && line !== null && line !== undefined ? Number(line) : null,
      service: deriveService(filePath, finding),
      confidence: normalizeConfidence(finding.confidence),
      sources: ['static'],
    };
  });
}

/**
 * Flatten CycloneDX-style cryptographic components into finding-shaped rows,
 * then use the existing pure mapping contract.
 * @param {Array<Object>} components
 * @returns {CryptoAsset[]}
 */
function componentsToCryptoAssets(components) {
  if (!Array.isArray(components)) throw new TypeError('components must be an array');
  const findings = [];
  for (const component of components) {
    if (!component || typeof component !== 'object' || Array.isArray(component)) {
      throw new TypeError('each component must be an object');
    }
    const algorithmProperties = component.cryptoProperties?.algorithmProperties || {};
    const parameter = algorithmProperties.parameterSetIdentifier;
    const sizeMatch = String(parameter || component.name || '').match(/\d+/);
    for (const occurrence of component.occurrences || []) {
      findings.push({
        id: occurrence.findingId,
        algorithm: component.name || algorithmProperties.primitive || 'UNKNOWN',
        keySize: sizeMatch ? Number(sizeMatch[0]) : null,
        usage: occurrence.usage || 'unknown',
        filePath: occurrence.file || '',
        lineNumber: occurrence.line ?? null,
        packageName: component.service || component.group || null,
        confidence: occurrence.confidence,
      });
    }
  }
  return findingsToCryptoAssets(findings);
}

module.exports = { findingsToCryptoAssets, componentsToCryptoAssets };