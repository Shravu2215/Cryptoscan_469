'use strict';

const crypto = require('crypto');
const { getMigrationGuidance } = require('../../../cbom-service/src/services/purposeDetection');

const RULES = [
  { test: e => /^(?:Math\.random|Python random\.|Non-cryptographic PRNG)/i.test(e.algorithm), family: 'UNKNOWN', severity: 'WARNING', quantum: 'Not Applicable', description: 'A non-cryptographic pseudo-random generator was observed. This is only a vulnerability if used for security-sensitive values.', recommendation: 'Use a cryptographically secure random generator for keys, tokens, nonces, and other security values.' },
  { test: e => /^(?:CSPRNG|crypto\.getRandomValues|secrets|os\.urandom|uuid\.uuid4)$/i.test(e.algorithm), family: 'UNKNOWN', severity: 'INFO', quantum: 'Quantum Safe', description: 'A cryptographically secure random generator was observed.', recommendation: 'No migration required; continue using a cryptographically secure random generator.' },
  { test: e => /^(?:MD5|HMAC-MD5)$/i.test(e.algorithm), family: 'MD5', severity: 'HIGH', quantum: 'Classically Broken', description: 'MD5 was observed at runtime and is considered broken for security use.', purpose: 'hashing' },
  { test: e => /^(?:SHA-?1|HMAC-SHA-1)$/i.test(e.algorithm), family: 'SHA1', severity: 'HIGH', quantum: 'Classically Broken', description: 'SHA-1 was observed at runtime and is considered broken for security use.', recommendation: 'Replace SHA-1 with SHA-256 or SHA-3.' },
  { test: e => /^(?:SHA-?256|SHA-?384|SHA-?512|SHA3(?:-\d+)?|SHA-3(?:-\d+)?|Keccak-256|HMAC-SHA-(?:256|384|512))$/i.test(e.algorithm), family: 'SHA-256', severity: 'INFO', quantum: 'Quantum Weakened', description: 'A strong hash was observed. Grover\'s algorithm reduces the effective brute-force security level.', recommendation: 'No immediate migration required; prefer SHA-256 or stronger and monitor post-quantum guidance.' },
  { test: e => /^HMAC$/i.test(e.algorithm) && /^(?:MD5|SHA-1)$/i.test(e.keyInfo?.hash || ''), family: 'SHA1', severity: 'HIGH', quantum: 'Classically Broken', description: 'HMAC with a classically broken hash was observed; replace the digest with SHA-256 or stronger.', recommendation: 'Replace the HMAC digest with HMAC-SHA-256 or stronger.' },
  { test: e => /^HMAC$/i.test(e.algorithm) && /^SHA-(?:256|384|512)$/i.test(e.keyInfo?.hash || ''), family: 'HMAC', severity: 'INFO', quantum: 'Quantum Weakened', description: 'A strong HMAC hash was observed. Grover\'s algorithm reduces the effective brute-force security level.', recommendation: 'Use a strong secret and a SHA-256-or-stronger HMAC digest.' },
  { test: e => /^AES(?:-|$)/i.test(e.algorithm), family: 'AES', severity: 'LOW', quantum: 'Quantum Safe', description: 'AES was observed at runtime.', recommendation: 'Use AES-256 for long-lived sensitive data and authenticated modes such as GCM.' },
  { test: e => /^(?:RSA(?:-.+)?|RSASSA-PKCS1-v1_5|JWT RS256)$/i.test(e.algorithm), family: 'RSA', severity: e => Number(e.keyInfo.keySize || 0) > 0 && Number(e.keyInfo.keySize) < 2048 ? 'HIGH' : 'MEDIUM', quantum: 'Quantum Vulnerable', description: 'RSA was observed at runtime; Shor\'s algorithm threatens RSA public-key security.', purpose: 'digital_signature' },
  { test: e => /^(?:ECDSA|ECDH|Ed25519|Ed448|secp256k1|ECDSA secp256k1)$/i.test(e.algorithm), family: 'ECC', severity: 'MEDIUM', quantum: 'Quantum Vulnerable', description: 'Elliptic-curve cryptography was observed at runtime; Shor\'s algorithm threatens its public-key security.', purpose: 'digital_signature' },
  { test: e => /^(?:eth_(?:sendTransaction|signTypedData(?:_v\d+)?|requestAccounts)|personal_sign)$/i.test(e.algorithm), family: 'ECC', severity: 'MEDIUM', quantum: 'Quantum Vulnerable', description: 'A wallet operation was observed. Ethereum wallet signing uses ECDSA over secp256k1.', purpose: 'digital_signature' },
  { test: e => /^JWT HS256$/i.test(e.algorithm), family: 'HMAC', severity: 'INFO', quantum: 'Quantum Weakened', description: 'JWT HS256 was observed; it uses HMAC-SHA-256.', recommendation: 'Use a strong secret and rotate it as required; Grover\'s algorithm reduces the effective brute-force security level.' },
  { test: e => /^JWT none$/i.test(e.algorithm), family: 'UNKNOWN', severity: 'HIGH', quantum: 'Not Applicable', description: 'An unsigned JWT algorithm was observed.', recommendation: 'Reject unsigned JWTs and require a validated signing algorithm.' },
  { test: e => /^SSLContext$/i.test(e.algorithm), family: 'UNKNOWN', severity: 'INFO', quantum: 'Not Assessed', description: 'A Python SSL context was created; this observation does not inspect or probe a TLS connection.', recommendation: 'Review the context configuration and negotiated protocol policy through the existing application configuration.' },
  { test: e => /^(?:HKDF|PBKDF2)$/i.test(e.algorithm), family: 'UNKNOWN', severity: 'INFO', quantum: 'Not Assessed', description: 'A key-derivation function was observed at runtime.', recommendation: 'Confirm parameters are appropriate for the application and use a unique, high-entropy salt where required.' },
];

function classifyRuntimeEvent(event) {
  const rule = RULES.find(candidate => candidate.test(event));
  if (!rule) return null;
  const keyInfo = event.keyInfo || {};
  const mode = String(keyInfo.mode || '').toUpperCase();
  let severity = typeof rule.severity === 'function' ? rule.severity({ ...event, keyInfo }) : rule.severity;
  let description = rule.description;
  let recommendation = rule.recommendation;
  if (/^AES/i.test(event.algorithm) && mode === 'ECB') {
    severity = 'HIGH';
    description += ' ECB mode does not provide semantic security.';
    recommendation = 'Replace ECB with an authenticated mode such as AES-GCM.';
  } else if (/^AES/i.test(event.algorithm) && mode === 'CBC') {
    severity = 'WARNING';
    description += ' Confirm that ciphertext integrity is provided separately.';
    recommendation = 'Verify a separate MAC protects CBC ciphertext, or migrate to an authenticated mode such as AES-GCM.';
  }
  if (!recommendation) {
    recommendation = getMigrationGuidance(rule.family, rule.purpose || 'unknown', {
      algorithm: event.algorithm,
      keySize: keyInfo.keySize,
      mode,
    }).recommendation;
  }
  return { family: rule.family, severity, quantumStatus: rule.quantum, description, recommendation };
}

function runtimeEventToFinding(sessionId, event) {
  const classification = classifyRuntimeEvent(event);
  if (!classification) return null;
  const callSite = String(event.callSite || 'unknown:0').slice(0, 500);
  const callFile = callSite.replace(/:\d+$/, '') || 'unknown';
  const lineNumber = Number(callSite.match(/:(\d+)$/)?.[1]) || null;
  const keyInfo = event.keyInfo || {};
  const id = crypto.createHash('sha256')
    .update([sessionId, event.algorithm, event.operation, JSON.stringify(keyInfo), callSite].join('|'))
    .digest('hex').slice(0, 32);
  const parsedKeySize = Number(keyInfo.keySize);
  return {
    id,
    scanId: event.scanId,
    filePath: callFile,
    lineNumber,
    algorithm: event.algorithm,
    library: 'Runtime API',
    usage: event.operation,
    operation: event.operation,
    callSite,
    mode: keyInfo.mode || null,
    curve: keyInfo.curve || null,
    hash: keyInfo.hash || null,
    observedAt: event.timestamp || null,
    keySize: Number.isFinite(parsedKeySize) && parsedKeySize > 0 ? parsedKeySize : null,
    quantumStatus: classification.quantumStatus,
    severity: classification.severity,
    description: classification.description,
    recommendation: classification.recommendation,
    confidence: 'Observed|runtime',
    detection: 'RUNTIME',
    detection_method: 'runtime',
    language: event.language || 'JavaScript',
    source: 'runtime',
    count: event.count,
  };
}

module.exports = { classifyRuntimeEvent, runtimeEventToFinding };