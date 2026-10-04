/**
 * HNDL (Harvest-Now-Decrypt-Later) Engine - cbom-service backend
 *
 * Models quantum exposure risk based on data secrecy lifetime requirements
 * versus estimated years until a Cryptographically Relevant Quantum Computer (CRQC).
 *
 * DEFAULT_Z = 10 years (NIST/NSA CNSA 2.0 guidance; aligned with frontend QuantumRules.DEFAULT_Z)
 * BUFFER_YEARS = 5 (safety margin for VULNERABLE_WITHIN_HORIZON category)
 *
 * DEFINITIONS (do not swap X and Y):
 *   X = Data Lifetime (years data/key must stay secret)
 *   Y = Migration Time (years to complete migration)
 *   Z = Years until CRQC (Cryptographically Relevant Quantum Computer)
 *   exposure = X + Y
 *   margin   = Z - (X + Y)
 */

const PURPOSE_DATA_LIFETIME = {
  data_encryption: 20,
  key_exchange: 10,
  password_hashing: 15,
  digital_signature: 5,
  mac: 5,
  random_generation: 5,
  integrity_hashing: 3,
  unknown: 10,
};

const DEFAULT_YEARS_TO_QUANTUM_THREAT = 10; // DEFAULT_Z = 10 years (aligned with frontend QuantumRules.DEFAULT_Z)
const BUFFER_YEARS = 5;

/**
 * Calculates Mosca's Inequality: X (data lifetime) + Y (migration time) > Z (years to quantum threat)
 *
 * CORRECT DEFINITIONS (never swap these):
 *   X = dataLifetimeYears   - how long data must stay secret
 *   Y = migrationTimeYears  - time required to complete migration
 *   Z = yearsToQuantumThreat - years until CRQC
 *
 * @param {number} dataLifetimeYears    - X: data secrecy requirement (years)
 * @param {number} migrationTimeYears   - Y: estimated migration time (years)
 * @param {number} yearsToQuantumThreat - Z: estimated CRQC arrival (years, default=10)
 */
function calculateMoscaInequality(dataLifetimeYears, migrationTimeYears, yearsToQuantumThreat = DEFAULT_YEARS_TO_QUANTUM_THREAT) {
  const X = Math.max(0.5, parseFloat(Number(dataLifetimeYears || 10).toFixed(1)));   // X = data lifetime
  const Y = Math.max(0.5, parseFloat(Number(migrationTimeYears || 1.5).toFixed(1))); // Y = migration time
  const Z = parseFloat(Number(yearsToQuantumThreat || DEFAULT_YEARS_TO_QUANTUM_THREAT).toFixed(1));

  const totalRequirement = parseFloat((X + Y).toFixed(1));
  const moscaInequalityHolds = totalRequirement > Z;
  const exposureWindow = Math.max(0, parseFloat((totalRequirement - Z).toFixed(1)));

  let moscaRisk = 'LOW';
  if (totalRequirement > Z) {
    moscaRisk = 'HIGH';
  } else if (totalRequirement > Z - BUFFER_YEARS) {
    moscaRisk = 'MEDIUM'; // within BUFFER_YEARS=5 of threat horizon
  }

  const formulaReadout = `X (${X}y lifetime) + Y (${Y}y migration) ${moscaInequalityHolds ? '>' : '\u2264'} Z (${Z}y threat)`;

  return {
    X,
    Y,
    Z,
    totalRequirement,
    moscaInequalityHolds,
    moscaRisk,
    exposureWindow,
    formulaReadout,
  };
}

/**
 * Core HNDL function using Mosca's Inequality (corrected X/Y definitions).
 * X = data lifetime years, Y = migration time years, Z = years to CRQC
 */
function calculateHndl(algorithm, keySize, dataLifetimeYears, migrationTimeYears) {
  const X = dataLifetimeYears != null ? Number(dataLifetimeYears) : 10;   // X = data lifetime
  const Y = migrationTimeYears != null ? Number(migrationTimeYears) : 1.5; // Y = migration time
  const mosca = calculateMoscaInequality(X, Y, DEFAULT_YEARS_TO_QUANTUM_THREAT);

  return {
    dataLifetimeYears: X,    // X = data lifetime
    migrationTimeYears: Y,   // Y = migration time
    yearsToQuantumThreat: DEFAULT_YEARS_TO_QUANTUM_THREAT,
    hndlRisk: mosca.moscaRisk.toLowerCase(),
    quantumExposureWindow: mosca.exposureWindow,
    moscaInequalityHolds: mosca.moscaInequalityHolds,
    formulaReadout: mosca.formulaReadout,
    moscaDetails: mosca,
  };
}

/**
 * Calculates numeric HNDL risk score (0-100) for vulnerability scoring engine.
 *
 * @param {string} purpose                   - Derived purpose from purposeDetection
 * @param {number} quantumVulnerabilityScore - 0-100 quantum vulnerability score
 * @param {object} [options]
 * @param {number} [options.dataLifetimeYears]    - Override X (data lifetime) in years
 * @param {number} [options.migrationTimeYears]   - Override Y (migration time) in years
 * @param {number} [options.yearsToQuantumThreat] - Override Z in years
 * @param {number} [options.affectedFilesCount=1] - Number of affected locations (increases Y)
 * @param {boolean} [options.isHardcoded=false]   - Whether algorithm is hardcoded inline
 */
function calculateHndlRisk(purpose, quantumVulnerabilityScore, options = {}) {
  // X: data lifetime
  let dataLifetimeYears = options.dataLifetimeYears;
  if (dataLifetimeYears == null && options.dataSensitivity) {
    const sensMap = { HEALTH: 20, PII: 15, FINANCIAL: 12, AUTH: 5 };
    dataLifetimeYears = sensMap[options.dataSensitivity];
  }
  if (dataLifetimeYears == null) {
    dataLifetimeYears = PURPOSE_DATA_LIFETIME[purpose] || PURPOSE_DATA_LIFETIME.unknown;
  }
  const yearsToQuantumThreat = options.yearsToQuantumThreat ?? DEFAULT_YEARS_TO_QUANTUM_THREAT;

  // Y: migration time (derived if not provided)
  let migrationTimeYears = options.migrationTimeYears;
  if (migrationTimeYears == null) {
    const locCount = options.affectedFilesCount || 1;
    const locMultiplier = Math.min(3.0, (locCount - 1) * 0.5);
    const agilityPenalty = options.isHardcoded ? 1.5 : 0.5;
    migrationTimeYears = parseFloat((1.0 + locMultiplier + agilityPenalty).toFixed(1));
  }

  const mosca = calculateMoscaInequality(dataLifetimeYears, migrationTimeYears, yearsToQuantumThreat);

  let hndlRisk = 0;
  if (quantumVulnerabilityScore >= 80) {
    // Asymmetric algorithms broken outright by Shor's algorithm (RSA, ECC, DH)
    if (mosca.moscaInequalityHolds) {
      hndlRisk = Math.min(100, Math.round(80 + (mosca.exposureWindow / 15) * 20));
    } else {
      hndlRisk = 60; // Still high risk due to imminent threat
    }
  } else if (quantumVulnerabilityScore >= 40) {
    // Symmetric algorithms weakened by Grover's (e.g. AES-128)
    hndlRisk = Math.min(100, Math.round(quantumVulnerabilityScore * (0.4 + (mosca.exposureWindow / 20) * 0.6)));
  } else {
    // Strong symmetric/hash (AES-256, SHA-256)
    hndlRisk = Math.round(quantumVulnerabilityScore * 0.5);
  }

  return {
    dataLifetimeYears: mosca.X,    // X = data lifetime
    migrationTimeYears: mosca.Y,   // Y = migration time
    yearsToQuantumThreat: mosca.Z,
    quantumExposureWindow: mosca.exposureWindow,
    moscaInequalityHolds: mosca.moscaInequalityHolds,
    moscaRisk: mosca.moscaRisk,
    formulaReadout: mosca.formulaReadout,
    hndlRisk,
  };
}

module.exports = {
  calculateHndl,
  calculateHndlRisk,
  calculateMoscaInequality,
  PURPOSE_DATA_LIFETIME,
  DEFAULT_YEARS_TO_QUANTUM_THREAT,
  BUFFER_YEARS,
};
