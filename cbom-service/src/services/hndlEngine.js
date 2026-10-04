/**
 * HNDL (Harvest-Now-Decrypt-Later) Engine
 *
 * Models quantum exposure risk based on data secrecy lifetime requirements
 * versus estimated years until a Cryptographically Relevant Quantum Computer (CRQC).
 *
 * Timeline Baseline: NIST / NSA CNSA 2.0 guidance projects CRQC emergence between
 * 2030 and 2035. Using a baseline estimate of 7 years (2033 CRQC arrival).
 */

const PURPOSE_DATA_LIFETIME = {
  data_encryption: 20,
  password_hashing: 15,
  key_exchange: 10,
  digital_signature: 5,
  mac: 5,
  random_generation: 5,
  integrity_hashing: 3,
  unknown: 10,
};

const DEFAULT_YEARS_TO_QUANTUM_THREAT = 7; // Estimated CRQC arrival: ~7 years (NIST SP 800-208 timeline)

/**
 * Calculates Mosca's Inequality: X (data lifetime) + Y (migration time) > Z (years to quantum threat)
 *
 * @param {number} migrationTimeYears - Estimated migration time Y (years)
 * @param {number} dataLifetimeYears - Data secrecy lifetime requirement X (years)
 * @param {number} [yearsToQuantumThreat=7] - Estimated time to CRQC arrival Z (years)
 */
function calculateMoscaInequality(migrationTimeYears, dataLifetimeYears, yearsToQuantumThreat = DEFAULT_YEARS_TO_QUANTUM_THREAT) {
  const X = Math.max(0.5, parseFloat(Number(migrationTimeYears || 1.5).toFixed(1)));
  const Y = Math.max(1, parseFloat(Number(dataLifetimeYears || 10).toFixed(1)));
  const Z = parseFloat(Number(yearsToQuantumThreat || DEFAULT_YEARS_TO_QUANTUM_THREAT).toFixed(1));

  const totalRequirement = parseFloat((X + Y).toFixed(1));
  const moscaInequalityHolds = totalRequirement > Z;
  const exposureWindow = Math.max(0, parseFloat((totalRequirement - Z).toFixed(1)));

  let moscaRisk = 'LOW';
  if (totalRequirement > Z) {
    moscaRisk = 'HIGH';
  } else if (totalRequirement > Z - 2) {
    moscaRisk = 'MEDIUM';
  }

  const formulaReadout = `X (${Y}y lifetime) + Y (${X}y migration) ${moscaInequalityHolds ? '>' : '≤'} Z (${Z}y threat)`;

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
 * Core HNDL function as requested by specification using Mosca's Inequality:
 * Takes (algorithm, keySize, dataLifetimeYears, migrationTimeYears) and returns:
 * { dataLifetimeYears, migrationTimeYears, yearsToQuantumThreat, hndlRisk: "high"|"medium"|"low", quantumExposureWindow, moscaInequalityHolds, formulaReadout }
 */
function calculateHndl(algorithm, keySize, dataLifetimeYears, migrationTimeYears) {
  const Y = dataLifetimeYears != null ? Number(dataLifetimeYears) : 10;
  const X = migrationTimeYears != null ? Number(migrationTimeYears) : 1.5;
  const mosca = calculateMoscaInequality(X, Y, DEFAULT_YEARS_TO_QUANTUM_THREAT);

  return {
    dataLifetimeYears: Y,
    migrationTimeYears: X,
    yearsToQuantumThreat: DEFAULT_YEARS_TO_QUANTUM_THREAT,
    hndlRisk: mosca.moscaRisk.toLowerCase(),
    quantumExposureWindow: mosca.exposureWindow,
    moscaInequalityHolds: mosca.moscaInequalityHolds,
    formulaReadout: mosca.formulaReadout,
    moscaDetails: mosca,
  };
}

/**
 * Calculates numeric HNDL risk score (0-100) for vulnerability scoring engine using Mosca's Inequality.
 *
 * @param {string} purpose - Derived purpose from purposeDetection
 * @param {number} quantumVulnerabilityScore - 0-100 quantum vulnerability score
 * @param {object} [options]
 * @param {number} [options.dataLifetimeYears] - Override secrecy requirement Y in years
 * @param {number} [options.migrationTimeYears] - Override migration time X in years
 * @param {number} [options.yearsToQuantumThreat] - Override estimated years to CRQC Z
 * @param {number} [options.affectedFilesCount=1] - Number of affected locations
 * @param {boolean} [options.isHardcoded=false] - Whether algorithm is hardcoded inline
 */
function calculateHndlRisk(purpose, quantumVulnerabilityScore, options = {}) {
  let dataLifetimeYears = options.dataLifetimeYears;
  if (dataLifetimeYears == null && options.dataSensitivity) {
    const sensMap = { HEALTH: 20, PII: 15, FINANCIAL: 12, AUTH: 5 };
    dataLifetimeYears = sensMap[options.dataSensitivity];
  }
  if (dataLifetimeYears == null) {
    dataLifetimeYears = PURPOSE_DATA_LIFETIME[purpose] || PURPOSE_DATA_LIFETIME.unknown;
  }
  const yearsToQuantumThreat = options.yearsToQuantumThreat ?? DEFAULT_YEARS_TO_QUANTUM_THREAT;

  let migrationTimeYears = options.migrationTimeYears;
  if (migrationTimeYears == null) {
    const locCount = options.affectedFilesCount || 1;
    const locMultiplier = Math.min(3.0, (locCount - 1) * 0.5);
    const agilityPenalty = options.isHardcoded ? 1.5 : 0.5;
    migrationTimeYears = parseFloat((1.0 + locMultiplier + agilityPenalty).toFixed(1));
  }

  const mosca = calculateMoscaInequality(migrationTimeYears, dataLifetimeYears, yearsToQuantumThreat);

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
    dataLifetimeYears: mosca.Y,
    migrationTimeYears: mosca.X,
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
};
