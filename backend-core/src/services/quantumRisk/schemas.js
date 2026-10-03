'use strict';

/**
 * Runtime validators for the quantum-risk contracts. Validators are pure and
 * return { valid, errors }; they do not coerce or mutate caller objects.
 *
 * @typedef {'RSA'|'ECC'|'DH'|'AES'|'HASH'|'OTHER'|'PQC'} CryptoFamily
 * @typedef {{valid:boolean, errors:string[]}} ValidationResult
 * @typedef {Object} CryptoAsset
 * @property {string} assetId @property {string} findingId @property {string} algorithm
 * @property {CryptoFamily} family @property {number|null} keySize @property {string} usage
 * @property {string} filePath @property {number|null} lineNumber @property {string|null} service
 * @property {number} confidence @property {Array<'static'|'runtime'|'network'>} sources
 * @typedef {Object} ThreatScenario
 * @property {string} id @property {'optimistic'|'median'|'pessimistic'|'custom'} name
 * @property {Object<string,{distribution:'triangular'|'normal'|'lognormal',params:Object}>} familyTimelines
 * @property {string} source @property {string} citationNote @property {boolean} editable
 * @property {string} createdBy
 * @typedef {Object} ThreatAssessment
 * @property {string} assetId @property {string} scenarioId @property {number} dataLifetimeYears
 * @property {number} migrationTimeYears @property {number} pBreakBeforeMigration
 * @property {number} pMoscaViolated @property {number} p10 @property {number} p50 @property {number} p90
 * @property {string} riskBand @property {number} iterations @property {number} seed
 * @typedef {Object} SensitiveDataField
 * @property {string} fieldId @property {'AADHAAR'|'PAN'|'PAYMENT_CARD'|'HEALTH'|'PII_OTHER'} dataClass
 * @property {Object} location @property {number} retentionYears
 * @property {'stated'|'default'|'inferred'} retentionSource @property {string[]} protectedBy
 * @property {number} detectionConfidence @property {number} lineageConfidence @property {string[]} evidence
 * @typedef {Object} DataExposure
 * @property {string} fieldId @property {string} assetId @property {string} scenarioId
 * @property {number} exposureProbability @property {number} sensitivityWeight
 * @property {number} retentionYears @property {string} explanation
 * @typedef {Object} MigrationTask
 * @property {string} taskId @property {string[]} assetIds @property {string|null} service
 * @property {number} effortPersonDays @property {string[]} dependsOn @property {string|null} deadline
 * @property {number} exposureWeightPerMonth
 * @typedef {Object} ScheduleInput
 * @property {MigrationTask[]} tasks @property {number} teamCapacityPerMonth
 * @property {number} horizonMonths @property {string} scenarioId @property {'min_exposure'} objective
 * @typedef {Object} ScheduleResult
 * @property {Array<{wave:number,startMonth:number,endMonth:number,taskIds:string[]}>} waves
 * @property {Array<{taskId:string,startMonth:number,endMonth:number}>} ganttRows
 * @property {number} totalExposure @property {number} baselineTotalExposure
 * @property {number} improvementPct @property {string} solverStatus @property {Object[]} sensitivity
 */

const CRYPTO_FAMILIES = new Set(['RSA', 'ECC', 'DH', 'AES', 'HASH', 'OTHER', 'PQC']);
const DATA_CLASSES = new Set(['AADHAAR', 'PAN', 'PAYMENT_CARD', 'HEALTH', 'PII_OTHER']);
const SOURCES = new Set(['static', 'runtime', 'network']);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function isProbability(value) {
  return isFiniteNumber(value) && value >= 0 && value <= 1;
}

function resultFor(value, errors) {
  if (!isObject(value)) errors.push('value must be an object');
  return { valid: errors.length === 0, errors };
}

function requireString(value, field, errors) {
  if (typeof value !== 'string' || value.trim() === '') errors.push(`${field} must be a non-empty string`);
}

function requireNonNegative(value, field, errors) {
  if (!isFiniteNumber(value) || value < 0) errors.push(`${field} must be a non-negative number`);
}

function validateCryptoAsset(value) {
  const errors = [];
  if (!isObject(value)) return resultFor(value, errors);
  for (const field of ['assetId', 'findingId', 'algorithm', 'usage', 'filePath']) requireString(value[field], field, errors);
  if (!CRYPTO_FAMILIES.has(value.family)) errors.push('family is not a supported CryptoFamily');
  if (value.keySize !== null && (!Number.isInteger(value.keySize) || value.keySize < 0)) errors.push('keySize must be a non-negative integer or null');
  if (value.lineNumber !== null && (!Number.isInteger(value.lineNumber) || value.lineNumber < 1)) errors.push('lineNumber must be a positive integer or null');
  if (value.service !== null && typeof value.service !== 'string') errors.push('service must be a string or null');
  if (!isProbability(value.confidence)) errors.push('confidence must be between 0 and 1');
  if (!Array.isArray(value.sources) || value.sources.some((source) => !SOURCES.has(source))) errors.push('sources must contain only static, runtime, or network');
  return resultFor(value, errors);
}

function validateThreatScenario(value) {
  const errors = [];
  if (!isObject(value)) return resultFor(value, errors);
  requireString(value.id, 'id', errors);
  if (!['optimistic', 'median', 'pessimistic', 'custom'].includes(value.name)) errors.push('name is not a supported scenario name');
  requireString(value.source, 'source', errors);
  requireString(value.citationNote, 'citationNote', errors);
  if (typeof value.editable !== 'boolean') errors.push('editable must be a boolean');
  requireString(value.createdBy, 'createdBy', errors);
  if (!isObject(value.familyTimelines) || Object.keys(value.familyTimelines).length === 0) {
    errors.push('familyTimelines must be a non-empty object');
  } else {
    for (const [family, timeline] of Object.entries(value.familyTimelines)) {
      if (!family.trim() || !isObject(timeline)) {
        errors.push(`familyTimelines.${family} must be an object`);
        continue;
      }
      if (!['triangular', 'normal', 'lognormal'].includes(timeline.distribution)) {
        errors.push(`familyTimelines.${family}.distribution is unsupported`);
        continue;
      }
      const params = timeline.params;
      if (!isObject(params)) {
        errors.push(`familyTimelines.${family}.params must be an object`);
      } else if (timeline.distribution === 'triangular') {
        for (const key of ['min', 'mode', 'max']) requireNonNegative(params[key], `familyTimelines.${family}.params.${key}`, errors);
        if (isFiniteNumber(params.min) && isFiniteNumber(params.mode) && isFiniteNumber(params.max) && !(params.min <= params.mode && params.mode <= params.max)) {
          errors.push(`familyTimelines.${family} triangular params must satisfy min <= mode <= max`);
        }
      } else {
        requireNonNegative(params.mean, `familyTimelines.${family}.params.mean`, errors);
        if (!isFiniteNumber(params.sd) || params.sd <= 0) errors.push(`familyTimelines.${family}.params.sd must be greater than 0`);
      }
    }
  }
  return resultFor(value, errors);
}

function validateThreatScenarioPatch(value) {
  const errors = [];
  if (!isObject(value)) return resultFor(value, errors);
  requireString(value.name, 'name', errors);
  if (typeof value.name === 'string' && value.name.length > 60) errors.push('name must be at most 60 characters');
  requireString(value.source, 'source', errors);
  requireString(value.citationNote, 'citationNote', errors);
  const candidate = {
    id: 'scenario-validation',
    name: 'custom',
    familyTimelines: value.familyTimelines,
    source: value.source,
    citationNote: value.citationNote,
    editable: true,
    createdBy: 'validation',
  };
  const scenarioResult = validateThreatScenario(candidate);
  scenarioResult.errors.forEach((error) => {
    if (!error.includes('source is required') && !error.includes('citationNote is required')) errors.push(error);
  });
  return resultFor(value, errors);
}

function validateThreatScenarioCreateInput(value) {
  const errors = [];
  if (!isObject(value)) return resultFor(value, errors);
  requireString(value.basedOn, 'basedOn', errors);
  const patchResult = validateThreatScenarioPatch(value.patch);
  patchResult.errors.forEach((error) => errors.push(`patch.${error}`));
  return resultFor(value, errors);
}

function validateThreatModelRunInput(value) {
  const errors = [];
  if (!isObject(value)) return resultFor(value, errors);
  if (!Array.isArray(value.scenarioIds) || value.scenarioIds.length === 0) {
    errors.push('scenarioIds must be a non-empty array');
  } else {
    if (value.scenarioIds.length > 10) errors.push('scenarioIds may contain at most 10 entries');
    if (value.scenarioIds.some((id) => typeof id !== 'string' || id.trim() === '')) errors.push('scenarioIds must contain non-empty strings');
    if (new Set(value.scenarioIds).size !== value.scenarioIds.length) errors.push('scenarioIds must be unique');
  }
  if (value.iterations !== undefined && (!Number.isInteger(value.iterations) || value.iterations < 1 || value.iterations > 100000)) {
    errors.push('iterations must be an integer from 1 to 100000');
  }
  if (value.seed !== undefined && (!Number.isInteger(value.seed) || value.seed < -2147483648 || value.seed > 2147483647)) {
    errors.push('seed must be a signed 32-bit integer');
  }
  if (value.overrides !== undefined) {
    if (!isObject(value.overrides)) {
      errors.push('overrides must be an object keyed by assetId');
    } else {
      for (const [assetId, override] of Object.entries(value.overrides)) {
        if (!assetId.trim() || !isObject(override)) {
          errors.push(`overrides.${assetId} must be an object`);
          continue;
        }
        for (const field of ['dataLifetimeYears', 'migrationTimeYears']) {
          if (override[field] !== undefined && (!isFiniteNumber(override[field]) || override[field] < 0)) {
            errors.push(`overrides.${assetId}.${field} must be non-negative`);
          }
        }
        if (Object.keys(override).some((field) => !['dataLifetimeYears', 'migrationTimeYears'].includes(field))) {
          errors.push(`overrides.${assetId} contains an unsupported field`);
        }
      }
    }
  }
  if (value.devSample !== undefined && typeof value.devSample !== 'boolean') errors.push('devSample must be a boolean');
  return resultFor(value, errors);
}

function validateThreatModelSweepInput(value) {
  const errors = [];
  if (!isObject(value)) return resultFor(value, errors);
  requireString(value.scenarioId, 'scenarioId', errors);
  if (value.shifts !== undefined) {
    if (!Array.isArray(value.shifts)) {
      errors.push('shifts must be an array');
    } else {
      if (value.shifts.length > 21) errors.push('shifts may contain at most 21 values');
      if (value.shifts.some((shift) => !Number.isInteger(shift) || shift < -5 || shift > 5)) {
        errors.push('shifts must be integer years from -5 to +5');
      }
    }
  }
  if (value.metric !== undefined && !['pMoscaViolated', 'pBreakBeforeMigration'].includes(value.metric)) errors.push('metric is unsupported');
  if (value.rows !== undefined && !['service', 'family', 'asset'].includes(value.rows)) errors.push('rows is unsupported');
  if (value.iterations !== undefined && (!Number.isInteger(value.iterations) || value.iterations < 1 || value.iterations > 100000)) {
    errors.push('iterations must be an integer from 1 to 100000');
  }
  if (value.seed !== undefined && (!Number.isInteger(value.seed) || value.seed < -2147483648 || value.seed > 2147483647)) {
    errors.push('seed must be a signed 32-bit integer');
  }
  if (value.overrides !== undefined) {
    if (!isObject(value.overrides)) {
      errors.push('overrides must be an object keyed by assetId');
    } else {
      for (const [assetId, override] of Object.entries(value.overrides)) {
        if (!assetId.trim() || !isObject(override)) {
          errors.push(`overrides.${assetId} must be an object`);
          continue;
        }
        for (const field of ['dataLifetimeYears', 'migrationTimeYears']) {
          if (override[field] !== undefined && (!isFiniteNumber(override[field]) || override[field] < 0)) {
            errors.push(`overrides.${assetId}.${field} must be non-negative`);
          }
        }
        if (Object.keys(override).some((field) => !['dataLifetimeYears', 'migrationTimeYears'].includes(field))) {
          errors.push(`overrides.${assetId} contains an unsupported field`);
        }
      }
    }
  }
  if (value.devSample !== undefined && typeof value.devSample !== 'boolean') errors.push('devSample must be a boolean');
  return resultFor(value, errors);
}

function validateScenarioIdsQuery(value) {
  const errors = [];
  if (!Array.isArray(value) || value.length === 0) {
    errors.push('scenarioIds must be a non-empty array');
  } else {
    if (value.length > 10) errors.push('scenarioIds may contain at most 10 entries');
    if (value.some((id) => typeof id !== 'string' || id.trim() === '')) errors.push('scenarioIds must contain non-empty strings');
    if (new Set(value).size !== value.length) errors.push('scenarioIds must be unique');
  }
  return { valid: errors.length === 0, errors };
}

function validateThreatAssessment(value) {
  const errors = [];
  if (!isObject(value)) return resultFor(value, errors);
  requireString(value.assetId, 'assetId', errors);
  requireString(value.scenarioId, 'scenarioId', errors);
  requireNonNegative(value.dataLifetimeYears, 'dataLifetimeYears', errors);
  requireNonNegative(value.migrationTimeYears, 'migrationTimeYears', errors);
  if (!isProbability(value.pBreakBeforeMigration)) errors.push('pBreakBeforeMigration must be between 0 and 1');
  if (!isProbability(value.pMoscaViolated)) errors.push('pMoscaViolated must be between 0 and 1');
  for (const field of ['p10', 'p50', 'p90']) requireNonNegative(value[field], field, errors);
  if ([value.p10, value.p50, value.p90].every(isFiniteNumber) && !(value.p10 <= value.p50 && value.p50 <= value.p90)) errors.push('p10, p50, and p90 must be ordered');
  requireString(value.riskBand, 'riskBand', errors);
  if (!Number.isInteger(value.iterations) || value.iterations < 1) errors.push('iterations must be a positive integer');
  if (!Number.isInteger(value.seed)) errors.push('seed must be an integer');
  return resultFor(value, errors);
}

function validateSensitiveDataField(value) {
  const errors = [];
  if (!isObject(value)) return resultFor(value, errors);
  requireString(value.fieldId, 'fieldId', errors);
  if (!DATA_CLASSES.has(value.dataClass)) errors.push('dataClass is unsupported');
  const location = value.location;
  if (!isObject(location)) {
    errors.push('location must be an object');
  } else {
    const fileLocation = typeof location.filePath === 'string' && location.filePath.trim() !== '' && Number.isInteger(location.line) && location.line > 0;
    const schemaLocation = typeof location.schemaTable === 'string' && location.schemaTable.trim() !== '' && typeof location.column === 'string' && location.column.trim() !== '';
    if (!fileLocation && !schemaLocation) errors.push('location must identify filePath+line or schemaTable+column');
  }
  requireNonNegative(value.retentionYears, 'retentionYears', errors);
  if (!['stated', 'default', 'inferred'].includes(value.retentionSource)) errors.push('retentionSource is unsupported');
  if (!Array.isArray(value.protectedBy) || value.protectedBy.some((id) => typeof id !== 'string')) errors.push('protectedBy must be an array of asset IDs');
  if (!isProbability(value.detectionConfidence)) errors.push('detectionConfidence must be between 0 and 1');
  if (!isProbability(value.lineageConfidence)) errors.push('lineageConfidence must be between 0 and 1');
  if (!Array.isArray(value.evidence) || value.evidence.some((entry) => typeof entry !== 'string')) errors.push('evidence must be an array of strings');
  return resultFor(value, errors);
}

function validateDataExposure(value) {
  const errors = [];
  if (!isObject(value)) return resultFor(value, errors);
  for (const field of ['fieldId', 'assetId', 'scenarioId', 'explanation']) requireString(value[field], field, errors);
  if (!isProbability(value.exposureProbability)) errors.push('exposureProbability must be between 0 and 1');
  requireNonNegative(value.sensitivityWeight, 'sensitivityWeight', errors);
  requireNonNegative(value.retentionYears, 'retentionYears', errors);
  return resultFor(value, errors);
}

function validateMigrationTask(value) {
  const errors = [];
  if (!isObject(value)) return resultFor(value, errors);
  requireString(value.taskId, 'taskId', errors);
  if (!Array.isArray(value.assetIds) || value.assetIds.some((id) => typeof id !== 'string')) errors.push('assetIds must be an array of strings');
  if (value.service !== null && typeof value.service !== 'string') errors.push('service must be a string or null');
  requireNonNegative(value.effortPersonDays, 'effortPersonDays', errors);
  if (!Array.isArray(value.dependsOn) || value.dependsOn.some((id) => typeof id !== 'string')) errors.push('dependsOn must be an array of task IDs');
  if (value.deadline !== null && typeof value.deadline !== 'string') errors.push('deadline must be a string or null');
  requireNonNegative(value.exposureWeightPerMonth, 'exposureWeightPerMonth', errors);
  return resultFor(value, errors);
}

function validateScheduleInput(value) {
  const errors = [];
  if (!isObject(value)) return resultFor(value, errors);
  if (!Array.isArray(value.tasks)) {
    errors.push('tasks must be an array');
  } else {
    value.tasks.forEach((task, index) => {
      const taskResult = validateMigrationTask(task);
      taskResult.errors.forEach((error) => errors.push(`tasks[${index}].${error}`));
    });
  }
  if (!isFiniteNumber(value.teamCapacityPerMonth) || value.teamCapacityPerMonth <= 0) errors.push('teamCapacityPerMonth must be greater than 0');
  if (!Number.isInteger(value.horizonMonths) || value.horizonMonths < 1) errors.push('horizonMonths must be a positive integer');
  requireString(value.scenarioId, 'scenarioId', errors);
  if (value.objective !== 'min_exposure') errors.push('objective must be min_exposure');
  return resultFor(value, errors);
}

function validateScheduleResult(value) {
  const errors = [];
  if (!isObject(value)) return resultFor(value, errors);
  if (!Array.isArray(value.waves)) {
    errors.push('waves must be an array');
  } else {
    value.waves.forEach((wave, index) => {
      if (!isObject(wave)) return errors.push(`waves[${index}] must be an object`);
      if (!Number.isInteger(wave.wave) || wave.wave < 1) errors.push(`waves[${index}].wave must be a positive integer`);
      if (!Number.isInteger(wave.startMonth) || wave.startMonth < 0) errors.push(`waves[${index}].startMonth must be a non-negative integer`);
      if (!Number.isInteger(wave.endMonth) || wave.endMonth < wave.startMonth) errors.push(`waves[${index}].endMonth must be an integer >= startMonth`);
      if (!Array.isArray(wave.taskIds) || wave.taskIds.some((id) => typeof id !== 'string')) errors.push(`waves[${index}].taskIds must be an array of strings`);
    });
  }
  if (!Array.isArray(value.ganttRows)) {
    errors.push('ganttRows must be an array');
  } else {
    value.ganttRows.forEach((row, index) => {
      if (!isObject(row)) return errors.push(`ganttRows[${index}] must be an object`);
      requireString(row.taskId, `ganttRows[${index}].taskId`, errors);
      if (!Number.isInteger(row.startMonth) || row.startMonth < 0) errors.push(`ganttRows[${index}].startMonth must be a non-negative integer`);
      if (!Number.isInteger(row.endMonth) || row.endMonth < row.startMonth) errors.push(`ganttRows[${index}].endMonth must be an integer >= startMonth`);
    });
  }
  requireNonNegative(value.totalExposure, 'totalExposure', errors);
  requireNonNegative(value.baselineTotalExposure, 'baselineTotalExposure', errors);
  if (!isFiniteNumber(value.improvementPct)) errors.push('improvementPct must be a finite number');
  requireString(value.solverStatus, 'solverStatus', errors);
  if (!Array.isArray(value.sensitivity) || value.sensitivity.some((entry) => !isObject(entry))) errors.push('sensitivity must be an array of objects');
  return resultFor(value, errors);
}

module.exports = {
  validateCryptoAsset,
  validateThreatScenario,
  validateThreatScenarioPatch,
  validateThreatScenarioCreateInput,
  validateThreatModelRunInput,
  validateThreatModelSweepInput,
  validateScenarioIdsQuery,
  validateThreatAssessment,
  validateSensitiveDataField,
  validateDataExposure,
  validateMigrationTask,
  validateScheduleInput,
  validateScheduleResult,
};