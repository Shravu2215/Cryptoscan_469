'use strict';

/** Authenticated Feature 1 API. Assets are read-only; only scenario/result records are written. */

const express = require('express');
const fs = require('fs');
const path = require('path');
const { requireAuth } = require('../middleware/auth');
const prisma = require('../utils/prismaClient');
const { canAccessRepo } = require('../utils/authz');
const { findingsToCryptoAssets, componentsToCryptoAssets } = require('../services/quantumRisk/adapter');
const {
  validateThreatScenarioCreateInput,
  validateThreatScenarioPatch,
  validateThreatModelRunInput,
  validateThreatModelSweepInput,
  validateScenarioIdsQuery,
} = require('../services/quantumRisk/schemas');
const { loadDefaultScenarios, cloneScenarioForEdit, validateScenario } = require('../services/quantumRisk/threatModel/scenarios');
const { assessThreat, buildHeatmap, sweepArrivalShift } = require('../services/quantumRisk/threatModel');
const { DEFAULT_ITERATIONS, DEFAULT_SEED } = require('../services/quantumRisk/threatModel/monteCarlo');
const { detectSensitiveData, linkFieldsToAssets, computeDataExposure } = require('../services/quantumRisk/hndl');
const { SENSITIVITY_WEIGHTS } = require('../services/quantumRisk/hndl/exposure');
const { DEFAULT_RETENTION_POLICY } = require('../services/quantumRisk/hndl/retention');
const { SIGNAL_WEIGHTS } = require('../services/quantumRisk/hndl/lineage');
const { generateSchedule, buildBaselineSchedule } = require('../services/quantumRisk/scheduler');


const router = express.Router({ mergeParams: true });
const ASSET_LIMIT = 5000;
const SCENARIO_LIMIT = 10;
const SENSITIVITY_VARIATION_LIMIT = 9;
const SCHEDULE_TIME_LIMIT_SENSITIVITY = 5;
const ENGINE_VERSION = '1.0.0';
const DEV_SAMPLE_SCAN_ID = 'dev-quantum-sample';
const DEFAULT_SHIFTS = Array.from({ length: 11 }, (_, index) => index - 5);
const DEFAULT_SCENARIOS = loadDefaultScenarios();
const DEFAULT_SCENARIO_IDS = new Set(DEFAULT_SCENARIOS.map((scenario) => scenario.id));
const SAMPLE_CBOM_PATH = path.resolve(__dirname, '../../test/quantumRisk/fixtures/sampleCbom.json');

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

router.use(requireAuth, async (req, res, next) => {
  try {
    let scan;
    try {
      scan = await prisma.scan.findUnique({
        where: { id: req.params.scanId },
        include: { repo: true },
      });
    } catch (error) {
      if (!(req.params.scanId === DEV_SAMPLE_SCAN_ID && isDevelopment(req))) throw error;
    }
    
    if (!scan) {
      const { getScan } = require('../utils/devStore');
      scan = getScan(req.params.scanId);
    }

    if (!scan && req.params.scanId === DEV_SAMPLE_SCAN_ID && isDevelopment(req)) {
      scan = { id: DEV_SAMPLE_SCAN_ID, repo: { uploadedBy: req.user.id }, isDevelopmentSample: true };
    }
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.repo && !canAccessRepo(req.user, scan.repo)) {
      return res.status(403).json({ error: 'You do not have access to this scan' });
    }
    req.quantumRiskScan = scan;
    return next();
  } catch (err) {
    console.error('Quantum-risk ownership check error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

function validationError(res, validation) {
  return res.status(400).json({ error: validation.errors.join('; ') || 'Invalid request body' });
}

function isDevelopment(req) {
  if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test') return true;
  if (process.env.NODE_ENV) return false;
  return ['localhost', '127.0.0.1'].includes(String(req?.hostname || '').toLowerCase());
}

function serializeSavedScenario(row) {
  return {
    id: row.id,
    name: 'custom',
    displayName: row.name,
    familyTimelines: row.familyTimelines,
    source: row.source,
    citationNote: row.citationNote,
    editable: Boolean(row.editable),
    createdBy: row.createdBy,
  };
}

function assumptionsFor(scenarios) {
  return Object.fromEntries(scenarios.map((scenario) => [scenario.id, {
    source: scenario.source,
    citationNote: scenario.citationNote,
  }]));
}

async function getSavedScenarios(scanId) {
  return prisma.threatScenario.findMany({
    where: { scanId },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
  });
}

async function getAllScenarios(scanId) {
  const saved = await getSavedScenarios(scanId);
  return [
    ...DEFAULT_SCENARIOS,
    ...saved.map(serializeSavedScenario),
  ];
}

async function getScenario(scanId, scenarioId) {
  const defaultScenario = DEFAULT_SCENARIOS.find((scenario) => scenario.id === scenarioId);
  if (defaultScenario) return defaultScenario;
  const saved = await prisma.threatScenario.findFirst({ where: { id: scenarioId, scanId } });
  return saved ? serializeSavedScenario(saved) : null;
}

function developmentSampleAssets() {
  const fixture = JSON.parse(fs.readFileSync(SAMPLE_CBOM_PATH, 'utf8'));
  return componentsToCryptoAssets(fixture.components);
}

async function loadAssetsForScan(scanId, useDevSample = false, req) {
  if (useDevSample) {
    if (!isDevelopment(req)) throw new HttpError(400, 'Sample data is available only in development');
    return developmentSampleAssets();
  }
  const findings = await prisma.finding.findMany({
    where: { scanId, suppressed: false },
    orderBy: { id: 'asc' },
    take: ASSET_LIMIT + 1,
  });
  if (findings.length > ASSET_LIMIT) throw new HttpError(400, `A scan may contain at most ${ASSET_LIMIT} crypto assets`);
  return findingsToCryptoAssets(findings);
}

function interval95(probability, iterations) {
  const error = 1.96 * Math.sqrt((probability * (1 - probability)) / iterations);
  return { lower: Math.max(0, probability - error), upper: Math.min(1, probability + error) };
}

function assessmentFromRow(row, asset, scenario) {
  const pBreakBeforeMigration = Number(row.pBreakBeforeMigration);
  const pMoscaViolated = Number(row.pMoscaViolated);
  const familyTimelinePresent = Boolean(
    scenario && (scenario.familyTimelines[asset?.family] || (asset?.family === 'DH' && scenario.familyTimelines['DH/DSA']))
  );
  return {
    assetId: row.assetId,
    scenarioId: row.scenarioId,
    dataLifetimeYears: Number(row.dataLifetimeYears),
    migrationTimeYears: Number(row.migrationTimeYears),
    pBreakBeforeMigration,
    pMoscaViolated,
    pBreakBeforeMigrationCI95: interval95(pBreakBeforeMigration, row.iterations),
    pMoscaViolatedCI95: interval95(pMoscaViolated, row.iterations),
    p10: Number(row.p10),
    p50: Number(row.p50),
    p90: Number(row.p90),
    riskBand: row.riskBand,
    iterations: row.iterations,
    seed: row.seed,
    lowConfidenceFamily: asset ? asset.family === 'OTHER' || !familyTimelinePresent : false,
  };
}

function summarizeAssessments(assessments) {
  let expectedAssetsViolated = 0;
  let maxP = 0;
  let assetsAtHighOrCritical = 0;
  for (const assessment of assessments) {
    expectedAssetsViolated += assessment.pMoscaViolated;
    maxP = Math.max(maxP, assessment.pMoscaViolated);
    if (assessment.riskBand === 'HIGH' || assessment.riskBand === 'CRITICAL') assetsAtHighOrCritical += 1;
  }
  return {
    assetsAtHighOrCritical,
    expectedAssetsViolated,
    maxP,
    meanP: assessments.length ? expectedAssetsViolated / assessments.length : 0,
  };
}

function resultMeta(rows) {
  let latest = null;
  for (const row of rows) {
    const date = row.createdAt ? new Date(row.createdAt) : null;
    if (date && Number.isFinite(date.getTime()) && (!latest || date > latest)) latest = date;
  }
  const newest = rows[0];
  return {
    seed: newest ? newest.seed : DEFAULT_SEED,
    iterations: newest ? newest.iterations : DEFAULT_ITERATIONS,
    generatedAt: latest ? latest.toISOString() : null,
    engineVersion: ENGINE_VERSION,
  };
}

async function loadResultContext(scanId, requestedScenarioIds = null, req) {
  const scenarios = await getAllScenarios(scanId);
  let selected = scenarios;
  if (requestedScenarioIds) {
    const validation = validateScenarioIdsQuery(requestedScenarioIds);
    if (!validation.valid) throw new HttpError(400, validation.errors.join('; '));
    const byId = new Map(scenarios.map((scenario) => [scenario.id, scenario]));
    for (const id of requestedScenarioIds) {
      if (!byId.has(id)) throw new HttpError(404, `Unknown scenario: ${id}`);
    }
    selected = requestedScenarioIds.map((id) => byId.get(id));
  }

  const scenarioIds = selected.map((scenario) => scenario.id);
  const rows = scenarioIds.length
    ? await prisma.threatAssessment.findMany({
      where: { scanId, scenarioId: { in: scenarioIds } },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    })
    : [];
  let assets = await loadAssetsForScan(scanId, false, req);
  if (isDevelopment(req) && rows.length > 0 && !rows.some((row) => assets.some((asset) => asset.assetId === row.assetId))) {
    const sampleAssets = developmentSampleAssets();
    if (rows.some((row) => sampleAssets.some((asset) => asset.assetId === row.assetId))) assets = sampleAssets;
  }

  const assetsById = new Map(assets.map((asset) => [asset.assetId, asset]));
  const scenariosById = new Map(selected.map((scenario) => [scenario.id, scenario]));
  const byScenario = Object.fromEntries(selected.map((scenario) => [scenario.id, []]));
  for (const row of rows) {
    if (!byScenario[row.scenarioId]) continue;
    byScenario[row.scenarioId].push(assessmentFromRow(row, assetsById.get(row.assetId), scenariosById.get(row.scenarioId)));
  }
  const summary = Object.fromEntries(Object.entries(byScenario).map(([id, assessments]) => [id, summarizeAssessments(assessments)]));
  return { scenarios: selected, rows, assets, byScenario, summary, meta: resultMeta(rows) };
}

async function handleRouteError(res, error, context) {
  if (error instanceof HttpError) return res.status(error.status).json({ error: error.message });
  if (error instanceof TypeError || error instanceof RangeError) return res.status(400).json({ error: error.message });
  console.error(`${context}:`, error);
  return res.status(500).json({ error: 'Internal server error' });
}

router.get('/scenarios', async (req, res) => {
  try {
    const scenarios = await getAllScenarios(req.params.scanId);
    return res.json({ scenarios, assumptions: assumptionsFor(scenarios), engineVersion: ENGINE_VERSION });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk scenario list error');
  }
});

router.post('/scenarios', async (req, res) => {
  try {
    const validation = validateThreatScenarioCreateInput(req.body);
    if (!validation.valid) return validationError(res, validation);
    const savedScenarios = await getSavedScenarios(req.params.scanId);
    if (DEFAULT_SCENARIOS.length + savedScenarios.length >= SCENARIO_LIMIT) {
      return res.status(400).json({ error: `A scan may have at most ${SCENARIO_LIMIT} scenarios` });
    }
    const base = await getScenario(req.params.scanId, req.body.basedOn);
    if (!base) return res.status(404).json({ error: 'Base scenario not found' });
    const patch = req.body.patch;
    const scenario = cloneScenarioForEdit(base, { ...patch, name: 'custom' });
    scenario.source = patch.source;
    scenario.citationNote = patch.citationNote;
    scenario.displayName = patch.name;
    scenario.createdBy = req.user.id;
    validateScenario(scenario);
    const saved = await prisma.threatScenario.create({
      data: {
        scanId: req.params.scanId,
        name: patch.name,
        familyTimelines: scenario.familyTimelines,
        source: scenario.source,
        citationNote: scenario.citationNote,
        editable: true,
        createdBy: req.user.id,
      },
    });
    const result = serializeSavedScenario(saved);
    return res.status(201).json({ scenario: result, assumptions: assumptionsFor([result]), engineVersion: ENGINE_VERSION });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk scenario create error');
  }
});

router.put('/scenarios/:id', async (req, res) => {
  try {
    if (DEFAULT_SCENARIO_IDS.has(req.params.id)) return res.status(400).json({ error: 'Default scenarios cannot be edited' });
    const validation = validateThreatScenarioPatch(req.body && (req.body.patch || req.body));
    if (!validation.valid) return validationError(res, validation);
    const saved = await prisma.threatScenario.findFirst({ where: { id: req.params.id, scanId: req.params.scanId } });
    if (!saved) return res.status(404).json({ error: 'Custom scenario not found' });
    if (!saved.editable) return res.status(400).json({ error: 'This scenario is not editable' });
    const base = serializeSavedScenario(saved);
    const patch = req.body.patch || req.body;
    const scenario = cloneScenarioForEdit(base, { ...patch, name: 'custom' });
    scenario.source = patch.source;
    scenario.citationNote = patch.citationNote;
    scenario.displayName = patch.name;
    scenario.createdBy = saved.createdBy;
    validateScenario(scenario);
    const updated = await prisma.threatScenario.update({
      where: { id: saved.id },
      data: {
        name: patch.name,
        familyTimelines: scenario.familyTimelines,
        source: scenario.source,
        citationNote: scenario.citationNote,
      },
    });
    const result = serializeSavedScenario(updated);
    return res.json({ scenario: result, assumptions: assumptionsFor([result]), engineVersion: ENGINE_VERSION });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk scenario update error');
  }
});

router.delete('/scenarios/:id', async (req, res) => {
  try {
    if (DEFAULT_SCENARIO_IDS.has(req.params.id)) return res.status(400).json({ error: 'Default scenarios cannot be deleted' });
    const saved = await prisma.threatScenario.findFirst({ where: { id: req.params.id, scanId: req.params.scanId } });
    if (!saved) return res.status(404).json({ error: 'Custom scenario not found' });
    if (!saved.editable) return res.status(400).json({ error: 'This scenario cannot be deleted' });
    await prisma.$transaction(async (tx) => {
      await tx.threatAssessment.deleteMany({ where: { scanId: req.params.scanId, scenarioId: saved.id } });
      await tx.threatScenario.delete({ where: { id: saved.id } });
    });
    return res.json({ deleted: true, id: saved.id, assumptions: assumptionsFor([serializeSavedScenario(saved)]), engineVersion: ENGINE_VERSION });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk scenario delete error');
  }
});

router.post('/threat-model/run', async (req, res) => {
  try {
    const validation = validateThreatModelRunInput(req.body);
    if (!validation.valid) return validationError(res, validation);
    if (req.body.devSample && !isDevelopment(req)) return res.status(400).json({ error: 'Sample data is available only in development' });
    const scenarios = await Promise.all(req.body.scenarioIds.map((id) => getScenario(req.params.scanId, id)));
    const missingScenario = req.body.scenarioIds.findIndex((_, index) => !scenarios[index]);
    if (missingScenario >= 0) return res.status(404).json({ error: `Unknown scenario: ${req.body.scenarioIds[missingScenario]}` });
    const assets = await loadAssetsForScan(req.params.scanId, req.body.devSample === true, req);
    const assetIds = new Set(assets.map((asset) => asset.assetId));
    const unknownOverride = Object.keys(req.body.overrides || {}).find((assetId) => !assetIds.has(assetId));
    if (unknownOverride) return res.status(400).json({ error: `Override references unknown asset: ${unknownOverride}` });
    const generatedAt = new Date().toISOString();
    const result = assessThreat({
      assets,
      scenarios,
      options: {
        iterations: req.body.iterations,
        seed: req.body.seed,
        overrides: req.body.overrides,
        generatedAt,
      },
    });
    await prisma.$transaction(async (tx) => {
      for (const scenario of scenarios) {
        await tx.threatAssessment.deleteMany({ where: { scanId: req.params.scanId, scenarioId: scenario.id } });
        const assessments = result.byScenario[scenario.id];
        if (assessments.length) {
          await tx.threatAssessment.createMany({
            data: assessments.map((assessment) => ({
              scanId: req.params.scanId,
              assetId: assessment.assetId,
              scenarioId: assessment.scenarioId,
              dataLifetimeYears: assessment.dataLifetimeYears,
              migrationTimeYears: assessment.migrationTimeYears,
              pBreakBeforeMigration: assessment.pBreakBeforeMigration,
              pMoscaViolated: assessment.pMoscaViolated,
              p10: assessment.p10,
              p50: assessment.p50,
              p90: assessment.p90,
              riskBand: assessment.riskBand,
              iterations: assessment.iterations,
              seed: assessment.seed,
            })),
          });
        }
      }
    });
    const heatmap = buildHeatmap(result.byScenario, assets, { rows: 'service', metric: 'pMoscaViolated' });
    return res.json({
      ...result,
      heatmap,
      assets,
      assumptions: assumptionsFor(scenarios),
      engineVersion: ENGINE_VERSION,
      ...(assets.length === 0 ? { message: 'No non-suppressed findings were found for this scan.' } : {}),
    });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk assessment run error');
  }
});

router.get('/threat-model/heatmap', async (req, res) => {
  try {
    const rows = req.query.rows || 'service';
    const metric = req.query.metric || 'pMoscaViolated';
    if (!['service', 'family', 'asset'].includes(rows)) return res.status(400).json({ error: 'rows must be service, family, or asset' });
    if (!['pMoscaViolated', 'pBreakBeforeMigration'].includes(metric)) return res.status(400).json({ error: 'metric is unsupported' });
    const allScenarios = await getAllScenarios(req.params.scanId);
    const scenarioIds = req.query.scenarioIds === undefined
      ? allScenarios.map((scenario) => scenario.id)
      : String(req.query.scenarioIds).split(',').filter(Boolean);
    const validation = validateScenarioIdsQuery(scenarioIds);
    if (scenarioIds.length && !validation.valid) return validationError(res, validation);
    const context = await loadResultContext(req.params.scanId, scenarioIds.length ? scenarioIds : null, req);
    const heatmap = buildHeatmap(context.byScenario, context.assets, { rows, metric });
    return res.json({
      heatmap,
      assumptions: assumptionsFor(context.scenarios),
      engineVersion: ENGINE_VERSION,
      meta: context.meta,
      ...(context.assets.length === 0 ? { message: 'No non-suppressed findings were found for this scan.' } : {}),
    });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk heatmap error');
  }
});

router.get('/threat-model', async (req, res) => {
  try {
    const context = await loadResultContext(req.params.scanId, null, req);
    const heatmap = buildHeatmap(context.byScenario, context.assets, { rows: 'service', metric: 'pMoscaViolated' });
    return res.json({
      byScenario: context.byScenario,
      summary: context.summary,
      heatmap,
      assets: context.assets,
      meta: context.meta,
      assumptions: assumptionsFor(context.scenarios),
      engineVersion: ENGINE_VERSION,
      ...(context.assets.length === 0 ? { message: 'No non-suppressed findings were found for this scan.' } : {}),
    });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk persisted result error');
  }
});

router.post('/threat-model/sweep', async (req, res) => {
  try {
    const validation = validateThreatModelSweepInput(req.body);
    if (!validation.valid) return validationError(res, validation);
    if (req.body.devSample && !isDevelopment(req)) return res.status(400).json({ error: 'Sample data is available only in development' });
    const scenario = await getScenario(req.params.scanId, req.body.scenarioId);
    if (!scenario) return res.status(404).json({ error: `Unknown scenario: ${req.body.scenarioId}` });
    const assets = await loadAssetsForScan(req.params.scanId, req.body.devSample === true, req);
    if (assets.length > ASSET_LIMIT) return res.status(400).json({ error: `A scan may contain at most ${ASSET_LIMIT} crypto assets` });
    const assetIds = new Set(assets.map((asset) => asset.assetId));
    const unknownOverride = Object.keys(req.body.overrides || {}).find((assetId) => !assetIds.has(assetId));
    if (unknownOverride) return res.status(400).json({ error: `Override references unknown asset: ${unknownOverride}` });
    const shifts = req.body.shifts || DEFAULT_SHIFTS;
    const iterations = req.body.iterations || DEFAULT_ITERATIONS;
    const seed = req.body.seed ?? DEFAULT_SEED;
    const result = sweepArrivalShift(assets, scenario, shifts, {
      iterations,
      seed,
      overrides: req.body.overrides || {},
      generatedAt: new Date().toISOString(),
    });
    const heatmap = buildHeatmap(result.byScenario, assets, {
      rows: req.body.rows || 'service',
      metric: req.body.metric || 'pMoscaViolated',
    });
    const assumptions = Object.fromEntries(Object.keys(result.byScenario).map((id) => [id, {
      source: scenario.source,
      citationNote: scenario.citationNote,
    }]));
    return res.json({
      ...result,
      heatmap,
      assets,
      assumptions,
      engineVersion: ENGINE_VERSION,
      ...(assets.length === 0 ? { message: 'No non-suppressed findings were found for this scan.' } : {}),
    });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk arrival sweep error');
  }
});

function getDevSampleSourceFiles() {
  const schemaPath = path.resolve(__dirname, '../../test/quantumRisk/fixtures/sampleSchema.sql');
  const schemaContent = fs.existsSync(schemaPath) ? fs.readFileSync(schemaPath, 'utf8') : '';
  return [
    {
      filePath: 'schema/sampleSchema.sql',
      content: schemaContent || 'CREATE TABLE identity_records (\n  aadhaar_number VARCHAR(12),\n  pan_number VARCHAR(10)\n);',
    },
    {
      filePath: 'services/payments/src/keys.ts',
      content: 'const aadhaarNumber = row.aadhaarNumber;\nconst cardNumber = row.cardNumber;\nencrypt(aadhaarNumber);',
    },
    {
      filePath: 'services/records/src/keys.ts',
      content: 'const diagnosis = patient.diagnosis;\nconst panNumber = user.panNumber;\nencrypt(diagnosis);',
    },
  ];
}

function loadSourceFilesForScan(scan, useDevSample, req) {
  if (useDevSample || scan.id === DEV_SAMPLE_SCAN_ID || scan.isDevelopmentSample) {
    if (!isDevelopment(req)) throw new HttpError(400, 'Sample data is available only in development');
    return getDevSampleSourceFiles();
  }

  const repoPath = scan.repo && scan.repo.filePath;
  if (!repoPath) {
    throw new HttpError(400, 'File contents are not available for this scan after completion. Use devSample in development.');
  }

  const absoluteRepoPath = path.isAbsolute(repoPath) ? repoPath : path.resolve(__dirname, '../../../', repoPath);
  if (!fs.existsSync(absoluteRepoPath)) {
    throw new HttpError(400, 'File contents are not available for this scan after completion. Use devSample in development.');
  }

  const files = [];
  function scanDir(dir) {
    if (files.length >= 20000) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (files.length >= 20000) break;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (['node_modules', '.git', 'dist', 'build', '.venv'].includes(entry.name)) continue;
        scanDir(fullPath);
      } else if (entry.isFile()) {
        const stat = fs.statSync(fullPath);
        if (stat.size > 1024 * 1024) continue;
        const relativePath = path.relative(absoluteRepoPath, fullPath).replace(/\\/g, '/');
        const content = fs.readFileSync(fullPath, 'utf8');
        files.push({ filePath: relativePath, content });
      }
    }
  }

  const stat = fs.statSync(absoluteRepoPath);
  if (stat.isFile()) {
    files.push({ filePath: path.basename(absoluteRepoPath), content: fs.readFileSync(absoluteRepoPath, 'utf8') });
  } else if (stat.isDirectory()) {
    scanDir(absoluteRepoPath);
  }

  return files;
}

router.post('/hndl/run', async (req, res) => {
  try {
    const { scenarioIds, iterations = DEFAULT_ITERATIONS, seed = DEFAULT_SEED, retentionOverrides, devSample } = req.body || {};

    if (devSample && !isDevelopment(req)) {
      return res.status(400).json({ error: 'Sample data is available only in development' });
    }

    if (!Number.isInteger(iterations) || iterations < 1 || iterations > 100000) {
      return res.status(400).json({ error: 'iterations must be an integer between 1 and 100000' });
    }

    if (scenarioIds !== undefined) {
      if (!Array.isArray(scenarioIds) || scenarioIds.length > SCENARIO_LIMIT) {
        return res.status(400).json({ error: `scenarioIds cannot exceed ${SCENARIO_LIMIT} scenarios` });
      }
    }

    let scenarios;
    if (Array.isArray(scenarioIds) && scenarioIds.length > 0) {
      scenarios = await Promise.all(scenarioIds.map((id) => getScenario(req.params.scanId, id)));
      const missingIndex = scenarioIds.findIndex((_, idx) => !scenarios[idx]);
      if (missingIndex >= 0) {
        return res.status(404).json({ error: `Unknown scenario: ${scenarioIds[missingIndex]}` });
      }
    } else {
      scenarios = DEFAULT_SCENARIOS;
    }

    let fields = [];
    let assets = [];
    let detectStats = { filesScanned: 0, filesSkipped: [], byClass: {}, truncated: false };

    const isDevSampleScan = Boolean(devSample || req.params.scanId === DEV_SAMPLE_SCAN_ID || (req.quantumRiskScan && req.quantumRiskScan.isDevelopmentSample));

    if (isDevSampleScan) {
      const files = getDevSampleSourceFiles();
      assets = await loadAssetsForScan(req.params.scanId, true, req);
      const detectResult = detectSensitiveData({ files, options: { overrides: retentionOverrides } });
      detectStats = detectResult.stats;
      fields = linkFieldsToAssets({ fields: detectResult.fields, assets, files });
    } else {
      const dbFields = await prisma.sensitiveDataField.findMany({
        where: { scanId: req.params.scanId },
      });

      if (!dbFields || dbFields.length === 0) {
        const assumptions = {
          sensitivityWeights: SENSITIVITY_WEIGHTS,
          retentionDefaults: DEFAULT_RETENTION_POLICY,
          lineageWeights: SIGNAL_WEIGHTS,
          scenarios: assumptionsFor(scenarios),
        };
        return res.json({
          fields: [],
          exposures: [],
          unprotected: [],
          summary: { byScenario: {}, byField: {}, skipped: [] },
          message: 'No HNDL data for this scan; rescan with HNDL_SCAN_HOOK enabled',
          assumptions,
          meta: { engineVersion: ENGINE_VERSION, seed, iterations, generatedAt: new Date().toISOString() },
        });
      }

      assets = await loadAssetsForScan(req.params.scanId, false, req);

      fields = dbFields.map((f) => {
        const loc = typeof f.location === 'object' && f.location ? f.location : {};
        const override = retentionOverrides && retentionOverrides[f.fieldId];
        const retentionYears = override && Number.isFinite(override.retentionYears)
          ? override.retentionYears
          : f.retentionYears;

        return {
          fieldId: f.fieldId,
          dataClass: f.dataClass,
          location: loc,
          column: loc.column || (f.location && f.location.column) || null,
          retentionYears,
          retentionSource: override ? 'override' : f.retentionSource,
          protectedBy: f.protectedBy || [],
          detectionConfidence: f.detectionConfidence || 0,
          lineageConfidence: f.lineageConfidence || 0,
          lineageStatus: loc.lineageStatus || (f.protectedBy && f.protectedBy.length ? 'linked' : 'no_crypto_found'),
          evidence: f.evidence || [],
        };
      });
    }

    const exposureResult = computeDataExposure({
      fields,
      assets,
      scenarios,
      options: {
        iterations,
        seed,
        overrides: retentionOverrides,
      },
    });

    await prisma.$transaction(async (tx) => {
      if (isDevSampleScan) {
        await tx.sensitiveDataField.deleteMany({ where: { scanId: req.params.scanId } });
        if (fields.length > 0) {
          await tx.sensitiveDataField.createMany({
            data: fields.map((f) => ({
              scanId: req.params.scanId,
              fieldId: f.fieldId,
              dataClass: f.dataClass,
              location: {
                ...(f.location || {}),
                lineageStatus: f.lineageStatus,
                column: f.column || (f.location && f.location.column) || null,
              },
              retentionYears: f.retentionYears,
              retentionSource: f.retentionSource,
              protectedBy: f.protectedBy || [],
              detectionConfidence: f.detectionConfidence || 0,
              lineageConfidence: f.lineageConfidence || 0,
              evidence: f.evidence || [],
            })),
          });
        }
      }

      await tx.dataExposure.deleteMany({ where: { scanId: req.params.scanId } });
      if (exposureResult.exposures.length > 0) {
        await tx.dataExposure.createMany({
          data: exposureResult.exposures.map((e) => ({
            scanId: req.params.scanId,
            fieldId: e.fieldId,
            assetId: e.assetId,
            scenarioId: e.scenarioId,
            exposureProbability: e.exposureProbability,
            sensitivityWeight: e.sensitivityWeight,
            retentionYears: e.retentionYears,
            explanation: e.explanation,
          })),
        });
      }
    });

    const assumptions = {
      sensitivityWeights: SENSITIVITY_WEIGHTS,
      retentionDefaults: DEFAULT_RETENTION_POLICY,
      lineageWeights: SIGNAL_WEIGHTS,
      scenarios: assumptionsFor(scenarios),
    };

    return res.json({
      fields,
      exposures: exposureResult.exposures,
      unprotected: exposureResult.unprotected,
      summary: exposureResult.summary,
      stats: detectStats,
      assumptions,
      meta: exposureResult.meta,
    });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk HNDL run error');
  }
});


router.get('/hndl', async (req, res) => {
  try {
    const fields = await prisma.sensitiveDataField.findMany({
      where: { scanId: req.params.scanId },
    });
    const exposures = await prisma.dataExposure.findMany({
      where: { scanId: req.params.scanId },
    });

    const scenarioIds = [...new Set(exposures.map((e) => e.scenarioId))];
    const byScenario = {};
    for (const scenarioId of scenarioIds) {
      const scenarioExposures = exposures.filter((e) => e.scenarioId === scenarioId);
      const fieldMaxMap = new Map();
      for (const exp of scenarioExposures) {
        const riskScore = exp.exposureProbability * exp.sensitivityWeight;
        const existing = fieldMaxMap.get(exp.fieldId);
        if (!existing || riskScore > existing.riskScore) {
          fieldMaxMap.set(exp.fieldId, { ...exp, riskScore });
        }
      }

      let highCriticalCount = 0;
      let expectedFieldsExposed = 0;
      const fieldSummaries = [];

      for (const [fId, topExp] of fieldMaxMap.entries()) {
        expectedFieldsExposed += topExp.exposureProbability;
        if (topExp.exposureProbability >= 0.2) {
          highCriticalCount += 1;
        }
        fieldSummaries.push({
          fieldId: fId,
          riskScore: topExp.riskScore,
          exposureProbability: topExp.exposureProbability,
          assetId: topExp.assetId,
        });
      }

      fieldSummaries.sort((a, b) => b.riskScore - a.riskScore);
      byScenario[scenarioId] = {
        highCriticalCount,
        expectedFieldsExposed,
        top5Fields: fieldSummaries.slice(0, 5),
      };
    }

    const byField = {};
    for (const exp of exposures) {
      const riskScore = exp.exposureProbability * exp.sensitivityWeight;
      const existing = byField[exp.fieldId];
      if (!existing || exp.exposureProbability > existing.worstCaseProbability) {
        byField[exp.fieldId] = {
          worstCaseProbability: exp.exposureProbability,
          worstCaseAssetId: exp.assetId,
          scenarioId: exp.scenarioId,
          worstCaseRiskScore: riskScore,
        };
      }
    }

    const unprotected = fields
      .filter((f) => !f.protectedBy || f.protectedBy.length === 0 || f.lineageConfidence === 0)
      .map((f) => ({
        fieldId: f.fieldId,
        dataClass: f.dataClass,
        location: f.location,
        reason: 'protection unknown',
      }));

    const assumptions = {
      sensitivityWeights: SENSITIVITY_WEIGHTS,
      retentionDefaults: DEFAULT_RETENTION_POLICY,
      lineageWeights: SIGNAL_WEIGHTS,
    };

    return res.json({
      fields,
      exposures,
      unprotected,
      summary: {
        byScenario,
        byField,
        skipped: [],
      },
      assumptions,
      meta: {
        engineVersion: ENGINE_VERSION,
        totalFields: fields.length,
        totalExposures: exposures.length,
      },
    });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk HNDL get error');
  }
});

router.get('/hndl/fields/:fieldId', async (req, res) => {
  try {
    const field = await prisma.sensitiveDataField.findFirst({
      where: { scanId: req.params.scanId, fieldId: req.params.fieldId },
    });
    if (!field) {
      return res.status(404).json({ error: 'Field not found' });
    }

    const exposures = await prisma.dataExposure.findMany({
      where: { scanId: req.params.scanId, fieldId: req.params.fieldId },
    });

    const assumptions = {
      sensitivityWeights: SENSITIVITY_WEIGHTS,
      retentionDefaults: DEFAULT_RETENTION_POLICY,
      lineageWeights: SIGNAL_WEIGHTS,
    };

    return res.json({
      field,
      exposures,
      assumptions,
      meta: {
        engineVersion: ENGINE_VERSION,
      },
    });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk HNDL field get error');
  }
});

// ── Schedule routes (Feature 2) ─────────────────────────────────────────────

/**
 * Load tasks for a schedule run from the scan's non-suppressed findings.
 * Tasks are derived from crypto assets via adapter; each asset becomes a task.
 * Falls back to dev sample fixture when devSample=true.
 */
async function loadScheduleTasksForScan(scan, assets, scenarioResult) {
  // Build tasks from assets: each asset is a migration task.
  // Duration, peopleNeeded, dependsOn and exposureWeightPerMonth come from
  // the asset's Monte Carlo result (if available) or sane defaults.
  return assets.map((asset) => {
    const result = scenarioResult && scenarioResult[asset.assetId];
    const pMosca = result ? (result.pMoscaViolated || 0) : 0;
    return {
      taskId: asset.assetId,
      durationMonths: asset.migrationMonths || 3,
      peopleNeeded: asset.peopleNeeded || 1,
      dependsOn: asset.dependsOn || [],
      deadlineMonth: asset.deadlineMonth || null,
      exposureWeightPerMonth: pMosca,
    };
  });
}

/**
 * POST /schedule/run
 * Body: { tasks[], teamCapacity, horizonMonths, timeLimitSeconds?, devSample? }
 * Runs the CP-SAT scheduler and persists the result.
 */
router.post('/schedule/run', async (req, res) => {
  try {
    const {
      tasks,
      teamCapacity,
      horizonMonths,
      timeLimitSeconds = 30,
      devSample,
    } = req.body || {};

    if (devSample && !isDevelopment(req)) {
      return res.status(400).json({ error: 'Sample data is available only in development' });
    }

    if (!Array.isArray(tasks) || tasks.length === 0) {
      return res.status(400).json({ error: 'tasks must be a non-empty array' });
    }
    if (tasks.length > 500) {
      return res.status(400).json({ error: 'tasks cannot exceed 500' });
    }
    if (!Number.isFinite(teamCapacity) || teamCapacity < 1 || teamCapacity > 100) {
      return res.status(400).json({ error: 'teamCapacity must be between 1 and 100' });
    }
    if (!Number.isFinite(horizonMonths) || horizonMonths < 1 || horizonMonths > 120) {
      return res.status(400).json({ error: 'horizonMonths must be between 1 and 120' });
    }
    if (!Number.isFinite(timeLimitSeconds) || timeLimitSeconds < 1 || timeLimitSeconds > 30) {
      return res.status(400).json({ error: 'timeLimitSeconds must be between 1 and 30' });
    }

    const result = await generateSchedule({
      tasks,
      teamCapacity,
      horizonMonths,
      timeLimitSeconds,
    });

    const responseData = {
      ...result,
      engineVersion: ENGINE_VERSION,
      meta: {
        teamCapacity,
        horizonMonths,
        taskCount: tasks.length,
        generatedAt: new Date().toISOString(),
      },
    };

    await prisma.$transaction(async (tx) => {
      await tx.migrationSchedule.deleteMany({ where: { scanId: req.params.scanId } });
      await tx.migrationSchedule.create({
        data: {
          scanId: req.params.scanId,
          input: { tasks, teamCapacity, horizonMonths, timeLimitSeconds },
          result: responseData,
        }
      });
    });

    return res.json(responseData);
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk schedule run error');
  }
});

/**
 * GET /schedule
 * Returns the latest persisted schedule result for the scan (from threat assessments).
 * Since schedule results are not yet stored in a dedicated table, this
 * returns the task list derived from findings with risk weights from stored assessments.
 */
router.get('/schedule', async (req, res) => {
  try {
    const schedule = await prisma.migrationSchedule.findFirst({
      where: { scanId: req.params.scanId },
      orderBy: { createdAt: 'desc' },
    });
    
    if (schedule) {
      return res.json({
        ...schedule.result,
        tasks: schedule.input.tasks,
        hasAssessments: true,
      });
    }

    const assets = await loadAssetsForScan(req.params.scanId, false, req);
    const latestAssessments = await prisma.threatAssessment.findMany({
      where: { scanId: req.params.scanId },
      orderBy: [{ createdAt: 'desc' }],
    });

    // Build a risk-weight map from stored assessments (max pMoscaViolated per asset)
    const riskMap = new Map();
    for (const row of latestAssessments) {
      const existing = riskMap.get(row.assetId);
      const p = Number(row.pMoscaViolated || 0);
      if (!existing || p > existing) riskMap.set(row.assetId, p);
    }

    const tasks = assets.map((asset) => ({
      taskId: asset.assetId,
      algorithm: asset.algorithm,
      family: asset.family,
      service: asset.service,
      filePath: asset.filePath,
      durationMonths: asset.migrationMonths || 3,
      peopleNeeded: asset.peopleNeeded || 1,
      dependsOn: asset.dependsOn || [],
      deadlineMonth: asset.deadlineMonth || null,
      exposureWeightPerMonth: riskMap.get(asset.assetId) || 0,
    }));

    return res.json({
      tasks,
      hasAssessments: latestAssessments.length > 0,
      engineVersion: ENGINE_VERSION,
      meta: {
        taskCount: tasks.length,
        assessmentCount: latestAssessments.length,
        generatedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk schedule get error');
  }
});

/**
 * POST /schedule/sensitivity
 * Body: {
 *   tasks[],
 *   teamCapacity, horizonMonths,
 *   variations: [{ label, teamCapacity?, horizonMonths?, deadlineShiftMonths? }]  (max 9)
 * }
 * Runs generateSchedule per variation (time limit 5 s each). NOT persisted.
 * Returns [{ label, totalExposure, baselineTotalExposure, improvementPct,
 *            solverStatus, makespanMonths, waveCount, changedTaskIds }]
 */
router.post('/schedule/sensitivity', async (req, res) => {
  try {
    const { tasks, teamCapacity, horizonMonths, variations } = req.body || {};

    if (!Array.isArray(tasks) || tasks.length === 0) {
      return res.status(400).json({ error: 'tasks must be a non-empty array' });
    }
    if (!Number.isFinite(teamCapacity) || teamCapacity < 1) {
      return res.status(400).json({ error: 'teamCapacity must be a positive number' });
    }
    if (!Number.isFinite(horizonMonths) || horizonMonths < 1) {
      return res.status(400).json({ error: 'horizonMonths must be a positive number' });
    }
    if (!Array.isArray(variations) || variations.length === 0) {
      return res.status(400).json({ error: 'variations must be a non-empty array' });
    }
    if (variations.length > SENSITIVITY_VARIATION_LIMIT) {
      return res.status(400).json({ error: `variations cannot exceed ${SENSITIVITY_VARIATION_LIMIT}` });
    }
    for (const v of variations) {
      if (!v || typeof v.label !== 'string' || !v.label.trim()) {
        return res.status(400).json({ error: 'Each variation must have a non-empty label string' });
      }
    }

    // Run base schedule to get comparison point
    const baseResult = await generateSchedule({
      tasks,
      teamCapacity,
      horizonMonths,
      timeLimitSeconds: SCHEDULE_TIME_LIMIT_SENSITIVITY,
    });
    const baseTotalExposure = baseResult.totalExposure || 0;
    const baseGanttMap = new Map((baseResult.ganttRows || []).map((r) => [r.taskId, r]));

    // Run each variation
    const results = await Promise.all(variations.map(async (variation) => {
      const varCapacity = Number.isFinite(variation.teamCapacity) ? variation.teamCapacity : teamCapacity;
      const varHorizon = Number.isFinite(variation.horizonMonths) ? variation.horizonMonths : horizonMonths;
      const deadlineShift = Number.isFinite(variation.deadlineShiftMonths) ? variation.deadlineShiftMonths : 0;

      // Apply deadline shift to tasks if requested
      const varTasks = deadlineShift !== 0
        ? tasks.map((t) => ({
          ...t,
          deadlineMonth: t.deadlineMonth != null ? Math.max(1, t.deadlineMonth + deadlineShift) : null,
        }))
        : tasks;

      let varResult;
      try {
        varResult = await generateSchedule({
          tasks: varTasks,
          teamCapacity: varCapacity,
          horizonMonths: varHorizon,
          timeLimitSeconds: SCHEDULE_TIME_LIMIT_SENSITIVITY,
        });
      } catch (_err) {
        varResult = {
          solverStatus: 'ERROR',
          waves: [],
          ganttRows: [],
          totalExposure: baseTotalExposure,
          message: _err.message,
        };
      }

      const varTotalExposure = varResult.totalExposure || 0;
      const improvementPct = baseTotalExposure > 0
        ? Math.round(((baseTotalExposure - varTotalExposure) / baseTotalExposure) * 10000) / 100
        : 0;

      // Find tasks whose startMonth differs from the base run
      const changedTaskIds = [];
      for (const row of (varResult.ganttRows || [])) {
        const base = baseGanttMap.get(row.taskId);
        if (!base || base.startMonth !== row.startMonth) {
          changedTaskIds.push(row.taskId);
        }
      }

      const makespanMonths = varResult.ganttRows && varResult.ganttRows.length > 0
        ? Math.max(...varResult.ganttRows.map((r) => r.endMonth))
        : 0;

      return {
        label: variation.label,
        totalExposure: varTotalExposure,
        baselineTotalExposure: baseTotalExposure,
        improvementPct,
        solverStatus: varResult.solverStatus,
        message: varResult.message,
        makespanMonths,
        waveCount: (varResult.waves || []).length,
        changedTaskIds,
        ganttRows: varResult.ganttRows || [],
        waves: varResult.waves || [],
      };
    }));

    return res.json({
      base: {
        totalExposure: baseTotalExposure,
        solverStatus: baseResult.solverStatus,
        message: baseResult.message,
        makespanMonths: baseResult.ganttRows && baseResult.ganttRows.length > 0
          ? Math.max(...baseResult.ganttRows.map((r) => r.endMonth))
          : 0,
        waveCount: (baseResult.waves || []).length,
        ganttRows: baseResult.ganttRows || [],
        waves: baseResult.waves || [],
      },
      variations: results,
      engineVersion: ENGINE_VERSION,
      meta: {
        taskCount: tasks.length,
        variationCount: results.length,
        generatedAt: new Date().toISOString(),
        note: 'ASSUMPTION — results not persisted; re-run to refresh',
      },
    });
  } catch (error) {
    return handleRouteError(res, error, 'Quantum-risk schedule sensitivity error');
  }
});

router.all('*', (req, res) => {

  return res.status(501).json({
    error: 'This quantum-risk feature is not implemented yet',
    assumptions: {},
    engineVersion: ENGINE_VERSION,
  });
});

module.exports = router;