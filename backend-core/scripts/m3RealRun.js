'use strict';

const prisma = require('../src/utils/prismaClient');
const { findingsToCryptoAssets } = require('../src/services/quantumRisk/adapter');
const { assessThreat } = require('../src/services/quantumRisk/threatModel/index');
const { loadDefaultScenarios } = require('../src/services/quantumRisk/threatModel/scenarios');
const { computeDataExposure } = require('../src/services/quantumRisk/hndl/exposure');
const { generateSchedule } = require('../src/services/quantumRisk/scheduler/index');

async function run() {
  const scanId = process.argv[2];
  if (!scanId) {
    console.error("Usage: node backend-core/scripts/m3RealRun.js <scanId>");
    process.exit(1);
  }

  try {
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) {
      console.log("Scan not found.");
      return process.exit(0);
    }

    const findings = await prisma.finding.findMany({ where: { scanId, suppressed: false } });
    if (findings.length === 0) {
      console.log("Zero findings.");
      return process.exit(0);
    }

    const sensitiveFields = await prisma.sensitiveDataField.findMany({ where: { scanId } });
    if (sensitiveFields.length === 0) {
      console.log('Zero persisted sensitive fields ("rescan with HNDL_SCAN_HOOK=true").');
      return process.exit(0);
    }

    const customScenarios = await prisma.threatScenario.findMany({ where: { scanId } });
    const scenarios = [...loadDefaultScenarios(), ...customScenarios];
    
    // 1. Adapter
    const assets = findingsToCryptoAssets(findings);
    
    // 2. Assess threat
    const threatResult = assessThreat({ assets, scenarios });

    // 3. Compute data exposure
    const exposureResult = computeDataExposure({ fields: sensitiveFields, assets, scenarios });

    // 4. Build schedule input
    // The default scenario is usually the first one (e.g. median)
    const baseScenarioId = scenarios[0].id;
    const scenarioResult = threatResult.byScenario[baseScenarioId] || [];
    const resultByAsset = new Map(scenarioResult.map(r => [r.assetId, r]));

    const tasks = assets.map((asset) => {
      const res = resultByAsset.get(asset.assetId);
      const pMosca = res ? (res.pMoscaViolated || 0) : 0;
      return {
        taskId: asset.assetId,
        durationMonths: asset.migrationMonths || 3,
        peopleNeeded: asset.peopleNeeded || 1,
        dependsOn: asset.dependsOn || [],
        deadlineMonth: asset.deadlineMonth || null,
        exposureWeightPerMonth: pMosca,
      };
    });

    if (!process.env.PYTHON_BIN) {
      process.env.PYTHON_BIN = process.platform === 'win32' ? 'python' : 'python3';
    }

    // 5. Generate schedule
    const schedule = await generateSchedule({ tasks, teamCapacity: 5, horizonMonths: 60, timeLimitSeconds: 5 });
    
    // Print report
    console.log("--- M3 Real Run Report ---");
    console.log(`Counts: ${findings.length} findings, ${assets.length} assets, ${sensitiveFields.length} sensitive fields`);
    
    console.log("\nHIGH/CRITICAL assets per scenario:");
    for (const scen of scenarios) {
      const summary = threatResult.summary[scen.id];
      if (summary) {
        console.log(`  ${scen.name}: ${summary.assetsAtHighOrCritical}`);
      }
    }

    console.log("\nTop 5 exposed fields:");
    const sortedExposures = [...exposureResult.exposures].sort((a, b) => (b.pExposedMax || 0) - (a.pExposedMax || 0)).slice(0, 5);
    for (const exp of sortedExposures) {
      // Find one algorithm from protecting assets
      let algo = 'unknown';
      if (exp.protectingAssetIds && exp.protectingAssetIds.length > 0) {
        const pAsset = assets.find(a => a.assetId === exp.protectingAssetIds[0]);
        if (pAsset) algo = pAsset.algorithm;
      }
      const loc = exp.location || 'unknown';
      const maskedLoc = loc.substring(0, Math.min(20, loc.length)) + (loc.length > 20 ? '...' : '');
      const ret = `${exp.retentionYears || 0}y (${exp.retentionSource || 'unknown'})`;
      const p = (exp.pExposedMax || 0).toFixed(4);
      const conf = (exp.lineageConfidence || 0).toFixed(2);
      
      console.log(`  Class: ${exp.dataClass}, Loc: ${maskedLoc}, Algo: ${algo}, Ret: ${ret}, P: ${p}, Conf: ${conf}`);
    }

    console.log("\nFields with protection unknown:");
    for (const unp of exposureResult.unprotected) {
      console.log(`  Class: ${unp.dataClass}, Loc: ${unp.location}, Reason: ${unp.reason}`);
    }

    if (schedule.solverStatus === 'ERROR' && schedule.message === 'Scheduler runtime unavailable') {
      console.log("\nSchedule skipped: Python/ortools unavailable.");
    } else {
      console.log("\nSchedule Results:");
      console.log(`  Waves: ${schedule.waves ? schedule.waves.length : 0}`);
      console.log(`  Optimized Exposure: ${schedule.totalExposure}`);
      console.log(`  Baseline Exposure: ${schedule.baselineTotalExposure}`);
      console.log(`  Improvement: ${schedule.improvementPct ? schedule.improvementPct.toFixed(1) : 0}%`);
    }
  } catch (err) {
    console.log(`Error: ${err.message}`);
  } finally {
    await prisma.$disconnect();
  }
}

run();
