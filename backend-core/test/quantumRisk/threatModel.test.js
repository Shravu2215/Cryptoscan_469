'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { componentsToCryptoAssets } = require('../../src/services/quantumRisk/adapter');
const {
	loadDefaultScenarios,
	validateScenario,
	cloneScenarioForEdit,
	ScenarioValidationError,
} = require('../../src/services/quantumRisk/threatModel/scenarios');
const {
	RISK_BAND_THRESHOLDS,
	deterministicMosca,
	riskBandFromProbability,
} = require('../../src/services/quantumRisk/threatModel/mosca');
const {
	DistributionParameterError,
	mulberry32,
	sampleTriangular,
	sampleNormal,
	sampleLognormal,
	runMonteCarlo,
} = require('../../src/services/quantumRisk/threatModel/monteCarlo');
const {
	assessThreat,
	buildHeatmap,
	sweepArrivalShift,
} = require('../../src/services/quantumRisk/threatModel');

function makeAsset(assetId, family = 'RSA', usage = 'data_encryption', keySize = 2048, service = 'payments') {
	return {
		assetId,
		findingId: `finding-${assetId}`,
		algorithm: family,
		family,
		keySize,
		usage,
		filePath: `services/${service}/src/crypto.js`,
		lineNumber: 1,
		service,
		confidence: 0.9,
		sources: ['static'],
	};
}

function makeScenario(id, params, name = 'custom', family = 'RSA', distribution = 'triangular') {
	return {
		id,
		name,
		familyTimelines: { [family]: { distribution, params } },
		source: 'ASSUMPTION',
		citationNote: 'ASSUMPTION - editable, cite before final demo',
		editable: true,
		createdBy: 'test',
	};
}

function runTests() {
	const custom = makeScenario('test-rsa', { min: 10, mode: 20, max: 30 });
	const asset = makeAsset('rsa-1', 'RSA', 'key_exchange');

	// Same seed and inputs are identical; a distinct seed varies within MC error.
	const first = runMonteCarlo({ scenario: custom, assets: [asset], options: { iterations: 5000, seed: 7 } });
	const repeated = runMonteCarlo({ scenario: custom, assets: [asset], options: { iterations: 5000, seed: 7 } });
	const differentSeed = runMonteCarlo({ scenario: custom, assets: [asset], options: { iterations: 5000, seed: 8 } });
	assert.deepStrictEqual(first, repeated);
	const p1 = first[0].pMoscaViolated;
	const p2 = differentSeed[0].pMoscaViolated;
	const seedDifferenceLimit = 3 * Math.sqrt((p1 * (1 - p1) + p2 * (1 - p2)) / 5000);
	assert.notStrictEqual(p1, p2);
	assert(Math.abs(p1 - p2) <= seedDifferenceLimit, 'seed variation should remain within three combined standard errors');
	assert(first[0].pMoscaViolatedCI95.lower <= p1 && first[0].pMoscaViolatedCI95.upper >= p1);

	// More retained lifetime or migration time cannot reduce either probability.
	const override = (dataLifetimeYears, migrationTimeYears) => runMonteCarlo({
		scenario: custom,
		assets: [asset],
		options: { iterations: 4000, seed: 11, overrides: { 'rsa-1': { dataLifetimeYears, migrationTimeYears } } },
	})[0];
	const baseline = override(5, 2);
	const longerData = override(12, 2);
	const longerMigration = override(5, 8);
	assert(longerData.pMoscaViolated >= baseline.pMoscaViolated);
	assert(longerMigration.pMoscaViolated >= baseline.pMoscaViolated);
	assert(longerMigration.pBreakBeforeMigration >= baseline.pBreakBeforeMigration);

	// The default scenario ordering means later Z is less risky.
	const defaults = loadDefaultScenarios();
	const ordered = assessThreat({ assets: [asset], scenarios: defaults, options: { iterations: 5000, seed: 4 } });
	const optimisticP = ordered.byScenario['scenario-optimistic-v1'][0].pMoscaViolated;
	const medianP = ordered.byScenario['scenario-median-v1'][0].pMoscaViolated;
	const pessimisticP = ordered.byScenario['scenario-pessimistic-v1'][0].pMoscaViolated;
	assert(pessimisticP >= medianP && medianP >= optimisticP);

	// PQC is exact zero; signature X is forced to zero, including overrides.
	const pqc = runMonteCarlo({ scenario: custom, assets: [makeAsset('pqc', 'PQC', 'key_exchange')], options: { iterations: 20 } })[0];
	assert.deepStrictEqual(
		[pqc.pBreakBeforeMigration, pqc.pMoscaViolated, pqc.p10, pqc.p50, pqc.p90],
		[0, 0, 0, 0, 0]
	);
	const signature = runMonteCarlo({
		scenario: custom,
		assets: [makeAsset('sig', 'RSA', 'digital_signature')],
		options: { iterations: 1000, seed: 1, overrides: { sig: { dataLifetimeYears: 50, migrationTimeYears: 0 } } },
	})[0];
	assert.strictEqual(signature.dataLifetimeYears, 0);
	assert.strictEqual(signature.pMoscaViolated, signature.pBreakBeforeMigration);
	assert.strictEqual(signature.pBreakBeforeMigration, 0);

	const future = runMonteCarlo({
		scenario: makeScenario('far-future', { min: 100000, mode: 120000, max: 150000 }),
		assets: [asset],
		options: { iterations: 1000 },
	})[0];
	assert.strictEqual(future.pMoscaViolated, 0);
	const past = runMonteCarlo({
		scenario: makeScenario('far-past', { min: -100, mode: -90, max: -80 }),
		assets: [asset],
		options: { iterations: 1000 },
	})[0];
	assert.strictEqual(past.pMoscaViolated, 1);
	assert.strictEqual(past.pBreakBeforeMigration, 1);

	// For triangular Z=[5,10,20], P(Z < 12) has a closed-form CDF of 1 - 64/150.
	const analyticalScenario = makeScenario('analytical', { min: 5, mode: 10, max: 20 });
	const analyticalAsset = makeAsset('analytic', 'RSA', 'key_exchange');
	const analytical = runMonteCarlo({
		scenario: analyticalScenario,
		assets: [analyticalAsset],
		options: { iterations: 50000, seed: 123, overrides: { analytic: { dataLifetimeYears: 10, migrationTimeYears: 2 } } },
	})[0];
	const expected = 1 - ((20 - 12) ** 2 / ((20 - 5) * (20 - 10)));
	const analyticalSe = Math.sqrt((expected * (1 - expected)) / 50000);
	assert(Math.abs(analytical.pMoscaViolated - expected) <= 3 * analyticalSe);

	// RSA/DH size nudges later; AES-128 receives less Grover margin than AES-256.
	const rsa2048 = runMonteCarlo({
		scenario: makeScenario('rsa-size', { min: 5, mode: 15, max: 30 }),
		assets: [makeAsset('rsa-2048', 'RSA', 'data_encryption', 2048)],
		options: { iterations: 5000, seed: 31, overrides: { 'rsa-2048': { dataLifetimeYears: 10, migrationTimeYears: 2 } } },
	})[0];
	const rsa4096 = runMonteCarlo({
		scenario: makeScenario('rsa-size', { min: 5, mode: 15, max: 30 }),
		assets: [makeAsset('rsa-4096', 'RSA', 'data_encryption', 4096)],
		options: { iterations: 5000, seed: 31, overrides: { 'rsa-4096': { dataLifetimeYears: 10, migrationTimeYears: 2 } } },
	})[0];
	assert(rsa2048.pMoscaViolated >= rsa4096.pMoscaViolated);
	const dh2048 = runMonteCarlo({
		scenario: makeScenario('dh-size', { min: 5, mode: 15, max: 30 }),
		assets: [makeAsset('dh-2048', 'DH', 'data_encryption', 2048)],
		options: { iterations: 5000, seed: 31, overrides: { 'dh-2048': { dataLifetimeYears: 10, migrationTimeYears: 2 } } },
	})[0];
	const dh4096 = runMonteCarlo({
		scenario: makeScenario('dh-size', { min: 5, mode: 15, max: 30 }),
		assets: [makeAsset('dh-4096', 'DH', 'data_encryption', 4096)],
		options: { iterations: 5000, seed: 31, overrides: { 'dh-4096': { dataLifetimeYears: 10, migrationTimeYears: 2 } } },
	})[0];
	assert(dh2048.pMoscaViolated >= dh4096.pMoscaViolated);
	const aesScenario = makeScenario('aes-grover', { min: 15, mode: 30, max: 50 }, 'custom', 'AES');
	const aes128 = runMonteCarlo({
		scenario: aesScenario,
		assets: [makeAsset('aes-128', 'AES', 'data_encryption', 128)],
		options: { iterations: 5000, seed: 32, overrides: { 'aes-128': { dataLifetimeYears: 20, migrationTimeYears: 2 } } },
	})[0];
	const aes256 = runMonteCarlo({
		scenario: aesScenario,
		assets: [makeAsset('aes-256', 'AES', 'data_encryption', 256)],
		options: { iterations: 5000, seed: 32, overrides: { 'aes-256': { dataLifetimeYears: 20, migrationTimeYears: 2 } } },
	})[0];
	assert(aes128.pMoscaViolated > aes256.pMoscaViolated);
	const other = runMonteCarlo({ scenario: custom, assets: [makeAsset('other', 'OTHER')], options: { iterations: 100 } })[0];
	assert.strictEqual(other.lowConfidenceFamily, true);

	// Signature ignores retained-data lifetime; encryption includes it.
	const sigVsEncryption = runMonteCarlo({
		scenario: custom,
		assets: [makeAsset('sig-2', 'RSA', 'jwt'), makeAsset('enc-2', 'RSA', 'data_encryption')],
		options: {
			iterations: 3000,
			seed: 19,
			overrides: {
				'sig-2': { dataLifetimeYears: 50, migrationTimeYears: 4 },
				'enc-2': { dataLifetimeYears: 50, migrationTimeYears: 4 },
			},
		},
	});
	assert.strictEqual(sigVsEncryption[0].dataLifetimeYears, 0);
	assert.strictEqual(sigVsEncryption[0].pMoscaViolated, sigVsEncryption[0].pBreakBeforeMigration);
	assert.strictEqual(sigVsEncryption[1].dataLifetimeYears, 50);
	assert(sigVsEncryption[1].pMoscaViolated >= sigVsEncryption[0].pMoscaViolated);

	// Overrides, validation, cloning, deterministic Mosca, and sampler errors.
	const overridden = runMonteCarlo({
		scenario: custom,
		assets: [asset],
		options: { iterations: 50, overrides: { 'rsa-1': { dataLifetimeYears: 3.5, migrationTimeYears: 1.25 } } },
	})[0];
	assert.strictEqual(overridden.dataLifetimeYears, 3.5);
	assert.strictEqual(overridden.migrationTimeYears, 1.25);
	const original = JSON.parse(JSON.stringify(custom));
	const edited = cloneScenarioForEdit(custom, { familyTimelines: { RSA: { params: { mode: 21 } }, ECC: { distribution: 'normal', params: { mean: 20, sd: 2 } } }, source: 'ignored' });
	assert.deepStrictEqual(custom, original);
	assert.strictEqual(edited.name, 'custom');
	assert.strictEqual(edited.editable, true);
	assert.strictEqual(edited.source, custom.source);
	assert.strictEqual(edited.citationNote, custom.citationNote);
	assert.strictEqual(edited.familyTimelines.RSA.params.mode, 21);
	assert(validateScenario(edited));
	assert.throws(() => validateScenario({ ...custom, citationNote: '' }), ScenarioValidationError);
	assert.throws(() => sampleTriangular({ min: 3, mode: 1, max: 5 }, mulberry32(1)), DistributionParameterError);
	assert.throws(() => sampleNormal({ mean: 0, sd: -1 }, mulberry32(1)), DistributionParameterError);
	assert.throws(() => sampleLognormal({ mean: 0, sd: 1 }, mulberry32(1)), DistributionParameterError);
	assert(Number.isFinite(sampleNormal({ mean: 10, sd: 2 }, mulberry32(7))));
	assert(sampleLognormal({ mean: 10, sd: 2 }, mulberry32(7)) > 0);
	assert(Number.isFinite(sampleTriangular({ min: 1, mode: 2, max: 3 }, mulberry32(7))));
	assert.deepStrictEqual(deterministicMosca(3, 2, 4), { violated: true, marginYears: -1 });
	assert.deepStrictEqual(RISK_BAND_THRESHOLDS, { MINIMAL_MAX: 0.01, LOW_MAX: 0.05, MODERATE_MAX: 0.2, HIGH_MAX: 0.5 });
	assert.deepStrictEqual([0, 0.01, 0.05, 0.2, 0.5].map(riskBandFromProbability), ['MINIMAL', 'LOW', 'MODERATE', 'HIGH', 'CRITICAL']);

	// Heatmap and arrival-shift sensitivity outputs.
	const heatmap = buildHeatmap(ordered.byScenario, [asset], { rows: 'service', metric: 'pMoscaViolated' });
	assert.deepStrictEqual(heatmap.rows, ['payments']);
	assert.strictEqual(heatmap.columns.length, 3);
	assert.strictEqual(heatmap.cells.length, 1);
	const swept = sweepArrivalShift([asset], defaults[1], [-5, 0, 5], { iterations: 1500, seed: 42 });
	const shiftIds = Object.keys(swept.byScenario);
	assert.strictEqual(shiftIds.length, 3);
	assert(swept.byScenario[shiftIds[0]][0].pMoscaViolated >= swept.byScenario[shiftIds[2]][0].pMoscaViolated);
	const otherShift = sweepArrivalShift([makeAsset('other-shift', 'OTHER')], defaults[1], [-5, 5], { iterations: 1000, seed: 42 });
	const otherShiftIds = Object.keys(otherShift.byScenario);
	assert(otherShift.byScenario[otherShiftIds[0]][0].pMoscaViolated >= otherShift.byScenario[otherShiftIds[1]][0].pMoscaViolated);

	// 500 assets x 10,000 iterations is the accepted loose performance budget.
	const manyAssets = Array.from({ length: 500 }, (_, index) => makeAsset(`perf-${index}`, 'RSA', 'key_exchange'));
	const started = Date.now();
	const performanceResult = runMonteCarlo({ scenario: custom, assets: manyAssets, options: { iterations: 10000, seed: 9 } });
	const elapsedMs = Date.now() - started;
	assert.strictEqual(performanceResult.length, 500);
	assert(elapsedMs < 5000, `500 x 10,000 simulation took ${elapsedMs}ms`);

	// Use all fixture occurrences and print a compact scenario summary.
	const fixturePath = path.join(__dirname, 'fixtures', 'sampleCbom.json');
	const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
	const fixtureAssets = componentsToCryptoAssets(fixture.components);
	assert.strictEqual(fixtureAssets.length, 12);
	assert.strictEqual(new Set(fixtureAssets.map((item) => item.service)).size, 3);
	const fixtureResult = assessThreat({ assets: fixtureAssets, scenarios: defaults, options: { iterations: 10000, seed: 42 } });
	console.log('\nFixture scenario results (expected assets violated = sum of per-asset probabilities)');
	console.log('scenario       high/critical  expected-violated  max-p  mean-p');
	for (const scenario of defaults) {
		const row = fixtureResult.summary[scenario.id];
		console.log(`${scenario.name.padEnd(14)}${String(row.assetsAtHighOrCritical).padEnd(15)}${row.expectedAssetsViolated.toFixed(3).padEnd(19)}${row.maxP.toFixed(3).padEnd(7)}${row.meanP.toFixed(3)}`);
	}

	console.log(`\nThreat-model tests passed; performance: ${elapsedMs}ms.`);
}

runTests();