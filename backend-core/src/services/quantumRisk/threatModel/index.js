'use strict';

/** Pure orchestration, summaries, heatmap aggregation, and arrival-shift sweeps. */

const { validateCryptoAsset } = require('../schemas');
const { cloneScenarioForEdit, getFamilyTimeline, validateScenario } = require('./scenarios');
const { runMonteCarlo, DEFAULT_ITERATIONS, DEFAULT_SEED } = require('./monteCarlo');

const ENGINE_VERSION = '1.0.0';

function assertAssets(assets) {
	if (!Array.isArray(assets)) throw new TypeError('assets must be an array');
	for (const asset of assets) {
		const validation = validateCryptoAsset(asset);
		if (!validation.valid) throw new TypeError(`Invalid CryptoAsset: ${validation.errors.join('; ')}`);
	}
}

function summarize(assessments) {
	let expectedAssetsViolated = 0;
	let maxP = 0;
	let assetsAtHighOrCritical = 0;
	for (const assessment of assessments) {
		const probability = assessment.pMoscaViolated;
		expectedAssetsViolated += probability;
		if (probability > maxP) maxP = probability;
		if (assessment.riskBand === 'HIGH' || assessment.riskBand === 'CRITICAL') assetsAtHighOrCritical += 1;
	}
	return {
		assetsAtHighOrCritical,
		expectedAssetsViolated,
		maxP,
		meanP: assessments.length ? expectedAssetsViolated / assessments.length : 0,
	};
}

/**
 * Assess every asset under each scenario without IO or mutation.
 * `generatedAt` is caller-supplied (or null) to keep this function deterministic.
 */
function assessThreat({ assets, scenarios, options = {} } = {}) {
	assertAssets(assets);
	if (!Array.isArray(scenarios) || scenarios.length === 0) throw new TypeError('scenarios must be a non-empty array');
	const scenarioIds = new Set();
	const byScenario = {};
	const summary = {};

	for (const scenario of scenarios) {
		validateScenario(scenario);
		if (scenarioIds.has(scenario.id)) throw new TypeError(`duplicate scenario id: ${scenario.id}`);
		scenarioIds.add(scenario.id);
		const assessments = runMonteCarlo({ scenario, assets, options });
		byScenario[scenario.id] = assessments;
		summary[scenario.id] = summarize(assessments);
	}

	return {
		byScenario,
		summary,
		meta: {
			seed: options.seed ?? DEFAULT_SEED,
			iterations: options.iterations ?? DEFAULT_ITERATIONS,
			generatedAt: options.generatedAt ?? null,
			engineVersion: ENGINE_VERSION,
		},
	};
}

/**
 * Aggregate row probabilities by arithmetic mean. Asset rows retain each
 * asset's raw probability; service/family rows represent the mean within group.
 */
function buildHeatmap(assessmentsByScenario, assets, { rows, metric } = {}) {
	assertAssets(assets);
	if (!assessmentsByScenario || typeof assessmentsByScenario !== 'object' || Array.isArray(assessmentsByScenario)) {
		throw new TypeError('assessmentsByScenario must be an object keyed by scenarioId');
	}
	if (!['service', 'family', 'asset'].includes(rows)) throw new TypeError('rows must be service, family, or asset');
	if (!['pMoscaViolated', 'pBreakBeforeMigration'].includes(metric)) throw new TypeError('unsupported heatmap metric');

	const groupFor = (asset) => {
		if (rows === 'asset') return asset.assetId;
		if (rows === 'family') return asset.family;
		return asset.service || 'Unknown service';
	};
	const assetsByRow = new Map();
	for (const asset of assets) {
		const row = groupFor(asset);
		if (!assetsByRow.has(row)) assetsByRow.set(row, []);
		assetsByRow.get(row).push(asset.assetId);
	}

	const columns = Object.keys(assessmentsByScenario).sort();
	const rowLabels = [...assetsByRow.keys()].sort((left, right) => left.localeCompare(right));
	const cells = rowLabels.map((row) => columns.map((scenarioId) => {
		const valuesByAsset = new Map();
		for (const assessment of assessmentsByScenario[scenarioId] || []) {
			if (Number.isFinite(assessment[metric])) valuesByAsset.set(assessment.assetId, assessment[metric]);
		}
		let sum = 0;
		let count = 0;
		for (const assetId of assetsByRow.get(row)) {
			if (valuesByAsset.has(assetId)) {
				sum += valuesByAsset.get(assetId);
				count += 1;
			}
		}
		return count ? sum / count : null;
	}));
	return { rows: rowLabels, columns, cells };
}

function shiftTimeline(timeline, delta) {
	const params = { ...timeline.params };
	if (timeline.distribution === 'triangular') {
		params.min += delta;
		params.mode += delta;
		params.max += delta;
	} else if (timeline.distribution === 'normal') {
		params.mean += delta;
	} else {
		params.mean = Math.max(Number.MIN_VALUE, params.mean + delta);
	}
	return { distribution: timeline.distribution, params };
}

/** Return assessThreat-shaped results keyed by shifted scenario IDs. */
function sweepArrivalShift(assets, scenario, shiftsYears, options = {}) {
	assertAssets(assets);
	validateScenario(scenario);
	if (!Array.isArray(shiftsYears) || shiftsYears.some((shift) => !Number.isFinite(shift))) {
		throw new TypeError('shiftsYears must be an array of finite numbers');
	}
	const byScenario = {};
	const summary = {};
	const seen = new Set();
	let meta = null;

	for (const shift of shiftsYears) {
		const label = shift >= 0 ? `+${shift}` : String(shift);
		const id = `${scenario.id}:arrival-shift:${label}`;
		if (seen.has(id)) throw new TypeError(`duplicate arrival shift: ${shift}`);
		seen.add(id);
		const timelinesToShift = { ...scenario.familyTimelines };
		if (!timelinesToShift.OTHER) {
			timelinesToShift.OTHER = getFamilyTimeline(scenario, 'OTHER');
		}
		const familyTimelines = Object.fromEntries(
			Object.entries(timelinesToShift).map(([family, timeline]) => [family, shiftTimeline(timeline, shift)])
		);
		const shiftedScenario = cloneScenarioForEdit(scenario, { id, familyTimelines });
		const result = assessThreat({ assets, scenarios: [shiftedScenario], options });
		byScenario[id] = result.byScenario[id];
		summary[id] = result.summary[id];
		meta = result.meta;
	}

	return {
		byScenario,
		summary,
		meta: meta || {
			seed: options.seed ?? DEFAULT_SEED,
			iterations: options.iterations ?? DEFAULT_ITERATIONS,
			generatedAt: options.generatedAt ?? null,
			engineVersion: ENGINE_VERSION,
		},
	};
}

module.exports = { assessThreat, buildHeatmap, sweepArrivalShift };