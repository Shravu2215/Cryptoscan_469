'use strict';

/** Seeded, pure Monte Carlo engine for scenario-based quantum threat assessment. */

const {
	validateScenario,
	ScenarioValidationError,
	getTimelineMultiplier,
	getFamilyTimeline,
} = require('./scenarios');
const {
	resolveMigrationDefaults,
	riskBandFromProbability,
} = require('./mosca');

const DEFAULT_ITERATIONS = 10000;
const DEFAULT_SEED = 42;
const MAX_ITERATIONS = 1000000;
const CONFIDENCE_Z_95 = 1.96;
const FAMILIES = new Set(['RSA', 'ECC', 'DH', 'AES', 'HASH', 'OTHER', 'PQC']);

class DistributionParameterError extends TypeError {
	constructor(message) {
		super(message);
		this.name = 'DistributionParameterError';
	}
}

function mulberry32(seed) {
	if (!Number.isSafeInteger(seed)) throw new TypeError('seed must be a safe integer');
	let state = seed >>> 0;
	return function random() {
		state += 0x6D2B79F5;
		let value = state;
		value = Math.imul(value ^ (value >>> 15), value | 1);
		value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
		return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
	};
}

function assertRandomSource(random) {
	if (typeof random !== 'function') throw new TypeError('random must be a function');
}

function sampleTriangular(params, random) {
	assertRandomSource(random);
	const { min, mode, max } = params || {};
	if (![min, mode, max].every(Number.isFinite) || !(min <= mode && mode <= max)) {
		throw new DistributionParameterError('triangular params require finite min <= mode <= max');
	}
	if (min === max) return min;
	const unit = random();
	if (!Number.isFinite(unit) || unit < 0 || unit >= 1) throw new DistributionParameterError('random source must return values in [0, 1)');
	const split = (mode - min) / (max - min);
	const sampled = unit < split
		? min + Math.sqrt(unit * (max - min) * (mode - min))
		: max - Math.sqrt((1 - unit) * (max - min) * (max - mode));
	if (!Number.isFinite(sampled)) throw new DistributionParameterError('triangular sample overflowed');
	return sampled;
}

function sampleStandardNormal(random) {
	assertRandomSource(random);
	const rawFirst = random();
	const second = random();
	if (!Number.isFinite(rawFirst) || !Number.isFinite(second) || rawFirst < 0 || rawFirst >= 1 || second < 0 || second >= 1) {
		throw new DistributionParameterError('random source must return values in [0, 1)');
	}
	const first = Math.max(rawFirst, Number.MIN_VALUE);
	return Math.sqrt(-2 * Math.log(first)) * Math.cos(2 * Math.PI * second);
}

function sampleNormal(params, random) {
	const { mean, sd } = params || {};
	if (!Number.isFinite(mean) || !Number.isFinite(sd) || sd <= 0) {
		throw new DistributionParameterError('normal params require finite mean and sd > 0');
	}
	const sampled = mean + sd * sampleStandardNormal(random);
	if (!Number.isFinite(sampled)) throw new DistributionParameterError('normal sample overflowed');
	return sampled;
}

function sampleLognormal(params, random) {
	const { mean, sd } = params || {};
	if (!Number.isFinite(mean) || mean <= 0 || !Number.isFinite(sd) || sd <= 0) {
		throw new DistributionParameterError('lognormal params require arithmetic mean > 0 and sd > 0');
	}
	const varianceRatio = (sd / mean) ** 2;
	const sigmaSquared = Math.log1p(varianceRatio);
	const mu = Math.log(mean) - sigmaSquared / 2;
	const sampled = Math.exp(mu + Math.sqrt(sigmaSquared) * sampleStandardNormal(random));
	if (!Number.isFinite(sampled)) throw new DistributionParameterError('lognormal sample overflowed');
	return sampled;
}

function sampleDistribution(distribution, params, random) {
	if (distribution === 'triangular') return sampleTriangular(params, random);
	if (distribution === 'normal') return sampleNormal(params, random);
	if (distribution === 'lognormal') return sampleLognormal(params, random);
	throw new DistributionParameterError(`unsupported distribution: ${distribution}`);
}

function validateAssets(assets) {
	if (!Array.isArray(assets)) throw new TypeError('assets must be an array');
	const ids = new Set();
	for (const asset of assets) {
		if (!asset || typeof asset !== 'object' || Array.isArray(asset)) throw new TypeError('each asset must be an object');
		if (typeof asset.assetId !== 'string' || !asset.assetId.trim()) throw new TypeError('each asset requires assetId');
		if (ids.has(asset.assetId)) throw new TypeError(`duplicate assetId: ${asset.assetId}`);
		ids.add(asset.assetId);
		if (!FAMILIES.has(asset.family)) throw new TypeError(`unsupported family for asset ${asset.assetId}`);
		if (typeof asset.usage !== 'string') throw new TypeError(`usage must be a string for asset ${asset.assetId}`);
		if (asset.keySize !== null && asset.keySize !== undefined && (!Number.isFinite(asset.keySize) || asset.keySize < 0)) {
			throw new TypeError(`keySize must be non-negative or null for asset ${asset.assetId}`);
		}
	}
}

function validateOptions(options) {
	if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('options must be an object');
	const iterations = options.iterations ?? DEFAULT_ITERATIONS;
	const seed = options.seed ?? DEFAULT_SEED;
	if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_ITERATIONS) {
		throw new RangeError(`iterations must be an integer in [1, ${MAX_ITERATIONS}]`);
	}
	if (!Number.isSafeInteger(seed)) throw new TypeError('seed must be a safe integer');
	const overrides = options.overrides ?? {};
	if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) throw new TypeError('overrides must be an object');
	for (const [assetId, override] of Object.entries(overrides)) {
		if (!override || typeof override !== 'object' || Array.isArray(override)) throw new TypeError(`override for ${assetId} must be an object`);
		for (const field of ['dataLifetimeYears', 'migrationTimeYears']) {
			if (override[field] !== undefined && (!Number.isFinite(override[field]) || override[field] < 0)) {
				throw new TypeError(`${field} override for ${assetId} must be non-negative`);
			}
		}
	}
	if (options.generatedAt !== undefined && options.generatedAt !== null && typeof options.generatedAt !== 'string') {
		throw new TypeError('generatedAt must be a string or null');
	}
	return { iterations, seed, overrides };
}

function resolveTimes(asset, override) {
	return resolveMigrationDefaults(asset, override);
}

function hasScenarioTimeline(scenario, family) {
	return Boolean(scenario.familyTimelines[family] || (family === 'DH' && scenario.familyTimelines['DH/DSA']));
}

function familyQuantiles(values) {
	const sorted = new Float64Array(values);
	sorted.sort();
	const percentile = (fraction) => {
		const position = (sorted.length - 1) * fraction;
		const lower = Math.floor(position);
		const upper = Math.ceil(position);
		if (lower === upper) return sorted[lower];
		return sorted[lower] + (sorted[upper] - sorted[lower]) * (position - lower);
	};
	return { p10: percentile(0.1), p50: percentile(0.5), p90: percentile(0.9) };
}

function binomialInterval(successes, iterations) {
	const probability = successes / iterations;
	const error = CONFIDENCE_Z_95 * Math.sqrt((probability * (1 - probability)) / iterations);
	return {
		lower: Math.max(0, probability - error),
		upper: Math.min(1, probability + error),
	};
}

/**
 * Evaluate assets against a single scenario. Z draws are shared by family
 * across all assets (common random numbers); per-asset evaluation is O(N).
 * @param {{scenario:Object,assets:Object[],options?:Object}} input
 * @returns {Object[]} ThreatAssessment-compatible records with probability CIs.
 */
function runMonteCarlo({ scenario, assets, options = {} }) {
	validateScenario(scenario);
	validateAssets(assets);
	const { iterations, seed, overrides } = validateOptions(options);
	const random = mulberry32(seed);
	const families = [...new Set(assets.map((asset) => asset.family).filter((family) => family !== 'PQC'))].sort();
	const samplesByFamily = new Map();

	for (const family of families) {
		const timeline = getFamilyTimeline(scenario, family);
		const samples = new Float64Array(iterations);
		for (let index = 0; index < iterations; index += 1) {
			const sample = sampleDistribution(timeline.distribution, timeline.params, random);
			if (!Number.isFinite(sample)) throw new DistributionParameterError('sampled Z must be finite');
			samples[index] = Math.max(0, sample);
		}
		samplesByFamily.set(family, { samples, quantiles: familyQuantiles(samples) });
	}

	return assets.map((asset) => {
		const { X, Y } = resolveTimes(asset, overrides[asset.assetId] || {});
		if (asset.family === 'PQC') {
			return {
				assetId: asset.assetId,
				scenarioId: scenario.id,
				dataLifetimeYears: X,
				migrationTimeYears: Y,
				pBreakBeforeMigration: 0,
				pMoscaViolated: 0,
				pBreakBeforeMigrationCI95: { lower: 0, upper: 0 },
				pMoscaViolatedCI95: { lower: 0, upper: 0 },
				p10: 0,
				p50: 0,
				p90: 0,
				riskBand: riskBandFromProbability(0),
				iterations,
				seed,
				lowConfidenceFamily: false,
			};
		}

		const { samples, quantiles } = samplesByFamily.get(asset.family);
		const timelineMultiplier = getTimelineMultiplier(asset.family, asset.keySize);
		let breakCount = 0;
		let moscaCount = 0;
		const moscaThreshold = X + Y;
		for (let index = 0; index < iterations; index += 1) {
			const z = Math.max(0, samples[index] * timelineMultiplier);
			if (z < Y) breakCount += 1;
			if (z < moscaThreshold) moscaCount += 1;
		}
		const pBreakBeforeMigration = breakCount / iterations;
		const pMoscaViolated = moscaCount / iterations;
		const lowConfidenceFamily = asset.family === 'OTHER' || !hasScenarioTimeline(scenario, asset.family);

		return {
			assetId: asset.assetId,
			scenarioId: scenario.id,
			dataLifetimeYears: X,
			migrationTimeYears: Y,
			pBreakBeforeMigration,
			pMoscaViolated,
			pBreakBeforeMigrationCI95: binomialInterval(breakCount, iterations),
			pMoscaViolatedCI95: binomialInterval(moscaCount, iterations),
			p10: quantiles.p10 * timelineMultiplier,
			p50: quantiles.p50 * timelineMultiplier,
			p90: quantiles.p90 * timelineMultiplier,
			riskBand: riskBandFromProbability(pMoscaViolated),
			iterations,
			seed,
			lowConfidenceFamily,
		};
	});
}

module.exports = {
	DEFAULT_ITERATIONS,
	DEFAULT_SEED,
	DistributionParameterError,
	mulberry32,
	sampleTriangular,
	sampleNormal,
	sampleLognormal,
	sampleDistribution,
	runMonteCarlo,
};