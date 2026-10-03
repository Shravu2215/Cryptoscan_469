'use strict';

/**
 * Pure scenario helpers and editable key-size timeline adjustments.
 * All multipliers are ASSUMPTIONs, not estimates derived from cited research.
 */

const DEFAULT_SCENARIOS = require('./defaultScenarios.json');

class ScenarioValidationError extends TypeError {
	constructor(errors) {
		super(`Invalid threat scenario: ${errors.join('; ')}`);
		this.name = 'ScenarioValidationError';
		this.errors = errors;
	}
}

const OTHER_DEFAULT_TIMELINE = {
	distribution: 'triangular',
	params: { min: 1, mode: 4, max: 12 },
};

const KEY_SIZE_TIMELINE_MULTIPLIERS = {
	RSA: [
		{ maxKeySize: 2047, multiplier: 0.98, source: 'ASSUMPTION', rationale: 'Undersized RSA keys receive a very small earlier-break adjustment.' },
		{ minKeySize: 2048, maxKeySize: 3071, multiplier: 1.0, source: 'ASSUMPTION', rationale: 'RSA-2048 through RSA-3072 use the baseline family timeline.' },
		{ minKeySize: 3072, maxKeySize: 4095, multiplier: 1.03, source: 'ASSUMPTION', rationale: 'Larger RSA keys slightly delay the estimated break timeline.' },
		{ minKeySize: 4096, multiplier: 1.05, source: 'ASSUMPTION', rationale: 'RSA-4096 and larger receive a conservative small delay.' },
	],
	DH: [
		{ maxKeySize: 2047, multiplier: 0.98, source: 'ASSUMPTION', rationale: 'Undersized DH parameters receive a very small earlier-break adjustment.' },
		{ minKeySize: 2048, maxKeySize: 3071, multiplier: 1.0, source: 'ASSUMPTION', rationale: 'DH-2048 through DH-3072 use the baseline family timeline.' },
		{ minKeySize: 3072, maxKeySize: 4095, multiplier: 1.03, source: 'ASSUMPTION', rationale: 'Larger DH parameters slightly delay the estimated break timeline.' },
		{ minKeySize: 4096, multiplier: 1.05, source: 'ASSUMPTION', rationale: 'DH-4096 and larger receive a conservative small delay.' },
	],
};

const GROVER_TIMELINE_MULTIPLIERS = {
	AES: [
		{ maxKeySize: 127, multiplier: 0.45, source: 'ASSUMPTION', rationale: 'Sub-128-bit symmetric keys have the shortest modeled Grover margin.' },
		{ minKeySize: 128, maxKeySize: 191, multiplier: 0.6, source: 'ASSUMPTION', rationale: 'AES-128 is modeled earlier than AES-256 under Grover search.' },
		{ minKeySize: 192, maxKeySize: 255, multiplier: 0.8, source: 'ASSUMPTION', rationale: 'AES-192 is placed between AES-128 and AES-256.' },
		{ minKeySize: 256, multiplier: 1.0, source: 'ASSUMPTION', rationale: 'AES-256 uses the scenario baseline, with a large but finite Z.' },
		{ multiplier: 0.55, source: 'ASSUMPTION', rationale: 'Unknown AES key size receives a conservative earlier timeline.' },
	],
	HASH: [
		{ maxKeySize: 255, multiplier: 0.7, source: 'ASSUMPTION', rationale: 'Short hash outputs receive a conservative earlier Grover timeline.' },
		{ minKeySize: 256, multiplier: 1.0, source: 'ASSUMPTION', rationale: '256-bit and larger hash outputs use the scenario baseline.' },
		{ multiplier: 0.7, source: 'ASSUMPTION', rationale: 'Unknown hash output size receives a conservative earlier timeline.' },
	],
};

function isPlainObject(value) {
	return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validateScenario(scenario) {
	const errors = [];
	if (!isPlainObject(scenario)) throw new ScenarioValidationError(['scenario must be an object']);
	if (typeof scenario.id !== 'string' || !scenario.id.trim()) errors.push('id must be a non-empty string');
	if (!['optimistic', 'median', 'pessimistic', 'custom'].includes(scenario.name)) errors.push('name is unsupported');
	if (typeof scenario.source !== 'string' || !scenario.source.trim()) errors.push('source is required');
	if (typeof scenario.citationNote !== 'string' || !scenario.citationNote.trim()) errors.push('citationNote is required');
	if (typeof scenario.editable !== 'boolean') errors.push('editable must be a boolean');
	if (typeof scenario.createdBy !== 'string' || !scenario.createdBy.trim()) errors.push('createdBy must be a non-empty string');
	if (!isPlainObject(scenario.familyTimelines) || Object.keys(scenario.familyTimelines).length === 0) {
		errors.push('familyTimelines must be a non-empty object');
	} else {
		for (const [family, timeline] of Object.entries(scenario.familyTimelines)) {
			if (!family.trim() || !isPlainObject(timeline)) {
				errors.push(`familyTimelines.${family} must be an object`);
				continue;
			}
			const params = timeline.params;
			if (!isPlainObject(params)) {
				errors.push(`familyTimelines.${family}.params must be an object`);
				continue;
			}
			if (timeline.distribution === 'triangular') {
				const { min, mode, max } = params;
				if (![min, mode, max].every(Number.isFinite) || !(min <= mode && mode <= max)) {
					errors.push(`familyTimelines.${family} triangular params must be finite and satisfy min <= mode <= max`);
				}
			} else if (timeline.distribution === 'normal') {
				if (!Number.isFinite(params.mean) || !Number.isFinite(params.sd) || params.sd <= 0) {
					errors.push(`familyTimelines.${family} normal params require finite mean and sd > 0`);
				}
			} else if (timeline.distribution === 'lognormal') {
				if (!Number.isFinite(params.mean) || params.mean <= 0 || !Number.isFinite(params.sd) || params.sd <= 0) {
					errors.push(`familyTimelines.${family} lognormal params require arithmetic mean > 0 and sd > 0`);
				}
			} else {
				errors.push(`familyTimelines.${family}.distribution must be triangular, normal, or lognormal`);
			}
		}
	}
	if (errors.length) throw new ScenarioValidationError(errors);
	return true;
}

function cloneScenarioForEdit(scenario, patch = {}) {
	validateScenario(scenario);
	if (!isPlainObject(patch)) throw new ScenarioValidationError(['patch must be an object']);
	const clone = JSON.parse(JSON.stringify(scenario));
	const { familyTimelines: familyPatch, ...scalarPatch } = patch;
	Object.assign(clone, scalarPatch);
	if (isPlainObject(familyPatch)) {
		for (const [family, timelinePatch] of Object.entries(familyPatch)) {
			const existing = clone.familyTimelines[family] || {};
			clone.familyTimelines[family] = {
				...existing,
				...timelinePatch,
				params: { ...(existing.params || {}), ...((timelinePatch && timelinePatch.params) || {}) },
			};
		}
	}
	clone.name = patch.name || 'custom';
	clone.editable = true;
	clone.source = scenario.source;
	clone.citationNote = scenario.citationNote;
	validateScenario(clone);
	return clone;
}

function loadDefaultScenarios() {
	const scenarios = JSON.parse(JSON.stringify(DEFAULT_SCENARIOS));
	scenarios.forEach(validateScenario);
	return scenarios;
}

function matchesKeySize(entry, keySize) {
	if (!Number.isFinite(keySize)) return entry.minKeySize === undefined && entry.maxKeySize === undefined;
	return (entry.minKeySize === undefined || keySize >= entry.minKeySize) &&
		(entry.maxKeySize === undefined || keySize <= entry.maxKeySize);
}

function getTimelineMultiplier(family, keySize) {
	const table = KEY_SIZE_TIMELINE_MULTIPLIERS[family] || GROVER_TIMELINE_MULTIPLIERS[family];
	if (!table) return 1;
	const match = table.find((entry) => matchesKeySize(entry, keySize));
	return match ? match.multiplier : 1;
}

function getFamilyTimeline(scenario, family) {
	if (family === 'PQC') return null;
	const direct = scenario.familyTimelines[family];
	if (direct) return direct;
	if (family === 'DH' && scenario.familyTimelines['DH/DSA']) return scenario.familyTimelines['DH/DSA'];
	return scenario.familyTimelines.OTHER || OTHER_DEFAULT_TIMELINE;
}

module.exports = {
	ScenarioValidationError,
	OTHER_DEFAULT_TIMELINE,
	KEY_SIZE_TIMELINE_MULTIPLIERS,
	GROVER_TIMELINE_MULTIPLIERS,
	validateScenario,
	loadDefaultScenarios,
	cloneScenarioForEdit,
	getTimelineMultiplier,
	getFamilyTimeline,
};