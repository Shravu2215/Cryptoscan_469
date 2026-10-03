'use strict';

/**
 * Feature 3: Quantum Risk Exposure Engine for Sensitive Data Fields (HNDL).
 *
 * Computes data exposure risk by mapping sensitive data fields and their retention
 * lifetimes to protecting cryptographic assets, running Monte Carlo threat scenario
 * simulations, and producing granular risk scores and explanations.
 *
 * Pure functions only; no DB access, no routes, no UI, no new dependencies.
 */

const { runMonteCarlo } = require('../threatModel/monteCarlo');
const { loadDefaultScenarios } = require('../threatModel/scenarios');
const { riskBandFromProbability, isSignatureUsage } = require('../threatModel/mosca');

const ENGINE_VERSION = '1.0.0';

/**
 * Sensitivity weights per data class (ASSUMPTION).
 * Editable weights used to calculate riskScore = exposureProbability * sensitivityWeight.
 */
const SENSITIVITY_WEIGHTS = {
	AADHAAR: 1.0,
	PAN: 0.8,
	PAYMENT_CARD: 0.9,
	HEALTH: 1.0,
	PII_OTHER: 0.4,
};

/**
 * Retrieve sensitivity weight for a given data class.
 */
function getSensitivityWeight(dataClass) {
	if (dataClass && typeof SENSITIVITY_WEIGHTS[dataClass] === 'number') {
		return SENSITIVITY_WEIGHTS[dataClass];
	}
	return SENSITIVITY_WEIGHTS.PII_OTHER;
}

/**
 * Format data class for display in explanations.
 */
function formatDataClassLabel(dataClass) {
	if (!dataClass) return 'Data';
	switch (dataClass) {
		case 'AADHAAR': return 'Aadhaar';
		case 'PAN': return 'PAN';
		case 'PAYMENT_CARD': return 'Payment card';
		case 'HEALTH': return 'Health';
		case 'PII_OTHER': return 'PII';
		default: return String(dataClass);
	}
}

/**
 * Format field location for display in explanations.
 */
function formatLocation(loc) {
	if (!loc) return 'unknown location';
	if (loc.filePath) {
		const lineStr = loc.line != null ? `:${loc.line}` : '';
		return `${loc.filePath}${lineStr}`;
	}
	if (loc.schemaTable && loc.column) {
		return `${loc.schemaTable}.${loc.column}`;
	}
	return 'unknown location';
}

/**
 * Format asset algorithm info for display in explanations.
 */
function formatAssetAlgo(asset) {
	const algo = asset.algorithm || asset.family || 'cryptographic';
	const keySizeStr = asset.keySize ? `-${asset.keySize}` : '';
	const usageStr = asset.usage ? ` ${asset.usage.replace(/_/g, ' ')}` : '';
	return `${algo}${keySizeStr}${usageStr}`;
}

/**
 * Build a human-readable explanation sentence without raw sensitive values.
 */
function buildExplanation({ field, asset, scenario, exposureProbability, lineageConfidence }) {
	const classLabel = formatDataClassLabel(field.dataClass);
	const fieldName = field.fieldName || field.column || field.fieldId || field.id || 'unnamed';
	const locStr = formatLocation(field.location);
	const algoStr = formatAssetAlgo(asset);
	const retention = field.retentionYears ?? 5;
	const retSource = field.retentionSource || 'default assumption';
	const pStr = exposureProbability.toFixed(2);
	const scenarioName = scenario.name || scenario.id || 'median';
	const lineageConfStr = Number(lineageConfidence.toFixed(2));

	return `${classLabel} field '${fieldName}' (${locStr}) is protected by ${algoStr}, ${retention}-year retention (${retSource}), P(exposed) = ${pStr} under ${scenarioName} scenario, lineage confidence ${lineageConfStr}.`;
}

/**
 * Compute quantum risk data exposure for sensitive fields.
 *
 * @param {{
 *   fields: Array<Object>,
 *   assets: Array<Object>,
 *   scenarios?: Array<Object>,
 *   options?: Object
 * }} input
 * @returns {{
 *   exposures: Array<Object>,
 *   unprotected: Array<Object>,
 *   summary: Object,
 *   meta: Object
 * }}
 */
function computeDataExposure({ fields, assets, scenarios, options = {} } = {}) {
	if (!Array.isArray(fields)) throw new TypeError('fields must be an array');
	if (!Array.isArray(assets)) throw new TypeError('assets must be an array');

	const activeScenarios = Array.isArray(scenarios) && scenarios.length > 0
		? scenarios
		: loadDefaultScenarios();

	const assetsMap = new Map();
	for (const asset of assets) {
		if (asset && asset.assetId) {
			assetsMap.set(asset.assetId, asset);
		}
	}

	const exposures = [];
	const unprotected = [];
	const skipped = [];

	const pseudoAssets = [];
	const pseudoOverrides = {};
	const pseudoPairMap = new Map();

	for (const field of fields) {
		const fieldId = field.fieldId || field.id || '';
		const status = field.lineageStatus;
		const protectedBy = Array.isArray(field.protectedBy) ? field.protectedBy : [];

		if (status === 'no_crypto_found' || protectedBy.length === 0) {
			unprotected.push({
				fieldId,
				dataClass: field.dataClass,
				location: field.location || null,
				reason: 'protection unknown',
			});
			continue;
		}

		for (const assetId of protectedBy) {
			const asset = assetsMap.get(assetId);
			if (!asset) continue;

			// Skip PQC family
			if (asset.family === 'PQC') {
				skipped.push({
					fieldId,
					assetId: asset.assetId,
					reason: 'PQC algorithm family (exposure 0)',
				});
				continue;
			}

			// Skip non-confidentiality usages (signature, auth, jwt, cert)
			if (isSignatureUsage(asset.usage)) {
				skipped.push({
					fieldId,
					assetId: asset.assetId,
					reason: 'Signature/authentication usage (exposure 0)',
				});
				continue;
			}

			const pseudoId = `${fieldId}|${asset.assetId}`;
			const pseudoAsset = {
				...asset,
				assetId: pseudoId,
			};

			pseudoAssets.push(pseudoAsset);
			pseudoOverrides[pseudoId] = {
				dataLifetimeYears: field.retentionYears ?? 5,
			};
			pseudoPairMap.set(pseudoId, { field, asset });
		}
	}

	// Run Monte Carlo for each scenario across pseudo-assets
	if (pseudoAssets.length > 0) {
		for (const scenario of activeScenarios) {
			const mcOptions = {
				...options,
				overrides: {
					...(options && options.overrides ? options.overrides : {}),
					...pseudoOverrides,
				},
			};

			const assessments = runMonteCarlo({
				scenario,
				assets: pseudoAssets,
				options: mcOptions,
			});

			for (const assessment of assessments) {
				const pair = pseudoPairMap.get(assessment.assetId);
				if (!pair) continue;
				const { field, asset } = pair;

				const exposureProbability = assessment.pMoscaViolated;
				const ci95 = assessment.pMoscaViolatedCI95 || { lower: 0, upper: 0 };
				const sensitivityWeight = getSensitivityWeight(field.dataClass);
				const riskScore = exposureProbability * sensitivityWeight;
				const detectionConfidence = field.detectionConfidence ?? field.confidence ?? 1.0;
				const lineageConfidence = field.lineageConfidence ?? 0;
				const overallConfidence = detectionConfidence * lineageConfidence;
				const lowConfidence = overallConfidence < 0.4;

				const explanation = buildExplanation({
					field,
					asset,
					scenario,
					exposureProbability,
					lineageConfidence,
				});

				exposures.push({
					fieldId: field.fieldId || field.id || '',
					assetId: asset.assetId,
					scenarioId: scenario.id,
					exposureProbability,
					ci95,
					sensitivityWeight,
					riskScore,
					retentionYears: field.retentionYears ?? 5,
					retentionSource: field.retentionSource || 'default',
					detectionConfidence,
					lineageConfidence,
					overallConfidence,
					lowConfidence,
					explanation,
				});
			}
		}
	}

	// Calculate summary per scenario and per field
	const byScenario = {};
	for (const scenario of activeScenarios) {
		const scenarioExposures = exposures.filter((e) => e.scenarioId === scenario.id);

		const fieldMaxMap = new Map();
		for (const exp of scenarioExposures) {
			const existing = fieldMaxMap.get(exp.fieldId);
			if (!existing || exp.riskScore > existing.riskScore) {
				fieldMaxMap.set(exp.fieldId, exp);
			}
		}

		let highCriticalCount = 0;
		let expectedFieldsExposed = 0;
		const fieldSummaries = [];

		for (const [fId, topExp] of fieldMaxMap.entries()) {
			expectedFieldsExposed += topExp.exposureProbability;
			const band = riskBandFromProbability(topExp.exposureProbability);
			if (band === 'HIGH' || band === 'CRITICAL') {
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
		const top5Fields = fieldSummaries.slice(0, 5);

		byScenario[scenario.id] = {
			highCriticalCount,
			expectedFieldsExposed,
			top5Fields,
		};
	}

	// Per-field worst case across all scenarios & assets
	const byField = {};
	for (const exp of exposures) {
		const existing = byField[exp.fieldId];
		if (!existing || exp.exposureProbability > existing.worstCaseProbability) {
			byField[exp.fieldId] = {
				worstCaseProbability: exp.exposureProbability,
				worstCaseAssetId: exp.assetId,
				scenarioId: exp.scenarioId,
				worstCaseRiskScore: exp.riskScore,
			};
		}
	}

	return {
		exposures,
		unprotected,
		summary: {
			byScenario,
			byField,
			skipped,
		},
		meta: {
			engineVersion: ENGINE_VERSION,
			seed: options && options.seed !== undefined ? options.seed : 42,
			iterations: options && options.iterations !== undefined ? options.iterations : 10000,
			generatedAt: options && options.generatedAt ? options.generatedAt : null,
		},
	};
}

module.exports = {
	computeDataExposure,
	SENSITIVITY_WEIGHTS,
};