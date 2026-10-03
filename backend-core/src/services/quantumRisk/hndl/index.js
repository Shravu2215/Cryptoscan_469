'use strict';

/**
 * HNDL detection entry point.
 * Exposes detectSensitiveData({ files, options }) which orchestrates:
 *   detectValues → detectNames → combineSignals → assignRetention
 * and shapes each field to the SensitiveDataField contract in
 * docs/member3/CONTRACTS.md.
 *
 * Pure functions only; no DB access, no routes, no UI.
 */

const { detectValues, detectNames, combineSignals } = require('./detector');
const { assignRetention, defaultRetention } = require('./retention');
const { linkFieldsToAssets } = require('./lineage');
const { computeDataExposure } = require('./exposure');


const ENGINE_VERSION = '1.0.0';
const MAX_FILES = 20000;

/**
 * Deterministic field ordering: filePath → line → dataClass.
 * Fields without a numeric line (name-only) sort by column alphabetically.
 */
function fieldSortKey(field) {
	return [
		String(field.location && field.location.filePath ? field.location.filePath : ''),
		Number(field.location && field.location.line != null ? field.location.line : 0),
		String(field.dataClass || ''),
	];
}

function compareFields(a, b) {
	const ka = fieldSortKey(a);
	const kb = fieldSortKey(b);
	if (ka[0] < kb[0]) return -1;
	if (ka[0] > kb[0]) return 1;
	if (ka[1] !== kb[1]) return ka[1] - kb[1];
	if (ka[2] < kb[2]) return -1;
	if (ka[2] > kb[2]) return 1;
	return 0;
}

/**
 * Shape a combined finding into a SensitiveDataField contract object.
 * Raw sensitive values are never included.
 */
function toSensitiveDataField(finding, files, options) {
	const column = finding.column || null;
	const schemaTable = finding.schemaTable || null;
	const location =
		schemaTable && column
			? { schemaTable, column }
			: { filePath: finding.filePath || '', line: finding.line || 0 };

	const retentionResult =
		assignRetention(column || '', files, { overrides: options && options.overrides, fieldId: finding.fieldId }) ||
		defaultRetention(finding.dataClass);

	// Never expose raw sensitive values; 'evidence' from detectValues is already masked (****XXXX)
	const evidence = finding.evidence ? [finding.evidence] : [];

	return {
		fieldId: finding.fieldId || '',
		dataClass: finding.dataClass,
		location,
		retentionYears: retentionResult.retentionYears,
		retentionSource: retentionResult.retentionSource,
		retentionNote: retentionResult.note,
		protectedBy: [],                          // lineage: not yet implemented
		detectionConfidence: finding.confidence || 0,
		lineageConfidence: 0,                     // not yet implemented
		evidence,
		signals: finding.signals || [],
	};
}

/**
 * Run the full HNDL detection pipeline on an array of source files.
 *
 * @param {{ files: Array<{filePath:string,content:string}>, options?: { overrides?: Record<string,{retentionYears:number}> } }} input
 * @returns {{
 *   fields: SensitiveDataField[],
 *   stats: { filesScanned: number, filesSkipped: Array<{filePath:string,reason:string}>, byClass: Record<string,number>, truncated: boolean },
 *   meta: { engineVersion: string }
 * }}
 */
function detectSensitiveData({ files, options } = {}) {
	if (!Array.isArray(files)) throw new TypeError('files must be an array');

	// Cap input at MAX_FILES; record the rest as skipped
	const truncated = files.length > MAX_FILES;
	const safeFiles = truncated ? files.slice(0, MAX_FILES) : files;

	// Run the three detector stages
	const valueFindings = detectValues(safeFiles);
	const nameFindings = detectNames(safeFiles);
	const combined = combineSignals(valueFindings, nameFindings);

	// Merge skipped-file lists from both detectors (deduplicate by filePath+reason)
	const skippedMap = new Map();
	const addSkipped = (list) => {
		for (const item of list) {
			const key = `${item.filePath}\x00${item.reason}`;
			if (!skippedMap.has(key)) skippedMap.set(key, item);
		}
	};
	addSkipped(valueFindings.skippedFiles || []);
	addSkipped(nameFindings.skippedFiles || []);
	const filesSkipped = [...skippedMap.values()].sort((a, b) => {
		if (a.filePath < b.filePath) return -1;
		if (a.filePath > b.filePath) return 1;
		return a.reason < b.reason ? -1 : a.reason > b.reason ? 1 : 0;
	});

	// Count files actually scanned (not skipped)
	const skippedPaths = new Set(filesSkipped.map((s) => s.filePath));
	const filesScanned = safeFiles.filter((f) => !skippedPaths.has(
		String(f && f.filePath || '').replace(/\\/g, '/')
	)).length;

	// Shape findings into SensitiveDataField contracts
	const fields = combined
		.map((finding) => toSensitiveDataField(finding, safeFiles, options || {}))
		.sort(compareFields);

	// Aggregate by dataClass
	const byClass = {};
	for (const field of fields) {
		byClass[field.dataClass] = (byClass[field.dataClass] || 0) + 1;
	}

	return {
		fields,
		stats: {
			filesScanned,
			filesSkipped,
			byClass,
			truncated,
		},
		meta: {
			engineVersion: ENGINE_VERSION,
		},
	};
}

module.exports = { detectSensitiveData, linkFieldsToAssets, computeDataExposure };