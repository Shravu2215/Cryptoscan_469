'use strict';

/**
 * Lineage: link sensitive data fields to the CryptoAssets that protect them.
 *
 * Pure functions - no DB, no routes, no UI, no new deps.
 * Every weight in SIGNAL_WEIGHTS is labeled ASSUMPTION; edit before production use.
 *
 * Algorithm:
 *   For each field, score every candidate asset on up to 6 signals.
 *   Combine: confidence = 1 - prod(1 - w_i)  for all fired signals.
 *   Cap at CONFIDENCE_CAP (0.9 - static heuristics are never certain).
 *   Top-3 assets by score -> protectedBy[]; status based on count / score spread.
 */

// ---------------------------------------------------------------------------
// Editable signal weights (ASSUMPTION - verify before use)
// ---------------------------------------------------------------------------

/**
 * Editable table of signal weights used by linkFieldsToAssets.
 * Each entry: { weight: 0..1, description: string, source: string }
 * 'runtimeBonus' fires when asset.sources includes 'runtime'.
 */
const SIGNAL_WEIGHTS = {
	sameFile: {
		weight: 0.6,
		description: 'Asset and field are in the same source file.',
		source: 'ASSUMPTION - verify before use',
	},
	closeLines: {
		weight: 0.25,
		description: 'Asset is within LINE_DISTANCE_THRESHOLD lines of the field in the same file.',
		source: 'ASSUMPTION - verify before use',
	},
	encryptCallRef: {
		weight: 0.45,
		description: 'Field name appears as an argument in an encrypt/sign/wrap/hash call near the asset line.',
		source: 'ASSUMPTION - verify before use',
	},
	sameDirectory: {
		weight: 0.15,
		description: 'Asset and field share the same immediate parent directory (different files).',
		source: 'ASSUMPTION - verify before use',
	},
	importLink: {
		weight: 0.3,
		description: 'File containing the field imports the file containing the asset (one-hop only).',
		source: 'ASSUMPTION - verify before use',
	},
	sameService: {
		weight: 0.1,
		description: 'DB-column field in a model/migration file is in the same service path segment as an encryption asset.',
		source: 'ASSUMPTION - verify before use',
	},
	runtimeBonus: {
		weight: 0.15,
		description: 'Bonus when asset.sources includes "runtime" (stronger evidence of actual protection).',
		source: 'ASSUMPTION - verify before use',
	},
};

const CONFIDENCE_CAP = 0.9;
const LINE_DISTANCE_THRESHOLD = 30;
const TOP_K = 3; // max assets kept per field

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Normalise a file path to forward-slash for comparison. */
function normPath(p) {
	return String(p || '').replace(/\\/g, '/');
}

/** Extract the directory (everything before the last '/') of a path. */
function dirOf(p) {
	const s = normPath(p);
	const idx = s.lastIndexOf('/');
	return idx >= 0 ? s.slice(0, idx) : '';
}

/**
 * Extract the top-level service segment from a path.
 * Mirrors CONTRACTS.md: first segment under apps/, packages/, or services/;
 * otherwise the top-level directory.
 */
function serviceOf(p) {
	const parts = normPath(p).split('/').filter(Boolean);
	const SERVICE_ROOTS = new Set(['apps', 'packages', 'services']);
	for (let i = 0; i < parts.length - 1; i += 1) {
		if (SERVICE_ROOTS.has(parts[i])) return parts[i + 1] || '';
	}
	return parts[0] || '';
}

/**
 * Parse require/import statements; returns Set<string> of specifier strings.
 * One-hop only; linear scan, no AST.
 */
function parseImports(content) {
	const imported = new Set();
	const esm = /\bfrom\s+['"]([^'"]+)['"]/g;
	const cjs = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
	let m;
	esm.lastIndex = 0;
	while ((m = esm.exec(content)) !== null) imported.add(m[1]);
	cjs.lastIndex = 0;
	while ((m = cjs.exec(content)) !== null) imported.add(m[1]);
	return imported;
}

/**
 * Return true if importingContent (at importingFilePath) imports assetFilePath
 * via a relative specifier (one hop only).
 */
function fileImportsAsset(importingContent, importingFilePath, assetFilePath) {
	const imported = parseImports(importingContent);
	const importingDir = dirOf(importingFilePath);
	const assetNorm = normPath(assetFilePath);
	const assetNoExt = assetNorm.replace(/\.[^./]+$/, '');

	for (const spec of imported) {
		if (!spec.startsWith('.')) continue;
		// Resolve: join dir + spec then collapse ./ segments
		const joined = normPath(importingDir + '/' + spec);
		// Collapse internal ./ segments (e.g. src/./crypto -> src/crypto)
		const resolved = joined.replace(/\/\.\//g, '/').replace(/^\.\//, '');
		const resolvedNoExt = resolved.replace(/\.[^./]+$/, '');
		if (resolved === assetNorm || resolvedNoExt === assetNoExt) return true;
	}
	return false;
}

/**
 * Return true when fieldName appears as an identifier in an
 * encrypt/sign/wrap/hash call within the line-distance window.
 * Linear-time: single scan of window lines.
 * Never returns or logs raw source content.
 */
function hasEncryptCallRef(fieldName, fieldLine, assetLine, threshold, fileContent) {
	if (!fieldName || !fileContent) return false;
	const lines = fileContent.split(/\r?\n/);
	const lo = Math.max(0, Math.min(fieldLine, assetLine) - 1);
	const hi = Math.min(lines.length, Math.max(fieldLine, assetLine) + threshold);

	const nameLower = fieldName.toLowerCase().replace(/[^a-z0-9]/g, '');
	if (!nameLower) return false;

	const cryptoRe = /\b(?:encrypt|sign|wrap|hash|seal|protect|cipher)\s*\(/i;
	for (let i = lo; i < hi; i += 1) {
		if (!cryptoRe.test(lines[i])) continue;
		const jlo = Math.max(0, i - 2);
		const jhi = Math.min(lines.length - 1, i + 2);
		for (let j = jlo; j <= jhi; j += 1) {
			const norm = lines[j].toLowerCase().replace(/[^a-z0-9]/g, '');
			if (norm.includes(nameLower)) return true;
		}
	}
	return false;
}

/**
 * Independent-evidence combination: 1 - prod(1 - w_i), capped at CONFIDENCE_CAP.
 */
function combineWeights(weights) {
	let product = 1;
	for (const w of weights) product *= 1 - w;
	return Math.min(CONFIDENCE_CAP, 1 - product);
}

/**
 * Score a single (field, asset) pair.
 * Returns { score: number, evidence: string[] }.
 * Evidence items are short masked strings - never raw values or code lines.
 */
function scoreCandidate(field, asset, fileContentMap, threshold) {
	const fieldFilePath = normPath(
		field.location && field.location.filePath ? field.location.filePath : ''
	);
	const fieldLine = (field.location && field.location.line) || 0;
	const assetFilePath = normPath(asset.filePath || '');
	const assetLine = asset.lineNumber || 0;

	const weights = [];
	const evidence = [];

	// Signal 1: same file
	const sameFile = Boolean(fieldFilePath && assetFilePath && fieldFilePath === assetFilePath);
	if (sameFile) {
		weights.push(SIGNAL_WEIGHTS.sameFile.weight);
		evidence.push('same file as asset');

		// Signal 2: close lines (only meaningful in same file)
		if (assetLine > 0 && fieldLine > 0) {
			const dist = Math.abs(fieldLine - assetLine);
			if (dist <= threshold) {
				weights.push(SIGNAL_WEIGHTS.closeLines.weight);
				evidence.push(`${dist} line${dist === 1 ? '' : 's'} apart in same file`);
			}
		}

		// Signal 3: field name referenced in a crypto call
		const colName = field.column || (field.location && field.location.column) || '';
		const fileContent = fileContentMap.get(fieldFilePath) || '';
		if (colName && fileContent && hasEncryptCallRef(colName, fieldLine, assetLine, threshold, fileContent)) {
			weights.push(SIGNAL_WEIGHTS.encryptCallRef.weight);
			evidence.push('field name referenced in crypto call');
		}
	}

	// Signal 4: same directory (different file)
	if (fieldFilePath && assetFilePath && !sameFile && dirOf(fieldFilePath) === dirOf(assetFilePath)) {
		weights.push(SIGNAL_WEIGHTS.sameDirectory.weight);
		evidence.push('same directory as asset');
	}

	// Signal 5: import link (field file imports asset file, one hop)
	if (fieldFilePath && assetFilePath && !sameFile) {
		const fieldContent = fileContentMap.get(fieldFilePath) || '';
		if (fieldContent && fileImportsAsset(fieldContent, fieldFilePath, assetFilePath)) {
			weights.push(SIGNAL_WEIGHTS.importLink.weight);
			evidence.push('field file imports asset file');
		}
	}

	// Signal 6: DB-column field + encryption asset in same service (weak)
	if (field.location && field.location.schemaTable) {
		const fieldService = serviceOf(fieldFilePath);
		const assetService = serviceOf(assetFilePath);
		if (fieldService && assetService && fieldService === assetService) {
			if (/encrypt|key.?wrap|protect|seal/i.test(String(asset.usage || ''))) {
				weights.push(SIGNAL_WEIGHTS.sameService.weight);
				evidence.push('DB model in same service as encryption asset');
			}
		}
	}

	// Runtime bonus
	if (Array.isArray(asset.sources) && asset.sources.includes('runtime')) {
		weights.push(SIGNAL_WEIGHTS.runtimeBonus.weight);
		evidence.push('runtime evidence present');
	}

	const score = weights.length ? combineWeights(weights) : 0;
	return { score, evidence };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Link sensitive data fields to the CryptoAssets that may protect them.
 * Mutates each field in place; returns the same array for chaining.
 *
 * @param {{
 *   fields: SensitiveDataField[],
 *   assets: CryptoAsset[],
 *   files:  Array<{filePath:string,content:string}>,
 *   options?: { lineDistanceThreshold?: number }
 * }} input
 * @returns {SensitiveDataField[]}
 */
function linkFieldsToAssets({ fields, assets, files, options } = {}) {
	if (!Array.isArray(fields)) throw new TypeError('fields must be an array');
	if (!Array.isArray(assets)) throw new TypeError('assets must be an array');

	const safeFiles = Array.isArray(files) ? files : [];
	const threshold =
		options && typeof options.lineDistanceThreshold === 'number'
			? options.lineDistanceThreshold
			: LINE_DISTANCE_THRESHOLD;

	// O(n) lookup: normPath -> content
	const fileContentMap = new Map();
	for (const file of safeFiles) {
		if (file && typeof file.content === 'string') {
			fileContentMap.set(normPath(file.filePath || ''), file.content);
		}
	}

	for (const field of fields) {
		if (!field) continue;

		const scored = [];
		for (const asset of assets) {
			if (!asset) continue;
			const { score, evidence } = scoreCandidate(field, asset, fileContentMap, threshold);
			if (score > 0) scored.push({ assetId: String(asset.assetId || ''), score, evidence });
		}

		// Deterministic: score desc, assetId asc
		scored.sort((a, b) => {
			if (b.score !== a.score) return b.score - a.score;
			return a.assetId < b.assetId ? -1 : a.assetId > b.assetId ? 1 : 0;
		});

		if (scored.length === 0) {
			field.protectedBy = [];
			field.lineageConfidence = 0;
			field.lineageEvidence = ['protection unknown'];
			field.lineageStatus = 'no_crypto_found';
			continue;
		}

		const top = scored.slice(0, TOP_K);
		const best = top[0];
		const allEqual = top.length > 1 && top.every((t) => Math.abs(t.score - best.score) < 1e-9);

		field.protectedBy = top.map((t) => t.assetId);
		field.lineageConfidence = Math.round(best.score * 1000) / 1000;
		field.lineageEvidence = best.evidence.slice();
		field.lineageStatus = allEqual ? 'ambiguous' : 'linked';
	}

	return fields;
}

module.exports = {
	linkFieldsToAssets,
	SIGNAL_WEIGHTS,
	CONFIDENCE_CAP,
	LINE_DISTANCE_THRESHOLD,
};
