'use strict';

/**
 * Retention resolution for sensitive data fields.
 * Pure functions; no DB access, no HTTP, no side effects.
 *
 * Priority (highest → lowest):
 *   1. options.overrides[fieldId].retentionYears
 *   2. 'stated'  – value found in code/config/comments near the field
 *   3. 'inferred' – config key clearly names the same table/field
 *   4. 'default' – per-class policy table (editable; verify with legal/compliance)
 */

/** Editable default-retention policy. Verify every entry with legal/compliance before use. */
const DEFAULT_RETENTION_POLICY = {
	AADHAAR: {
		years: 5,
		source: 'ASSUMPTION - verify with legal/compliance',
		rationale: 'Aadhaar-linked records are frequently retained for the duration of a customer relationship plus a short post-closure period.',
	},
	PAN: {
		years: 8,
		source: 'ASSUMPTION - verify with legal/compliance',
		rationale: 'Tax-related identifiers are commonly held for several years to support audit and dispute resolution cycles.',
	},
	PAYMENT_CARD: {
		years: 5,
		source: 'ASSUMPTION - verify with legal/compliance',
		rationale: 'Payment card data is typically retained for the life of a transaction dispute window plus a buffer period.',
	},
	HEALTH: {
		years: 7,
		source: 'ASSUMPTION - verify with legal/compliance',
		rationale: 'Health records are often kept for an extended period to support continuity of care and medico-legal obligations.',
	},
	PII_OTHER: {
		years: 3,
		source: 'ASSUMPTION - verify with legal/compliance',
		rationale: 'General personal identifiers are retained for the minimum period needed to fulfil the original collection purpose.',
	},
};

/**
 * Patterns that indicate an explicit retention duration in source text.
 * Capture group 1 = numeric quantity, capture group 2 = optional unit word.
 * All patterns use fixed literal prefixes — linear-time, no catastrophic backtracking.
 */
const STATED_PATTERNS = [
	// "retain for 10 years" / "retained 2 months"
	/\bretain(?:ed)?\s+(?:for\s+)?(\d+)\s*(year|month|day)s?\b/gi,
	// retention_days = 365 / ttl = 86400 / retention_period_years = 3
	/\bretention[_\s](?:days?|months?|years?|period[_\s]?(?:days?|months?|years?)?)\s*[:=]\s*(\d+)\b/gi,
	// ttl = 2592000 / TTL: 90
	/\bttl\s*[:=]\s*(\d+)\b/gi,
	// expiresAt / expires_after_days / expiry_years
	/\bexpir(?:es?|y|ation)[_\s](?:after[_\s])?(?:days?|months?|years?)\s*[:=]\s*(\d+)\b/gi,
	// DELETE ... WHERE created_at < now() - interval '3 years'
	/\binterval\s+['"](10|\d+)\s*(year|month|day)s?['"]/gi,
	// INTERVAL 90 DAY / interval 3 year
	/\binterval\s+(\d+)\s*(year|month|day)s?\b/gi,
];

/** Convert a raw number + unit string to fractional years. Returns null on bad input. */
function toYears(quantity, unit) {
	const n = Number(quantity);
	if (!Number.isFinite(n) || n <= 0) return null;
	const u = String(unit || '').toLowerCase();
	if (u.startsWith('year')) return n;
	if (u.startsWith('month')) return n / 12;
	if (u.startsWith('day')) return n / 365;
	// unitless – treat as days if plausibly a day-count (<= 36500), else seconds
	if (n <= 36500) return n / 365;
	return n / (365 * 24 * 3600);
}

/** Round fractional years to 1 decimal place, minimum 0.1. */
function roundYears(years) {
	return Math.max(0.1, Math.round(years * 10) / 10);
}

/**
 * Scan all file contents for explicit retention durations.
 * When field is provided, the generic "N unit" match is restricted to lines
 * within 5 lines of a mention of the field name.
 *
 * @param {string} field
 * @param {Array<{filePath:string,content:string}>} files
 * @returns {{ retentionYears:number, note:string }|null}
 */
function scanForStatedRetention(field, files) {
	const fieldNorm = field ? field.toLowerCase().replace(/[^a-z0-9]/g, '_') : '';
	const candidates = [];

	for (const file of files) {
		if (!file || typeof file.content !== 'string') continue;
		const lines = file.content.split(/\r?\n/);

		for (let i = 0; i < lines.length; i += 1) {
			const lineLower = lines[i].toLowerCase();

			const inContext =
				fieldNorm &&
				lines
					.slice(Math.max(0, i - 5), Math.min(lines.length, i + 6))
					.some((l) => l.toLowerCase().includes(fieldNorm));

			for (let pi = 0; pi < STATED_PATTERNS.length; pi += 1) {
				const pattern = STATED_PATTERNS[pi];
				pattern.lastIndex = 0;
				let match;
				while ((match = pattern.exec(lineLower)) !== null) {
					const qty = match[1];
					const unit = match[2] || '';
					const years = toYears(qty, unit);
					if (years !== null) {
						candidates.push({ years, filePath: file.filePath, line: i + 1 });
					}
				}
			}

			// Generic "N unit" scan — only when field is nearby
			if (inContext) {
				const generic = /\b(\d+)\s*(year|month|day)s?\b/gi;
				generic.lastIndex = 0;
				let gm;
				while ((gm = generic.exec(lineLower)) !== null) {
					const years = toYears(gm[1], gm[2]);
					if (years !== null) {
						candidates.push({ years, filePath: file.filePath, line: i + 1 });
					}
				}
			}
		}
	}

	if (!candidates.length) return null;

	candidates.sort((a, b) => b.years - a.years);
	const longest = candidates[0];
	const distinct = [...new Set(candidates.map((c) => roundYears(c.years)))];
	let note = `stated retention found in ${longest.filePath}:${longest.line}`;
	if (distinct.length > 1) {
		note += `; conflicting values detected (${distinct.join(', ')} years) – longest taken`;
	}
	return { retentionYears: roundYears(longest.years), note };
}

/**
 * Scan config-like files for a key that clearly names the same table/field.
 *
 * @param {string} field
 * @param {Array<{filePath:string,content:string}>} files
 * @returns {{ retentionYears:number, note:string }|null}
 */
function scanForInferredRetention(field, files) {
	if (!field) return null;
	const fieldNorm = field.toLowerCase().replace(/[^a-z0-9]/g, '_');
	// Build pattern: <fieldName>_retention_days / <fieldName>_ttl / etc.
	const escaped = fieldNorm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
	const keyRe = new RegExp(
		`\\b${escaped}[_.](retention[_.]?(?:days?|months?|years?)?|ttl|expir[a-z]*)['"]?\\s*[:=]\\s*(\\d+)`,
		'i'
	);

	for (const file of files) {
		if (!file || typeof file.content !== 'string') continue;
		const isConfigLike = /\.(json|yaml|yml|toml|ini|env|conf|config|properties|constants?)\b/i.test(
			file.filePath || ''
		);
		if (!isConfigLike) continue;
		keyRe.lastIndex = 0;
		const match = keyRe.exec(file.content);
		if (match) {
			const years = toYears(match[2], 'day');
			if (years !== null) {
				return {
					retentionYears: roundYears(years),
					note: `inferred from config key in ${file.filePath}`,
				};
			}
		}
	}
	return null;
}

/**
 * Assign a retention period to a detected sensitive field.
 *
 * @param {string} field - column/field name
 * @param {Array<{filePath:string,content:string}>} files - scanned files
 * @param {{ overrides?: Record<string,{retentionYears:number}>, fieldId?: string }} [options]
 * @returns {{ retentionYears:number, retentionSource:'stated'|'inferred'|'default', note:string }}
 */
function assignRetention(field, files, options) {
	const safeFiles = Array.isArray(files) ? files : [];
	const overrides = (options && options.overrides) || {};
	const fieldId = (options && options.fieldId) || null;

	// 1. Override wins over everything
	if (fieldId && overrides[fieldId] && Number.isFinite(overrides[fieldId].retentionYears)) {
		return {
			retentionYears: overrides[fieldId].retentionYears,
			retentionSource: 'stated',
			note: `override applied for fieldId ${fieldId}`,
		};
	}

	// 2. Stated – found in source text
	const stated = scanForStatedRetention(field, safeFiles);
	if (stated) {
		return {
			retentionYears: stated.retentionYears,
			retentionSource: 'stated',
			note: stated.note,
		};
	}

	// 3. Inferred – config key names this field
	const inferred = scanForInferredRetention(field, safeFiles);
	if (inferred) {
		return {
			retentionYears: inferred.retentionYears,
			retentionSource: 'inferred',
			note: inferred.note,
		};
	}

	// 4. Caller resolves default using dataClass (handled in index.js)
	return null;
}

/**
 * Return the default retention for a data class.
 *
 * @param {string} dataClass
 * @returns {{ retentionYears:number, retentionSource:'default', note:string }}
 */
function defaultRetention(dataClass) {
	const policy = DEFAULT_RETENTION_POLICY[dataClass] || DEFAULT_RETENTION_POLICY.PII_OTHER;
	return {
		retentionYears: policy.years,
		retentionSource: 'default',
		note: `${policy.source}. ${policy.rationale}`,
	};
}

module.exports = { assignRetention, defaultRetention, DEFAULT_RETENTION_POLICY };