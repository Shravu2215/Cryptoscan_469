'use strict';

/** Pure, value-based sensitive-data detection. Matched values and source lines are never returned. */

const { createHash } = require('crypto');
const {
	SENSITIVE_NAME_SYNONYMS,
	COLUMN_TYPE_HINTS,
	PAYMENT_CONTEXT_CUES,
	INCOME_TAX_CONTEXT_CUES,
	BOOLEAN_ENUM_TYPE_CUES,
	NAME_CONFIDENCE,
	NAME_AND_TYPE_CONFIDENCE,
	WEAK_BOOLEAN_ENUM_CONFIDENCE,
} = require('./patterns');

const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FINDINGS_PER_FILE = 200;

const VERHOEFF_D = [
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
	[1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
	[2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
	[3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
	[4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
	[5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
	[6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
	[7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
	[8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
	[9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P = [
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
	[1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
	[5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
	[8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
	[9, 4, 3, 8, 1, 2, 6, 7, 5, 0],
	[4, 2, 7, 9, 3, 1, 5, 0, 6, 8],
	[2, 7, 8, 3, 6, 0, 1, 9, 4, 5],
	[7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

const VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

function asDigits(value) {
	if (typeof value !== 'string' && typeof value !== 'number') return null;
	const digits = String(value);
	return /^\d+$/.test(digits) ? digits : null;
}

function verhoeff(value) {
	const digits = asDigits(value);
	if (!digits) return false;
	let checksum = 0;
	for (let index = 0; index < digits.length; index += 1) {
		const digit = digits.charCodeAt(digits.length - index - 1) - 48;
		checksum = VERHOEFF_D[checksum][VERHOEFF_P[index % 8][digit]];
	}
	return checksum === 0;
}

function verhoeffCheckDigit(value) {
	const digits = asDigits(value);
	if (!digits) throw new TypeError('Verhoeff input must contain only digits');
	let checksum = 0;
	for (let index = 0; index < digits.length; index += 1) {
		const digit = digits.charCodeAt(digits.length - index - 1) - 48;
		checksum = VERHOEFF_D[checksum][VERHOEFF_P[(index + 1) % 8][digit]];
	}
	return String(VERHOEFF_INV[checksum]);
}

function luhn(value) {
	const digits = asDigits(value);
	if (!digits || digits.length < 2) return false;
	let sum = 0;
	let doubleDigit = false;
	for (let index = digits.length - 1; index >= 0; index -= 1) {
		let digit = digits.charCodeAt(index) - 48;
		if (doubleDigit) {
			digit *= 2;
			if (digit > 9) digit -= 9;
		}
		sum += digit;
		doubleDigit = !doubleDigit;
	}
	return sum % 10 === 0;
}

const SKIPPED_DIRECTORY = /(?:^|\/)(?:node_modules|vendor|dist)(?:\/|$)/i;
const LOCKFILE_NAME = /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|cargo\.lock|composer\.lock|gemfile\.lock|pipfile\.lock|poetry\.lock|pdm\.lock|go\.sum|mix\.lock|pubspec\.lock|gradle\.lockfile|\.lock)(?:$|\/)/i;

const SUPPRESSION_PATTERNS = [
	/(?<![A-Fa-f0-9])[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}(?![A-Fa-f0-9])/g,
	/(?<![A-Fa-f0-9])[A-Fa-f0-9]{40,64}(?![A-Fa-f0-9])/gi,
	/\b(?:commit|git[_ -]?sha|sha|revision|hash)\s*[:= ]\s*[A-Fa-f0-9]{7,40}\b/gi,
	/(?<!\d)\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\.\d{1,9}Z?(?!\d)/g,
	/(?<!\d)\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}Z?(?!\d)/g,
	/(?<!\d)\d{4}-\d{2}-\d{2}(?!\d)/g,
	/(?<![A-Za-z0-9])v\d+\.\d+\.\d+\.\d+(?![A-Za-z0-9])/gi,
	/(?<![A-Za-z0-9])v\d+\.\d+\.\d+(?![A-Za-z0-9])/gi,
	/(?<![A-Za-z0-9])\d+\.\d+\.\d+\.\d+(?![A-Za-z0-9])/g,
	/(?<![A-Za-z0-9])\d+\.\d+\.\d+(?![A-Za-z0-9])/g,
];

const AADHAAR_PATTERN = /(?<!\d)([2-9]\d{3}\d{8}|[2-9]\d{3} \d{4} \d{4}|[2-9]\d{3}-\d{4}-\d{4})(?!\d)/g;
const PAN_PATTERN = /(^|[^A-Za-z0-9])([A-Z]{5}[0-9]{4}[A-Z])(?![A-Za-z0-9])/g;
const PAYMENT_CARD_PATTERN = /(?<![A-Za-z0-9])(\d{13,19})(?![A-Za-z0-9])/g;

const TEST_CARD_NUMBERS = new Set([
	'4111111111111111',
	'4012888888881881',
	'4242424242424242',
	'5555555555554444',
	'5105105105105100',
	'378282246310005',
	'371449635398431',
]);

function normalizePath(filePath) {
	return String(filePath || '').replace(/\\/g, '/');
}

function skippedReason(filePath) {
	if (SKIPPED_DIRECTORY.test(filePath)) return 'ignored dependency/build directory';
	if (LOCKFILE_NAME.test(filePath) || /(?:^|\/)[^/]+\.lock(?:$|\/)/i.test(filePath)) return 'ignored lockfile';
	return null;
}

function maskSuppressedSpans(content) {
	let safe = content;
	for (const pattern of SUPPRESSION_PATTERNS) {
		pattern.lastIndex = 0;
		safe = safe.replace(pattern, (match) => match.replace(/[^\r\n]/g, '\u0000'));
	}
	return safe;
}

function makeFinding(dataClass, filePath, line, confidence, matchedDigits, isLikelyTestData = false) {
	return {
		dataClass,
		filePath,
		line,
		confidence,
		evidence: `****${matchedDigits.slice(-4)}`,
		isLikelyTestData,
	};
}

function findCandidates(safeContent, originalContent, filePath) {
	const candidates = [];
	let match;
	AADHAAR_PATTERN.lastIndex = 0;
	while ((match = AADHAAR_PATTERN.exec(safeContent)) !== null) {
		const digits = match[1].replace(/[ -]/g, '');
		if (digits.length === 12 && verhoeff(digits)) {
			candidates.push({
				index: match.index,
				classOrder: 0,
				finding: makeFinding('AADHAAR', filePath, 0, 0.95, digits),
			});
		}
	}

	PAN_PATTERN.lastIndex = 0;
	while ((match = PAN_PATTERN.exec(safeContent)) !== null) {
		const valueIndex = match.index + match[1].length;
		candidates.push({
			index: valueIndex,
			classOrder: 1,
			finding: makeFinding('PAN', filePath, 0, 0.95, match[2]),
		});
	}

	PAYMENT_CARD_PATTERN.lastIndex = 0;
	while ((match = PAYMENT_CARD_PATTERN.exec(safeContent)) !== null) {
		const digits = match[1];
		if (!luhn(digits) || !hasKnownIssuerPrefix(digits)) continue;
		candidates.push({
			index: match.index,
			classOrder: 2,
			finding: makeFinding('PAYMENT_CARD', filePath, 0, 0.9, digits, TEST_CARD_NUMBERS.has(digits)),
		});
	}

	candidates.sort((left, right) => {
		if (left.index !== right.index) return left.index - right.index;
		return left.classOrder - right.classOrder;
	});
	const limited = candidates.slice(0, MAX_FINDINGS_PER_FILE);
	let position = 0;
	let line = 1;
	for (const candidate of limited) {
		while (position < candidate.index) {
			if (originalContent.charCodeAt(position) === 10) line += 1;
			position += 1;
		}
		candidate.finding.line = line;
	}
	return limited.map((candidate) => candidate.finding);
}

function hasKnownIssuerPrefix(digits) {
	if (digits.startsWith('4')) return true;
	if (digits.length === 15 && (digits.startsWith('34') || digits.startsWith('37'))) return true;
	const twoDigitPrefix = Number(digits.slice(0, 2));
	if (twoDigitPrefix >= 51 && twoDigitPrefix <= 55) return true;
	const fourDigitPrefix = Number(digits.slice(0, 4));
	if (fourDigitPrefix >= 2221 && fourDigitPrefix <= 2720) return true;
	return digits.startsWith('60') || digits.startsWith('6521') || digits.startsWith('6522') || digits.startsWith('508');
}

/**
 * Validate and locate sensitive values without retaining the value or source line.
 * Oversized/ignored files are exposed as non-enumerable `findings.skippedFiles`
 * diagnostics so the return value remains an array of finding contracts.
 *
 * @param {Array<{filePath:string,content:string}>} files
 * @returns {Array<{dataClass:string,filePath:string,line:number,confidence:number,evidence:string,isLikelyTestData:boolean}>}
 */
function detectValues(files) {
	if (!Array.isArray(files)) throw new TypeError('files must be an array');
	const findings = [];
	const skippedFiles = [];

	for (const file of files) {
		const filePath = normalizePath(file && file.filePath);
		if (!file || typeof file !== 'object' || typeof file.content !== 'string') {
			skippedFiles.push({ filePath, reason: 'content must be a string' });
			continue;
		}
		const skip = skippedReason(filePath);
		if (skip) {
			skippedFiles.push({ filePath, reason: skip });
			continue;
		}
		if (Buffer.byteLength(file.content, 'utf8') > MAX_FILE_BYTES) {
			skippedFiles.push({ filePath, reason: 'file exceeds 1 MiB limit' });
			continue;
		}
		const safeContent = maskSuppressedSpans(file.content);
		findings.push(...findCandidates(safeContent, file.content, filePath));
	}

	findings.sort((left, right) => {
		if (left.filePath < right.filePath) return -1;
		if (left.filePath > right.filePath) return 1;
		if (left.line !== right.line) return left.line - right.line;
		return left.dataClass < right.dataClass ? -1 : left.dataClass > right.dataClass ? 1 : 0;
	});
	skippedFiles.sort((left, right) => {
		if (left.filePath < right.filePath) return -1;
		if (left.filePath > right.filePath) return 1;
		return left.reason < right.reason ? -1 : left.reason > right.reason ? 1 : 0;
	});
	Object.defineProperty(findings, 'skippedFiles', { value: skippedFiles, enumerable: false });
	return findings;
}

const NAME_BOOLEAN_PREFIXES = ['has', 'is', 'was', 'can', 'should', 'enabled', 'valid', 'verified'];
const NON_FIELD_SQL_NAMES = new Set(['constraint', 'primary', 'foreign', 'unique', 'check', 'index', 'key']);
const NAME_PRIORITY = { both: 4, strongValue: 3, name: 2, weak: 1 };

function normalizeIdentifier(identifier) {
	return String(identifier || '')
		.replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
		.replace(/([a-z0-9])([A-Z])/g, '$1_$2')
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '_')
		.replace(/^_+|_+$/g, '');
}

function hasPhrase(identifier, phrase) {
	const words = normalizeIdentifier(identifier).split('_').filter(Boolean);
	const wanted = normalizeIdentifier(phrase).split('_').filter(Boolean);
	if (!wanted.length || wanted.length > words.length) return false;
	for (let start = 0; start <= words.length - wanted.length; start += 1) {
		let matched = true;
		for (let offset = 0; offset < wanted.length; offset += 1) {
			if (words[start + offset] !== wanted[offset]) {
				matched = false;
				break;
			}
		}
		if (matched) return true;
	}
	return false;
}

function matchesAny(identifier, values) {
	return values.some((value) => hasPhrase(identifier, value));
}

function classifyIdentifier(column, context) {
	const matches = Object.entries(SENSITIVE_NAME_SYNONYMS)
		.filter(([, synonyms]) => matchesAny(column, synonyms))
		.map(([dataClass]) => dataClass);
	if (!matches.length) return null;

	if (matches.includes('PAN')) {
		const specificTaxName = hasPhrase(column, 'pan_number') || hasPhrase(column, 'permanent_account');
		const taxContext = matchesAny(context, INCOME_TAX_CONTEXT_CUES);
		const paymentContextCues = PAYMENT_CONTEXT_CUES.filter((cue) => cue !== 'card');
		const paymentContext = matchesAny(context, paymentContextCues);
		if (!specificTaxName && !taxContext && paymentContext) return 'PAYMENT_CARD';
		return 'PAN';
	}
	if (matches.includes('PAYMENT_CARD')) return 'PAYMENT_CARD';
	for (const dataClass of ['AADHAAR', 'HEALTH', 'PII_OTHER']) {
		if (matches.includes(dataClass)) return dataClass;
	}
	return matches[0];
}

function isBooleanOrEnumType(typeText) {
	const type = String(typeText || '').toLowerCase();
	return /\b(?:bool|boolean)\w*\b|\benum\b|\bchoice\b|\byesno\b|\bflag\b/.test(type);
}

function matchingTextLength(typeText) {
	const type = String(typeText || '');
	const match = type.match(/(?:varchar|nvarchar|nchar|char|character\s+varying)\s*\(\s*(\d+)\s*\)|(?:max_length|length|size)\s*[:=]\s*(\d+)/i);
	if (!match) return null;
	return Number(match[1] || match[2]);
}

function isTextLikeType(typeText) {
	return /\b(?:string|str|varchar|nvarchar|nchar|char|character\s+varying|text|textfield|charfield)\b/i.test(String(typeText || ''));
}

function isPositiveTypeHint(dataClass, column, typeText) {
	const hints = COLUMN_TYPE_HINTS[dataClass] || {};
	const type = String(typeText || '').toLowerCase();
	if ((hints.numericTypes || []).some((name) => new RegExp(`\\b${name}\\b`, 'i').test(type))) return true;
	const length = matchingTextLength(typeText);
	if (length === null || !isTextLikeType(typeText)) return false;
	const fixedTextLengths = hints.fixedTextLengths || hints.textLengths || [];
	if (fixedTextLengths.includes(length)) return true;
	const textLengthRange = hints.textLengthRange || hints.textRange || null;
	if (textLengthRange && length >= textLengthRange[0] && length <= textLengthRange[1]) return true;
	if (dataClass === 'PII_OTHER' && (hasPhrase(column, 'dob') || hasPhrase(column, 'date_of_birth')) && /\b(?:date|datetime|timestamp)\b/i.test(type)) return true;
	if (dataClass === 'PII_OTHER' && matchesAny(column, ['phone', 'mobile']) && length >= 7 && length <= 20) return true;
	return false;
}

function isBooleanName(column) {
	const first = normalizeIdentifier(column).split('_')[0];
	return NAME_BOOLEAN_PREFIXES.includes(first);
}

function makeNameFinding({ filePath, line, schemaTable, column, typeText, context }) {
	const dataClass = classifyIdentifier(column, `${context || ''} ${schemaTable || ''} ${filePath || ''}`);
	if (!dataClass) return null;
	const weak = isBooleanOrEnumType(typeText) || isBooleanName(column);
	const typeMatch = isPositiveTypeHint(dataClass, column, typeText);
	const signals = ['name'];
	if (weak || typeMatch) signals.push('type');
	return {
		dataClass,
		filePath,
		line,
		schemaTable: schemaTable || null,
		column: String(column),
		confidence: weak ? WEAK_BOOLEAN_ENUM_CONFIDENCE : typeMatch ? NAME_AND_TYPE_CONFIDENCE : NAME_CONFIDENCE,
		signals,
	};
}

function unquoteIdentifier(identifier) {
	return String(identifier || '').replace(/^['"`\[]|['"`\]]$/g, '');
}

function splitSqlDefinitions(text) {
	const definitions = [];
	let start = 0;
	let depth = 0;
	let quote = '';
	let closed = false;
	for (let index = 0; index < text.length; index += 1) {
		const character = text[index];
		if (quote) {
			if (character === quote) {
				if (text[index + 1] === quote) index += 1;
				else quote = '';
			}
			continue;
		}
		if (character === '"' || character === '`' || character === "'") {
			quote = character;
			continue;
		}
		if (character === '(') depth += 1;
		else if (character === ')') {
			if (depth === 0) {
				definitions.push(text.slice(start, index));
				closed = true;
				break;
			}
			depth -= 1;
		} else if (character === ',' && depth === 0) {
			definitions.push(text.slice(start, index));
			start = index + 1;
		}
	}
	if (!closed) definitions.push(text.slice(start));
	return { definitions, closed };
}

function parseSqlDefinition(definition) {
	const trimmed = definition.trim().replace(/,$/, '').trim();
	if (!trimmed || /^\s*(?:constraint|primary|foreign|unique|check|index|key)\b/i.test(trimmed)) return null;
	const match = trimmed.match(/^(?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([A-Za-z_][A-Za-z0-9_$]*))\s+(.+)$/);
	if (!match) return null;
	const column = match[1] || match[2] || match[3] || match[4];
	if (NON_FIELD_SQL_NAMES.has(column.toLowerCase())) return null;
	return { column, typeText: match[5] };
}

function getPropertyNameFromObjectLine(line) {
	const pattern = /(^|[{,])\s*(?:"([^"]+)"|'([^']+)'|([A-Za-z_$][A-Za-z0-9_$-]*))\s*:\s*([^,}]+)/g;
	const found = [];
	let match;
	while ((match = pattern.exec(line)) !== null) {
		found.push({
			column: match[2] || match[3] || match[4],
		typeText: line,
		});
	}
	return found;
}

function extractParameterNames(line) {
	const names = [];
	const parentheses = /\(([^()]*)\)/g;
	let group;
	while ((group = parentheses.exec(line)) !== null) {
		for (const parameter of group[1].split(',')) {
			const clean = parameter.trim().split('=')[0].trim();
			if (!clean) continue;
			const colon = clean.match(/(?:^|\s)([A-Za-z_$][A-Za-z0-9_$-]*)\s*(?:\??\s*:)/);
			if (colon) {
				names.push({ column: colon[1], typeText: clean });
				continue;
			}
			const typed = clean.match(/(?:^|\s)([A-Za-z_$][A-Za-z0-9_$-]*)\s*$/);
			if (typed) names.push({ column: typed[1], typeText: clean });
		}
	}
	return names;
}

function dedupeNameFindings(findings) {
	const byField = new Map();
	for (const finding of findings) {
		const normalizedColumn = normalizeIdentifier(finding.column);
		const fieldScope = finding.schemaTable
			? `${finding.filePath}\u0000${normalizeIdentifier(finding.schemaTable)}\u0000${normalizedColumn}`
			: `${finding.filePath}\u0000${finding.line}\u0000${normalizedColumn}`;
		const key = `${fieldScope}\u0000${finding.dataClass}`;
		const existing = byField.get(key);
		if (!existing) {
			byField.set(key, finding);
			continue;
		}
		if (finding.confidence > existing.confidence) existing.confidence = finding.confidence;
		existing.signals = [...new Set([...existing.signals, ...finding.signals])].sort();
		existing.line = Math.min(existing.line, finding.line);
	}
	return [...byField.values()];
}

/**
 * Detect sensitive identifiers/schema fields; never returns source values or lines.
 * @param {Array<{filePath:string,content:string}>} files
 * @returns {Array<{dataClass:string,filePath:string,line:number,schemaTable:string|null,column:string,confidence:number,signals:string[]}>}
 */
function detectNames(files) {
	if (!Array.isArray(files)) throw new TypeError('files must be an array');
	const findings = [];
	const skippedFiles = [];
	for (const file of files) {
		const filePath = normalizePath(file && file.filePath);
		if (!file || typeof file !== 'object' || typeof file.content !== 'string') {
			skippedFiles.push({ filePath, reason: 'content must be a string' });
			continue;
		}
		const skip = skippedReason(filePath);
		if (skip) {
			skippedFiles.push({ filePath, reason: skip });
			continue;
		}
		if (Buffer.byteLength(file.content, 'utf8') > MAX_FILE_BYTES) {
			skippedFiles.push({ filePath, reason: 'file exceeds 1 MiB limit' });
			continue;
		}

		const fileFindings = [];
		const lines = file.content.split(/\r?\n/);
		let sqlTable = null;
		let currentTable = null;
		let pendingTypeOrmColumn = null;
		const add = (column, lineNumber, schemaTable, typeText, context) => {
			const finding = makeNameFinding({ filePath, line: lineNumber, schemaTable, column, typeText, context });
			if (finding) fileFindings.push(finding);
		};

		for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
			const line = lines[lineIndex];
			const trimmed = line.trim();
			if (!trimmed || /^(?:\/\/|#|--|\/\*|\*)/.test(trimmed)) continue;

			const createTable = line.match(/\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?("[^"]+"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][A-Za-z0-9_$.]*)/i);
			if (createTable) {
				sqlTable = unquoteIdentifier(createTable[1]);
				const open = line.indexOf('(', createTable.index + createTable[0].length);
				if (open >= 0) {
					const result = splitSqlDefinitions(line.slice(open + 1));
					for (const definition of result.definitions) {
						const field = parseSqlDefinition(definition);
						if (field) add(field.column, lineIndex + 1, sqlTable, field.typeText, line);
					}
					if (result.closed) sqlTable = null;
				}
				continue;
			}

			const alterTable = line.match(/\bALTER\s+TABLE\s+("[^"]+"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][A-Za-z0-9_$.]*)\s+ADD\s+(?:COLUMN\s+)?("[^"]+"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][A-Za-z0-9_$]*)\s+(.+)$/i);
			if (alterTable) {
				add(unquoteIdentifier(alterTable[2]), lineIndex + 1, unquoteIdentifier(alterTable[1]), alterTable[3], line);
				continue;
			}

			if (sqlTable) {
				const result = splitSqlDefinitions(line);
				for (const definition of result.definitions) {
					const field = parseSqlDefinition(definition);
					if (field) add(field.column, lineIndex + 1, sqlTable, field.typeText, line);
				}
				if (result.closed || /^\)\s*;?\s*$/.test(trimmed)) sqlTable = null;
			}

			const prismaModel = line.match(/^\s*model\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{/);
		if (prismaModel) currentTable = prismaModel[1];
		const classDeclaration = line.match(/\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*[:{]/);
		if (classDeclaration) currentTable = classDeclaration[1];
		const schemaVariable = line.match(/\b(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+(?:Schema|schema)\s*\(/i);
		if (schemaVariable) currentTable = schemaVariable[1];
		const table = sqlTable || currentTable;

		if (currentTable && prismaModel === null && !/^\s*(?:model|enum|datasource|generator)\b/.test(line)) {
			const prismaField = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z][A-Za-z0-9_]*(?:\s*\([^)]*\))?\??)(.*)$/);
			if (prismaField && !prismaField[1].startsWith('@')) {
				add(prismaField[1], lineIndex + 1, currentTable, `${prismaField[2]} ${prismaField[3]}`, line);
			}
		}

		const typeOrmDecorator = line.match(/@Column\s*\((.*)\)/);
		if (typeOrmDecorator) pendingTypeOrmColumn = { text: typeOrmDecorator[1], table: currentTable };
		const typeOrmProperty = line.match(/^\s*(?:(?:public|private|protected|readonly|static)\s+)*([A-Za-z_$][A-Za-z0-9_$]*)[?!]?\s*:\s*([^;]+);?\s*$/);
		if (pendingTypeOrmColumn && typeOrmProperty) {
			const explicitName = pendingTypeOrmColumn.text.match(/\bname\s*:\s*['"]([^'"]+)['"]/i);
			const column = explicitName ? explicitName[1] : typeOrmProperty[1];
			add(column, lineIndex + 1, pendingTypeOrmColumn.table, `${pendingTypeOrmColumn.text} ${typeOrmProperty[2]}`, line);
			pendingTypeOrmColumn = null;
		}

		const djangoField = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:models\.)?([A-Za-z_][A-Za-z0-9_]*Field)\s*\((.*)\)/);
		if (djangoField) add(djangoField[1], lineIndex + 1, currentTable, `${djangoField[2]} ${djangoField[3]}`, line);
		const sqlAlchemyField = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:(?:db\.)?Column|mapped_column)\s*\((.*)\)/);
		if (sqlAlchemyField) add(sqlAlchemyField[1], lineIndex + 1, currentTable, sqlAlchemyField[2], line);

		for (const property of getPropertyNameFromObjectLine(line)) {
			add(property.column, lineIndex + 1, table, property.typeText, line);
		}

		const variableDeclaration = line.match(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*([^=;]+))?\s*=/);
		if (variableDeclaration) add(variableDeclaration[1], lineIndex + 1, table, variableDeclaration[2] || '', line);
		const pythonAssignment = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?!models\.|Column\b|mapped_column\b)(.*)$/);
		if (pythonAssignment) add(pythonAssignment[1], lineIndex + 1, table, pythonAssignment[2], line);
		const typedDeclaration = line.match(/^\s*(?:(?:public|private|protected|static|final|readonly|volatile|transient)\s+)*(String|Long|Integer|int|long|boolean|Boolean|BigInteger|Date|LocalDate|LocalDateTime|str|CharField|TextField)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:[=;,)])/);
		if (typedDeclaration) add(typedDeclaration[2], lineIndex + 1, table, typedDeclaration[1], line);
		for (const parameter of extractParameterNames(line)) add(parameter.column, lineIndex + 1, table, parameter.typeText, line);

		if (/^\s*}\s*;?\s*$/.test(line) && !sqlTable) currentTable = null;
	}

	const uniqueFields = dedupeNameFindings(fileFindings);
	uniqueFields.sort((left, right) => {
		if (left.line !== right.line) return left.line - right.line;
		const leftName = normalizeIdentifier(left.column);
		const rightName = normalizeIdentifier(right.column);
		return leftName < rightName ? -1 : leftName > rightName ? 1 : 0;
	});
	findings.push(...uniqueFields.slice(0, MAX_FINDINGS_PER_FILE));
}

	findings.sort((left, right) => {
		if (left.filePath < right.filePath) return -1;
		if (left.filePath > right.filePath) return 1;
		if (left.line !== right.line) return left.line - right.line;
		const leftName = normalizeIdentifier(left.column);
		const rightName = normalizeIdentifier(right.column);
		return leftName < rightName ? -1 : leftName > rightName ? 1 : 0;
	});
	Object.defineProperty(findings, 'skippedFiles', { value: skippedFiles.sort((left, right) => left.filePath.localeCompare(right.filePath)), enumerable: false });
	return findings;
}

function stableFieldId(finding) {
	const column = normalizeIdentifier(finding.column || '');
	const schemaTable = normalizeIdentifier(finding.schemaTable || '');
	const location = schemaTable && column
		? [finding.filePath || '', schemaTable, column]
		: [finding.filePath || '', String(finding.line || ''), column];
	const digest = createHash('sha256').update(JSON.stringify([finding.dataClass, ...location])).digest('hex');
	return `field-${digest.slice(0, 24)}`;
}

function isSameValueField(valueFinding, nameFinding) {
	if (valueFinding.filePath !== nameFinding.filePath || valueFinding.dataClass !== nameFinding.dataClass) return false;
	if (valueFinding.schemaTable || valueFinding.column) {
		return normalizeIdentifier(valueFinding.schemaTable || '') === normalizeIdentifier(nameFinding.schemaTable || '') &&
			normalizeIdentifier(valueFinding.column || '') === normalizeIdentifier(nameFinding.column || '');
	}
	return valueFinding.line === nameFinding.line;
}

function priorityFor(finding) {
	const signals = finding.signals || [];
	const hasValue = signals.includes('value');
	const hasName = signals.includes('name');
	if (hasValue && hasName) return NAME_PRIORITY.both;
	if (hasValue && finding.confidence >= 0.85) return NAME_PRIORITY.strongValue;
	if (hasName) return NAME_PRIORITY.name;
	return NAME_PRIORITY.weak;
}

/** Combine value and identifier evidence; duplicate schema fields collapse only by table+column. */
function combineSignals(valueFindings, nameFindings) {
	if (!Array.isArray(valueFindings) || !Array.isArray(nameFindings)) throw new TypeError('valueFindings and nameFindings must be arrays');
	const names = dedupeNameFindings(nameFindings.map((finding) => ({ ...finding, signals: [...(finding.signals || ['name'])] })));
	const usedNames = new Set();
	const combined = [];

	for (const source of valueFindings) {
		const value = { ...source, signals: [...new Set([...(source.signals || []), 'value'])] };
		const matches = [];
		for (let index = 0; index < names.length; index += 1) {
			if (!usedNames.has(index) && isSameValueField(value, names[index])) matches.push(index);
		}
		if (matches.length === 1) {
			const index = matches[0];
			usedNames.add(index);
			const name = names[index];
			const confidence = 1 - ((1 - value.confidence) * (1 - name.confidence));
			const merged = {
				...value,
				schemaTable: name.schemaTable,
				column: name.column,
				signals: [...new Set([...value.signals, ...name.signals])].sort(),
				confidence,
			};
			merged.fieldId = stableFieldId(merged);
			combined.push(merged);
		} else {
			value.fieldId = stableFieldId(value);
			combined.push(value);
		}
	}

	for (let index = 0; index < names.length; index += 1) {
		if (usedNames.has(index)) continue;
		const name = { ...names[index], signals: [...new Set(names[index].signals || ['name'])].sort() };
		name.fieldId = stableFieldId(name);
		combined.push(name);
	}

	combined.sort((left, right) => {
		const priorityDifference = priorityFor(right) - priorityFor(left);
		if (priorityDifference) return priorityDifference;
		if (left.filePath < right.filePath) return -1;
		if (left.filePath > right.filePath) return 1;
		if ((left.line || 0) !== (right.line || 0)) return (left.line || 0) - (right.line || 0);
		return left.fieldId < right.fieldId ? -1 : left.fieldId > right.fieldId ? 1 : 0;
	});
	return combined;
}

module.exports = {
	MAX_FILE_BYTES,
	MAX_FINDINGS_PER_FILE,
	verhoeff,
	verhoeffCheckDigit,
	luhn,
	detectValues,
	normalizeIdentifier,
	detectNames,
	combineSignals,
};