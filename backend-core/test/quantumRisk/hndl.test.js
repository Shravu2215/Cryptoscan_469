'use strict';

const assert = require('assert');
const {
	MAX_FINDINGS_PER_FILE,
	verhoeff,
	verhoeffCheckDigit,
	luhn,
	detectValues,
	detectNames,
	combineSignals,
	normalizeIdentifier,
} = require('../../src/services/quantumRisk/hndl/detector');

function makeAadhaar(prefix = '23456789012') {
	return prefix + verhoeffCheckDigit(prefix);
}

function makeLuhnNumber(prefix, length) {
	let body = prefix;
	while (body.length < length - 1) body += String((body.length * 7 + 3) % 10);
	for (let digit = 0; digit <= 9; digit += 1) {
		const candidate = body + digit;
		if (luhn(candidate)) return candidate;
	}
	throw new Error('could not construct a Luhn-valid test number');
}

function runTests() {
	assert.strictEqual(verhoeff('2363'), true);
	assert.strictEqual(verhoeff('2364'), false);
	assert.strictEqual(verhoeff('23-63'), false);
	assert.strictEqual(luhn('79927398713'), true);
	assert.strictEqual(luhn('79927398714'), false);
	assert.strictEqual(luhn('7992-7398-713'), false);

	const aadhaar = makeAadhaar();
	const aadhaarFormatted = `${aadhaar.slice(0, 4)}-${aadhaar.slice(4, 8)}-${aadhaar.slice(8)}`;
	const visa = makeLuhnNumber('4', 16);
	const mastercard = makeLuhnNumber('555', 16);
	const rupay = makeLuhnNumber('6521', 16);
	const amex = makeLuhnNumber('37', 15);
	const pan = 'ABCPD1234Q';
	const invalidAadhaar = aadhaar.slice(0, -1) + ((Number(aadhaar.slice(-1)) + 1) % 10);
	const invalidCard = visa.slice(0, -1) + ((Number(visa.slice(-1)) + 1) % 10);
	const uuid = '123e4567-e89b-12d3-a456-426614174000';
	const gitSha = '0123456789abcdef0123456789abcdef01234567';
	const timestamp = '2025-10-03T12:34:56Z';
	const version = 'v2.4.10';

	const content = [
		`Aadhaar ${aadhaarFormatted}`,
		`PAN ${pan}`,
		`Visa ${visa}`,
		`Mastercard ${mastercard}`,
		`RuPay ${rupay}`,
		`Amex ${amex}`,
		`Sandbox test card 4111111111111111`,
		`invalid aadhaar ${invalidAadhaar}`,
		`invalid card ${invalidCard}`,
		`uuid ${uuid}`,
		`commit ${gitSha}`,
		`created ${timestamp}`,
		`version ${version}`,
	].join('\n');

	const findings = detectValues([{ filePath: 'src/records.ts', content }]);
	assert.deepStrictEqual(findings.map((finding) => finding.dataClass), [
		'AADHAAR', 'PAN', 'PAYMENT_CARD', 'PAYMENT_CARD', 'PAYMENT_CARD', 'PAYMENT_CARD', 'PAYMENT_CARD',
	]);
	assert.deepStrictEqual(findings.map((finding) => finding.line), [1, 2, 3, 4, 5, 6, 7]);
	assert.strictEqual(findings[0].evidence, `****${aadhaar.slice(-4)}`);
	assert.strictEqual(findings[1].evidence, `****${pan.slice(-4)}`);
	assert(findings.every((finding) => finding.confidence > 0 && finding.confidence <= 1));
	assert(findings.slice(0, 6).every((finding) => finding.isLikelyTestData === false));
	assert.strictEqual(findings[6].isLikelyTestData, true);
	const serialized = JSON.stringify(findings);
	for (const sample of [aadhaar, aadhaarFormatted, pan, visa, mastercard, rupay, amex, '4111111111111111']) {
		assert(!serialized.includes(sample), 'serialized findings must not expose a complete sample value');
	}

	const skipped = detectValues([
		{ filePath: 'repo/node_modules/data.txt', content: `PAN ${pan}` },
		{ filePath: 'repo/vendor/data.txt', content: `PAN ${pan}` },
		{ filePath: 'repo/dist/data.txt', content: `PAN ${pan}` },
		{ filePath: 'repo/package-lock.json', content: `PAN ${pan}` },
		{ filePath: 'repo/large.txt', content: 'x'.repeat(1024 * 1024 + 1) },
	]);
	assert.strictEqual(skipped.length, 0);
	assert.strictEqual(skipped.skippedFiles.length, 5);
	assert(skipped.skippedFiles.some((item) => item.filePath === 'repo/large.txt' && /exceeds 1 MiB/.test(item.reason)));

	const manyPans = Array.from({ length: MAX_FINDINGS_PER_FILE + 50 }, (_, index) => {
		const suffix = String(index).padStart(4, '0');
		return `ABCPD${suffix}Q`;
	}).join('\n');
	const capped = detectValues([{ filePath: 'z-file.txt', content: manyPans }, { filePath: 'a-file.txt', content: `PAN ${pan}` }]);
	assert.strictEqual(capped.filter((finding) => finding.filePath === 'z-file.txt').length, MAX_FINDINGS_PER_FILE);
	assert.strictEqual(capped[0].filePath, 'a-file.txt');
	assert(capped.every((finding, index) => index === 0 || capped[index - 1].filePath <= finding.filePath));

	const longLine = '1234567890'.repeat(90000);
	const started = Date.now();
	const pathological = detectValues([{ filePath: 'src/long-line.txt', content: longLine }]);
	const elapsed = Date.now() - started;
	assert.strictEqual(pathological.length, 0);
	assert(elapsed < 3000, `pathological long-line input took ${elapsed}ms`);

	const nameFiles = [
		{
			filePath: 'models/identity.sql',
			content: [
				'CREATE TABLE identity_records (',
				'  aadhaar_number VARCHAR(12),',
				'  pan_number CHAR(10),',
				'  card_number VARCHAR(16),',
				'  diagnosis TEXT,',
				'  email VARCHAR(254)',
				');',
			].join('\n'),
		},
		{ filePath: 'models/prisma.prisma', content: 'model Member {\n  UIDAI String @db.VarChar(12)\n}' },
		{ filePath: 'models/django.py', content: 'class Patient(models.Model):\n    patient = models.CharField(max_length=100)' },
		{
			filePath: 'models/typeorm.ts',
			content: "@Entity()\nclass Account {\n  @Column({ type: 'varchar', length: 10 })\n  panNumber: string;\n}",
		},
		{ filePath: 'models/schema.json', content: '{\n  "properties": {\n    "dateOfBirth": { "type": "string", "format": "date" }\n  }\n}' },
		{ filePath: 'models/mongoose.js', content: 'const recordSchema = new Schema({\n  bloodGroup: { type: String },\n});' },
		{ filePath: 'src/plain.ts', content: 'function lookup(aadhaarNumber: string) {\n  const cardHolder = "masked";\n}' },
	];
	const named = detectNames(nameFiles);
	assert(named.some((finding) => finding.dataClass === 'AADHAAR' && finding.filePath === 'models/identity.sql'));
	assert(named.some((finding) => finding.dataClass === 'PAN' && finding.filePath === 'models/identity.sql'));
	assert(named.some((finding) => finding.dataClass === 'PAYMENT_CARD' && finding.column === 'card_number'));
	assert(named.some((finding) => finding.dataClass === 'HEALTH' && finding.column === 'diagnosis'));
	assert(named.some((finding) => finding.dataClass === 'PII_OTHER' && finding.column === 'email'));
	assert(named.some((finding) => finding.dataClass === 'AADHAAR' && finding.filePath === 'models/prisma.prisma'));
	assert(named.some((finding) => finding.dataClass === 'HEALTH' && finding.filePath === 'models/django.py'));
	assert(named.some((finding) => finding.dataClass === 'PAN' && finding.filePath === 'models/typeorm.ts'));
	assert(named.some((finding) => finding.dataClass === 'PII_OTHER' && finding.column === 'dateOfBirth'));
	assert(named.some((finding) => finding.dataClass === 'HEALTH' && finding.column === 'bloodGroup'));
	assert(named.some((finding) => finding.dataClass === 'AADHAAR' && finding.column === 'aadhaarNumber'));
	assert(named.some((finding) => finding.dataClass === 'PAYMENT_CARD' && finding.column === 'cardHolder'));
	assert.strictEqual(normalizeIdentifier('AadhaarNumber'), 'aadhaar_number');
	assert.strictEqual(normalizeIdentifier('PAN_NUMBER'), 'pan_number');
	assert.strictEqual(normalizeIdentifier('card-holder'), 'card_holder');
	assert.strictEqual(named.find((finding) => finding.filePath === 'models/identity.sql' && finding.column === 'aadhaar_number').confidence, 0.9);

	const flag = detectNames([{ filePath: 'models/flags.prisma', content: 'model Flags {\n has_pan Boolean\n}' }])
		.find((finding) => finding.column === 'has_pan');
	assert(flag);
	assert(flag.confidence < 0.5);
	assert(flag.signals.includes('type'));

	const disambiguated = detectNames([
		{ filePath: 'models/payment.sql', content: 'CREATE TABLE payments (\n  pan VARCHAR(16)\n);' },
		{ filePath: 'models/tax.sql', content: 'CREATE TABLE income_tax_records (\n  pan VARCHAR(10)\n);' },
	]);
	assert(disambiguated.some((finding) => finding.dataClass === 'PAYMENT_CARD' && finding.schemaTable === 'payments'));
	assert(disambiguated.some((finding) => finding.dataClass === 'PAN' && finding.schemaTable === 'income_tax_records'));

	const nameMatch = detectNames([{ filePath: 'src/identity.py', content: 'x = 1\naadhaar_number = None' }])[0];
	const bothValue = { dataClass: 'AADHAAR', filePath: 'src/identity.py', line: 2, confidence: 0.9, evidence: '****1234' };
	const strongValue = { dataClass: 'PAN', filePath: 'src/value.py', line: 4, confidence: 0.95, evidence: '****1234' };
	const weakValue = { dataClass: 'HEALTH', filePath: 'src/weak.py', line: 8, confidence: 0.4, evidence: '****1234' };
	const combined = combineSignals([bothValue, strongValue, weakValue], [nameMatch]);
	assert.strictEqual(combined[0].dataClass, 'AADHAAR');
	assert(combined[0].signals.includes('value') && combined[0].signals.includes('name'));
	assert(combined[0].confidence > bothValue.confidence && combined[0].confidence > nameMatch.confidence);
	assert(combined[0].fieldId.startsWith('field-'));
	assert.deepStrictEqual(combined.map((finding) => finding.filePath), ['src/identity.py', 'src/value.py', 'src/weak.py']);
	assert.strictEqual(combineSignals([], [nameMatch])[0].fieldId, combineSignals([], [nameMatch])[0].fieldId);

	const deduped = combineSignals([], [
		{ ...nameMatch, schemaTable: 'Identity', column: 'email', dataClass: 'PII_OTHER' },
		{ ...nameMatch, schemaTable: 'Identity', column: 'email', line: nameMatch.line + 1, dataClass: 'PII_OTHER', confidence: 0.8 },
		{ ...nameMatch, schemaTable: 'Identity', column: 'phone', dataClass: 'PII_OTHER' },
	]);
	assert.strictEqual(deduped.length, 2, 'only identical table+column fields are deduplicated');

	const skippedNames = detectNames([
		{ filePath: 'repo/node_modules/schema.prisma', content: 'model User {\n aadhaarNumber String\n}' },
	]);
	assert.strictEqual(skippedNames.length, 0);
	assert.strictEqual(skippedNames.skippedFiles[0].reason, 'ignored dependency/build directory');
	assert.deepStrictEqual(detectNames(nameFiles), detectNames(nameFiles));

	console.log(`HNDL value detector tests passed (${elapsed}ms pathological-line check).`);
}

// ─── Retention + detectSensitiveData tests ───────────────────────────────────

function runRetentionTests() {
	const { assignRetention, defaultRetention, DEFAULT_RETENTION_POLICY } = require('../../src/services/quantumRisk/hndl/retention');
	const { detectSensitiveData } = require('../../src/services/quantumRisk/hndl/index');

	// 1. Default policy exists for every data class and has required shape
	const CLASSES = ['AADHAAR', 'PAN', 'PAYMENT_CARD', 'HEALTH', 'PII_OTHER'];
	for (const cls of CLASSES) {
		const def = defaultRetention(cls);
		assert.strictEqual(def.retentionSource, 'default', `${cls} retentionSource should be 'default'`);
		assert(Number.isFinite(def.retentionYears) && def.retentionYears > 0, `${cls} retentionYears must be positive`);
		assert(typeof def.note === 'string' && def.note.length > 0, `${cls} note must be non-empty`);
		assert(def.note.includes('ASSUMPTION'), `${cls} note must mention ASSUMPTION`);
		assert(!def.note.match(/section\s+\d|act\s+\d{4}|article\s+\d/i), `${cls} note must not cite law sections`);
	}

	// 2. Stated beats default
	const statedFiles = [{ filePath: 'config/settings.yml', content: 'retain for 10 years\naadhaar_number = null' }];
	const statedResult = assignRetention('aadhaar_number', statedFiles, {});
	assert(statedResult !== null, 'should find stated retention');
	assert.strictEqual(statedResult.retentionSource, 'stated');
	assert.strictEqual(statedResult.retentionYears, 10);

	// 3. Conflicting values — take the longest
	const conflictFiles = [{
		filePath: 'src/policy.js',
		content: [
			'// retain for 3 years',
			'// aadhaar_number retention period',
			'// retain for 7 years',
		].join('\n'),
	}];
	const conflictResult = assignRetention('aadhaar_number', conflictFiles, {});
	assert(conflictResult !== null, 'should detect conflicting stated values');
	assert.strictEqual(conflictResult.retentionYears, 7, 'longest retention should win');
	assert(conflictResult.note.includes('conflict'), 'note should mention conflict');

	// 4. Inferred case — config key names the field
	const inferredFiles = [{
		filePath: 'config/app.json',
		content: JSON.stringify({ aadhaar_number_retention_days: 1825 }),
	}];
	const noStatedResult = assignRetention('aadhaar_number', inferredFiles, {});
	assert(noStatedResult !== null, 'should find inferred retention');
	assert.strictEqual(noStatedResult.retentionSource, 'inferred');
	assert(noStatedResult.retentionYears > 0);

	// 5. Override wins over everything
	const overrideFiles = [{ filePath: 'src/data.js', content: 'retain for 3 years\naadhaar_number = x' }];
	const overrideResult = assignRetention('aadhaar_number', overrideFiles, {
		fieldId: 'field-abc',
		overrides: { 'field-abc': { retentionYears: 25 } },
	});
	assert(overrideResult !== null, 'override should return a result');
	assert.strictEqual(overrideResult.retentionYears, 25, 'override years should be 25');

	// 6. End-to-end detectSensitiveData on a small inline fixture
	const { verhoeffCheckDigit, luhn } = require('../../src/services/quantumRisk/hndl/detector');
	const aadhaarPrefix = '23456789012';
	const aadhaar = aadhaarPrefix + verhoeffCheckDigit(aadhaarPrefix);
	function makeLuhnNum(prefix, length) {
		let body = prefix;
		while (body.length < length - 1) body += String((body.length * 7 + 3) % 10);
		for (let d = 0; d <= 9; d += 1) {
			const candidate = body + d;
			if (luhn(candidate)) return candidate;
		}
		throw new Error('no luhn');
	}
	const visa = makeLuhnNum('4', 16);

	const fixtureFiles = [
		{
			filePath: 'src/records.ts',
			content: [
				`const aadhaarNumber = "${aadhaar}";`,
				`const cardNumber = "${visa}";`,
			].join('\n'),
		},
		{
			filePath: 'schema/users.sql',
			content: [
				'CREATE TABLE users (',
				'  aadhaar_number VARCHAR(12),',
				'  email VARCHAR(254)',
				');',
			].join('\n'),
		},
	];

	const result = detectSensitiveData({ files: fixtureFiles });

	assert(result && Array.isArray(result.fields), 'fields must be an array');
	assert(typeof result.stats === 'object', 'stats must be an object');
	assert(typeof result.meta === 'object', 'meta must be an object');
	assert(typeof result.meta.engineVersion === 'string', 'engineVersion must be a string');
	assert(Number.isFinite(result.stats.filesScanned), 'filesScanned must be finite');
	assert(Array.isArray(result.stats.filesSkipped), 'filesSkipped must be an array');
	assert(typeof result.stats.byClass === 'object', 'byClass must be an object');

	// Every field must have retentionSource
	for (const field of result.fields) {
		assert(
			['stated', 'inferred', 'default'].includes(field.retentionSource),
			`field ${field.fieldId} missing valid retentionSource, got: ${field.retentionSource}`
		);
		assert(Number.isFinite(field.retentionYears) && field.retentionYears > 0, `field ${field.fieldId} retentionYears must be positive`);
		assert(Array.isArray(field.protectedBy), 'protectedBy must be an array');
		assert.strictEqual(field.lineageConfidence, 0, 'lineageConfidence must be 0');
	}

	// 7. Serialized output contains no raw sample values
	const serialized = JSON.stringify(result);
	for (const raw of [aadhaar, visa]) {
		assert(!serialized.includes(raw), `serialized output must not contain raw value: ${raw}`);
	}

	// 8. Output is deterministic
	const result2 = detectSensitiveData({ files: fixtureFiles });
	assert.deepStrictEqual(
		result.fields.map((f) => f.fieldId),
		result2.fields.map((f) => f.fieldId),
		'detectSensitiveData must be deterministic'
	);

	// 9. byClass counts are correct
	for (const [cls, count] of Object.entries(result.stats.byClass)) {
		assert.strictEqual(
			result.fields.filter((f) => f.dataClass === cls).length,
			count,
			`byClass[${cls}] count mismatch`
		);
	}

	console.log('Retention + detectSensitiveData tests passed.');
}

runTests();
runRetentionTests();

// ─── Lineage tests ────────────────────────────────────────────────────────────

function runLineageTests() {
	const { linkFieldsToAssets, SIGNAL_WEIGHTS, CONFIDENCE_CAP } = require('../../src/services/quantumRisk/hndl/lineage');

	// Helper: build a minimal SensitiveDataField
	function makeField(filePath, line, column, schemaTable) {
		return {
			fieldId: 'field-test-' + filePath + line,
			dataClass: 'AADHAAR',
			column: column || null,                        // top-level, as detector produces
			location: schemaTable ? { schemaTable, column } : { filePath, line },
			retentionYears: 5,
			retentionSource: 'default',
			protectedBy: [],
			detectionConfidence: 0.9,
			lineageConfidence: 0,
			evidence: [],
			signals: ['name'],
		};
	}

	// Helper: build a minimal CryptoAsset
	function makeAsset(id, filePath, lineNumber, usage, sources) {
		return {
			assetId: id,
			findingId: 'finding-' + id,
			algorithm: 'AES-256',
			family: 'AES',
			keySize: 256,
			usage: usage || 'encryption',
			filePath,
			lineNumber: lineNumber || 10,
			service: null,
			confidence: 1,
			sources: sources || ['static'],
		};
	}

	// ── Test 1: same file, close lines -> high confidence ─────────────────────
	const f1 = makeField('src/user.js', 5, 'aadhaar_number');
	const a1 = makeAsset('asset-1', 'src/user.js', 8, 'encryption');
	linkFieldsToAssets({ fields: [f1], assets: [a1], files: [] });
	assert.strictEqual(f1.lineageStatus, 'linked', 'same file close: should be linked');
	assert(f1.lineageConfidence >= 0.7, `same file close: confidence should be >=0.7, got ${f1.lineageConfidence}`);
	assert(f1.protectedBy.includes('asset-1'), 'same file close: assetId in protectedBy');
	assert(f1.lineageEvidence.some((e) => /same file/.test(e)), 'same file evidence present');

	// ── Test 2: same file, far apart -> lower confidence than close ───────────
	const f2 = makeField('src/user.js', 5, 'aadhaar_number');
	const a2 = makeAsset('asset-2', 'src/user.js', 200, 'encryption');
	linkFieldsToAssets({ fields: [f2], assets: [a2], files: [] });
	assert.strictEqual(f2.lineageStatus, 'linked', 'far apart: should still be linked (same file)');
	assert(f2.lineageConfidence < f1.lineageConfidence, `far apart: confidence ${f2.lineageConfidence} should be < close ${f1.lineageConfidence}`);
	assert(!f2.lineageEvidence.some((e) => /apart/.test(e)), 'far apart: no close-lines evidence');

	// ── Test 3: field name referenced in encrypt() call -> boosted confidence ─
	const fileWithEncrypt = [
		'const aadhaarNumber = row.aadhaarNumber;',
		'',
		'',
		'function protect(data) {',
		'  return encrypt(aadhaarNumber, key);',
		'}',
	].join('\n');
	const f3 = makeField('src/crypto.js', 1, 'aadhaarNumber');
	const a3 = makeAsset('asset-3', 'src/crypto.js', 4, 'encryption');
	linkFieldsToAssets({
		fields: [f3],
		assets: [a3],
		files: [{ filePath: 'src/crypto.js', content: fileWithEncrypt }],
	});
	assert.strictEqual(f3.lineageStatus, 'linked');
	assert(
		f3.lineageEvidence.some((e) => /crypto call/.test(e)),
		`encrypt call: expected crypto call evidence, got: ${JSON.stringify(f3.lineageEvidence)}`
	);
	// boosted > same-file-only confidence
	assert(f3.lineageConfidence > f2.lineageConfidence, 'encrypt call: confidence should exceed far-apart same-file');

	// ── Test 4: import link (field file imports asset file, one hop) ──────────
	const fieldFileContent = "import { aesEncrypt } from './crypto/aes';\nconst aadhaar = row.aadhaarId;";
	const f4 = makeField('src/service.js', 2, 'aadhaar');
	const a4 = makeAsset('asset-4', 'src/crypto/aes.js', 1, 'encryption');
	linkFieldsToAssets({
		fields: [f4],
		assets: [a4],
		files: [
			{ filePath: 'src/service.js', content: fieldFileContent },
			{ filePath: 'src/crypto/aes.js', content: 'export function aesEncrypt() {}' },
		],
	});
	assert.strictEqual(f4.lineageStatus, 'linked', 'import link: should be linked');
	assert(f4.protectedBy.includes('asset-4'), 'import link: asset-4 in protectedBy');
	assert(
		f4.lineageEvidence.some((e) => /import/.test(e)),
		`import link: expected import evidence, got: ${JSON.stringify(f4.lineageEvidence)}`
	);

	// ── Test 5: different service -> low or no confidence ─────────────────────
	const f5 = makeField('services/billing/src/invoice.js', 10, 'pan_number');
	const a5 = makeAsset('asset-5', 'services/auth/src/crypto.js', 5, 'encryption');
	linkFieldsToAssets({ fields: [f5], assets: [a5], files: [] });
	// Different service, no file match, no import link -> score should be 0 or very low
	assert(
		f5.lineageConfidence < 0.2,
		`different service: confidence should be <0.2, got ${f5.lineageConfidence}`
	);

	// ── Test 6: no crypto asset -> no_crypto_found with confidence 0 ──────────
	const f6 = makeField('src/records.js', 3, 'aadhaar_id');
	linkFieldsToAssets({ fields: [f6], assets: [], files: [] });
	assert.strictEqual(f6.lineageStatus, 'no_crypto_found', 'no assets: should be no_crypto_found');
	assert.strictEqual(f6.lineageConfidence, 0, 'no assets: confidence must be 0');
	assert.deepStrictEqual(f6.protectedBy, [], 'no assets: protectedBy must be empty');
	assert(f6.lineageEvidence.some((e) => /unknown/.test(e)), 'no assets: evidence should mention unknown');

	// ── Test 7: output is deterministic ───────────────────────────────────────
	const fA = makeField('src/data.js', 1, 'email');
	const fB = makeField('src/data.js', 1, 'email');
	const assets7 = [
		makeAsset('asset-x', 'src/data.js', 2, 'encryption'),
		makeAsset('asset-y', 'src/data.js', 3, 'encryption'),
	];
	linkFieldsToAssets({ fields: [fA], assets: assets7, files: [] });
	linkFieldsToAssets({ fields: [fB], assets: assets7, files: [] });
	assert.deepStrictEqual(fA.protectedBy, fB.protectedBy, 'lineage must be deterministic');
	assert.strictEqual(fA.lineageConfidence, fB.lineageConfidence, 'lineage confidence must be deterministic');

	// ── Test 8: confidence cap is respected ───────────────────────────────────
	// Stack all signals on one field: same file + close + encrypt call + runtime
	const multiSignalContent = 'const x = encrypt(email, key);';
	const fCap = makeField('src/x.js', 1, 'email');
	const aCap = makeAsset('asset-cap', 'src/x.js', 1, 'encryption', ['static', 'runtime']);
	linkFieldsToAssets({
		fields: [fCap],
		assets: [aCap],
		files: [{ filePath: 'src/x.js', content: multiSignalContent }],
	});
	assert(fCap.lineageConfidence <= CONFIDENCE_CAP, `confidence must not exceed cap ${CONFIDENCE_CAP}, got ${fCap.lineageConfidence}`);

	// ── Test 9: serialized lineage output contains no raw sensitive values ─────
	const serialized = JSON.stringify({ protectedBy: f1.protectedBy, evidence: f1.lineageEvidence });
	// Evidence items are short masked strings; check no full Aadhaar/PAN-style numbers leak
	assert(!/\b\d{12}\b/.test(serialized), 'lineage serialization must not contain 12-digit Aadhaar');

	console.log('Lineage tests passed.');
}

runLineageTests();

// ─── Exposure tests ───────────────────────────────────────────────────────────

function runExposureTests() {
	const { computeDataExposure, SENSITIVITY_WEIGHTS } = require('../../src/services/quantumRisk/hndl/exposure');

	// Helper for fields
	function makeField(id, dataClass, retentionYears, lineageStatus, protectedBy, detConf = 0.9, linConf = 0.8) {
		return {
			fieldId: id,
			dataClass,
			location: { filePath: 'src/user.js', line: 10 },
			retentionYears,
			retentionSource: 'stated',
			protectedBy: protectedBy || [],
			detectionConfidence: detConf,
			lineageConfidence: linConf,
			lineageStatus: lineageStatus || (protectedBy && protectedBy.length ? 'linked' : 'no_crypto_found'),
			evidence: ['****1234'],
		};
	}

	// Helper for assets
	function makeAsset(id, family, usage, keySize = 2048) {
		return {
			assetId: id,
			algorithm: `${family}-${keySize}`,
			family,
			keySize,
			usage,
			filePath: 'src/crypto.js',
			lineNumber: 5,
		};
	}

	const rsaAsset = makeAsset('asset-rsa-2048', 'RSA', 'encryption', 2048);
	const sigAsset = makeAsset('asset-sig', 'RSA', 'digital_signature', 2048);
	const pqcAsset = makeAsset('asset-pqc', 'PQC', 'key_exchange', null);

	// 1. retention 5 vs 20 => higher p for 20
	const field5 = makeField('field-5yr', 'AADHAAR', 5, 'linked', ['asset-rsa-2048']);
	const field20 = makeField('field-20yr', 'AADHAAR', 20, 'linked', ['asset-rsa-2048']);
	const resRet = computeDataExposure({
		fields: [field5, field20],
		assets: [rsaAsset],
		options: { seed: 42, iterations: 1000 },
	});
	const exp5 = resRet.exposures.find((e) => e.fieldId === 'field-5yr');
	const exp20 = resRet.exposures.find((e) => e.fieldId === 'field-20yr');
	assert(exp5 && exp20, 'both exposures should exist');
	assert(
		exp20.exposureProbability > exp5.exposureProbability,
		`20-year retention probability (${exp20.exposureProbability}) should be higher than 5-year (${exp5.exposureProbability})`
	);

	// 2. same asset protecting two fields with different retention gives different p
	assert.notStrictEqual(
		exp5.exposureProbability,
		exp20.exposureProbability,
		'same asset protecting fields with different retention must give different p'
	);
	assert.strictEqual(exp5.assetId, 'asset-rsa-2048');
	assert.strictEqual(exp20.assetId, 'asset-rsa-2048');

	// 3. signature asset skipped
	const fieldSig = makeField('field-sig', 'PAN', 5, 'linked', ['asset-sig']);
	const resSig = computeDataExposure({
		fields: [fieldSig],
		assets: [sigAsset],
	});
	assert.strictEqual(resSig.exposures.length, 0, 'signature asset should produce 0 exposures');
	assert(
		resSig.summary.skipped.some((s) => s.assetId === 'asset-sig'),
		'signature asset should be listed in summary.skipped'
	);

	// 4. PQC asset skipped
	const fieldPqc = makeField('field-pqc', 'PAYMENT_CARD', 5, 'linked', ['asset-pqc']);
	const resPqc = computeDataExposure({
		fields: [fieldPqc],
		assets: [pqcAsset],
	});
	assert.strictEqual(resPqc.exposures.length, 0, 'PQC asset should produce 0 exposures');
	assert(
		resPqc.summary.skipped.some((s) => s.assetId === 'asset-pqc'),
		'PQC asset should be listed in summary.skipped'
	);

	// 5. no_crypto_found goes to unprotected
	const fieldUnprotected = makeField('field-unprot', 'HEALTH', 5, 'no_crypto_found', []);
	const resUnprot = computeDataExposure({
		fields: [fieldUnprotected],
		assets: [rsaAsset],
	});
	assert.strictEqual(resUnprot.exposures.length, 0, 'unprotected field should produce no exposures');
	assert.strictEqual(resUnprot.unprotected.length, 1, 'unprotected field should be in unprotected array');
	assert.strictEqual(resUnprot.unprotected[0].reason, 'protection unknown');

	// 6. pessimistic >= optimistic
	const { loadDefaultScenarios } = require('../../src/services/quantumRisk/threatModel/scenarios');
	const defaultScenarios = loadDefaultScenarios();
	const optScenario = defaultScenarios.find((s) => s.name === 'optimistic' || s.id.includes('optimistic'));
	const pessScenario = defaultScenarios.find((s) => s.name === 'pessimistic' || s.id.includes('pessimistic'));
	assert(optScenario && pessScenario, 'optimistic and pessimistic scenarios should exist');

	const fieldScen = makeField('field-scen', 'AADHAAR', 10, 'linked', ['asset-rsa-2048']);
	const resScen = computeDataExposure({
		fields: [fieldScen],
		assets: [rsaAsset],
		scenarios: [optScenario, pessScenario],
		options: { seed: 42, iterations: 1000 },
	});
	const expOpt = resScen.exposures.find((e) => e.scenarioId === optScenario.id);
	const expPess = resScen.exposures.find((e) => e.scenarioId === pessScenario.id);
	assert(expOpt && expPess, 'exposures for optimistic and pessimistic scenarios should exist');
	assert(
		expPess.exposureProbability >= expOpt.exposureProbability,
		`pessimistic p (${expPess.exposureProbability}) should be >= optimistic p (${expOpt.exposureProbability})`
	);

	// 7. deterministic with same seed
	const resDet1 = computeDataExposure({
		fields: [field5],
		assets: [rsaAsset],
		options: { seed: 123, iterations: 500 },
	});
	const resDet2 = computeDataExposure({
		fields: [field5],
		assets: [rsaAsset],
		options: { seed: 123, iterations: 500 },
	});
	assert.strictEqual(
		resDet1.exposures[0].exposureProbability,
		resDet2.exposures[0].exposureProbability,
		'same seed must yield deterministic exposureProbability'
	);
	assert.strictEqual(
		resDet1.exposures[0].riskScore,
		resDet2.exposures[0].riskScore,
		'same seed must yield deterministic riskScore'
	);

	// 8. explanation contains no raw sample value
	const rawSample = '987654321098';
	const fieldWithEvidence = makeField('field-raw', 'AADHAAR', 5, 'linked', ['asset-rsa-2048']);
	fieldWithEvidence.evidence = [rawSample];
	const resRaw = computeDataExposure({
		fields: [fieldWithEvidence],
		assets: [rsaAsset],
	});
	const expRaw = resRaw.exposures[0];
	assert(expRaw && typeof expRaw.explanation === 'string', 'explanation must be a string');
	assert(!expRaw.explanation.includes(rawSample), 'explanation must contain no raw sample value');
	assert(expRaw.explanation.includes('Aadhaar'), 'explanation should contain class label');

	// 9. lowConfidence flag set
	const fieldHighConf = makeField('field-high-conf', 'PAN', 5, 'linked', ['asset-rsa-2048'], 0.9, 0.8); // 0.9 * 0.8 = 0.72 >= 0.4
	const fieldLowConf = makeField('field-low-conf', 'PAN', 5, 'linked', ['asset-rsa-2048'], 0.5, 0.6);   // 0.5 * 0.6 = 0.30 < 0.4
	const resConf = computeDataExposure({
		fields: [fieldHighConf, fieldLowConf],
		assets: [rsaAsset],
	});
	const expHighConf = resConf.exposures.find((e) => e.fieldId === 'field-high-conf');
	const expLowConf = resConf.exposures.find((e) => e.fieldId === 'field-low-conf');
	assert.strictEqual(expHighConf.lowConfidence, false, 'overallConfidence >= 0.4 should have lowConfidence = false');
	assert.strictEqual(expLowConf.lowConfidence, true, 'overallConfidence < 0.4 should have lowConfidence = true');

	console.log('Exposure tests passed.');
}

async function runScanHookTests() {
	const { collectHndlForScan, runHndlScanHook } = require('../../src/services/quantumRisk/hndl/scanHook');
	const { verhoeffCheckDigit } = require('../../src/services/quantumRisk/hndl/detector');

	const prefix = '23456789012';
	const rawAadhaar = prefix + verhoeffCheckDigit(prefix);

	const files = [
		{
			filePath: 'src/user.js',
			content: `const aadhaar = "${rawAadhaar}";\nfunction protect() { return encrypt(aadhaar); }`,
		},
	];
	const findings = [
		{
			id: 'finding-1',
			scanId: 'hook-scan-1',
			filePath: 'src/user.js',
			lineNumber: 2,
			algorithm: 'RSA-2048',
			keySize: 2048,
			usage: 'key_exchange',
		},
	];

	// 1. Hook output has no raw sample value
	const fields = await collectHndlForScan({ scanId: 'hook-scan-1', files, findings });
	assert(fields.length > 0, 'collectHndlForScan should return detected fields');
	const serialized = JSON.stringify(fields);
	assert(!serialized.includes(rawAadhaar), 'hook output must not contain raw sample value');

	// 2. Hook failure does not throw into scan flow
	let threw = false;
	try {
		await runHndlScanHook({ scanId: null, targetPath: '/invalid/path/does/not/exist', findings: null });
	} catch (e) {
		threw = true;
	}
	assert.strictEqual(threw, false, 'runHndlScanHook must not throw on error');

	console.log('ScanHook unit tests passed.');
}

runExposureTests();
runScanHookTests();
