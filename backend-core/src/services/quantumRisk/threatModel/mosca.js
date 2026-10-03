'use strict';

/** Deterministic Mosca comparison and assumption-labeled migration defaults. */

const RISK_BAND_THRESHOLDS = {
	MINIMAL_MAX: 0.01,
	LOW_MAX: 0.05,
	MODERATE_MAX: 0.2,
	HIGH_MAX: 0.5,
};

const ASSUMPTION = 'ASSUMPTION';

function dataLifetime(years, rationale) {
	return { years, source: ASSUMPTION, rationale };
}

const DEFAULT_DATA_LIFETIME_BY_USAGE = {
	key_exchange: dataLifetime(20, 'Long-lived confidential data protected by key establishment.'),
	key_wrap: dataLifetime(20, 'Wrapped data keys can protect long-lived encrypted data.'),
	encryption: dataLifetime(20, 'Encrypted data is assumed to require long-term confidentiality.'),
	data_encryption: dataLifetime(20, 'Encrypted data is assumed to require long-term confidentiality.'),
	digital_signature: dataLifetime(0, 'Signature validity is modeled as break-before-migration, not harvest exposure.'),
	signature: dataLifetime(0, 'Signature validity is modeled as break-before-migration, not harvest exposure.'),
	auth: dataLifetime(0, 'Authentication is modeled as break-before-migration, not harvest exposure.'),
	jwt: dataLifetime(0, 'JWT authentication is modeled as break-before-migration, not harvest exposure.'),
	certificate: dataLifetime(0, 'Certificate signatures are modeled as break-before-migration, not harvest exposure.'),
	integrity_hashing: dataLifetime(10, 'Integrity artifacts are conservatively assumed to remain relevant for ten years.'),
	mac: dataLifetime(0, 'Message authentication is modeled as break-before-migration, not harvest exposure.'),
	unknown: dataLifetime(10, 'Unknown usage receives a conservative ten-year confidentiality lifetime.'),
};

function migrationEntry(years, family) {
	return {
		years,
		source: ASSUMPTION,
		rationale: `${family} migration duration is a planning placeholder; replace with organization evidence.`,
	};
}

function migrationTable(values) {
	return Object.fromEntries(Object.entries(values).map(([family, years]) => [family, migrationEntry(years, family)]));
}

const DEFAULT_MIGRATION_TIME_BY_USAGE_FAMILY = {
	key_exchange: migrationTable({ RSA: 2.5, ECC: 2, DH: 2.5, AES: 1.5, HASH: 1, OTHER: 4, PQC: 0.5 }),
	key_wrap: migrationTable({ RSA: 2.5, ECC: 2, DH: 2.5, AES: 1.5, HASH: 1, OTHER: 4, PQC: 0.5 }),
	encryption: migrationTable({ RSA: 2, ECC: 2, DH: 2, AES: 1.5, HASH: 1, OTHER: 4, PQC: 0.5 }),
	data_encryption: migrationTable({ RSA: 2, ECC: 2, DH: 2, AES: 1.5, HASH: 1, OTHER: 4, PQC: 0.5 }),
	digital_signature: migrationTable({ RSA: 3, ECC: 3, DH: 2.5, AES: 1.5, HASH: 1.5, OTHER: 4, PQC: 0.5 }),
	signature: migrationTable({ RSA: 3, ECC: 3, DH: 2.5, AES: 1.5, HASH: 1.5, OTHER: 4, PQC: 0.5 }),
	auth: migrationTable({ RSA: 3, ECC: 3, DH: 2.5, AES: 1.5, HASH: 1.5, OTHER: 4, PQC: 0.5 }),
	jwt: migrationTable({ RSA: 3, ECC: 3, DH: 2.5, AES: 1.5, HASH: 1.5, OTHER: 4, PQC: 0.5 }),
	certificate: migrationTable({ RSA: 3, ECC: 3, DH: 2.5, AES: 1.5, HASH: 1.5, OTHER: 4, PQC: 0.5 }),
	integrity_hashing: migrationTable({ RSA: 2, ECC: 2, DH: 2, AES: 1.5, HASH: 1, OTHER: 4, PQC: 0.5 }),
	mac: migrationTable({ RSA: 2, ECC: 2, DH: 2, AES: 1.5, HASH: 1.5, OTHER: 4, PQC: 0.5 }),
	unknown: migrationTable({ RSA: 3, ECC: 3, DH: 3, AES: 2, HASH: 2, OTHER: 4, PQC: 0.5 }),
};

function deterministicMosca(X, Y, Z) {
	if (![X, Y, Z].every(Number.isFinite) || X < 0 || Y < 0 || Z < 0) {
		throw new TypeError('X, Y, and Z must be finite non-negative numbers');
	}
	const marginYears = Z - (X + Y);
	return { violated: X + Y > Z, marginYears };
}

function riskBandFromProbability(probability) {
	if (!Number.isFinite(probability) || probability < 0 || probability > 1) {
		throw new RangeError('probability must be between 0 and 1');
	}
	if (probability < RISK_BAND_THRESHOLDS.MINIMAL_MAX) return 'MINIMAL';
	if (probability < RISK_BAND_THRESHOLDS.LOW_MAX) return 'LOW';
	if (probability < RISK_BAND_THRESHOLDS.MODERATE_MAX) return 'MODERATE';
	if (probability < RISK_BAND_THRESHOLDS.HIGH_MAX) return 'HIGH';
	return 'CRITICAL';
}

function canonicalUsage(usage) {
	const normalized = String(usage || 'unknown')
		.replace(/([a-z])([A-Z])/g, '$1_$2')
		.toLowerCase()
		.trim()
		.replace(/[ -]+/g, '_');
	if (DEFAULT_DATA_LIFETIME_BY_USAGE[normalized]) return normalized;
	if (normalized.includes('signature')) return 'digital_signature';
	if (normalized.includes('certificate')) return 'certificate';
	if (normalized.includes('jwt')) return 'jwt';
	if (normalized.includes('auth')) return 'auth';
	return 'unknown';
}

function isSignatureUsage(usage) {
	return /(signature|auth|jwt|certificate)/i.test(String(usage || ''));
}

function resolveMigrationDefaults(asset, override = {}) {
	const usage = canonicalUsage(asset.usage);
	const family = DEFAULT_MIGRATION_TIME_BY_USAGE_FAMILY[usage] || DEFAULT_MIGRATION_TIME_BY_USAGE_FAMILY.unknown;
	const signatureUsage = isSignatureUsage(asset.usage);
	const X = signatureUsage
		? 0
		: (override.dataLifetimeYears ?? DEFAULT_DATA_LIFETIME_BY_USAGE[usage].years);
	const familyEntry = family[asset.family] || family.OTHER;
	const Y = override.migrationTimeYears ?? familyEntry.years;
	if (![X, Y].every((value) => Number.isFinite(value) && value >= 0)) {
		throw new TypeError(`Invalid X/Y override for asset ${asset.assetId || '(unknown)'}`);
	}
	return { X, Y, signatureUsage };
}

module.exports = {
	RISK_BAND_THRESHOLDS,
	DEFAULT_DATA_LIFETIME_BY_USAGE,
	DEFAULT_MIGRATION_TIME_BY_USAGE_FAMILY,
	deterministicMosca,
	riskBandFromProbability,
	isSignatureUsage,
	resolveMigrationDefaults,
};