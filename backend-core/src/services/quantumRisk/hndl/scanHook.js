'use strict';

/**
 * HNDL Scan Hook.
 * Runs field detection and lineage linking during scan execution while source files
 * are present on disk, persisting masked SensitiveDataField records to the database.
 *
 * Designed to be non-blocking, time-budgeted (<=10s), and fail-safe.
 */

const fs = require('fs');
const path = require('path');
const prisma = require('../../../utils/prismaClient');
const { findingsToCryptoAssets } = require('../adapter');
const { detectSensitiveData } = require('./index');
const { linkFieldsToAssets } = require('./lineage');

const MAX_HOOK_FILES = 20000;
const MAX_FILE_SIZE_BYTES = 1024 * 1024; // 1 MB
const TIME_BUDGET_MS = 10000; // 10s budget

function isHookEnabled() {
	if (process.env.HNDL_SCAN_HOOK !== undefined) {
		return process.env.HNDL_SCAN_HOOK === 'true' || process.env.HNDL_SCAN_HOOK === '1';
	}
	const env = process.env.NODE_ENV;
	return env === 'development' || env === 'test' || !env;
}

function readFilesFromDir(dirPath, startTime) {
	const files = [];
	if (!dirPath) return files;
	const absoluteDir = path.isAbsolute(dirPath) ? dirPath : path.resolve(dirPath);

	function scan(currentDir) {
		if (files.length >= MAX_HOOK_FILES) return;
		if (Date.now() - startTime > TIME_BUDGET_MS) return;

		let entries;
		try {
			entries = fs.readdirSync(currentDir, { withFileTypes: true });
		} catch (_) {
			return;
		}

		for (const entry of entries) {
			if (files.length >= MAX_HOOK_FILES) break;
			if (Date.now() - startTime > TIME_BUDGET_MS) break;

			const fullPath = path.join(currentDir, entry.name);
			if (entry.isDirectory()) {
				if (['node_modules', '.git', 'dist', 'vendor', 'build', '.venv'].includes(entry.name)) continue;
				scan(fullPath);
			} else if (entry.isFile()) {
				try {
					const stat = fs.statSync(fullPath);
					if (stat.size > MAX_FILE_SIZE_BYTES) continue;
					const content = fs.readFileSync(fullPath, 'utf8');
					const relativePath = path.relative(absoluteDir, fullPath).replace(/\\/g, '/');
					files.push({ filePath: relativePath, content });
				} catch (_) {}
			}
		}
	}

	try {
		const stat = fs.statSync(absoluteDir);
		if (stat.isFile()) {
			if (stat.size <= MAX_FILE_SIZE_BYTES) {
				files.push({ filePath: path.basename(absoluteDir), content: fs.readFileSync(absoluteDir, 'utf8') });
			}
		} else if (stat.isDirectory()) {
			scan(absoluteDir);
		}
	} catch (_) {}

	return files;
}

/**
 * Perform sensitive field detection and lineage linking for a scan.
 */
async function collectHndlForScan({ scanId, files, findings, targetPath }) {
	const startTime = Date.now();
	let scanFiles = Array.isArray(files) ? files : [];

	if (scanFiles.length === 0 && targetPath) {
		scanFiles = readFilesFromDir(targetPath, startTime);
	}

	if (Date.now() - startTime > TIME_BUDGET_MS) {
		console.warn(`[HNDL ScanHook] Time budget exceeded reading files for scan ${scanId}`);
		return [];
	}

	const assets = findingsToCryptoAssets(findings || []);
	const detectResult = detectSensitiveData({ files: scanFiles });

	if (Date.now() - startTime > TIME_BUDGET_MS) {
		console.warn(`[HNDL ScanHook] Time budget exceeded during detection for scan ${scanId}`);
		return [];
	}

	const linkedFields = linkFieldsToAssets({ fields: detectResult.fields, assets, files: scanFiles });
	return linkedFields;
}

/**
 * Fail-safe wrapper to collect and persist HNDL sensitive data fields during scan.
 */
async function runHndlScanHook({ scanId, targetPath, findings, files }) {
	if (!isHookEnabled()) return;

	try {
		const startTime = Date.now();
		const fields = await collectHndlForScan({ scanId, files, findings, targetPath });

		if (Date.now() - startTime > TIME_BUDGET_MS) {
			console.warn(`[HNDL ScanHook] Time budget exceeded for scan ${scanId}`);
			return;
		}

		await prisma.$transaction(async (tx) => {
			await tx.sensitiveDataField.deleteMany({ where: { scanId } });
			if (fields.length > 0) {
				await tx.sensitiveDataField.createMany({
					data: fields.map((f) => ({
						scanId,
						fieldId: f.fieldId,
						dataClass: f.dataClass,
						location: {
							...(f.location || {}),
							lineageStatus: f.lineageStatus,
							column: f.column || (f.location && f.location.column) || null,
						},
						retentionYears: f.retentionYears,
						retentionSource: f.retentionSource,
						protectedBy: f.protectedBy || [],
						detectionConfidence: f.detectionConfidence || 0,
						lineageConfidence: f.lineageConfidence || 0,
						evidence: f.evidence || [],
					})),
				});
			}
		});
	} catch (err) {
		console.warn(`[HNDL ScanHook] Warning: Scan hook failed for scan ${scanId}:`, err.message);
	}
}

module.exports = {
	collectHndlForScan,
	runHndlScanHook,
	isHookEnabled,
};
