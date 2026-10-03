'use strict';

const path = require('path');
const fs = require('fs');
const { execFile } = require('child_process');
const { Worker, UnrecoverableError } = require('bullmq');
const Redis = require('ioredis');

const prisma = require('../utils/prismaClient');
const { isDev, logStructuredError } = require('../utils/failClosed');
const { QUEUE_NAME } = require('./scanQueue');

function getScanTimeoutMs() {
  const val = Number(process.env.SCAN_TIMEOUT_MS);
  return Number.isFinite(val) && val > 0 ? Math.floor(val) : 120000;
}

function getRedisConnectionOptions() {
  const url = process.env.REDIS_URL || 'redis://localhost:6379';
  const parsed = new URL(url);
  return {
    host: parsed.hostname || 'localhost',
    port: Number(parsed.port) || 6379,
    password: parsed.password || undefined,
    username: parsed.username || undefined,
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
  };
}

async function markScanFailed(scanId, reason, errorObj = null) {
  const failureReason = String(reason || 'Scan failed').substring(0, 500);
  logStructuredError('scan.failed', errorObj || new Error(failureReason), { scanId, failureReason });
  try {
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'FAILED', failureReason },
    });
  } catch (dbErr) {
    logStructuredError('scan.failed_status_write_failed', dbErr, { scanId });
  }

  if (isDev) {
    try {
      const devStore = require('../utils/devStore');
      const scan = devStore.getScan(scanId);
      if (scan) {
        scan.status = 'FAILED';
        scan.failureReason = failureReason;
        devStore.saveScan(scan);
      }
    } catch (_) {}
  }
}

async function runScanProcess(targetPath) {
  const scannerDir = path.resolve(__dirname, '../../../scanner');
  const absoluteRepoPath = path.isAbsolute(targetPath)
    ? targetPath
    : path.resolve(__dirname, '../../../', targetPath);

  const isWin = process.platform === 'win32';
  const venvPython = path.join(scannerDir, '.venv', isWin ? 'Scripts\\python.exe' : 'bin/python');
  const pythonExecutable = fs.existsSync(venvPython) ? venvPython : (isWin ? 'python' : 'python3');

  const args = ['pipeline.py', absoluteRepoPath];

  const timeout = getScanTimeoutMs();

  return new Promise((resolve, reject) => {
    execFile(
      pythonExecutable,
      args,
      {
        cwd: scannerDir,
        timeout,
        killSignal: 'SIGKILL',
        maxBuffer: 50 * 1024 * 1024,
      },
      (error, stdout, stderr) => {
        if (error) {
          if (error.killed || error.signal === 'SIGKILL' || error.code === 'ETIMEDOUT') {
            const timeoutErr = new Error(`Scan timed out after ${timeout}ms`);
            timeoutErr.isTimeout = true;
            return reject(timeoutErr);
          }
          return reject(error);
        }
        try {
          const result = JSON.parse(stdout);
          resolve(result);
        } catch (parseError) {
          parseError.isFatal = true;
          reject(parseError);
        }
      }
    );
  });
}

async function processScanJob(job) {
  const { scanId } = job.data;
  if (!scanId) {
    throw new UnrecoverableError('Missing scanId in job data');
  }

  let scan;
  try {
    scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { repo: true },
    });
  } catch (dbErr) {
    if (!isDev) throw dbErr;
    try {
      scan = require('../utils/devStore').getScan(scanId);
    } catch (_) {}
    if (!scan) throw dbErr;
  }

  if (!scan && isDev) {
    try {
      scan = require('../utils/devStore').getScan(scanId);
    } catch (_) {}
  }

  if (!scan) {
    throw new UnrecoverableError(`Scan not found: ${scanId}`);
  }

  // Idempotency: skip scans already COMPLETED or FAILED
  if (scan.status === 'COMPLETED' || scan.status === 'FAILED') {
    return { skipped: true, scanId, status: scan.status };
  }

  // Transition to RUNNING
  scan.status = 'RUNNING';
  try {
    await prisma.scan.update({
      where: { id: scan.id },
      data: { status: 'RUNNING' },
    });
  } catch (err) {
    if (!isDev) throw err; // transient error -> retry
  }
  if (isDev) {
    try {
      require('../utils/devStore').saveScan(scan);
    } catch (_) {}
  }

  const targetPath = scan.repo?.filePath || scan.filePath;
  if (!targetPath) {
    const errReason = 'Repository file path not found';
    await markScanFailed(scan.id, errReason);
    throw new UnrecoverableError(errReason);
  }

  const absoluteRepoPath = path.isAbsolute(targetPath)
    ? targetPath
    : path.resolve(__dirname, '../../../', targetPath);

  if (!fs.existsSync(absoluteRepoPath)) {
    const errReason = `Repository path does not exist: ${targetPath}`;
    await markScanFailed(scan.id, errReason);
    throw new UnrecoverableError(errReason);
  }

  let result;
  try {
    result = await runScanProcess(targetPath);
  } catch (procErr) {
    if (procErr.isTimeout) {
      const reason = `Scan exceeded hard wall-clock timeout limit of ${getScanTimeoutMs()}ms`;
      await markScanFailed(scan.id, reason, procErr);
      throw new UnrecoverableError(reason);
    }
    const reason = procErr.message || 'Scanner process execution failed';
    await markScanFailed(scan.id, reason, procErr);
    throw new UnrecoverableError(reason);
  }

  if (result.status === 'FAILED') {
    const reason = result.failure_reason || result.error || 'Scan pipeline reported failure';
    await markScanFailed(scan.id, reason);
    throw new UnrecoverableError(reason);
  }

  const findings = result.findings || [];
  const dbFindings = findings.map((f) => ({
    scanId: scan.id,
    filePath: f.file,
    lineNumber: f.line || null,
    algorithm: f.algorithm || 'UNKNOWN',
    library: f.library || 'Standard API',
    version: f.version || '',
    exposure: f.exposure || 'internal',
    dataSensitivity: f.dataSensitivity || 'GENERAL',
    usage: f.category || null,
    keySize:
      f.key_size ||
      (f.algorithm.includes('8192')
        ? 8192
        : f.algorithm.includes('4096')
        ? 4096
        : f.algorithm.includes('3072')
        ? 3072
        : f.algorithm.includes('2048')
        ? 2048
        : f.algorithm.includes('1024')
        ? 1024
        : f.algorithm.includes('512')
        ? 512
        : f.algorithm.includes('56') || (f.algorithm.includes('DES') && !f.algorithm.includes('3DES'))
        ? 56
        : f.algorithm.includes('256')
        ? 256
        : f.algorithm.includes('128')
        ? 128
        : null),
    quantumStatus: ['Quantum-Broken', 'Quantum-Weakened'].includes(f.quantum_risk)
      ? 'Quantum Vulnerable'
      : 'Quantum Safe',
    severity: (f.severity || 'Informational').toUpperCase(),
    description: f.message || f.raw_call || '',
    recommendation: f.recommendation || null,
    confidence: `${f.confidence || 'Likely'}|${f.detection_method || 'ast'}`,
    suppressed: Boolean(f.suppressed),
    suppressionReason: f.suppression_reason || null,
  }));

  try {
    if (dbFindings.length > 0) {
      await prisma.finding.createMany({ data: dbFindings });
    }
    await prisma.scan.update({
      where: { id: scan.id },
      data: { status: 'COMPLETED', completedAt: new Date() },
    });
  } catch (err) {
    if (!isDev) throw err;
  }

  try {
    const { runHndlScanHook } = require('../services/quantumRisk/hndl/scanHook');
    await runHndlScanHook({ scanId: scan.id, targetPath: absoluteRepoPath, findings: dbFindings });
  } catch (_) {}


  scan.status = 'COMPLETED';
  scan.completedAt = new Date();
  scan.filesScanned =
    result.files_scanned !== undefined
      ? result.files_scanned
      : result.file_manifest
      ? result.file_manifest.length
      : 0;
  scan.systems = result.systems || [];

  if (isDev) {
    try {
      const devStore = require('../utils/devStore');
      devStore.saveFindings(scan.id, dbFindings);
      devStore.saveScan(scan);
    } catch (_) {}
  }

  return { scanId: scan.id, findingsCount: dbFindings.length, status: 'COMPLETED' };
}

function createWorker() {
  const connection = getRedisConnectionOptions();
  const worker = new Worker(
    QUEUE_NAME,
    async (job) => {
      try {
        return await processScanJob(job);
      } finally {
        // Clean up any worker-level temp files if applicable
      }
    },
    {
      connection,
      concurrency: Number(process.env.WORKER_CONCURRENCY || 4),
    }
  );

  worker.on('failed', (job, err) => {
    console.error(`[ScanWorker] Job ${job?.id} failed:`, err.message);
  });

  return worker;
}

async function startWorker() {
  // Refuse to start without Redis
  try {
    const redis = new Redis(getRedisConnectionOptions());
    await redis.ping();
    await redis.quit();
  } catch (err) {
    console.error('FATAL: Worker cannot connect to Redis. Refusing to start.', err.message);
    process.exit(1);
  }

  console.log(`[ScanWorker] Starting BullMQ worker for queue "${QUEUE_NAME}"...`);
  const worker = createWorker();

  const shutdown = async () => {
    console.log('[ScanWorker] Shutting down worker...');
    await worker.close();
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  return worker;
}

if (require.main === module) {
  startWorker();
}

module.exports = {
  createWorker,
  startWorker,
  processScanJob,
  runScanProcess,
  markScanFailed,
};
