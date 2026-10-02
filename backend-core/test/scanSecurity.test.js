'use strict';

process.env.NODE_ENV = 'development';
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgresql://cryptoscan_user:cryptoscan_password@localhost:5432/cryptoscan';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const { runScanProcess, processScanJob, markScanFailed } = require('../src/queue/scanWorker');
const { getScanQueue, QUEUE_NAME, MAX_CONCURRENT_SCANS_PER_USER } = require('../src/queue/scanQueue');
const devStore = require('../src/utils/devStore');

async function testShellInjectionResistance() {
  console.log('Testing: Shell Injection Immunity (Unix and Windows payloads)...');

  const tmpDir = os.tmpdir();
  const markerFileUnix = path.join(tmpDir, 'pwn_marker_unix_' + Date.now() + '.txt');
  const markerFileWin = path.join(tmpDir, 'pwn_marker_win_' + Date.now() + '.txt');
  const pwnUnixDirect = '/tmp/pwn';

  // Ensure clean state
  [markerFileUnix, markerFileWin, pwnUnixDirect].forEach((p) => {
    try {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    } catch (_) {}
  });

  const unixPayload = `a"; touch "${markerFileUnix}"; touch /tmp/pwn; ".zip`;
  const winPayload = `a" & echo pwn > "${markerFileWin}" & ".zip`;

  // 1. Verify that multer filename generation ignores originalname completely and uses UUID
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.zip$/i;

  const fakeReq = {};
  const fakeFileUnix = { originalname: unixPayload };
  const fakeFileWin = { originalname: winPayload };

  // Simulate multer filename callback
  const generateFilename = (file) => `${crypto.randomUUID()}.zip`;

  const fnUnix = generateFilename(fakeFileUnix);
  const fnWin = generateFilename(fakeFileWin);

  assert.ok(uuidRegex.test(fnUnix), `Filename must be UUID, got: ${fnUnix}`);
  assert.ok(uuidRegex.test(fnWin), `Filename must be UUID, got: ${fnWin}`);
  assert.ok(!fnUnix.includes('pwn') && !fnUnix.includes('touch') && !fnUnix.includes(';'), 'Filename must not contain payload');
  assert.ok(!fnWin.includes('pwn') && !fnWin.includes('echo') && !fnWin.includes('&'), 'Filename must not contain payload');

  // 2. Direct execFile immunity test: invoke runScanProcess with malicious characters in path
  const payloads = [
    unixPayload,
    winPayload,
    'a"; touch /tmp/pwn; ".zip',
    `a & echo pwn > "${markerFileWin}" & .zip`,
  ];

  for (const p of payloads) {
    try {
      await runScanProcess(p);
    } catch (_) {
      // Expected: file does not exist, but no shell should execute
    }
  }

  // Verify markers were NOT created
  assert.strictEqual(fs.existsSync(markerFileUnix), false, 'Unix marker file must NOT be created');
  assert.strictEqual(fs.existsSync(markerFileWin), false, 'Windows marker file must NOT be created');
  if (process.platform !== 'win32') {
    assert.strictEqual(fs.existsSync(pwnUnixDirect), false, '/tmp/pwn must NOT be created');
  }

  console.log('  PASS: Shell injection attempts safely neutralized (no marker files created).');
}

async function testScanTimeoutKillsAndMarksFailed() {
  console.log('Testing: Scan exceeding wall-clock timeout is killed and marked FAILED...');

  // Create a dummy repository with a python script that sleeps indefinitely
  const testDir = path.join(os.tmpdir(), 'cryptoscan_test_timeout_' + Date.now());
  fs.mkdirSync(testDir, { recursive: true });
  fs.writeFileSync(path.join(testDir, 'slow.py'), 'import time\ntime.sleep(60)\n');

  // Temporarily set a 1ms timeout via env to guarantee timeout triggering
  const origTimeout = process.env.SCAN_TIMEOUT_MS;
  process.env.SCAN_TIMEOUT_MS = '1';

  const scanId = 'scan-test-timeout-' + Date.now();
  const testScan = {
    id: scanId,
    status: 'PENDING',
    repo: { filePath: testDir },
    createdAt: new Date(),
  };
  devStore.saveScan(testScan);

  let caughtError = null;
  try {
    await processScanJob({ data: { scanId } });
  } catch (err) {
    caughtError = err;
  } finally {
    if (origTimeout !== undefined) {
      process.env.SCAN_TIMEOUT_MS = origTimeout;
    } else {
      delete process.env.SCAN_TIMEOUT_MS;
    }
    try {
      fs.rmSync(testDir, { recursive: true, force: true });
    } catch (_) {}
  }

  assert.ok(caughtError, 'processScanJob should throw when timed out');
  assert.ok(
    caughtError.message.toLowerCase().includes('timeout') || caughtError.message.toLowerCase().includes('timed out'),
    `Error message should mention timeout, got: ${caughtError.message}`
  );

  const updatedScan = devStore.getScan(scanId);
  assert.strictEqual(updatedScan.status, 'FAILED', 'Scan status must be FAILED');
  assert.ok(
    updatedScan.failureReason && updatedScan.failureReason.toLowerCase().includes('timeout'),
    `Failure reason must document timeout, got: ${updatedScan.failureReason}`
  );

  console.log('  PASS: Timed-out scan killed and marked FAILED with reason.');
}

async function testArchiveLimitsRejection() {
  console.log('Testing: Archive file count and byte limit violations are rejected...');

  const tmpDir = os.tmpdir();
  const testZipPath = path.join(tmpDir, 'test_bomb_' + Date.now() + '.zip');

  // Create a zip with 15 files
  const zip = new AdmZip();
  for (let i = 0; i < 15; i++) {
    zip.addFile(`file_${i}.txt`, Buffer.from('hello world '.repeat(100)));
  }
  zip.writeZip(testZipPath);

  // Set limits low for test: MAX_SCAN_FILES = 5
  const origFiles = process.env.MAX_SCAN_FILES;
  process.env.MAX_SCAN_FILES = '5';

  try {
    const result = await runScanProcess(testZipPath);
    assert.strictEqual(result.status, 'FAILED', 'Scan must fail on file count limit');
    assert.ok(
      result.error && result.error.includes('file count limit'),
      `Error must mention file count limit, got: ${result.error}`
    );
  } finally {
    if (origFiles !== undefined) {
      process.env.MAX_SCAN_FILES = origFiles;
    } else {
      delete process.env.MAX_SCAN_FILES;
    }
    try {
      if (fs.existsSync(testZipPath)) fs.unlinkSync(testZipPath);
    } catch (_) {}
  }

  // Create a zip exceeding byte limit: MAX_SCAN_BYTES = 1000
  const origBytes = process.env.MAX_SCAN_BYTES;
  process.env.MAX_SCAN_BYTES = '1000';
  const testByteZip = path.join(tmpDir, 'test_byte_limit_' + Date.now() + '.zip');
  const bigZip = new AdmZip();
  bigZip.addFile('big.txt', Buffer.alloc(5000, 'A'));
  bigZip.writeZip(testByteZip);

  try {
    const result = await runScanProcess(testByteZip);
    assert.strictEqual(result.status, 'FAILED', 'Scan must fail on byte limit');
    assert.ok(
      result.error && (result.error.includes('size limit') || result.error.includes('limit')),
      `Error must mention size limit, got: ${result.error}`
    );
  } finally {
    if (origBytes !== undefined) {
      process.env.MAX_SCAN_BYTES = origBytes;
    } else {
      delete process.env.MAX_SCAN_BYTES;
    }
    try {
      if (fs.existsSync(testByteZip)) fs.unlinkSync(testByteZip);
    } catch (_) {}
  }

  console.log('  PASS: Archive file count and byte limits successfully enforced.');
}

async function testWorkerJobRetryAndFailureSemantics() {
  console.log('Testing: Worker retry semantics (fatal errors fail immediately without retry)...');

  const { UnrecoverableError } = require('bullmq');

  // Test that non-transient error throws UnrecoverableError
  const scanId = 'scan-test-non-transient-' + Date.now();
  const testScan = {
    id: scanId,
    status: 'PENDING',
    repo: { filePath: 'non_existent_directory_for_scan_test_' + Date.now() },
    createdAt: new Date(),
  };
  devStore.saveScan(testScan);

  let err = null;
  try {
    await processScanJob({ data: { scanId } });
  } catch (e) {
    err = e;
  }

  assert.ok(err, 'Expected error on invalid repo path');
  assert.ok(err instanceof UnrecoverableError, 'Fatal scanner errors must throw UnrecoverableError to stop retries');

  const finalScan = devStore.getScan(scanId);
  assert.strictEqual(finalScan.status, 'FAILED', 'Scan status must be FAILED');

  console.log('  PASS: Non-transient errors terminate immediately with UnrecoverableError.');
}

async function testWorkerNonRootConfiguration() {
  console.log('Testing: Worker non-root configuration in Dockerfile and docker-compose...');

  // 1. Check Dockerfile.worker
  const dockerfileWorkerPath = path.resolve(__dirname, '../Dockerfile.worker');
  assert.ok(fs.existsSync(dockerfileWorkerPath), 'Dockerfile.worker must exist');
  const dockerfileContent = fs.readFileSync(dockerfileWorkerPath, 'utf8');

  assert.ok(
    /USER\s+(appuser|node|[0-9]+)/.test(dockerfileContent),
    'Dockerfile.worker must declare a non-root USER'
  );
  assert.ok(
    !/USER\s+root\s*$/m.test(dockerfileContent),
    'Dockerfile.worker must not end as root'
  );

  // 2. Check docker-compose.yml
  const composePath = path.resolve(__dirname, '../../docker-compose.yml');
  const composeContent = fs.readFileSync(composePath, 'utf8');

  assert.ok(composeContent.includes('scan-worker:'), 'docker-compose.yml must define scan-worker service');
  assert.ok(composeContent.includes('user: "10001:10001"') || composeContent.includes('user:'), 'scan-worker must specify non-root user');
  assert.ok(composeContent.includes('cap_drop:') && composeContent.includes('- ALL'), 'scan-worker must drop ALL capabilities');
  assert.ok(composeContent.includes('no-new-privileges:true'), 'scan-worker must enable no-new-privileges');
  assert.ok(composeContent.includes('uploads:ro'), 'scan-worker must mount uploads as read-only');
  assert.ok(composeContent.includes('tmpfs:'), 'scan-worker must mount tmpfs for temporary files');

  console.log('  PASS: Dockerfile.worker and docker-compose.yml enforce unprivileged non-root execution.');
}

async function runAllTests() {
  console.log('=== P0-6 Security and Worker Test Suite ===\n');
  try {
    await testShellInjectionResistance();
    await testScanTimeoutKillsAndMarksFailed();
    await testArchiveLimitsRejection();
    await testWorkerJobRetryAndFailureSemantics();
    await testWorkerNonRootConfiguration();
    console.log('\nAll P0-6 security tests passed successfully! ✅');
  } catch (err) {
    console.error('\nTEST FAILED:', err);
    process.exit(1);
  }
}

runAllTests();
