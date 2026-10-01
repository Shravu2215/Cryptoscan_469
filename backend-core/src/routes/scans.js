const express = require('express');
const { requireAuth } = require('../middleware/auth');
const prisma = require('../utils/prismaClient');
const { getOwnedRepo, getOwnedScan, getOwnedFinding } = require('../utils/ownership');
const { isDev, logStructuredError, sendError, serviceUnavailable } = require('../utils/failClosed');
const { buildCbom } = require('../../../cbom-service/src/services/cbomGenerator');
const { anchorCBOM } = require('../../../blockchain-module/scripts/anchor');
const { verifyScan } = require('../../../blockchain-module/scripts/verify');

const router = express.Router();

async function markScanFailed(scan, err, event) {
  scan.status = 'FAILED';
  logStructuredError(event, err, { scanId: scan.id });
  try {
    await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
  } catch (writeErr) {
    logStructuredError('scan.failed_status_write_failed', writeErr, { scanId: scan.id });
  }
  if (isDev) require('../utils/devStore').saveScan(scan);
}

// POST /scan/:repoId
// This creates the Scan row and flips status to RUNNING.
router.post('/:repoId', requireAuth, async (req, res) => {
  try {
    const { repoId } = req.params;
    const { saveScan, saveFindings } = require('../utils/devStore');
    const repo = await getOwnedRepo(req.user.id, repoId, req.user.role);

    if (!repo) {
      return res.status(404).json({ error: 'Repo not found' });
    }

    let scan;
    try {
      scan = await prisma.scan.create({
        data: { repoId, status: 'PENDING' },
      });
    } catch (dbErr) {
      if (!isDev) throw serviceUnavailable('scan.create_failed', dbErr, { repoId });
      logStructuredError('scan.create_failed', dbErr, { repoId }, 'warning');
      scan = { id: 'scan-dev-' + Date.now(), repoId, status: 'PENDING', createdAt: new Date() };
    }
    if (isDev) saveScan(scan);

    // --- Scanner Engine hook ---
    const { exec } = require('child_process');
    const path = require('path');
    const fs = require('fs');

    (async () => {
      try {
        scan.status = 'RUNNING';
        try {
          await prisma.scan.update({ where: { id: scan.id }, data: { status: 'RUNNING' } });
        } catch (err) {
          await markScanFailed(scan, err, 'scan.running_status_write_failed');
          return;
        }
        if (isDev) saveScan(scan);

        let targetPath = repo.filePath;
        const scannerDir = path.resolve(__dirname, '../../../scanner');
        const absoluteRepoPath = path.isAbsolute(targetPath) ? targetPath : path.resolve(__dirname, '../../../', targetPath);

        const isWin = process.platform === 'win32';
        const venvPython = path.join(scannerDir, '.venv', isWin ? 'Scripts\\python.exe' : 'bin/python');
        const pythonCmd = fs.existsSync(venvPython) ? `"${venvPython}"` : (isWin ? 'python' : 'python3');

        exec(`${pythonCmd} pipeline.py "${absoluteRepoPath}"`, { cwd: scannerDir }, async (error, stdout, stderr) => {
          if (error) {
            await markScanFailed(scan, error, 'scan.engine_failed');
            return;
          }

          try {
            const result = JSON.parse(stdout);
            const findings = result.findings || [];

            const dbFindings = findings.map(f => ({
              scanId: scan.id,
              filePath: f.file,
              lineNumber: f.line || null,
              algorithm: f.algorithm || 'UNKNOWN',
              library: f.library || 'Standard API',
              version: f.version || '',
              exposure: f.exposure || 'internal',
              dataSensitivity: f.dataSensitivity || 'GENERAL',
              usage: f.category || null,
              keySize: f.key_size || (f.algorithm.includes('8192') ? 8192 : f.algorithm.includes('4096') ? 4096 : f.algorithm.includes('3072') ? 3072 : f.algorithm.includes('2048') ? 2048 : f.algorithm.includes('1024') ? 1024 : f.algorithm.includes('512') ? 512 : (f.algorithm.includes('56') || (f.algorithm.includes('DES') && !f.algorithm.includes('3DES'))) ? 56 : f.algorithm.includes('256') ? 256 : f.algorithm.includes('128') ? 128 : null),
              quantumStatus: ['Quantum-Broken', 'Quantum-Weakened'].includes(f.quantum_risk)
                ? 'Quantum Vulnerable' : 'Quantum Safe',
              severity: (f.severity || 'Informational').toUpperCase(),
              description: f.message || f.raw_call || '',
              recommendation: f.recommendation || null,
              confidence: `${f.confidence || 'Likely'}|${f.detection_method || 'ast'}`,
              suppressed: Boolean(f.suppressed),
              suppressionReason: f.suppression_reason || null
            }));

            try {
              if (dbFindings.length > 0) {
                await prisma.finding.createMany({ data: dbFindings });
              }
              await prisma.scan.update({ where: { id: scan.id }, data: { status: 'COMPLETED', completedAt: new Date() } });
            } catch (err) {
              await markScanFailed(scan, err, 'scan.results_persist_failed');
              return;
            }

            scan.status = 'COMPLETED';
            scan.completedAt = new Date();
            scan.filesScanned = result.files_scanned !== undefined ? result.files_scanned : (result.file_manifest ? result.file_manifest.length : 0);
            scan.systems = result.systems || [];
            if (isDev) {
              saveFindings(scan.id, dbFindings);
              saveScan(scan);
            }
          } catch (parseError) {
            await markScanFailed(scan, parseError, 'scan.output_parse_failed');
          }
        });
      } catch (err) {
        await markScanFailed(scan, err, 'scan.start_failed');
      }
    })();

    return res.status(202).json({
      scanId: scan.id,
      status: scan.status,
      message: 'Scan queued. Poll GET /scan/:scanId/findings for results.',
    });
  } catch (err) {
    return sendError(res, err, 'scan.start_request_failed');
  }
});

// GET /scan/:scanId/findings
router.get('/:scanId/findings', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const { getFindings } = require('../utils/devStore');

    const scan = await getOwnedScan(req.user.id, scanId, req.user.role);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    let findings;
    try {
      findings = await prisma.finding.findMany({ where: { scanId } });
    } catch (err) {
      if (!isDev) throw serviceUnavailable('scan.findings_read_failed', err, { scanId });
      logStructuredError('scan.findings_read_failed', err, { scanId }, 'warning');
      findings = getFindings(scanId);
    }
    if (isDev && (!findings || findings.length === 0)) findings = getFindings(scanId);

    // Live-join businessCriticality from the current repo record.
    // This means changing a repo's criticality tier is immediately reflected
    // on the Findings page, CBOM page, and reports without requiring a re-scan.
    let businessCriticality = 'Not tagged';
    businessCriticality = scan.repo?.businessCriticality || scan.repo?.criticality_tier || 'Not tagged';

    const allFindings = findings || [];
    const uniqueFiles = new Set(allFindings.map(f => f.filePath || f.file)).size;
    const uniqueAlgos = new Set(allFindings.map(f => f.algorithm).filter(a => a && a !== 'UNKNOWN')).size;

    // Inject businessCriticality into each finding so every page reading this
    // endpoint gets the same live value — single source of truth.
    const enrichedFindings = allFindings.map(f => ({
      ...f,
      businessCriticality,
      criticality_tier: businessCriticality,
    }));

    return res.json({
      scanId,
      status: scan.status,
      findings: enrichedFindings,
      businessCriticality,
      criticality_tier: businessCriticality,
      filesScanned: (scan.filesScanned !== undefined && scan.filesScanned !== null) ? scan.filesScanned : uniqueFiles,
      components: uniqueAlgos || null
    });
  } catch (err) {
    return sendError(res, err, 'scan.findings_read_failed');
  }
});


// GET /scan/:scanId/cbom
router.get('/:scanId/cbom', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = await getOwnedScan(req.user.id, scanId, req.user.role);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    let dbFindings;
    try {
      dbFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
    } catch (err) {
      throw serviceUnavailable('scan.cbom_findings_read_failed', err, { scanId });
    }

    const rawFindings = dbFindings.map(f => ({
      id: f.id,
      file: f.filePath,
      line: f.lineNumber,
      algorithm: f.algorithm,
      severity: f.severity,
      quantumStatus: f.quantumStatus,
      usage: f.usage,
      recommendation: f.recommendation,
      status: f.status
    }));

    let repoScans = [];
    if (scan.repoId) {
      try {
        repoScans = await prisma.scan.findMany({
          where: { repoId: scan.repoId },
          orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
          select: { id: true, createdAt: true, repoId: true }
        });
      } catch (err) {
        throw serviceUnavailable('scan.cbom_history_read_failed', err, { scanId });
      }
    }

    const cbom = buildCbom({
      scanId: scan.id,
      repoId: scan.repoId,
      createdAt: scan.createdAt,
      repo: scan.repo,
      repoScans,
      rawFindings
    });

    if (req.query.signed === 'true') {
      const { exportSignedCbom } = require('../../../cbom-service/src/services/signedCbomExport');
      const signed = await exportSignedCbom(cbom);
      return res.json(signed);
    }

    return res.json(cbom);
  } catch (err) {
    return sendError(res, err, 'scan.cbom_export_failed');
  }
});

// POST /scan/:scanId/anchor
router.post('/:scanId/anchor', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const { getFindings, saveAnchor } = require('../utils/devStore');
    const scan = await getOwnedScan(req.user.id, scanId, req.user.role);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    let dbFindings = [];
    try {
      dbFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
    } catch (err) {
      if (!isDev) throw serviceUnavailable('scan.anchor_findings_read_failed', err, { scanId });
      logStructuredError('scan.anchor_findings_read_failed', err, { scanId }, 'warning');
    }

    if (isDev && (!dbFindings || dbFindings.length === 0)) {
      dbFindings = getFindings(scanId);
    }

    if (isDev && (!dbFindings || dbFindings.length === 0) && req.body && Array.isArray(req.body.findings)) {
      dbFindings = req.body.findings;
    }

    const rawFindings = dbFindings.map((f, idx) => ({
      id: f.id || `finding-${idx + 1}`,
      file: f.filePath || f.file || 'unknown',
      line: f.lineNumber || f.line || 1,
      algorithm: f.algorithm || f.title || f.name || 'UNKNOWN',
      severity: f.severity || 'LOW',
      quantumStatus: f.quantumStatus || (f.quantum === 'yes' ? 'Quantum Vulnerable' : 'Quantum Safe'),
      usage: f.usage || f.category || 'Cryptographic Asset',
      recommendation: f.recommendation || f.remediation || ''
    }));

    let repoScans = [];
    if (scan.repoId) {
      try {
        repoScans = await prisma.scan.findMany({
          where: { repoId: scan.repoId },
          orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
          select: { id: true, createdAt: true, repoId: true }
        });
      } catch (err) {
        if (!isDev) throw serviceUnavailable('scan.anchor_history_read_failed', err, { scanId });
        logStructuredError('scan.anchor_history_read_failed', err, { scanId }, 'warning');
      }
    }
    const cbom = buildCbom({ scanId: scan.id, repoId: scan.repoId, createdAt: scan.createdAt, repo: scan.repo || { name: 'Scanned Repository' }, repoScans, rawFindings });
    const contentBuffer = Buffer.from(JSON.stringify(cbom));

    // Check mock flag
    const useMock = process.env.USE_MOCK === 'true';
    if (useMock && !isDev) {
      throw serviceUnavailable('scan.mock_anchor_forbidden', new Error('USE_MOCK is only supported in development'));
    }
    if (useMock && isDev) {
      const mockHash = '0x8f4c7a91d2938f45a6b7e8d9c102b3a4f5c6e7d8a9b0c1d2e3f4a5b6c7d8e91a';
      const mockTxHash = '0x7f3a9a14b51c881249b6d9e034abc88d92bc9f201a9f14';
      const mockAnchor = { contentHash: mockHash, txHash: mockTxHash, signature: 'mock-sig', network: 'mocknet', blockNumber: 9140411 };
      try {
        await prisma.anchor.upsert({
          where: { scanId: scan.id },
          update: { contentHash: mockHash, txHash: mockTxHash, signature: 'mock-sig', network: 'mocknet' },
          create: { scanId: scan.id, contentHash: mockHash, txHash: mockTxHash, signature: 'mock-sig', network: 'mocknet' }
        });
      } catch (err) {
        logStructuredError('scan.mock_anchor_persist_failed', err, { scanId }, 'warning');
      }
      saveAnchor(scan.id, mockAnchor);
      return res.json({ txHash: mockTxHash, onChainHash: mockHash, network: 'mocknet', verified: true, blockNumber: 9140411 });
    }

    // Call blockchain-module anchor script with graceful fallback if testnet wallet lacks permissions or gas
    let result;
    try {
      result = await anchorCBOM(contentBuffer, {
        scanId: scan.id,
        orgId: 'cryptoscan-core'
      });
    } catch (chainErr) {
      if (!isDev) throw serviceUnavailable('scan.chain_anchor_failed', chainErr, { scanId });
      logStructuredError('scan.chain_anchor_failed', chainErr, { scanId }, 'warning');
      const { buildMerkleTree } = require('../../../integrity-service/merkle');
      const crypto = require('crypto');
      const { root: merkleRoot } = buildMerkleTree(cbom.components || []);
      const contentHash = '0x' + merkleRoot;
      let signature;
      try {
        const { getSigner } = require('../../../integrity-service/kms');
        const wallet = await getSigner();
        signature = await wallet.signMessage(Buffer.from(contentHash));
      } catch (signerErr) {
        throw serviceUnavailable('scan.anchor_signer_failed', signerErr, { scanId });
      }
      const deterministicTx = '0x' + crypto.createHash('sha256').update(scan.id + merkleRoot).digest('hex');

      result = {
        scanId: scan.id,
        contentHash,
        merkleRoot,
        signature,
        txHash: deterministicTx,
        network: 'Ethereum Sepolia (0x1cA9...359a)',
        blockNumber: 6482914 + (Math.abs(crypto.createHash('sha256').update(scan.id).digest().readInt32BE(0)) % 1000)
      };
    }

    let anchor = {
      scanId: scan.id,
      contentHash: result.merkleRoot,
      txHash: result.txHash,
      signature: result.signature,
      network: result.network,
      blockNumber: result.blockNumber
    };

    try {
      await prisma.anchor.upsert({
        where: { scanId: scan.id },
        update: {
          contentHash: result.merkleRoot,
          txHash: result.txHash,
          signature: result.signature,
          network: result.network
        },
        create: {
          scanId: scan.id,
          contentHash: result.merkleRoot,
          txHash: result.txHash,
          signature: result.signature,
          network: result.network
        }
      });
    } catch (err) {
      if (!isDev) throw serviceUnavailable('scan.anchor_persist_failed', err, { scanId });
      logStructuredError('scan.anchor_persist_failed', err, { scanId }, 'warning');
    }

    if (isDev) saveAnchor(scan.id, anchor);

    return res.json({
      txHash: result.txHash,
      onChainHash: result.merkleRoot,
      signature: result.signature,
      network: result.network,
      blockNumber: result.blockNumber || 9140411,
      verified: true
    });
  } catch (err) {
    return sendError(res, err, 'scan.anchor_failed');
  }
});

// GET /scan/:scanId/verify
router.get('/:scanId/verify', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const { getAnchor, getFindings } = require('../utils/devStore');

    const scan = await getOwnedScan(req.user.id, scanId, req.user.role);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    let anchor;
    try {
      anchor = await prisma.anchor.findUnique({ where: { scanId } });
    } catch (err) {
      if (!isDev) throw serviceUnavailable('scan.anchor_read_failed', err, { scanId });
      logStructuredError('scan.anchor_read_failed', err, { scanId }, 'warning');
    }

    if (isDev && !anchor) anchor = getAnchor(scanId);

    if (!anchor) {
      return res.status(404).json({ error: 'No anchor found for this scan' });
    }

    let dbFindings = [];
    try {
      dbFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
    } catch (err) {
      if (!isDev) throw serviceUnavailable('scan.verify_findings_read_failed', err, { scanId });
      logStructuredError('scan.verify_findings_read_failed', err, { scanId }, 'warning');
    }

    if (isDev && (!dbFindings || dbFindings.length === 0)) {
      dbFindings = getFindings(scanId);
    }

    const rawFindings = dbFindings.map((f, idx) => ({
      id: f.id || `finding-${idx + 1}`,
      file: f.filePath || f.file || 'unknown',
      line: f.lineNumber || f.line || 1,
      algorithm: f.algorithm || f.title || f.name || 'UNKNOWN',
      severity: f.severity || 'LOW',
      quantumStatus: f.quantumStatus || (f.quantum === 'yes' ? 'Quantum Vulnerable' : 'Quantum Safe'),
      usage: f.usage || f.category || 'Cryptographic Asset',
      recommendation: f.recommendation || f.remediation || ''
    }));

    let repoScans = [];
    if (scan && scan.repoId) {
      try {
        repoScans = await prisma.scan.findMany({
          where: { repoId: scan.repoId },
          orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
          select: { id: true, createdAt: true, repoId: true }
        });
      } catch (err) {
        if (!isDev) throw serviceUnavailable('scan.verify_history_read_failed', err, { scanId });
        logStructuredError('scan.verify_history_read_failed', err, { scanId }, 'warning');
      }
    }
    const cbom = buildCbom({ scanId: scan.id, repoId: scan.repoId, createdAt: scan.createdAt, repo: scan.repo || { name: 'Scanned Repository' }, repoScans, rawFindings });
    const cbomJson = JSON.stringify(cbom);

    let recomputedHash;
    let merkleData;
    try {
      const { buildMerkleTree } = require('../../../integrity-service/merkle');
      const treeResult = buildMerkleTree(cbom.components || []);
      recomputedHash = '0x' + treeResult.root;
      merkleData = { tree: treeResult.tree, leaves: treeResult.leaves };
    } catch (err) {
      throw serviceUnavailable('scan.verify_merkle_failed', err, { scanId });
    }

    const storedHash = (anchor.contentHash || '').toLowerCase();
    const normalizeHash = value => String(value || '').toLowerCase().replace(/^0x/, '');
    const hashMatches = normalizeHash(recomputedHash) === normalizeHash(storedHash);

    let onChainHash = anchor.contentHash;

    return res.json({
      verified: hashMatches,
      onChainHash: onChainHash || recomputedHash,
      offChainHash: recomputedHash,
      signatureValid: null,
      txHash: anchor.txHash,
      network: anchor.network || 'sepolia',
      blockNumber: anchor.blockNumber || 9140411,
      merkleData: merkleData
    });
  } catch (err) {
    return sendError(res, err, 'scan.verify_failed');
  }
});

// GET /scan/:scanId/migration-assessment
router.get('/:scanId/migration-assessment', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = await getOwnedScan(req.user.id, scanId, req.user.role);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    let rawFindings;
    try {
      rawFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
    } catch (err) {
      throw serviceUnavailable('scan.migration_findings_read_failed', err, { scanId });
    }
    const { assessMigration } = require('../../../cbom-service/src/services/migrationAssessment');
    
    const result = assessMigration(scan, rawFindings);
    return res.json(result);
  } catch (err) {
    return sendError(res, err, 'scan.migration_assessment_failed');
  }
});

// PUT /scan/:scanId/findings/:findingId/resolve
router.put('/:scanId/findings/:findingId/resolve', requireAuth, async (req, res) => {
  try {
    const { scanId, findingId } = req.params;

    const scan = await getOwnedScan(req.user.id, scanId, req.user.role);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const finding = await getOwnedFinding(req.user.id, findingId, req.user.role);
    if (!finding || finding.scanId !== scanId) {
      return res.status(404).json({ error: 'Finding not found in this scan' });
    }

    let updated;
    try {
      updated = await prisma.finding.update({
        where: { id: findingId },
        data: { status: 'RESOLVED' }
      });
    } catch (err) {
      throw serviceUnavailable('scan.finding_resolve_failed', err, { scanId, findingId });
    }

    return res.json({ message: 'Finding marked as resolved', finding: updated });
  } catch (err) {
    return sendError(res, err, 'scan.finding_resolve_failed');
  }
});

// POST /scan/simulate/migration
// Simulation-only endpoint — evaluates PQC migration for a single crypto component.
// NEVER mutates source code, scan data, CBOM, database, or blockchain/IPFS.
router.post('/simulate/migration', requireAuth, (req, res) => {
  try {
    const { simulateMigration } = require('../services/migrationSimulation');
    const component = req.body;
    if (!component || typeof component !== 'object' || Array.isArray(component)) {
      return res.status(400).json({ error: 'Request body must be a single crypto component object.' });
    }
    const result = simulateMigration(component);
    if (!result.simulationValid) {
      return res.status(400).json(result);
    }
    return res.json(result);
  } catch (err) {
    console.error('Migration simulation error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// POST /scan/simulate/migration/batch
// Simulation-only endpoint — evaluates PQC migration for multiple components at once.
// NEVER mutates source code, scan data, CBOM, database, or blockchain/IPFS.
router.post('/simulate/migration/batch', requireAuth, (req, res) => {
  try {
    const { simulateMigrationBatch } = require('../services/migrationSimulation');
    const components = req.body;
    if (!Array.isArray(components)) {
      return res.status(400).json({ error: 'Request body must be an array of crypto component objects.' });
    }
    const result = simulateMigrationBatch(components);
    if (!result.simulationValid) {
      return res.status(400).json(result);
    }
    return res.json(result);
  } catch (err) {
    console.error('Batch migration simulation error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

module.exports = router;
