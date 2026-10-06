'use strict';

/**
 * CryptoTwin API Routes
 * POST   /api/cryptotwin/runs                      — start a run
 * GET    /api/cryptotwin/runs/:id                  — poll run status
 * GET    /api/cryptotwin/runs?scanId=              — list runs for a scan
 * POST   /api/cryptotwin/runs/:id/reset            — reset a run
 * POST   /api/cryptotwin/runs/:id/approval         — record approval / rejection
 * GET    /api/cryptotwin/runs/:id/report           — download report (json)
 * POST   /api/cryptotwin/validate-upload           — validate uploaded migration plan JSON
 */

const express  = require('express');
const multer   = require('multer');
const crypto   = require('crypto');
const path     = require('path');

const { requireAuth }      = require('../middleware/auth');
const { appendAuditLog }   = require('../services/auditLog');
const { runCryptoTwin }    = require('../services/cryptoTwinEngine');

// In-memory store for runs (fallback when DB unavailable, keyed by runId)
const _memStore = new Map();

let prisma = null;
try { prisma = require('../utils/prismaClient'); } catch (_) {}

const router = express.Router();

// Multer for in-memory upload (max 2 MB)
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/json' || file.originalname.endsWith('.json')) cb(null, true);
    else cb(new Error('Only JSON files are accepted'));
  },
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function safe(s) { try { return JSON.parse(s); } catch (_) { return s; } }

function makeRunRow(id, userId, scanId, source, repoName, inputJson) {
  return {
    id, userId,
    scanId:   scanId || null,
    source:   source || 'direct',
    repoName: repoName || '',
    status:   'PENDING',
    inputJson: JSON.stringify(inputJson || {}),
    stagesJson:    '[]',
    attackPaths:   '[]',
    testsJson:     '[]',
    patchLog:      '[]',
    aiIterations:  '[]',
    verdict:       null,
    confidence:    null,
    blockers:      '[]',
    approval:      null,
    approvalBy:    null,
    approvalAt:    null,
    approvalNote:  null,
    overrideReason: null,
    reportJson:    null,
    errorMessage:  null,
    createdAt:     new Date(),
    updatedAt:     new Date(),
  };
}

async function saveRun(row) {
  _memStore.set(row.id, row);
  if (prisma) {
    try {
      await prisma.cryptoTwinRun.upsert({
        where: { id: row.id },
        create: row,
        update: row,
      });
    } catch (_) { /* DB unavailable — mem-store is fallback */ }
  }
}

async function loadRun(id) {
  if (_memStore.has(id)) return _memStore.get(id);
  if (prisma) {
    try {
      const row = await prisma.cryptoTwinRun.findUnique({ where: { id } });
      if (row) { _memStore.set(id, row); return row; }
    } catch (_) {}
  }
  return null;
}

function serializeRun(row) {
  if (!row) return null;
  return {
    id:            row.id,
    scanId:        row.scanId,
    userId:        row.userId,
    repoName:      row.repoName,
    source:        row.source,
    status:        row.status,
    stages:        safe(row.stagesJson),
    attackPaths:   safe(row.attackPaths),
    tests:         safe(row.testsJson),
    patchLog:      safe(row.patchLog),
    aiIterations:  safe(row.aiIterations),
    verdict:       row.verdict,
    confidence:    row.confidence,
    blockers:      safe(row.blockers),
    approval:      row.approval,
    approvalBy:    row.approvalBy,
    approvalAt:    row.approvalAt,
    approvalNote:  row.approvalNote,
    overrideReason: row.overrideReason,
    errorMessage:  row.errorMessage,
    createdAt:     row.createdAt,
    updatedAt:     row.updatedAt,
    // convenience counts
    inputSummary: (() => {
      try {
        const inp = safe(row.inputJson);
        return {
          repoName:   inp.repoName || row.repoName || '',
          source:     inp.source   || row.source   || 'direct',
          itemCount:  (inp.items   || []).length,
          algorithms: [...new Set((inp.items || []).map(i => i.currentAlgorithm || i.algorithm || '').filter(Boolean))],
          generatedAt: inp.generatedAt || null,
        };
      } catch (_) { return {}; }
    })(),
  };
}

// ── Validate CryptoTwinInput ───────────────────────────────────────────────────
function validateInput(body) {
  if (!body || typeof body !== 'object') return 'Request body must be a JSON object';
  if (!Array.isArray(body.items) || body.items.length === 0) return 'Input must contain a non-empty "items" array';
  for (let i = 0; i < body.items.length; i++) {
    const item = body.items[i];
    if (!item || typeof item !== 'object') return 'Each item must be an object (index ' + i + ')';
    if (!item.currentAlgorithm && !item.algorithm) return 'Each item must have "currentAlgorithm" or "algorithm" (index ' + i + ')';
    if (!item.filePath && !item.file) return 'Each item must have "filePath" or "file" (index ' + i + ')';
  }
  return null;
}

// ── POST /api/cryptotwin/runs ─────────────────────────────────────────────────
router.post('/runs', requireAuth, async (req, res) => {
  try {
    const { scanId, source, repoName, items, generatedAt, maxFixIterations } = req.body;

    // Allow empty direct calls that will populate from scan
    let inputItems = items;
    if (!inputItems && scanId && prisma) {
      // Pull findings from DB to build items
      try {
        const findings = await prisma.finding.findMany({
          where: { scanId, status: 'ACTIVE' },
          take: 100,
        });
        inputItems = findings.map(f => ({
          id:               f.id,
          filePath:         f.filePath,
          line:             f.lineNumber,
          language:         f.language || 'Unknown',
          currentAlgorithm: f.algorithm,
          usageContext:     f.usage || 'other',
          severity:         f.severity,
          quantumVulnerable: f.quantumStatus === 'VULNERABLE',
          targetAlgorithm:  null,
          priority:         1,
          effort:           'Medium',
          dependencies:     [],
        }));
      } catch (_) { inputItems = []; }
    }

    const input = { scanId, repoName: repoName || '', source: source || 'direct', generatedAt: generatedAt || new Date().toISOString(), items: inputItems || [] };
    const err = validateInput(input);
    if (err) return res.status(400).json({ error: err });

    const runId = crypto.randomUUID();
    const row   = makeRunRow(runId, req.user.id, scanId, source, input.repoName, input);
    await saveRun(row);

    // Run asynchronously
    const repoFilePath = scanId && prisma ? await (async () => {
      try {
        const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
        return scan && scan.repo ? scan.repo.filePath : null;
      } catch (_) { return null; }
    })() : null;

    // Kick off async run — do NOT await
    (async () => {
      try {
        row.status = 'RUNNING';
        await saveRun(row);

        const result = await runCryptoTwin(input, {
          repoFilePath,
          llmFn:           null,   // no LLM integration in base config; extend as needed
          maxFixIterations: maxFixIterations || 3,
        });

        row.status       = result.status;
        row.stagesJson   = JSON.stringify(result.stages   || []);
        row.attackPaths  = JSON.stringify(result.attackPaths || []);
        row.testsJson    = JSON.stringify(result.tests    || []);
        row.patchLog     = JSON.stringify(result.patchLog || []);
        row.aiIterations = JSON.stringify(result.aiIterations || []);
        row.verdict      = result.verdict || null;
        row.confidence   = result.confidence != null ? result.confidence : null;
        row.blockers     = JSON.stringify(result.blockers || []);
        row.errorMessage = result.errorMessage || null;
        row.reportJson   = JSON.stringify({
          inputSummary:  input,
          attackPaths:   result.attackPaths,
          tests:         result.tests,
          patchLog:      result.patchLog,
          aiIterations:  result.aiIterations,
          verdict:       result.verdict,
          confidence:    result.confidence,
          blockers:      result.blockers,
          approval:      null,
          generatedAt:   new Date().toISOString(),
        });
        row.updatedAt = new Date();
        await saveRun(row);

        appendAuditLog({ userId: req.user.id, action: 'CRYPTOTWIN_RUN_COMPLETED', method: 'POST', path: '/api/cryptotwin/runs/' + runId, statusCode: 200, requestHash: null }).catch(() => {});
      } catch (asyncErr) {
        row.status       = 'FAILED';
        row.errorMessage = asyncErr.message;
        row.updatedAt    = new Date();
        await saveRun(row);
      }
    })();

    appendAuditLog({ userId: req.user.id, action: 'CRYPTOTWIN_RUN_STARTED', method: 'POST', path: '/api/cryptotwin/runs', statusCode: 202, requestHash: null }).catch(() => {});
    return res.status(202).json({ runId, status: 'PENDING', message: 'CryptoTwin run started' });
  } catch (err) {
    console.error('POST /api/cryptotwin/runs error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── POST /api/cryptotwin/validate-upload ──────────────────────────────────────
router.post('/validate-upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  let parsed;
  try {
    parsed = JSON.parse(req.file.buffer.toString('utf8'));
  } catch (e) {
    return res.status(400).json({ error: 'Invalid JSON: ' + e.message });
  }
  // Normalize: accept both exported migration plan and raw CryptoTwinInput
  let items = parsed.items;
  if (!items && Array.isArray(parsed.candidates)) {
    items = parsed.candidates.map(c => ({ currentAlgorithm: c.algorithm, filePath: c.files && c.files[0] ? c.files[0] : 'unknown', usageContext: c.purpose || 'other', severity: c.severity || 'MEDIUM', targetAlgorithm: c.replacement || null }));
  }
  const input = { ...parsed, items: items || [], source: 'uploaded' };
  const err   = validateInput(input);
  if (err) return res.status(422).json({ error: err, detail: 'File parsed successfully but content is invalid' });
  return res.json({
    valid:     true,
    itemCount: input.items.length,
    repoName:  input.repoName || parsed.name || '',
    algorithms: [...new Set(input.items.map(i => i.currentAlgorithm || i.algorithm || '').filter(Boolean))],
    normalizedInput: input,
  });
});

// ── GET /api/cryptotwin/runs — list by scanId ─────────────────────────────────
router.get('/runs', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.query;
    let rows = [];
    if (prisma) {
      try {
        const where = { userId: req.user.id };
        if (scanId) where.scanId = scanId;
        rows = await prisma.cryptoTwinRun.findMany({ where, orderBy: { createdAt: 'desc' }, take: 20 });
      } catch (_) {}
    }
    if (rows.length === 0) {
      // fallback to mem store
      rows = [..._memStore.values()].filter(r => r.userId === req.user.id && (!scanId || r.scanId === scanId));
      rows.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    }
    return res.json({ runs: rows.map(serializeRun) });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── GET /api/cryptotwin/runs/:id ──────────────────────────────────────────────
router.get('/runs/:id', requireAuth, async (req, res) => {
  try {
    const row = await loadRun(req.params.id);
    if (!row) return res.status(404).json({ error: 'Run not found' });
    if (row.userId !== req.user.id && req.user.role !== 'Admin' && req.user.role !== 'Security Team') {
      return res.status(403).json({ error: 'Access denied' });
    }
    return res.json(serializeRun(row));
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── POST /api/cryptotwin/runs/:id/reset ───────────────────────────────────────
router.post('/runs/:id/reset', requireAuth, async (req, res) => {
  try {
    const row = await loadRun(req.params.id);
    if (!row) return res.status(404).json({ error: 'Run not found' });
    if (row.userId !== req.user.id) return res.status(403).json({ error: 'Access denied' });
    row.status        = 'PENDING';
    row.stagesJson    = '[]';
    row.attackPaths   = '[]';
    row.testsJson     = '[]';
    row.patchLog      = '[]';
    row.aiIterations  = '[]';
    row.verdict       = null;
    row.confidence    = null;
    row.blockers      = '[]';
    row.approval      = null;
    row.approvalBy    = null;
    row.approvalAt    = null;
    row.approvalNote  = null;
    row.overrideReason = null;
    row.reportJson    = null;
    row.errorMessage  = null;
    row.updatedAt     = new Date();
    await saveRun(row);
    appendAuditLog({ userId: req.user.id, action: 'CRYPTOTWIN_RUN_RESET', method: 'POST', path: '/api/cryptotwin/runs/' + req.params.id + '/reset', statusCode: 200 }).catch(() => {});
    return res.json({ message: 'Run reset', runId: row.id });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── POST /api/cryptotwin/runs/:id/approval ────────────────────────────────────
router.post('/runs/:id/approval', requireAuth, async (req, res) => {
  try {
    const { action, note, overrideReason } = req.body;   // action: APPROVED | REJECTED | APPROVED_WITH_OVERRIDE
    if (!['APPROVED', 'REJECTED', 'APPROVED_WITH_OVERRIDE', 'REVISE'].includes(action)) {
      return res.status(400).json({ error: 'action must be APPROVED, REJECTED, APPROVED_WITH_OVERRIDE, or REVISE' });
    }
    const row = await loadRun(req.params.id);
    if (!row) return res.status(404).json({ error: 'Run not found' });
    if (row.status !== 'DONE') return res.status(409).json({ error: 'Run has not completed yet' });

    // Enforce: approving NOT_READY or INCONCLUSIVE requires overrideReason
    if (action === 'APPROVED' && (row.verdict === 'PRODUCTION_NOT_READY' || row.verdict === 'INCONCLUSIVE')) {
      if (!overrideReason || overrideReason.trim().length < 10) {
        return res.status(422).json({ error: 'Approving a ' + row.verdict + ' result requires a detailed override reason (min 10 chars)' });
      }
      row.approval      = 'APPROVED_WITH_OVERRIDE';
      row.overrideReason = overrideReason.trim();
    } else {
      row.approval = action;
    }

    row.approvalBy   = req.user.id;
    row.approvalAt   = new Date();
    row.approvalNote = note || null;
    row.updatedAt    = new Date();

    // Update reportJson if it exists
    if (row.reportJson) {
      try {
        const report  = JSON.parse(row.reportJson);
        report.approval = { action: row.approval, by: req.user.id, at: row.approvalAt, note: row.approvalNote, overrideReason: row.overrideReason || null };
        row.reportJson = JSON.stringify(report);
      } catch (_) {}
    }

    await saveRun(row);
    appendAuditLog({ userId: req.user.id, action: 'CRYPTOTWIN_APPROVAL_' + row.approval, method: 'POST', path: '/api/cryptotwin/runs/' + req.params.id + '/approval', statusCode: 200 }).catch(() => {});
    return res.json({ message: 'Approval recorded', approval: row.approval, runId: row.id });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── GET /api/cryptotwin/runs/:id/report ───────────────────────────────────────
router.get('/runs/:id/report', requireAuth, async (req, res) => {
  try {
    const row = await loadRun(req.params.id);
    if (!row) return res.status(404).json({ error: 'Run not found' });
    if (row.userId !== req.user.id && req.user.role !== 'Admin' && req.user.role !== 'Security Team') {
      return res.status(403).json({ error: 'Access denied' });
    }
    if (!row.reportJson) return res.status(404).json({ error: 'Report not yet available — run is still in progress' });
    const report = JSON.parse(row.reportJson);
    // Attach approval if it was set after reportJson was created
    if (row.approval) report.approval = { action: row.approval, by: row.approvalBy, at: row.approvalAt, note: row.approvalNote, overrideReason: row.overrideReason || null };
    const format = req.query.format || 'json';
    if (format === 'json') {
      res.setHeader('Content-Disposition', 'attachment; filename="cryptotwin-report-' + row.id.slice(0, 8) + '.json"');
      res.setHeader('Content-Type', 'application/json');
      return res.json(report);
    }
    // pdf not implemented
    return res.status(400).json({ error: 'PDF export not supported; use format=json' });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── GET /api/cryptotwin/runs/:id/raw-logs/:migrationId ───────────────────────
router.get('/runs/:id/raw-logs/:migrationId', requireAuth, async (req, res) => {
  try {
    const row = await loadRun(req.params.id);
    if (!row) return res.status(404).json({ error: 'Run not found' });
    const report = safe(row.reportJson) || {};
    const migrations = report.migrations || safe(row.stagesJson) || [];
    const target = migrations.find(m => m.migrationId === req.params.migrationId);
    if (!target) return res.status(404).json({ error: 'Migration ID not found in run' });
    return res.json({
      migrationId: req.params.migrationId,
      rawLogs: target.evidence ? target.evidence.rawLogs : []
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── POST /api/cryptotwin/runs/:id/generate-app ──────────────────────────────
router.post('/runs/:id/generate-app', requireAuth, async (req, res) => {
  try {
    const { approvedIds } = req.body;
    const row = await loadRun(req.params.id);
    if (!row) return res.status(404).json({ error: 'Run not found' });

    const { generateUpdatedApplication } = require('../services/cryptoTwinEngine');
    const report = safe(row.reportJson) || {};
    const migrations = report.migrations || [];

    const result = generateUpdatedApplication(null, approvedIds || [], migrations);

    appendAuditLog({ userId: req.user.id, action: 'CRYPTOTWIN_GENERATE_APP', method: 'POST', path: '/api/cryptotwin/runs/' + req.params.id + '/generate-app', statusCode: 200 }).catch(() => {});

    return res.json({
      message: 'Updated Application Package Generated Successfully',
      approvedCount: result.approvedCount,
      diffText: result.diffText,
      generatedAt: result.generatedAt
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error: ' + err.message });
  }
});

module.exports = router;

