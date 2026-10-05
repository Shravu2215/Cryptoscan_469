'use strict';

/**
 * CryptoTwin REST API Routes
 * Endpoints for starting fire drills (direct scan or uploaded plan),
 * querying run progress, fetching events stream, resetting sandboxes,
 * uploading Migration Plan JSON files, and handling Final Approval workflows.
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { startTwinRun, getTwinRun, getTwinRunsForScan, resetTwinRun, handleRunApproval } = require('../services/cryptotwinEngine');
const { validateAndParseUploadInput } = require('../services/cryptotwinContract');

// POST /api/cryptotwin/runs — Create and start a fire drill
router.post('/runs', requireAuth, async (req, res) => {
  try {
    const { scanId, uploadedPlanJson, maxFixIterations } = req.body || {};
    if (!scanId && !uploadedPlanJson) {
      return res.status(400).json({ error: 'Either scanId or uploadedPlanJson must be provided.' });
    }

    const run = await startTwinRun(scanId, uploadedPlanJson, maxFixIterations || 3);
    res.status(201).json(run);
  } catch (err) {
    console.error('Error in POST /api/cryptotwin/runs:', err);
    res.status(400).json({ error: err.message || 'Failed to start CryptoTwin run' });
  }
});

// POST /api/cryptotwin/upload-plan — Validate uploaded Migration Plan JSON file
router.post('/upload-plan', requireAuth, async (req, res) => {
  try {
    const { jsonContent } = req.body || {};
    if (!jsonContent) {
      return res.status(400).json({ error: 'No JSON content received in upload request.' });
    }

    const parsedInput = validateAndParseUploadInput(jsonContent);
    res.json({ success: true, input: parsedInput });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Invalid Migration Plan JSON file.' });
  }
});

// GET /api/cryptotwin/runs?scanId= — List runs for a scan
router.get('/runs', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.query;
    const runs = getTwinRunsForScan(scanId);
    res.json(runs);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to list CryptoTwin runs' });
  }
});

// GET /api/cryptotwin/runs/:runId — Get full run state
router.get('/runs/:runId', requireAuth, async (req, res) => {
  try {
    const { runId } = req.params;
    const run = getTwinRun(runId);
    if (!run) {
      return res.status(404).json({ error: 'CryptoTwin run not found' });
    }
    res.json(run);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to get CryptoTwin run state' });
  }
});

// GET /api/cryptotwin/runs/:runId/events — Stream progress updates via SSE
router.get('/runs/:runId/events', requireAuth, (req, res) => {
  const { runId } = req.params;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const interval = setInterval(() => {
    const run = getTwinRun(runId);
    if (!run) {
      res.write(`data: ${JSON.stringify({ error: 'Run not found' })}\n\n`);
      clearInterval(interval);
      return res.end();
    }

    res.write(`data: ${JSON.stringify(run)}\n\n`);

    if (run.status === 'COMPLETED' || run.status === 'FAILED') {
      clearInterval(interval);
      res.end();
    }
  }, 1000);

  req.on('close', () => clearInterval(interval));
});

// POST /api/cryptotwin/runs/:runId/approve — Approve, Reject, or Revise a run
router.post('/runs/:runId/approve', requireAuth, async (req, res) => {
  try {
    const { runId } = req.params;
    const { action, overrideReason, reviewer } = req.body || {};
    if (!action) {
      return res.status(400).json({ error: 'Approval action (APPROVE, REJECT, REVISE) is required.' });
    }

    const updatedRun = handleRunApproval(runId, action, overrideReason, reviewer || 'Security Analyst');
    res.json(updatedRun);
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to process approval action' });
  }
});

// POST /api/cryptotwin/runs/:runId/reset — Reset Twin Sandbox
router.post('/runs/:runId/reset', requireAuth, async (req, res) => {
  try {
    const { runId } = req.params;
    const result = resetTwinRun(runId);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to reset CryptoTwin run' });
  }
});

// GET /api/cryptotwin/runs/:runId/report — Export Report as JSON
router.get('/runs/:runId/report', requireAuth, async (req, res) => {
  try {
    const { runId } = req.params;
    const format = (req.query.format || 'json').toLowerCase();
    const run = getTwinRun(runId);

    if (!run) {
      return res.status(404).json({ error: 'Run not found' });
    }

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=CryptoTwin_Report_${runId}.json`);
    return res.send(JSON.stringify(run, null, 2));
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to export CryptoTwin report' });
  }
});

module.exports = router;
