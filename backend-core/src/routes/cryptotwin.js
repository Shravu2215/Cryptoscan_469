'use strict';

/**
 * CryptoTwin REST API Routes
 * Endpoints for creating runs, fetching status, streaming progress events,
 * resetting twin sandboxes, and exporting reports.
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { startTwinRun, getTwinRun, getTwinRunsForScan, resetTwinRun } = require('../services/cryptotwinEngine');

// POST /api/cryptotwin/runs — Create and start a fire drill
router.post('/runs', requireAuth, async (req, res) => {
  try {
    const { scanId, maxFixIterations } = req.body || {};
    if (!scanId) {
      return res.status(400).json({ error: 'scanId is required' });
    }

    const run = await startTwinRun(scanId, maxFixIterations || 3);
    res.status(201).json(run);
  } catch (err) {
    console.error('Error in POST /api/cryptotwin/runs:', err);
    res.status(500).json({ error: err.message || 'Failed to start CryptoTwin run' });
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

// GET /api/cryptotwin/runs/:runId/report — Export Report as JSON or PDF
router.get('/runs/:runId/report', requireAuth, async (req, res) => {
  try {
    const { runId } = req.params;
    const format = (req.query.format || 'json').toLowerCase();
    const run = getTwinRun(runId);

    if (!run) {
      return res.status(404).json({ error: 'Run not found' });
    }

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename=CryptoTwin_Report_${runId}.json`);
      return res.send(JSON.stringify(run, null, 2));
    }

    // Default JSON formatted report if PDF library not installed
    res.setHeader('Content-Type', 'application/json');
    res.json(run);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to export CryptoTwin report' });
  }
});

module.exports = router;
