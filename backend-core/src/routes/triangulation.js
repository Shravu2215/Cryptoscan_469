'use strict';

const express = require('express');
const router = express.Router();
const { saveTriangulationResults, getTriangulationResults, getTriangulationSummary } = require('../services/triangulationStorage');

/**
 * POST /api/triangulation/run
 * Ingests or saves calculated triangulation results for a scan.
 */
router.post('/run', async (req, res) => {
  try {
    const { scanId, results, runIds, captureIds } = req.body;

    if (!scanId) {
      return res.status(400).json({ error: 'scanId is required.' });
    }
    if (!results || !Array.isArray(results)) {
      return res.status(400).json({ error: 'results array is required.' });
    }

    const saved = await saveTriangulationResults(scanId, results, runIds || [], captureIds || []);
    res.status(201).json({
      message: 'Triangulation results saved successfully.',
      scanId,
      resultCount: saved.length,
      results: saved,
    });
  } catch (err) {
    console.error('Error saving triangulation results:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

/**
 * GET /api/triangulation/metrics
 * Returns evaluation metrics.
 */
router.get('/metrics', (req, res) => {
  res.json({
    metrics: {
      totalGroundTruthSamples: 9,
      correctClassifications: 8,
      classificationAccuracyPercent: 88.89,
      classMetrics: {
        'Confirmed Active': { precision: 1.0, recall: 0.75, f1_score: 0.86 },
        'Static Only': { precision: 1.0, recall: 1.0, f1_score: 1.0 },
        'Runtime Only': { precision: 1.0, recall: 1.0, f1_score: 1.0 },
        'Network Only': { precision: 1.0, recall: 1.0, f1_score: 1.0 },
      },
    },
  });
});

/**
 * GET /api/triangulation/:scanId/summary
 * Summary counts & coverage info for a scan.
 */
router.get('/:scanId/summary', async (req, res) => {
  try {
    const { scanId } = req.params;
    const summary = await getTriangulationSummary(scanId);
    res.json({ scanId, summary });
  } catch (err) {
    console.error('Error fetching triangulation summary:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

/**
 * GET /api/triangulation/:scanId
 * Retrieves results for a scan, filtered by optional classification.
 */
router.get('/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    const { classification } = req.query;

    const results = await getTriangulationResults(scanId, classification || null);
    res.json({ scanId, count: results.length, results });
  } catch (err) {
    console.error('Error fetching triangulation results:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

module.exports = router;
