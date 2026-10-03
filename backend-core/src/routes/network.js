'use strict';

const express = require('express');
const router = express.Router();
const { createNetworkCapture, listNetworkCaptures } = require('../services/triangulationStorage');

/**
 * POST /api/network/captures
 * Ingests a network capture payload (JSON list of observations).
 */
router.post('/captures', async (req, res) => {
  try {
    const { scanId, source, fileName, observations } = req.body;

    if (!observations || !Array.isArray(observations) || observations.length === 0) {
      return res.status(400).json({ error: 'Payload must contain a non-empty "observations" array.' });
    }

    const capture = await createNetworkCapture({
      scanId,
      source: source || 'json',
      fileName: fileName || 'capture.json',
      observations,
    });

    res.status(201).json({
      message: 'Network capture ingested successfully.',
      capture,
    });
  } catch (err) {
    console.error('Error ingesting network capture:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

/**
 * GET /api/network/captures
 * Lists network captures, optionally filtered by scanId.
 */
router.get('/captures', async (req, res) => {
  try {
    const { scanId, limit } = req.query;
    const captures = await listNetworkCaptures(scanId || null, limit ? parseInt(limit, 10) : 50);
    res.json({ captures });
  } catch (err) {
    console.error('Error listing network captures:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

module.exports = router;
