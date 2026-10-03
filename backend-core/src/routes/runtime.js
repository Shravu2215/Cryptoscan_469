'use strict';

/**
 * Express REST API Routes for Runtime Execution Tracing.
 * Endpoints:
 * - POST /api/runtime/runs        : Ingest a run with events
 * - GET  /api/runtime/runs        : List runs (filtered by scan_id)
 * - GET  /api/runtime/runs/:id    : Run details and summary
 * - GET  /api/runtime/runs/:id/events : Paginated events
 * - GET  /api/runtime/runs/:id/report : Evidence report
 */

const express = require('express');
const router = express.Router();
const {
  createRun,
  bulkInsertEvents,
  getRunById,
  listRuns,
  getEventsByRunId,
} = require('../services/runtimeStorage');

const MAX_PAYLOAD_EVENTS = 10000;
const VALID_OPERATIONS = new Set([
  'hash', 'encrypt', 'decrypt', 'sign', 'verify', 'keygen', 'kdf', 'hmac', 'tls', 'other'
]);

/**
 * POST /api/runtime/runs
 * Ingest a run with events payload.
 */
router.post('/runs', async (req, res, next) => {
  try {
    const { run_id, scan_id, language, command, environment, events } = req.body || {};

    if (!language || !['python', 'node'].includes(String(language).toLowerCase())) {
      return res.status(400).json({ error: 'Invalid or missing language. Must be "python" or "node".' });
    }

    if (events && !Array.isArray(events)) {
      return res.status(400).json({ error: 'Events field must be an array.' });
    }

    if (events && events.length > MAX_PAYLOAD_EVENTS) {
      return res.status(400).json({
        error: `Payload size exceeded. Max ${MAX_PAYLOAD_EVENTS} events per batch.`,
      });
    }

    // Validate individual event items
    if (events) {
      for (let i = 0; i < events.length; i++) {
        const evt = events[i];
        if (!evt.operation || !VALID_OPERATIONS.has(evt.operation)) {
          return res.status(400).json({
            error: `Invalid event at index ${i}: invalid or missing operation '${evt.operation}'.`,
          });
        }
        if (!evt.algorithm) {
          return res.status(400).json({
            error: `Invalid event at index ${i}: missing algorithm.`,
          });
        }
      }
    }

    // 1. Create run record
    const runRecord = await createRun({
      id: run_id,
      scanId: scan_id,
      language: String(language).toLowerCase(),
      command: command || null,
      environment: environment || 'test',
    });

    // 2. Insert events if provided
    let insertedCount = 0;
    if (events && events.length > 0) {
      const resBulk = await bulkInsertEvents(runRecord.id, events);
      insertedCount = resBulk.count;
    }

    return res.status(201).json({
      success: true,
      run_id: runRecord.id,
      event_count: insertedCount,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/runtime/runs
 * List runs with optional scan_id filter.
 */
router.get('/runs', async (req, res, next) => {
  try {
    const scanId = req.query.scan_id || null;
    const limit = parseInt(req.query.limit || 50, 10);
    const offset = parseInt(req.query.offset || 0, 10);

    const runs = await listRuns(scanId, limit, offset);
    return res.json({ runs });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/runtime/runs/:run_id
 * Get run details and summary.
 */
router.get('/runs/:run_id', async (req, res, next) => {
  try {
    const run = await getRunById(req.params.run_id, false);
    if (!run) {
      return res.status(404).json({ error: 'Runtime run not found.' });
    }
    return res.json({ run });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/runtime/runs/:run_id/events
 * Get paginated events for a run.
 */
router.get('/runs/:run_id/events', async (req, res, next) => {
  try {
    const limit = parseInt(req.query.limit || 100, 10);
    const offset = parseInt(req.query.offset || 0, 10);

    const events = await getEventsByRunId(req.params.run_id, limit, offset);
    return res.json({ events, count: events.length, limit, offset });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/runtime/runs/:run_id/report
 * Generate Step 7 style evidence report for a run.
 */
router.get('/runs/:run_id/report', async (req, res, next) => {
  try {
    const run = await getRunById(req.params.run_id, true);
    if (!run) {
      return res.status(404).json({ error: 'Runtime run not found.' });
    }

    const QUANTUM_VULNERABLE = new Set(['RSA', 'ECDSA', 'ECDH', 'DH', 'DSA', 'ED25519', 'ED448']);
    const uniqueAlgos = new Set();
    const quantumVuln = new Set();
    let unmatched = 0;

    const aggregatedMap = {};

    for (const evt of run.events) {
      const algo = evt.algorithm || 'UNKNOWN';
      uniqueAlgos.add(algo);
      if (QUANTUM_VULNERABLE.has(algo)) quantumVuln.add(algo);

      if (!evt.matchedFindingId) unmatched++;

      const key = `${algo}|${evt.operation}|${evt.library}|${evt.callFile}|${evt.callLine}|${evt.callFunction}`;
      if (!aggregatedMap[key]) {
        aggregatedMap[key] = {
          algorithm: algo,
          operation: evt.operation,
          library: evt.library,
          key_size: evt.keySize,
          mode: evt.mode,
          padding: evt.padding,
          curve: evt.curve,
          call_file: evt.callFile,
          call_line: evt.callLine,
          call_function: evt.callFunction,
          matched_finding_id: evt.matchedFindingId,
          count: 1,
          first_seen: evt.timestamp,
          last_seen: evt.timestamp,
          is_quantum_vulnerable: QUANTUM_VULNERABLE.has(algo),
        };
      } else {
        aggregatedMap[key].count++;
        aggregatedMap[key].last_seen = evt.timestamp;
      }
    }

    const report = {
      run_id: run.id,
      scan_id: run.scanId,
      language: run.language,
      environment: run.environment,
      summary: {
        total_events: run.events.length,
        unique_algorithms: Array.from(uniqueAlgos).sort(),
        quantum_vulnerable_algorithms: Array.from(quantumVuln).sort(),
        unmatched_events: unmatched,
      },
      events: Object.values(aggregatedMap),
    };

    return res.json(report);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
