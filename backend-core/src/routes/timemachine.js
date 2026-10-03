const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');
const path = require('path');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// In-memory fallback cache for scans when DB is unreachable or in test mode
const scanMemoryCache = new Map();

/**
 * POST /api/timemachine/scan
 * Triggers a Time Machine history scan for a given repo path & ref.
 */
router.post('/scan', async (req, res) => {
  try {
    const { repoPath, ref = 'HEAD' } = req.body;
    if (!repoPath) {
      return res.status(400).json({ error: 'repoPath is required' });
    }

    const resolvedPath = path.resolve(repoPath);
    const pythonScript = path.join(__dirname, '../../../timemachine');
    const projectRoot = path.join(__dirname, '../../..');

    // Run python -m timemachine <resolvedPath> --ref <ref> --json
    execFile(
      'python',
      ['-m', 'timemachine', resolvedPath, '--ref', ref, '--json'],
      { cwd: projectRoot, maxBuffer: 10 * 1024 * 1024 },
      async (error, stdout, stderr) => {
        if (error) {
          console.error('[TimeMachine Error]', stderr || error.message);
          return res.status(500).json({ error: 'Time machine history scan failed', details: stderr || error.message });
        }

        let scanResult;
        try {
          scanResult = JSON.parse(stdout);
        } catch (parseErr) {
          return res.status(500).json({ error: 'Failed to parse timemachine scan JSON output', output: stdout });
        }

        const summary = scanResult.repository_summary;
        let savedScanId = 'tm_' + Date.now();

        // Attempt Prisma DB persistence
        try {
          const dbScan = await prisma.historyScan.create({
            data: {
              repoName: summary.repo_path,
              ref: summary.ref || ref,
              commitCount: summary.total_commits,
              firstCommitDate: new Date(summary.first_commit_date),
              lastCommitDate: new Date(summary.last_commit_date),
              cacheHits: summary.cache_hits || 0,
              cacheMisses: summary.cache_misses || 0,
              findings: {
                create: (scanResult.findings_lifecycle || []).map((f) => ({
                  findingKey: f.finding_key,
                  algorithm: f.algorithm,
                  keySize: f.key_size || null,
                  file: f.file,
                  function: f.function,
                  classification: f.classification,
                  introducedCommit: f.introduced_commit,
                  introducedCommitIndex: f.introduced_commit_index,
                  introducedDate: new Date(f.introduced_date),
                  removedCommit: f.removed_commit || null,
                  removedCommitIndex: f.removed_commit_index || null,
                  removedDate: f.removed_date ? new Date(f.removed_date) : null,
                  exposureCommits: f.exposure_commits,
                  exposureDays: f.exposure_days,
                  stillPresent: f.still_present,
                })),
              },
              secrets: {
                create: (scanResult.leaked_secrets || []).map((s) => ({
                  secretType: s.secret_type,
                  file: s.file,
                  addedCommit: s.added_commit,
                  addedCommitIndex: s.added_commit_index,
                  addedDate: new Date(s.added_date),
                  removedCommit: s.removed_commit || null,
                  removedCommitIndex: s.removed_commit_index || null,
                  removedDate: s.removed_date ? new Date(s.removed_date) : null,
                  presentInHistory: s.present_in_history,
                  fingerprint: s.fingerprint,
                })),
              },
            },
          });
          savedScanId = dbScan.id;
        } catch (dbErr) {
          console.warn('[TimeMachine DB Warning] Falling back to memory storage:', dbErr.message);
        }

        // Store result in memory cache for GET route fallback
        scanMemoryCache.set(savedScanId, {
          id: savedScanId,
          result: scanResult,
          createdAt: new Date().toISOString(),
        });

        return res.json({
          scanId: savedScanId,
          repository_summary: summary,
          findings_lifecycle: scanResult.findings_lifecycle,
          leaked_secrets: scanResult.leaked_secrets,
          timeline: scanResult.timeline,
          remediation_priorities: scanResult.remediation_priorities,
        });
      }
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/timemachine/scans/:id
 * Retrieves saved history scan details by ID.
 */
router.get('/scans/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const dbScan = await prisma.historyScan.findUnique({
      where: { id },
      include: { findings: true, secrets: true },
    });
    if (dbScan) {
      return res.json(dbScan);
    }
  } catch (dbErr) {
    // Ignore DB error and fallback to memory cache
  }

  if (scanMemoryCache.has(id)) {
    return res.json(scanMemoryCache.get(id));
  }

  return res.status(404).json({ error: 'History scan not found' });
});

/**
 * GET /api/timemachine/scans/:id/timeline
 * Retrieves risk timeline and burndown series for charts.
 */
router.get('/scans/:id/timeline', async (req, res) => {
  const { id } = req.params;

  if (scanMemoryCache.has(id)) {
    const cached = scanMemoryCache.get(id);
    return res.json({
      scanId: id,
      timeline: cached.result.timeline,
    });
  }

  return res.status(404).json({ error: 'Timeline data not found for specified scan' });
});

module.exports = router;
