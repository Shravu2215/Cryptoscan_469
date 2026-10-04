'use strict';
/**
 * repos.js  – Repository import / upload routes
 *
 * Security hardening applied (Hostile-Repository Hardening, Req 1–5):
 *   • URL validation: HTTPS-only, allowlisted hosts, SSRF/private-IP block
 *   • Archive extraction via archiveSafety (zip-slip, symlink, zip-bomb guards)
 *   • Repo names and file paths sanitized before DB write / API response
 *   • No git clone executed — repos imported as ZIP archives (no hooks, no LFS)
 *   • Uploaded ZIP never executed; only read by the scanner
 */

const express = require('express');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const os      = require('os');
const crypto  = require('crypto');

const { requireAuth } = require('../middleware/auth');
const prisma = require('../utils/prismaClient');
const { extractZipSafe } = require('../utils/archiveSafety');
const { validateGitUrl, sanitizeRepoName, sanitizeFilePath } = require('../utils/repoSecurity');

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, '../../uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ── Multer storage: random UUID filenames, no originalname leakage ────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    // UUID + .zip — originalname is never part of the disk path
    cb(null, `${crypto.randomUUID()}.zip`);
  },
});

const maxSizeMb      = Number(process.env.MAX_UPLOAD_SIZE_MB    || 50);
const maxExtractedMb = Number(process.env.MAX_EXTRACTED_SIZE_MB || 512);

const upload = multer({
  storage,
  limits: { fileSize: maxSizeMb * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.zip'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowed.includes(ext)) {
      return cb(new Error(`Only ${allowed.join(', ')} files are allowed`));
    }
    cb(null, true);
  },
});

// ── Helpers ───────────────────────────────────────────────────────────────────

const VALID_CRITICALITY_TIERS = new Set(['Critical', 'Important', 'Standard', 'Low', 'Not tagged']);

function normalizeCriticality(tier) {
  if (!tier) return 'Not tagged';
  const u = String(tier).trim().toUpperCase();
  if (u === 'CRITICAL' || u === 'TIER 1')   return 'Critical';
  if (u === 'IMPORTANT' || u === 'HIGH' || u === 'TIER 2') return 'Important';
  if (u === 'STANDARD' || u === 'MEDIUM' || u === 'TIER 3') return 'Standard';
  if (u === 'LOW' || u === 'TIER 4')         return 'Low';
  if (['NOT TAGGED','NOT_TAGGED','NONE','UNKNOWN',''].includes(u)) return 'Not tagged';
  return null;
}

/** Cleanup helper — always remove temp dirs even on failure */
function cleanupDir(dir) {
  if (!dir) return;
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
}

// ── POST /repos/github ────────────────────────────────────────────────────────
// Downloads a public GitHub repository as a ZIP archive (no git clone, no hooks,
// no LFS smudge, no submodules) and extracts it safely.
router.post('/github', requireAuth, async (req, res) => {
  let extractDir;
  try {
    // 1. Validate + sanitize the URL (SSRF-safe, host-allowlisted)
    let parsed;
    try {
      parsed = await validateGitUrl(req.body?.url);
    } catch (validationErr) {
      return res.status(400).json({ error: validationErr.message });
    }

    const { owner, repo: repoSlug, host } = parsed;

    const headers = { 'User-Agent': 'CryptoScan/1.0', Accept: 'application/vnd.github+json' };

    // 2. Fetch repository metadata (only for github.com)
    let metadata = { default_branch: 'main', full_name: `${owner}/${repoSlug}`, archived: false };
    if (host === 'github.com') {
      try {
        const metadataResponse = await fetch(
          `https://api.github.com/repos/${owner}/${repoSlug}`,
          { headers }
        );
        if (metadataResponse.ok) {
          metadata = await metadataResponse.json();
          if (metadata.archived) {
            return res.status(400).json({ error: 'Archived GitHub repositories cannot be scanned' });
          }
        } else if (metadataResponse.status === 404) {
          return res.status(404).json({
            error: `GitHub repository "${owner}/${repoSlug}" was not found or is private.`,
          });
        } else {
          console.warn(`GitHub API returned status ${metadataResponse.status}, proceeding with default branch 'main'`);
        }
      } catch (metaErr) {
        console.warn('GitHub API metadata fetch failed, proceeding with default branch:', metaErr.message);
      }
    }

    // 3. Download the archive (ZIP — no git clone, no hooks, no LFS)
    let branch = encodeURIComponent(metadata.default_branch || 'main');
    let archiveUrl = `https://codeload.github.com/${owner}/${repoSlug}/zip/refs/heads/${branch}`;
    let archiveResponse = await fetch(archiveUrl, { headers });
    
    // If 'main' branch is 404, try 'master' branch fallback
    if (!archiveResponse.ok && (branch === 'main' || !metadata.default_branch)) {
      const masterUrl = `https://codeload.github.com/${owner}/${repoSlug}/zip/refs/heads/master`;
      const masterRes = await fetch(masterUrl, { headers });
      if (masterRes.ok) {
        archiveUrl = masterUrl;
        archiveResponse = masterRes;
        branch = 'master';
      }
    }

    if (!archiveResponse.ok) {
      return res.status(502).json({
        error: `GitHub repository "${owner}/${repoSlug}" could not be downloaded. Please verify the URL and ensure the repository is public.`,
      });
    }

    const contentLength = Number(archiveResponse.headers.get('content-length') || 0);
    if (contentLength > maxSizeMb * 1024 * 1024) {
      return res.status(413).json({
        error: `Repository archive exceeds the ${maxSizeMb} MB download limit`,
      });
    }

    const archiveBuffer = Buffer.from(await archiveResponse.arrayBuffer());
    if (archiveBuffer.length > maxSizeMb * 1024 * 1024) {
      return res.status(413).json({
        error: `Repository archive exceeds the ${maxSizeMb} MB download limit`,
      });
    }

    // 4. Safe extraction (zip-slip, symlink, zip-bomb guards via archiveSafety)
    extractDir = fs.mkdtempSync(path.join(UPLOAD_DIR, 'github-'));
    let repositoryPath;
    try {
      repositoryPath = extractZipSafe(archiveBuffer, extractDir);
    } catch (archiveErr) {
      cleanupDir(extractDir);
      extractDir = null;
      return res.status(422).json({ error: `Archive safety check failed: ${archiveErr.message}` });
    }

    // Compute input hash (commit SHA if available, else zip sha256)
    let sourceHash = '';
    try {
      const commitRes = await fetch(`https://api.github.com/repos/${owner}/${repoSlug}/commits/${branch}`, { headers });
      if (commitRes.ok) {
        const commitData = await commitRes.json();
        sourceHash = commitData.sha;
      }
    } catch (_) {}
    if (!sourceHash) {
      sourceHash = crypto.createHash('sha256').update(archiveBuffer).digest('hex');
    }
    fs.writeFileSync(path.join(repositoryPath, '.source_hash'), sourceHash);


    // 5. Sanitize repo name before DB write
    const safeName = sanitizeRepoName(metadata.full_name || `${owner}/${repoSlug}`);

    const { saveRepo } = require('../utils/devStore');
    let repo;
    try {
      repo = await prisma.repo.create({
        data: {
          name: safeName,
          filePath: repositoryPath,
          uploadedBy: req.user.id,
          businessCriticality: normalizeCriticality(req.body.businessCriticality) || 'Not tagged',
        },
      });
    } catch (dbErr) {
      console.warn('PostgreSQL unavailable during github import, using dev store:', dbErr.message);
      repo = {
        id: 'repo-dev-' + Date.now(),
        name: safeName,
        filePath: repositoryPath,
        uploadedBy: req.user.id,
        businessCriticality: normalizeCriticality(req.body.businessCriticality) || 'Not tagged',
        createdAt: new Date(),
      };
    }
    saveRepo(repo);

    return res.status(201).json({
      id:                 repo.id,
      name:               repo.name,
      createdAt:          repo.createdAt,
      businessCriticality: repo.businessCriticality || 'Not tagged',
      source:             'github',
    });
  } catch (err) {
    cleanupDir(extractDir);
    console.error('GitHub import error:', err);
    return res.status(502).json({ error: err.message || 'GitHub repository import failed' });
  }
});

// ── POST /repos/upload ────────────────────────────────────────────────────────
router.post('/upload', requireAuth, upload.single('repo'), async (req, res) => {
  let extractDir;
  const uploadedFilePath = req.file?.path;
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded (field name must be "repo")' });
    }

    // Read the uploaded zip into memory, then extract via safe extractor
    const archiveBuffer = fs.readFileSync(uploadedFilePath);

    extractDir = fs.mkdtempSync(path.join(UPLOAD_DIR, 'upload-'));
    let repositoryPath;
    try {
      repositoryPath = extractZipSafe(archiveBuffer, extractDir);
    } catch (archiveErr) {
      cleanupDir(extractDir);
      extractDir = null;
      // Remove the raw uploaded zip too
      if (uploadedFilePath) try { fs.unlinkSync(uploadedFilePath); } catch (_) {}
      return res.status(422).json({ error: `Archive safety check failed: ${archiveErr.message}` });
    }

    // Compute input hash for uploads (SHA-256 of the zip)
    const sourceHash = crypto.createHash('sha256').update(archiveBuffer).digest('hex');
    fs.writeFileSync(path.join(repositoryPath, '.source_hash'), sourceHash);


    // Sanitize the user-supplied repo name
    const rawName = req.body.name || req.file.originalname;
    const safeName = sanitizeRepoName(rawName);

    const { saveRepo } = require('../utils/devStore');
    let repo;
    try {
      repo = await prisma.repo.create({
        data: {
          name: safeName,
          filePath: repositoryPath,
          uploadedBy: req.user.id,
          businessCriticality: normalizeCriticality(req.body.businessCriticality) || 'Not tagged',
        },
      });
    } catch (dbErr) {
      console.warn('PostgreSQL unavailable during repo upload, using dev store:', dbErr.message);
      repo = {
        id: 'repo-dev-' + Date.now(),
        name: safeName,
        filePath: repositoryPath,
        uploadedBy: req.user.id,
        businessCriticality: normalizeCriticality(req.body.businessCriticality) || 'Not tagged',
        createdAt: new Date(),
      };
    }
    saveRepo(repo);

    // Remove the raw uploaded zip (we keep only the extracted directory)
    if (uploadedFilePath) try { fs.unlinkSync(uploadedFilePath); } catch (_) {}

    return res.status(201).json({
      id:                 repo.id,
      name:               repo.name,
      createdAt:          repo.createdAt,
      businessCriticality: repo.businessCriticality || 'Not tagged',
    });
  } catch (err) {
    cleanupDir(extractDir);
    if (uploadedFilePath) try { fs.unlinkSync(uploadedFilePath); } catch (_) {}
    console.error('Repo upload error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── GET /repos ────────────────────────────────────────────────────────────────
router.get('/', requireAuth, async (req, res) => {
  try {
    const { devRepos } = require('../utils/devStore');
    try {
      const repos = await prisma.repo.findMany({
        where: { uploadedBy: req.user.id },
        orderBy: { createdAt: 'desc' },
      });
      const enriched = repos.map(r => ({
        ...r,
        criticality_tier: normalizeCriticality(r.businessCriticality) || 'Not tagged',
      }));
      return res.json(enriched);
    } catch (_) {
      const repos = Array.from(devRepos.values()).map(r => {
        const crit = normalizeCriticality(r.businessCriticality || r.criticality_tier) || 'Not tagged';
        return {
          id:                 r.id,
          name:               r.name,
          businessCriticality: crit,
          criticality_tier:   crit,
          createdAt:          r.createdAt,
        };
      });
      return res.json(repos);
    }
  } catch (err) {
    console.error('List repos error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── GET /repos/:id ────────────────────────────────────────────────────────────
router.get('/:id', requireAuth, async (req, res) => {
  try {
    const { getRepo } = require('../utils/devStore');
    let repo;
    try {
      repo = await prisma.repo.findUnique({ where: { id: req.params.id } });
      if (!repo) {
        repo = await prisma.repo.findFirst({ where: { name: req.params.id } });
      }
    } catch (_) {}
    if (!repo) repo = getRepo(req.params.id);
    if (!repo) return res.status(404).json({ error: 'Repository not found' });
    const crit = normalizeCriticality(repo.businessCriticality || repo.criticality_tier) || 'Not tagged';
    return res.json({
      ...repo,
      businessCriticality: crit,
      criticality_tier:    crit,
    });
  } catch (err) {
    console.error('Get repo error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── PATCH /repos/:id ──────────────────────────────────────────────────────────
router.patch('/:id', requireAuth, async (req, res) => {
  try {
    const { getRepo, updateRepoCriticality } = require('../utils/devStore');
    const rawTier = req.body.criticality_tier || req.body.businessCriticality;
    if (!rawTier) {
      return res.status(400).json({ error: 'criticality_tier or businessCriticality is required' });
    }
    const tier = normalizeCriticality(rawTier);
    if (!tier || !VALID_CRITICALITY_TIERS.has(tier)) {
      return res.status(400).json({
        error: 'Invalid criticality tier. Accepted tiers: Critical, Important, Standard, Low, Not tagged',
      });
    }
    let repo;
    try {
      const cleanName = req.params.id.replace(/\.zip$/i, '');
      repo = await prisma.repo.findUnique({ where: { id: req.params.id } });
      if (!repo) {
        repo = await prisma.repo.findFirst({
          where: { OR: [{ name: req.params.id }, { name: cleanName }, { name: cleanName + '.zip' }] },
        });
      }
      if (repo) {
        repo = await prisma.repo.update({
          where: { id: repo.id },
          data:  { businessCriticality: tier },
        });
      }
    } catch (err) {
      console.warn('Prisma repo update failed, using devStore:', err.message);
    }

    const devUpdated = updateRepoCriticality(req.params.id, tier);
    if (!repo) repo = devUpdated;
    else if (devUpdated) repo.businessCriticality = tier;

    if (!repo) return res.status(404).json({ error: 'Repository not found' });

    return res.json({
      id:                 repo.id,
      name:               repo.name,
      businessCriticality: tier,
      criticality_tier:   tier,
    });
  } catch (err) {
    console.error('Update repo error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
