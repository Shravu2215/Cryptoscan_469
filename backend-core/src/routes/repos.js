const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const AdmZip = require('adm-zip');
const { requireAuth } = require('../middleware/auth');
const prisma = require('../utils/prismaClient');
const {
  getOwnedRepo,
  getOwnedRepoByName,
  getOwnedRepos,
  updateOwnedDevRepoCriticality,
} = require('../utils/ownership');
const { isDev, logStructuredError, sendError, serviceUnavailable } = require('../utils/failClosed');

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, '../../uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `${unique}-${file.originalname}`);
  },
});

const maxSizeMb = Number(process.env.MAX_UPLOAD_SIZE_MB || 50);
const maxExtractedMb = Number(process.env.MAX_EXTRACTED_SIZE_MB || 250);

function parseGitHubUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }

  if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== 'github.com') {
    return null;
  }

  const parts = parsed.pathname.split('/').filter(Boolean);
  if (parts.length !== 2) return null;

  const owner = parts[0];
  let repo = parts[1].trim().replace(/\.git?$/i, '').replace(/\.+$/, '');
  if (!/^[A-Za-z0-9_.-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(repo)) {
    return null;
  }

  return { owner, repo };
}

function extractArchive(buffer, destination) {
  const archive = new AdmZip(buffer);
  const entries = archive.getEntries();
  if (entries.length > 10000) throw new Error('Repository archive contains too many files');

  const destinationRoot = path.resolve(destination) + path.sep;
  let extractedBytes = 0;
  for (const entry of entries) {
    const target = path.resolve(destination, entry.entryName);
    if (!target.startsWith(destinationRoot)) {
      throw new Error('Repository archive contains an unsafe path');
    }
    if (!entry.isDirectory) {
      extractedBytes += entry.header.size;
      if (extractedBytes > maxExtractedMb * 1024 * 1024) {
        throw new Error(`Repository archive exceeds the ${maxExtractedMb} MB extracted-size limit`);
      }
    }
  }

  archive.extractAllTo(destination, true);
  const children = fs.readdirSync(destination, { withFileTypes: true });
  const root = children.length === 1 && children[0].isDirectory()
    ? path.join(destination, children[0].name)
    : destination;
  return root;
}

const upload = multer({
  storage,
  limits: { fileSize: maxSizeMb * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    // Accept zip uploads of repos. Extend this list if scanner needs more.
    const allowed = ['.zip'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowed.includes(ext)) {
      return cb(new Error(`Only ${allowed.join(', ')} files are allowed`));
    }
    cb(null, true);
  },
});

// POST /repos/github
// Imports a public GitHub repository archive without executing repository code.
router.post('/github', requireAuth, async (req, res) => {
  let extractDir;
  try {
    const github = parseGitHubUrl(req.body?.url);
    if (!github) {
      return res.status(400).json({ error: 'Use a public GitHub repository URL such as https://github.com/owner/repository' });
    }

    const headers = { 'User-Agent': 'CryptoScan/1.0', Accept: 'application/vnd.github+json' };
    const metadataResponse = await fetch(`https://api.github.com/repos/${github.owner}/${github.repo}`, { headers });
    if (!metadataResponse.ok) {
      return res.status(metadataResponse.status === 404 ? 404 : 502).json({ error: 'GitHub repository could not be found or accessed' });
    }
    const metadata = await metadataResponse.json();
    if (metadata.archived) {
      return res.status(400).json({ error: 'Archived GitHub repositories cannot be scanned' });
    }

    const branch = encodeURIComponent(metadata.default_branch || 'main');
    const archiveUrl = `https://codeload.github.com/${github.owner}/${github.repo}/zip/refs/heads/${branch}`;
    const archiveResponse = await fetch(archiveUrl, { headers });
    if (!archiveResponse.ok) {
      return res.status(502).json({ error: 'GitHub repository archive could not be downloaded' });
    }
    const contentLength = Number(archiveResponse.headers.get('content-length') || 0);
    if (contentLength > maxSizeMb * 1024 * 1024) {
      return res.status(413).json({ error: `Repository archive exceeds the ${maxSizeMb} MB download limit` });
    }

    const archiveBuffer = Buffer.from(await archiveResponse.arrayBuffer());
    if (archiveBuffer.length > maxSizeMb * 1024 * 1024) {
      return res.status(413).json({ error: `Repository archive exceeds the ${maxSizeMb} MB download limit` });
    }

    extractDir = fs.mkdtempSync(path.join(UPLOAD_DIR, 'github-'));
    const repositoryPath = extractArchive(archiveBuffer, extractDir);
    let repo;
    try {
      repo = await prisma.repo.create({
        data: {
          name: metadata.full_name || `${github.owner}/${github.repo}`,
          filePath: repositoryPath,
          uploadedBy: req.user.id,
          businessCriticality: req.body.businessCriticality || 'Not tagged',
        },
      });
    } catch (dbErr) {
      if (!isDev) throw serviceUnavailable('repo.github_import_persist_failed', dbErr);
      logStructuredError('repo.github_import_persist_failed', dbErr, {}, 'warning');
      repo = {
        id: 'repo-dev-' + Date.now(),
        name: metadata.full_name || `${github.owner}/${github.repo}`,
        filePath: repositoryPath,
        uploadedBy: req.user.id,
        businessCriticality: req.body.businessCriticality || 'Not tagged',
        createdAt: new Date()
      };
    }
    if (isDev) require('../utils/devStore').saveRepo(repo);

    return res.status(201).json({
      id: repo.id,
      name: repo.name,
      createdAt: repo.createdAt,
      businessCriticality: repo.businessCriticality || 'Not tagged',
      source: 'github',
    });
  } catch (err) {
    if (extractDir) fs.rmSync(extractDir, { recursive: true, force: true });
    if (err?.status === 503) return sendError(res, err, 'repo.github_import_failed');
    logStructuredError('repo.github_import_failed', err);
    return res.status(502).json({ error: err.message || 'GitHub repository import failed' });
  }
});

// POST /repos/upload
router.post('/upload', requireAuth, upload.single('repo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded (field name must be "repo")' });
    }

    let repo;
    try {
      repo = await prisma.repo.create({
        data: {
          name: req.body.name || req.file.originalname,
          filePath: req.file.path,
          uploadedBy: req.user.id,
          businessCriticality: req.body.businessCriticality || 'Not tagged',
        },
      });
    } catch (dbErr) {
      if (!isDev) throw serviceUnavailable('repo.upload_persist_failed', dbErr);
      logStructuredError('repo.upload_persist_failed', dbErr, {}, 'warning');
      repo = {
        id: 'repo-dev-' + Date.now(),
        name: req.body.name || req.file.originalname,
        filePath: req.file.path,
        uploadedBy: req.user.id,
        businessCriticality: req.body.businessCriticality || 'Not tagged',
        createdAt: new Date()
      };
    }
    if (isDev) require('../utils/devStore').saveRepo(repo);

    return res.status(201).json({
      id: repo.id,
      name: repo.name,
      createdAt: repo.createdAt,
      businessCriticality: repo.businessCriticality || 'Not tagged',
    });
  } catch (err) {
    if (req.file?.path && fs.existsSync(req.file.path)) fs.rmSync(req.file.path, { force: true });
    return sendError(res, err, 'repo.upload_failed');
  }
});

const VALID_CRITICALITY_TIERS = new Set(['Critical', 'Important', 'Standard', 'Low', 'Not tagged']);

function normalizeCriticality(tier) {
  if (!tier) return 'Not tagged';
  const u = String(tier).trim().toUpperCase();
  if (u === 'CRITICAL' || u === 'TIER 1') return 'Critical';
  if (u === 'IMPORTANT' || u === 'HIGH' || u === 'TIER 2') return 'Important';
  if (u === 'STANDARD' || u === 'MEDIUM' || u === 'TIER 3') return 'Standard';
  if (u === 'LOW' || u === 'TIER 4') return 'Low';
  if (u === 'NOT TAGGED' || u === 'NOT_TAGGED' || u === 'NONE' || u === 'UNKNOWN' || u === '') return 'Not tagged';
  return null;
}

// GET /repos - list repositories
router.get('/', requireAuth, async (req, res) => {
  try {
    const repos = await getOwnedRepos(req.user.id, req.user.role);
    const enriched = repos.map(r => ({
      ...r,
      criticality_tier: normalizeCriticality(r.businessCriticality) || 'Not tagged',
    }));
    return res.json(enriched);
  } catch (err) {
    return sendError(res, err, 'repo.list_failed');
  }
});

// GET /repos/:id - get single repository
router.get('/:id', requireAuth, async (req, res) => {
  try {
    const repo = await getOwnedRepo(req.user.id, req.params.id, req.user.role)
      || await getOwnedRepoByName(req.user.id, req.params.id, req.user.role);
    if (!repo) return res.status(404).json({ error: 'Repository not found' });
    const crit = normalizeCriticality(repo.businessCriticality || repo.criticality_tier) || 'Not tagged';
    return res.json({
      ...repo,
      businessCriticality: crit,
      criticality_tier: crit,
    });
  } catch (err) {
    return sendError(res, err, 'repo.get_failed');
  }
});

// PATCH /repos/:id - update businessCriticality / criticality_tier
router.patch('/:id', requireAuth, async (req, res) => {
  try {
    const rawTier = req.body.criticality_tier || req.body.businessCriticality;
    if (!rawTier) {
      return res.status(400).json({ error: 'criticality_tier or businessCriticality is required' });
    }
    const tier = normalizeCriticality(rawTier);
    if (!tier || !VALID_CRITICALITY_TIERS.has(tier)) {
      return res.status(400).json({ 
        error: 'Invalid criticality tier. Accepted tiers: Critical, Important, Standard, Low, Not tagged' 
      });
    }
    const cleanName = req.params.id.replace(/\.zip$/i, '');
    const repo = await getOwnedRepo(req.user.id, req.params.id, req.user.role)
      || await getOwnedRepoByName(
        req.user.id,
        [req.params.id, cleanName, cleanName + '.zip'],
        req.user.role,
      );
    if (!repo) return res.status(404).json({ error: 'Repository not found' });

    let updatedRepo;
    if (isDev && require('../utils/devStore').devRepos.has(repo.id)) {
      updatedRepo = updateOwnedDevRepoCriticality(req.user.id, repo.id, tier, req.user.role);
    } else {
      try {
        updatedRepo = await prisma.repo.update({
          where: { id: repo.id },
          data: { businessCriticality: tier },
        });
      } catch (err) {
        if (!isDev) throw serviceUnavailable('repo.update_failed', err, { repoId: repo.id });
        logStructuredError('repo.update_failed', err, { repoId: repo.id }, 'warning');
        const devStore = require('../utils/devStore');
        devStore.saveRepo(repo);
        updatedRepo = updateOwnedDevRepoCriticality(req.user.id, repo.id, tier, req.user.role);
      }
    }

    if (!updatedRepo) return res.status(404).json({ error: 'Repository not found' });

    return res.json({
      id: updatedRepo.id,
      name: updatedRepo.name,
      businessCriticality: tier,
      criticality_tier: tier,
    });
  } catch (err) {
    return sendError(res, err, 'repo.update_failed');
  }
});

module.exports = router;
