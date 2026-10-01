'use strict';

const prisma = require('./prismaClient');
const devStore = require('./devStore');

const ELEVATED_ROLES = Object.freeze(['Admin', 'Security Team', 'Auditor']);

function isElevated(role) {
  return ELEVATED_ROLES.includes(role);
}

function repoOwnerFilter(userId, role) {
  return isElevated(role) ? {} : { uploadedBy: userId };
}

function canAccessRepo(userId, role, repo) {
  return Boolean(repo && (isElevated(role) || repo.uploadedBy === userId));
}

function getOwnedDevRepo(userId, idOrName, role) {
  const direct = devStore.devRepos.get(idOrName);
  if (canAccessRepo(userId, role, direct)) return direct;

  const cleanValue = String(idOrName || '').replace(/\.zip$/i, '').toLowerCase();
  for (const repo of devStore.devRepos.values()) {
    const cleanId = String(repo.id || '').replace(/\.zip$/i, '').toLowerCase();
    const cleanName = String(repo.name || '').replace(/\.zip$/i, '').toLowerCase();
    if ((repo.id === idOrName || repo.name === idOrName || cleanId === cleanValue || cleanName === cleanValue)
      && canAccessRepo(userId, role, repo)) {
      return repo;
    }
  }
  return null;
}

async function getOwnedRepo(userId, id, role) {
  try {
    const repo = await prisma.repo.findFirst({
      where: { id, ...repoOwnerFilter(userId, role) },
    });
    if (repo) return repo;
  } catch (_) {}
  return getOwnedDevRepo(userId, id, role);
}

async function getOwnedRepoByName(userId, names, role) {
  const candidates = [...new Set((Array.isArray(names) ? names : [names]).filter(Boolean))];
  if (candidates.length === 0) return null;

  try {
    const repo = await prisma.repo.findFirst({
      where: {
        OR: candidates.map(name => ({ name })),
        ...repoOwnerFilter(userId, role),
      },
    });
    if (repo) return repo;
  } catch (_) {}

  for (const name of candidates) {
    const repo = getOwnedDevRepo(userId, name, role);
    if (repo) return repo;
  }
  return null;
}

async function getOwnedRepos(userId, role) {
  try {
    return await prisma.repo.findMany({
      where: repoOwnerFilter(userId, role),
      orderBy: { createdAt: 'desc' },
    });
  } catch (_) {
    return Array.from(devStore.devRepos.values()).filter(repo => canAccessRepo(userId, role, repo));
  }
}

async function getOwnedScan(userId, id, role) {
  const where = { id };
  if (!isElevated(role)) where.repo = { uploadedBy: userId };

  try {
    const scan = await prisma.scan.findFirst({ where, include: { repo: true } });
    if (scan) return scan;
  } catch (_) {}

  const scan = devStore.getScan(id);
  if (!scan) return null;
  const repo = await getOwnedRepo(userId, scan.repoId, role);
  return repo ? { ...scan, repo } : null;
}

async function getOwnedFinding(userId, id, role) {
  const where = { id };
  if (!isElevated(role)) where.scan = { repo: { uploadedBy: userId } };

  try {
    const finding = await prisma.finding.findFirst({ where, include: { scan: { include: { repo: true } } } });
    if (finding) return finding;
  } catch (_) {}

  for (const [scanId, findings] of devStore.devFindings.entries()) {
    const finding = findings.find(item => String(item.id) === String(id));
    if (!finding) continue;
    const scan = await getOwnedScan(userId, scanId, role);
    if (scan) return { ...finding, scan };
  }
  return null;
}

function updateOwnedDevRepoCriticality(userId, id, tier, role) {
  const repo = getOwnedDevRepo(userId, id, role);
  if (!repo) return null;

  repo.businessCriticality = tier;
  repo.criticality_tier = tier;
  devStore.devRepos.set(repo.id, repo);
  for (const scan of devStore.devScans.values()) {
    if (scan.repoId === repo.id || scan.repoName === repo.name) {
      scan.businessCriticality = tier;
      scan.criticality_tier = tier;
    }
  }
  return repo;
}

// TODO(P1): Replace role checks with can(user, action, resource).
module.exports = {
  ELEVATED_ROLES,
  canAccessRepo,
  getOwnedRepo,
  getOwnedRepoByName,
  getOwnedRepos,
  getOwnedScan,
  getOwnedFinding,
  updateOwnedDevRepoCriticality,
};