'use strict';

const devRepos = new Map();
const devScans = new Map();
const devFindings = new Map();
const devAnchors = new Map();

function saveRepo(repo) {
  devRepos.set(repo.id, repo);
  return repo;
}

function getRepo(idOrName) {
  if (!idOrName) return undefined;
  if (devRepos.has(idOrName)) return devRepos.get(idOrName);
  const cleanId = String(idOrName).replace(/\.zip$/i, '').toLowerCase();
  for (const r of devRepos.values()) {
    if (r.id === idOrName || r.name === idOrName) return r;
    const rIdClean = String(r.id || '').replace(/\.zip$/i, '').toLowerCase();
    const rNameClean = String(r.name || '').replace(/\.zip$/i, '').toLowerCase();
    if (rIdClean === cleanId || rNameClean === cleanId) return r;
  }
  return undefined;
}

function updateRepoCriticality(idOrName, tier) {
  let repo = getRepo(idOrName);
  const cleanId = String(idOrName).replace(/\.zip$/i, '').toLowerCase();
  if (repo) {
    repo.businessCriticality = tier;
    repo.criticality_tier = tier;
    devRepos.set(repo.id, repo);
    for (const scan of devScans.values()) {
      const sRepoId = String(scan.repoId || '').replace(/\.zip$/i, '').toLowerCase();
      const sRepoName = String(scan.repoName || scan.name || '').replace(/\.zip$/i, '').toLowerCase();
      if (scan.repoId === repo.id || scan.repoName === repo.name || sRepoId === cleanId || sRepoName === cleanId) {
        scan.businessCriticality = tier;
        scan.criticality_tier = tier;
      }
    }
  } else {
    repo = {
      id: idOrName,
      name: idOrName,
      businessCriticality: tier,
      criticality_tier: tier,
    };
    devRepos.set(repo.id, repo);
  }
  return repo;
}

function saveScan(scan) {
  devScans.set(scan.id, scan);
  return scan;
}

function getScan(id) {
  return devScans.get(id);
}

function saveFindings(scanId, findings) {
  devFindings.set(scanId, findings);
  return findings;
}

function getFindings(scanId) {
  return devFindings.get(scanId) || [];
}

function saveAnchor(scanId, anchor) {
  devAnchors.set(scanId, anchor);
  return anchor;
}

function getAnchor(scanId) {
  return devAnchors.get(scanId);
}

module.exports = {
  devRepos,
  devScans,
  devFindings,
  devAnchors,
  saveRepo,
  getRepo,
  updateRepoCriticality,
  saveScan,
  getScan,
  saveFindings,
  getFindings,
  saveAnchor,
  getAnchor,
};
