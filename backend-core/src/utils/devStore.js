'use strict';

const fs = require('fs');
const path = require('path');

const STORE_FILE = path.join(__dirname, '../../uploads/devStore.json');

let storeData = {
  devRepos: [],
  devScans: [],
  devFindings: [],
  devAnchors: [],
  devRuns: []
};

function loadStore() {
  try {
    if (fs.existsSync(STORE_FILE)) {
      const data = fs.readFileSync(STORE_FILE, 'utf8');
      storeData = JSON.parse(data);
    }
  } catch (err) {
    console.error('Failed to load devStore:', err.message);
  }
}

function saveStore() {
  try {
    const dir = path.dirname(STORE_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(STORE_FILE, JSON.stringify(storeData, null, 2), 'utf8');
  } catch (err) {
    console.error('Failed to save devStore:', err.message);
  }
}

loadStore();

const devRepos = new Map(storeData.devRepos);
const devScans = new Map(storeData.devScans);
const devFindings = new Map(storeData.devFindings);
const devAnchors = new Map(storeData.devAnchors);
const devRuns = new Map(storeData.devRuns || []);

function syncStore() {
  storeData.devRepos = Array.from(devRepos.entries());
  storeData.devScans = Array.from(devScans.entries());
  storeData.devFindings = Array.from(devFindings.entries());
  storeData.devAnchors = Array.from(devAnchors.entries());
  storeData.devRuns = Array.from(devRuns.entries());
  saveStore();
}

function saveRepo(repo) {
  devRepos.set(repo.id, repo);
  syncStore();
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
    syncStore();
  } else {
    repo = {
      id: idOrName,
      name: idOrName,
      businessCriticality: tier,
      criticality_tier: tier,
    };
    devRepos.set(repo.id, repo);
    syncStore();
  }
  return repo;
}

function saveScan(scan) {
  devScans.set(scan.id, scan);
  syncStore();
  return scan;
}

function getScan(id) {
  return devScans.get(id);
}

function saveFindings(scanId, findings) {
  devFindings.set(scanId, findings);
  syncStore();
  return findings;
}

function getFindings(scanId) {
  return devFindings.get(scanId) || [];
}

function saveAnchor(scanId, anchor) {
  devAnchors.set(scanId, anchor);
  syncStore();
  return anchor;
}

function getAnchor(scanId) {
  return devAnchors.get(scanId);
}

function saveRun(run) {
  devRuns.set(run.id, run);
  syncStore();
  return run;
}

function getRun(runId) {
  return devRuns.get(runId);
}

function getRunsForScan(scanId) {
  const list = [];
  for (const r of devRuns.values()) {
    if (!scanId || r.scanId === scanId) {
      list.push(r);
    }
  }
  return list;
}

const devShieldAssets = new Map(storeData.devShieldAssets || []);
const devShieldPolicies = new Map(storeData.devShieldPolicies || []);
const devShieldEvents = new Map(storeData.devShieldEvents || []);
const devShieldPlans = new Map(storeData.devShieldPlans || []);
const devShieldAudits = storeData.devShieldAudits || [];

function syncShieldStore() {
  storeData.devShieldAssets = Array.from(devShieldAssets.entries());
  storeData.devShieldPolicies = Array.from(devShieldPolicies.entries());
  storeData.devShieldEvents = Array.from(devShieldEvents.entries());
  storeData.devShieldPlans = Array.from(devShieldPlans.entries());
  storeData.devShieldAudits = devShieldAudits;
  saveStore();
}

function saveShieldAsset(asset) {
  devShieldAssets.set(asset.assetId, asset);
  syncShieldStore();
  return asset;
}

function getShieldAsset(assetId) {
  return devShieldAssets.get(assetId);
}

function getShieldAssets() {
  return Array.from(devShieldAssets.values());
}

function saveShieldPolicy(policy) {
  devShieldPolicies.set(policy.id, policy);
  syncShieldStore();
  return policy;
}

function getShieldPolicies(assetId) {
  const list = Array.from(devShieldPolicies.values());
  return assetId ? list.filter(p => p.assetId === assetId) : list;
}

function saveShieldEvent(event) {
  devShieldEvents.set(event.eventId, event);
  syncShieldStore();
  return event;
}

function getShieldEvents() {
  return Array.from(devShieldEvents.values()).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

function saveShieldPlan(plan) {
  devShieldPlans.set(plan.id, plan);
  syncShieldStore();
  return plan;
}

function getShieldPlan(planId) {
  return devShieldPlans.get(planId);
}

function getShieldPlans() {
  return Array.from(devShieldPlans.values());
}

function addShieldAudit(audit) {
  const item = {
    id: `audit-${Date.now()}-${Math.floor(Math.random()*1000)}`,
    timestamp: new Date().toISOString(),
    ...audit
  };
  devShieldAudits.unshift(item);
  syncShieldStore();
  return item;
}

function getShieldAudits() {
  return devShieldAudits;
}

module.exports = {
  devRepos,
  devScans,
  devFindings,
  devAnchors,
  devRuns,
  devShieldAssets,
  devShieldPolicies,
  devShieldEvents,
  devShieldPlans,
  devShieldAudits,
  saveRepo,
  getRepo,
  updateRepoCriticality,
  saveScan,
  getScan,
  saveFindings,
  getFindings,
  saveAnchor,
  getAnchor,
  saveRun,
  getRun,
  getRunsForScan,
  saveShieldAsset,
  getShieldAsset,
  getShieldAssets,
  saveShieldPolicy,
  getShieldPolicies,
  saveShieldEvent,
  getShieldEvents,
  saveShieldPlan,
  getShieldPlan,
  getShieldPlans,
  addShieldAudit,
  getShieldAudits
};
