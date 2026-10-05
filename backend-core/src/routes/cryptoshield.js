'use strict';

/**
 * CryptoShield REST API Routes
 * Authenticated API endpoints for crypto access control monitoring, policy management,
 * security event simulation, blast radius inspection, CryptoTwin recovery testing,
 * human approval workflows, and audit logging.
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const devStore = require('../utils/devStore');
const { simulateAccessRequest, calculateBlastRadius, testRecoveryInCryptoTwin, processPlanApproval } = require('../services/cryptoshieldEngine');

// Seed demo data (runs once on module load if store is empty)
require('../services/cryptoshieldStore');

// GET /api/cryptoshield/dashboard — Summary metrics
router.get('/dashboard', requireAuth, (req, res) => {
  try {
    const assets = devStore.getShieldAssets();
    const policies = devStore.getShieldPolicies();
    const events = devStore.getShieldEvents();

    const protectedCount = assets.filter(a => a.status === 'PROTECTED').length;
    const criticalCount = assets.filter(a => a.criticality === 'CRITICAL').length;
    const blockedCount = events.filter(e => e.decision === 'BLOCKED').length;
    const activePoliciesCount = policies.filter(p => p.status === 'ACTIVE').length;

    res.json({
      totalAssets: assets.length,
      protectedAssets: protectedCount,
      criticalAssets: criticalCount,
      unauthorizedAttempts: blockedCount,
      activePolicies: activePoliciesCount,
      systemStatus: blockedCount > 0 ? 'ATTENTION_REQUIRED' : 'ALL_SYSTEMS_PROTECTED'
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to load CryptoShield dashboard metrics' });
  }
});

// GET /api/cryptoshield/assets — List all crypto asset identities
router.get('/assets', requireAuth, (req, res) => {
  try {
    const assets = devStore.getShieldAssets();
    res.json(assets);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to list CryptoShield assets' });
  }
});

// GET /api/cryptoshield/assets/:assetId — Asset details
router.get('/assets/:assetId', requireAuth, (req, res) => {
  try {
    const { assetId } = req.params;
    const asset = devStore.getShieldAsset(assetId);
    if (!asset) {
      return res.status(404).json({ error: `Asset "${assetId}" not found.` });
    }
    res.json(asset);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to fetch asset details' });
  }
});

// GET /api/cryptoshield/policies — List policies
router.get('/policies', requireAuth, (req, res) => {
  try {
    const { assetId } = req.query;
    const policies = devStore.getShieldPolicies(assetId);
    res.json(policies);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to fetch access policies' });
  }
});

// POST /api/cryptoshield/policies — Create new access policy
router.post('/policies', requireAuth, (req, res) => {
  try {
    const { assetId, allowedService, allowedOperations, environment } = req.body || {};
    if (!assetId || !allowedService) {
      return res.status(400).json({ error: 'assetId and allowedService are required.' });
    }

    const policy = {
      id: `pol-${Date.now()}`,
      assetId,
      allowedService,
      allowedOperations: Array.isArray(allowedOperations) ? allowedOperations : ['SIGN', 'VERIFY'],
      environment: environment || 'production',
      status: 'ACTIVE',
      createdAt: new Date().toISOString()
    };

    devStore.saveShieldPolicy(policy);

    devStore.addShieldAudit({
      action: 'CREATE_ACCESS_POLICY',
      user: req.user?.email || 'SecOps Lead',
      assetId,
      result: 'SUCCESS',
      details: `Created policy for ${allowedService} on asset ${assetId}.`
    });

    res.status(201).json(policy);
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to create access policy' });
  }
});

// POST /api/cryptoshield/simulate-access — Access control simulation
router.post('/simulate-access', requireAuth, async (req, res) => {
  try {
    const { assetId, requestingApplication, requestedOperation, environment } = req.body || {};
    const result = await simulateAccessRequest({ assetId, requestingApplication, requestedOperation, environment });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to evaluate access request' });
  }
});

// GET /api/cryptoshield/events — List security events
router.get('/events', requireAuth, (req, res) => {
  try {
    const events = devStore.getShieldEvents();
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to fetch security events' });
  }
});

// GET /api/cryptoshield/alerts — Crypto-only alerts stream
router.get('/alerts', requireAuth, (req, res) => {
  try {
    const events = devStore.getShieldEvents();
    const alerts = events
      .filter(e => e.decision === 'BLOCKED')
      .map(e => ({
        alertId: `alt-${e.eventId}`,
        severity: e.severity,
        assetId: e.assetId,
        title: `Unauthorized ${e.requestedOperation} Attempt by ${e.requestingApplication}`,
        description: e.reason,
        timestamp: e.timestamp
      }));
    res.json(alerts);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to fetch alerts' });
  }
});

// GET /api/cryptoshield/blast-radius/:assetId — Blast radius & 6-step recommendation
router.get('/blast-radius/:assetId', requireAuth, (req, res) => {
  try {
    const { assetId } = req.params;
    const result = calculateBlastRadius(assetId);
    res.json(result);
  } catch (err) {
    res.status(404).json({ error: err.message || 'Failed to calculate blast radius' });
  }
});

// POST /api/cryptoshield/test-recovery — Test recovery in CryptoTwin
router.post('/test-recovery', requireAuth, async (req, res) => {
  try {
    const { assetId, eventId } = req.body || {};
    if (!assetId) {
      return res.status(400).json({ error: 'assetId is required' });
    }
    const plan = await testRecoveryInCryptoTwin(assetId, eventId);
    res.status(201).json(plan);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to execute test recovery in CryptoTwin' });
  }
});

// GET /api/cryptoshield/recovery-plans — List recovery plans
router.get('/recovery-plans', requireAuth, (req, res) => {
  try {
    const plans = devStore.getShieldPlans();
    res.json(plans);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to fetch recovery plans' });
  }
});

// POST /api/cryptoshield/recovery-plans/:planId/approve — Human approval workflow
router.post('/recovery-plans/:planId/approve', requireAuth, async (req, res) => {
  try {
    const { planId } = req.params;
    const { action, overrideReason } = req.body || {};
    if (!action) {
      return res.status(400).json({ error: 'Approval action (APPROVE or DECLINE) is required.' });
    }

    const reviewer = req.user?.email || 'SecOps Lead';
    const updatedPlan = await processPlanApproval(planId, action, reviewer, overrideReason);
    res.json(updatedPlan);
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to process plan approval' });
  }
});

// GET /api/cryptoshield/audit — Audit Trail entries
router.get('/audit', requireAuth, (req, res) => {
  try {
    const audits = devStore.getShieldAudits();
    res.json(audits);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to fetch audit log' });
  }
});

module.exports = router;
