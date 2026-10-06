'use strict';

/**
 * Recovery Scenario Route — CryptoTwin
 *
 * POST /api/cryptotwin/recovery-scenarios
 *   Create / register a recovery scenario from CryptoShield.
 *   Input validated strictly; unknown fields rejected; no secret values accepted.
 *
 * POST /api/cryptotwin/recovery-scenarios/:planId/decision
 *   Record a human approval/rejection decision.
 *   Executes NOTHING in production — records decision only.
 *
 * RULES:
 *  - Never log or store raw secret values. Only masked values / fingerprints.
 *  - Approval records a decision and audit event only.
 *  - Wording: "validated in sandbox on <timestamp>", never "secure/complete".
 */

const express = require('express');
const crypto  = require('crypto');
const { requireAuth } = require('../middleware/auth');
const { appendAuditLog } = require('../services/auditLog');

const router = express.Router();

const SCENARIO_FIELDS = new Set([
  'recoveryPlanId', 'assetId', 'assetType', 'fingerprint',
  'affectedServices', 'environment', 'trigger', 'sourceEventId', 'proposedAction',
]);

const DECISION_FIELDS = new Set([
  'recoveryPlanId', 'runId', 'status', 'confidence',
  'criticalFailures', 'decision', 'completedAt',
]);

const VALID_TRIGGERS    = new Set(['simulated', 'suspected', 'confirmed']);
const VALID_STATUSES    = new Set(['PASSED', 'FAILED', 'PARTIAL']);
const VALID_DECISIONS   = new Set(['approved', 'rejected', 'revise']);
const VALID_ASSET_TYPES = new Set([
  'api_key', 'tls_cert', 'jwt_secret', 'db_password',
  'signing_key', 'env_var', 'other',
]);

function rejectUnknown(body, allowed, res) {
  const unknown = Object.keys(body).filter(k => !allowed.has(k));
  if (unknown.length > 0) {
    res.status(400).json({ error: 'Unknown fields rejected', fields: unknown });
    return true;
  }
  return false;
}

function maskFingerprint(fp) {
  if (!fp || typeof fp !== 'string') return null;
  if (!/^[0-9a-fA-F]{4,16}$/.test(fp)) return null;
  return fp.slice(0, 8) + '\u2026';
}

// In-memory store (dev fallback; swap for Prisma in production)
const scenarioStore = new Map();

/* POST /api/cryptotwin/recovery-scenarios */
router.post('/', requireAuth, async (req, res) => {
  const body = req.body;
  if (!body || typeof body !== 'object') return res.status(400).json({ error: 'Request body required' });
  if (rejectUnknown(body, SCENARIO_FIELDS, res)) return;

  const { recoveryPlanId, assetId, assetType, fingerprint, trigger } = body;
  if (!recoveryPlanId || typeof recoveryPlanId !== 'string' || recoveryPlanId.length > 128)
    return res.status(400).json({ error: 'recoveryPlanId required (string, max 128)' });
  if (!assetId || typeof assetId !== 'string' || assetId.length > 128)
    return res.status(400).json({ error: 'assetId required (string, max 128)' });
  if (!assetType || !VALID_ASSET_TYPES.has(assetType))
    return res.status(400).json({ error: 'assetType invalid' });
  if (!trigger || !VALID_TRIGGERS.has(trigger))
    return res.status(400).json({ error: 'trigger must be simulated|suspected|confirmed' });

  const fp = maskFingerprint(fingerprint);
  if (fingerprint && !fp)
    return res.status(400).json({ error: 'fingerprint must be 4-16 hex chars (SHA-256 prefix). Never submit full secret values.' });

  const affectedServices = Array.isArray(body.affectedServices)
    ? body.affectedServices.filter(s => typeof s === 'string' && s.length <= 100).slice(0, 50) : [];
  const environment = ['sandbox','staging','production'].includes(body.environment) ? body.environment : 'sandbox';

  const scenario = {
    recoveryPlanId, assetId, assetType,
    fingerprint: fp,
    affectedServices, environment, trigger,
    sourceEventId: typeof body.sourceEventId === 'string' ? body.sourceEventId.slice(0,128) : null,
    proposedAction: typeof body.proposedAction === 'string' ? body.proposedAction.slice(0,64) : 'rotate_credential',
    status: 'PENDING',
    createdAt: new Date().toISOString(),
    createdBy: req.user?.id || null,
  };

  scenarioStore.set(recoveryPlanId, scenario);

  await appendAuditLog({
    userId: req.user?.id,
    action: 'RECOVERY_SCENARIO_CREATED',
    method: 'POST',
    path: '/api/cryptotwin/recovery-scenarios',
    statusCode: 201,
    requestHash: crypto.createHash('sha256').update(JSON.stringify({ recoveryPlanId, assetId, assetType, trigger })).digest('hex'),
  }).catch(() => {});

  return res.status(201).json({
    ok: true, recoveryPlanId, status: 'PENDING',
    message: 'Recovery scenario registered.',
    validationUrl: `/migration-plan.html?recoveryPlanId=${encodeURIComponent(recoveryPlanId)}&assetId=${encodeURIComponent(assetId)}&assetType=${encodeURIComponent(assetType)}&trigger=${encodeURIComponent(trigger)}`,
  });
});

/* POST /api/cryptotwin/recovery-scenarios/:planId/decision */
router.post('/:planId/decision', requireAuth, async (req, res) => {
  const { planId } = req.params;
  const body = req.body;
  if (!body || typeof body !== 'object') return res.status(400).json({ error: 'Request body required' });
  if (rejectUnknown(body, DECISION_FIELDS, res)) return;

  const { runId, status, confidence, criticalFailures, decision, completedAt } = body;
  if (!VALID_DECISIONS.has(decision)) return res.status(400).json({ error: 'decision must be approved|rejected|revise' });
  if (status && !VALID_STATUSES.has(status)) return res.status(400).json({ error: 'status must be PASSED|FAILED|PARTIAL' });
  if (confidence !== undefined && (typeof confidence !== 'number' || confidence < 0 || confidence > 100))
    return res.status(400).json({ error: 'confidence must be 0-100' });

  const scenario = scenarioStore.get(planId) || { recoveryPlanId: planId };
  const decisionRecord = {
    recoveryPlanId: planId,
    runId: typeof runId === 'string' ? runId : null,
    status: status || (decision === 'approved' ? 'PASSED' : 'FAILED'),
    confidence: typeof confidence === 'number' ? confidence : null,
    criticalFailures: typeof criticalFailures === 'number' ? criticalFailures : null,
    decision,
    decidedBy: req.user?.id || null,
    decidedAt: new Date().toISOString(),
    completedAt: completedAt || new Date().toISOString(),
    productionActionExecuted: false,
    note: 'Recovery plan decision recorded. Production action NOT EXECUTED.',
  };

  scenario.latestDecision = decisionRecord;
  scenario.status = decisionRecord.status;
  scenarioStore.set(planId, scenario);

  const auditMsg = decision === 'approved'
    ? 'Recovery plan approved, production action NOT EXECUTED'
    : decision === 'rejected' ? 'Recovery plan rejected by reviewer' : 'Revision requested by reviewer';

  await appendAuditLog({
    userId: req.user?.id,
    action: 'RECOVERY_SCENARIO_DECISION',
    method: 'POST',
    path: `/api/cryptotwin/recovery-scenarios/${planId}/decision`,
    statusCode: 200,
    requestHash: crypto.createHash('sha256').update(JSON.stringify({ planId, decision, status })).digest('hex'),
    note: auditMsg,
  }).catch(() => {});

  return res.status(200).json({
    ok: true, recoveryPlanId: planId, decision,
    status: decisionRecord.status, confidence: decisionRecord.confidence,
    productionActionExecuted: false,
    note: 'Production Action: NOT EXECUTED. Decision recorded in audit log.',
    decidedAt: decisionRecord.decidedAt,
  });
});

/* GET /api/cryptotwin/recovery-scenarios/:planId */
router.get('/:planId', requireAuth, (req, res) => {
  const { planId } = req.params;
  const scenario = scenarioStore.get(planId);
  if (!scenario) return res.status(404).json({ error: 'Recovery scenario not found', recoveryPlanId: planId });
  const { assetId, assetType, fingerprint, trigger, environment, affectedServices, status, createdAt, latestDecision } = scenario;
  return res.json({ recoveryPlanId: planId, assetId, assetType, fingerprint, trigger, environment, affectedServices, status, createdAt, latestDecision });
});

module.exports = router;
