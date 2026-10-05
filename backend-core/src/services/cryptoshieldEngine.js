'use strict';

/**
 * CryptoShield Policy & Blast Radius Engine
 * Handles cryptographic access control evaluations (ALLOW vs BLOCK),
 * security event creation, blast radius calculations, 6-step recovery recommendations,
 * CryptoTwin test recovery integrations, and human approval audit trails.
 */

const crypto = require('crypto');
const devStore = require('../utils/devStore');
const { startTwinRun } = require('./cryptotwinEngine');

/**
 * Evaluate Cryptographic Access Policy (Policy Engine)
 * IF application allowed AND operation allowed AND environment allowed → ALLOW
 * Otherwise → BLOCK and log security event
 */
async function simulateAccessRequest({ assetId, requestingApplication, requestedOperation, environment = 'production' }) {
  if (!assetId || !requestingApplication || !requestedOperation) {
    throw new Error('assetId, requestingApplication, and requestedOperation are required.');
  }

  const asset = devStore.getShieldAsset(assetId);
  if (!asset) {
    throw new Error(`Crypto Asset "${assetId}" not found in identity registry.`);
  }

  const policies = devStore.getShieldPolicies(assetId);
  const allowedServices = asset.allowedServices || [];

  let isAllowedApp = allowedServices.includes(requestingApplication);
  let isAllowedOp = false;
  let isAllowedEnv = asset.environment === environment;

  // Check policies
  const matchingPolicy = policies.find(p => p.allowedService === requestingApplication && p.status === 'ACTIVE');
  if (matchingPolicy) {
    isAllowedApp = true;
    if (Array.isArray(matchingPolicy.allowedOperations) && matchingPolicy.allowedOperations.includes(requestedOperation.toUpperCase())) {
      isAllowedOp = true;
    }
  } else if (isAllowedApp) {
    // Default allowed operations for recognized service if no explicit restricted policy
    isAllowedOp = true;
  }

  const decision = (isAllowedApp && isAllowedOp && isAllowedEnv) ? 'ALLOWED' : 'BLOCKED';
  const reason = decision === 'ALLOWED'
    ? `Access policy verified for "${requestingApplication}" (${requestedOperation} operation in ${environment}).`
    : `Unauthorized request: "${requestingApplication}" is not authorized for ${requestedOperation} operation on ${assetId} in ${environment}.`;

  const severity = decision === 'BLOCKED' ? (asset.criticality === 'CRITICAL' ? 'CRITICAL' : 'HIGH') : 'LOW';

  const eventObj = {
    eventId: `evt-shield-${Date.now()}-${Math.floor(Math.random()*1000)}`,
    timestamp: new Date().toISOString(),
    assetId,
    requestingApplication,
    requestedOperation: requestedOperation.toUpperCase(),
    environment,
    decision,
    reason,
    severity
  };

  devStore.saveShieldEvent(eventObj);

  // If blocked, elevate asset status to SUSPECTED_MISUSE
  if (decision === 'BLOCKED') {
    asset.status = 'SUSPECTED_MISUSE';
    devStore.saveShieldAsset(asset);
  }

  // Record Audit Trail
  devStore.addShieldAudit({
    action: 'ACCESS_CONTROL_EVALUATION',
    user: 'PolicyEngine',
    assetId,
    result: decision,
    details: `${requestingApplication} -> ${requestedOperation} on ${assetId} [${decision}]`
  });

  return {
    event: eventObj,
    asset
  };
}

/**
 * Compute Blast Radius and 6-Step Recommended Response
 */
function calculateBlastRadius(assetId) {
  const asset = devStore.getShieldAsset(assetId);
  if (!asset) {
    throw new Error(`Asset "${assetId}" not found.`);
  }

  const dependencyChains = {
    'Payment-Key-01': [
      'Payment-Key-01 (RSA-2048)',
      'Payment Service (Microservice)',
      'Payment API Gateway (Internal Router)',
      'Transaction Core Engine (Database/Billing)',
      'Customer Checkout Portal'
    ],
    'Authentication-Key-01': [
      'Authentication-Key-01 (ECDSA-P256)',
      'Authentication Service (OAuth Provider)',
      'User Session Gateway',
      'Customer Portal & Mobile App'
    ],
    'TLS-Certificate-01': [
      'TLS-Certificate-01 (ECDH-P256)',
      'Notification Service (Email/SMS Worker)',
      'Event Bus Relay',
      'Third-Party SMS Gateway'
    ],
    'API-Credential-01': [
      'API-Credential-01 (AES-256-GCM)',
      'Developer Tool (Internal CLI)',
      'Staging Environment Pipeline'
    ]
  };

  const blastRadiusChain = dependencyChains[assetId] || [
    `${assetId} (${asset.algorithm})`,
    `${asset.application} (Primary Owner)`,
    'Upstream Microservices API Gateway',
    'Core Database Storage'
  ];

  const recommendations = [
    '1. Investigate the requesting application identity and source IP.',
    '2. Verify if the access attempt is legitimate or an unapproved service deployment.',
    '3. Review the affected crypto asset authorization policies.',
    '4. Prepare a credential replacement/recovery plan in sandbox.',
    '5. Test the proposed recovery plan using CryptoTwin before applying.',
    '6. Require human approval before executing any production credential or policy change.'
  ];

  return {
    assetId,
    assetName: asset.assetId,
    algorithm: asset.algorithm,
    criticality: asset.criticality,
    status: asset.status,
    potentialBlastRadius: blastRadiusChain,
    recommendedResponse: recommendations
  };
}

/**
 * Execute Recovery Simulation using CryptoTwin integration
 */
async function testRecoveryInCryptoTwin(assetId, eventId = null) {
  const asset = devStore.getShieldAsset(assetId);
  if (!asset) {
    throw new Error(`Asset "${assetId}" not found.`);
  }

  // Trigger real CryptoTwin fire drill run safely
  const twinRun = await startTwinRun('pqc-test-fixture-multilang', null, 3);

  const planId = `plan-shield-${Date.now()}`;
  const recoveryPlan = {
    id: planId,
    assetId,
    eventId,
    issue: `Suspected misuse / unauthorized access attempt on ${assetId} (${asset.algorithm}).`,
    potentialImpact: `High risk of unauthorized data access across ${asset.application} dependency chain.`,
    recommendedAction: `Isolate unauthorized service, migrate classical ${asset.algorithm} to PQC hybrid replacement, and update access policy.`,
    cryptoTwinValidation: {
      runId: twinRun.id,
      verdict: twinRun.verdict,
      confidence: twinRun.migrationConfidence,
      testsRun: twinRun.testsRun,
      testsPassed: twinRun.testsPassed,
      criticalFailures: twinRun.remainingBlockers
    },
    approvalStatus: 'PENDING',
    createdAt: new Date().toISOString()
  };

  devStore.saveShieldPlan(recoveryPlan);

  devStore.addShieldAudit({
    action: 'TEST_RECOVERY_IN_CRYPTOTWIN',
    user: 'SecOps Analyst',
    assetId,
    result: 'SIMULATED',
    details: `Created Recovery Plan ${planId} with CryptoTwin Validation Run ID ${twinRun.id}.`
  });

  return recoveryPlan;
}

/**
 * Process Human Approval of Security Recovery Plan
 * NOTE: Approval changes NO real credentials or production keys.
 */
async function processPlanApproval(planId, action, reviewer = 'SecOps Lead', overrideReason = null) {
  const plan = devStore.getShieldPlan(planId);
  if (!plan) {
    throw new Error(`Recovery Plan "${planId}" not found.`);
  }

  const normalizedAction = action.toUpperCase();

  if (normalizedAction === 'APPROVE') {
    if (!plan.cryptoTwinValidation) {
      throw new Error('Approval blocked: Recovery Plan must be validated via CryptoTwin test recovery first.');
    }

    plan.approvalStatus = 'APPROVED';
    plan.approvedBy = reviewer;
    plan.approvedAt = new Date().toISOString();
    plan.overrideReason = overrideReason || null;

    // Reset asset status to PROTECTED post approval
    const asset = devStore.getShieldAsset(plan.assetId);
    if (asset) {
      asset.status = 'PROTECTED';
      devStore.saveShieldAsset(asset);
    }
  } else if (normalizedAction === 'DECLINE') {
    plan.approvalStatus = 'DECLINED';
    plan.approvedBy = reviewer;
    plan.approvedAt = new Date().toISOString();
  } else {
    throw new Error('Invalid approval action. Must be APPROVE or DECLINE.');
  }

  devStore.saveShieldPlan(plan);

  devStore.addShieldAudit({
    action: `HUMAN_APPROVAL_${normalizedAction}`,
    user: reviewer,
    assetId: plan.assetId,
    result: normalizedAction,
    details: `Recovery Plan ${planId} ${normalizedAction} by ${reviewer}. No real credentials modified.`
  });

  return plan;
}

module.exports = {
  simulateAccessRequest,
  calculateBlastRadius,
  testRecoveryInCryptoTwin,
  processPlanApproval
};
