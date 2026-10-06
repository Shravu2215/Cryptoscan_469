'use strict';

const assert = require('node:assert/strict');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

// Ensure JWT_SECRET for test
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret-for-recovery-scenarios-32b';

const recoveryScenarioRoutes = require('../src/routes/recoveryScenario');

async function main() {
  console.log('Running Recovery Scenario Test Suite...');

  const app = express();
  app.use(express.json());
  app.use(cookieParser());
  app.use('/api/cryptotwin/recovery-scenarios', recoveryScenarioRoutes);

  const server = app.listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}/api/cryptotwin/recovery-scenarios`;

  const validToken = jwt.sign({ id: 'user-sec-001', email: 'secops@example.com' }, process.env.JWT_SECRET);
  const authHeaders = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${validToken}`,
  };

  try {
    // 1. Unauthenticated request rejected
    {
      const res = await fetch(base, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recoveryPlanId: 'rec-test-01',
          assetId: 'AWS_ACCESS_KEY',
          assetType: 'api_key',
          trigger: 'suspected',
        }),
      });
      assert.strictEqual(res.status, 401, 'Unauthenticated POST must be rejected with 401');
      console.log('✓ Test 1: Unauthenticated request rejected with 401');
    }

    // 2. Reject unknown fields (strict schema validation)
    {
      const res = await fetch(base, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          recoveryPlanId: 'rec-test-02',
          assetId: 'STRIPE_SECRET',
          assetType: 'api_key',
          trigger: 'simulated',
          rawSecretValue: 'sk_live_1234567890abcdef', // FORBIDDEN FIELD
        }),
      });
      assert.strictEqual(res.status, 400, 'Unknown fields must be rejected with 400');
      const data = await res.json();
      assert.strictEqual(data.error, 'Unknown fields rejected');
      assert(data.fields.includes('rawSecretValue'));
      console.log('✓ Test 2: Unknown/forbidden fields strictly rejected');
    }

    // 3. Reject invalid/raw secret as fingerprint (must be 4-16 hex chars)
    {
      const res = await fetch(base, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          recoveryPlanId: 'rec-test-03',
          assetId: 'DB_PASSWORD',
          assetType: 'db_password',
          trigger: 'confirmed',
          fingerprint: 'mySuperSecretPassword123!', // NOT hex
        }),
      });
      assert.strictEqual(res.status, 400, 'Non-hex fingerprint must be rejected');
      const data = await res.json();
      assert(data.error.includes('fingerprint must be 4-16 hex chars'));
      console.log('✓ Test 3: Raw secrets as fingerprint rejected');
    }

    // 4. Valid scenario creation with masked fingerprint
    {
      const res = await fetch(base, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          recoveryPlanId: 'rec-test-04',
          assetId: 'PAYMENT_SIGNING_KEY',
          assetType: 'signing_key',
          trigger: 'confirmed',
          fingerprint: 'a1b2c3d4e5f6',
          environment: 'sandbox',
          affectedServices: ['checkout-api', 'billing-worker'],
          proposedAction: 'rotate_and_reissue',
        }),
      });
      assert.strictEqual(res.status, 201, 'Valid creation returns 201');
      const data = await res.json();
      assert.strictEqual(data.ok, true);
      assert.strictEqual(data.recoveryPlanId, 'rec-test-04');
      assert.strictEqual(data.status, 'PENDING');
      assert(data.validationUrl.includes('recoveryPlanId=rec-test-04'));
      console.log('✓ Test 4: Valid scenario created with masked fingerprint');
    }

    // 5. GET scenario status
    {
      const res = await fetch(`${base}/rec-test-04`, {
        headers: authHeaders,
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.recoveryPlanId, 'rec-test-04');
      assert.strictEqual(data.assetId, 'PAYMENT_SIGNING_KEY');
      assert.strictEqual(data.fingerprint, 'a1b2c3d4…'); // Masked with ellipsis
      assert.strictEqual(data.trigger, 'confirmed');
      assert.deepStrictEqual(data.affectedServices, ['checkout-api', 'billing-worker']);
      console.log('✓ Test 5: GET scenario returns masked fingerprint and correct metadata');
    }

    // 6. Decision endpoint validation: rejects unknown fields
    {
      const res = await fetch(`${base}/rec-test-04/decision`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          decision: 'approved',
          executeInProductionNow: true, // FORBIDDEN
        }),
      });
      assert.strictEqual(res.status, 400);
      const data = await res.json();
      assert.strictEqual(data.error, 'Unknown fields rejected');
      console.log('✓ Test 6: Decision rejects forbidden fields');
    }

    // 7. Decision endpoint: records approval with productionActionExecuted: false
    {
      const res = await fetch(`${base}/rec-test-04/decision`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          recoveryPlanId: 'rec-test-04',
          runId: 'run-rec-987',
          status: 'PASSED',
          confidence: 100,
          criticalFailures: 0,
          decision: 'approved',
        }),
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.ok, true);
      assert.strictEqual(data.decision, 'approved');
      assert.strictEqual(data.productionActionExecuted, false, 'productionActionExecuted must be FALSE');
      assert(data.note.includes('Production Action: NOT EXECUTED'));
      console.log('✓ Test 7: Approval recorded with productionActionExecuted: false');
    }

    // 8. Rejection decision
    {
      const res = await fetch(`${base}/rec-test-04/decision`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          recoveryPlanId: 'rec-test-04',
          status: 'FAILED',
          confidence: 50,
          criticalFailures: 1,
          decision: 'rejected',
        }),
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.decision, 'rejected');
      assert.strictEqual(data.status, 'FAILED');
      assert.strictEqual(data.productionActionExecuted, false);
      console.log('✓ Test 8: Rejection recorded correctly');
    }

    console.log('\nAll Recovery Scenario route tests passed successfully!');
  } finally {
    await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
  }
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
