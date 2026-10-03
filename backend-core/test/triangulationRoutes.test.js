'use strict';

const assert = require('assert');
const express = require('express');
const http = require('http');
const triangulationRoutes = require('../src/routes/triangulation');
const networkRoutes = require('../src/routes/network');
const { prisma } = require('../src/services/triangulationStorage');

const app = express();
app.use(express.json());
app.use('/api/triangulation', triangulationRoutes);
app.use('/api/network', networkRoutes);

function makeRequest(appInstance, method, path, body = null) {
  return new Promise((resolve, reject) => {
    const server = appInstance.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const options = {
        hostname: '127.0.0.1',
        port: port,
        path: path,
        method: method,
        headers: {
          'Content-Type': 'application/json',
        },
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          server.close();
          try {
            const parsed = JSON.parse(data);
            resolve({ statusCode: res.statusCode, body: parsed });
          } catch (e) {
            resolve({ statusCode: res.statusCode, rawBody: data });
          }
        });
      });

      req.on('error', (err) => {
        server.close();
        reject(err);
      });

      if (body) {
        req.write(JSON.stringify(body));
      }
      req.end();
    });
  });
}

async function runTriangulationRouteTests() {
  console.log('[Test] Starting Triangulation & Network Express route integration tests...');

  try {
    const testScanId = 'scan-tri-test-' + Date.now();

    // 1. POST /api/triangulation/run invalid (missing scanId)
    const invalidRun1 = await makeRequest(app, 'POST', '/api/triangulation/run', { results: [] });
    assert.strictEqual(invalidRun1.statusCode, 400);
    assert(invalidRun1.body.error.includes('scanId is required'));
    console.log('✔ POST /api/triangulation/run (missing scanId) passed');

    // 2. POST /api/triangulation/run invalid (missing results array)
    const invalidRun2 = await makeRequest(app, 'POST', '/api/triangulation/run', { scanId: testScanId });
    assert.strictEqual(invalidRun2.statusCode, 400);
    assert(invalidRun2.body.error.includes('results array is required'));
    console.log('✔ POST /api/triangulation/run (missing results array) passed');

    // 3. POST /api/triangulation/run valid
    const validTriPayload = {
      scanId: testScanId,
      results: [
        {
          algorithm: 'AES-256',
          classification: 'Confirmed Active',
          location: 'demo_crypto_app.py:38:aes_encrypt',
          confidence: 'high',
          quantumVulnerable: false,
          evidenceCount: { static: 1, runtime: 1, network: 0 }
        },
        {
          algorithm: 'MD5',
          classification: 'Static Only',
          location: 'demo_crypto_app.py:65:legacy_weak_crypto',
          confidence: 'medium',
          quantumVulnerable: false,
          evidenceCount: { static: 1, runtime: 0, network: 0 }
        }
      ]
    };
    const validRunRes = await makeRequest(app, 'POST', '/api/triangulation/run', validTriPayload);
    assert.strictEqual(validRunRes.statusCode, 201);
    assert.strictEqual(validRunRes.body.resultCount, 2);
    console.log('✔ POST /api/triangulation/run (valid) passed');

    // 4. GET /api/triangulation/metrics
    const metricsRes = await makeRequest(app, 'GET', '/api/triangulation/metrics');
    assert.strictEqual(metricsRes.statusCode, 200);
    assert.strictEqual(metricsRes.body.metrics.totalGroundTruthSamples, 9);
    assert.strictEqual(metricsRes.body.metrics.correctClassifications, 8);
    console.log('✔ GET /api/triangulation/metrics passed');

    // 5. GET /api/triangulation/:scanId
    const getTriRes = await makeRequest(app, 'GET', `/api/triangulation/${testScanId}`);
    assert.strictEqual(getTriRes.statusCode, 200);
    assert.strictEqual(getTriRes.body.count, 2);
    console.log('✔ GET /api/triangulation/:scanId passed');

    // 6. GET /api/triangulation/:scanId/summary
    const summaryRes = await makeRequest(app, 'GET', `/api/triangulation/${testScanId}/summary`);
    assert.strictEqual(summaryRes.statusCode, 200);
    assert.strictEqual(summaryRes.body.summary.totalFindings, 2);
    assert.strictEqual(summaryRes.body.summary.counts['Confirmed Active'], 1);
    assert.strictEqual(summaryRes.body.summary.counts['Static Only'], 1);
    console.log('✔ GET /api/triangulation/:scanId/summary passed');

    // 7. POST /api/network/captures invalid (empty observations)
    const invalidCapRes = await makeRequest(app, 'POST', '/api/network/captures', { scanId: testScanId, observations: [] });
    assert.strictEqual(invalidCapRes.statusCode, 400);
    assert(invalidCapRes.body.error.includes('observations'));
    console.log('✔ POST /api/network/captures (empty observations rejection) passed');

    // 8. POST /api/network/captures valid
    const validCapPayload = {
      scanId: testScanId,
      source: 'json',
      fileName: 'test_cap.json',
      observations: [
        {
          algorithm: 'DH',
          server_name: 'legacy-auth.crypto.internal',
          port: 8443,
          tls_version: 'TLSv1.2'
        }
      ]
    };
    const validCapRes = await makeRequest(app, 'POST', '/api/network/captures', validCapPayload);
    assert.strictEqual(validCapRes.statusCode, 201);
    assert.strictEqual(validCapRes.body.capture.scanId, testScanId);
    console.log('✔ POST /api/network/captures (valid) passed');

    // 9. GET /api/network/captures
    const getCapRes = await makeRequest(app, 'GET', `/api/network/captures?scanId=${testScanId}`);
    assert.strictEqual(getCapRes.statusCode, 200);
    assert.strictEqual(getCapRes.body.captures.length, 1);
    console.log('✔ GET /api/network/captures passed');

    console.log('ALL Triangulation & Network API route tests passed successfully!');
  } finally {
    if (prisma) {
      await prisma.$disconnect();
    }
  }
}

runTriangulationRouteTests().catch((err) => {
  console.error('Triangulation Route Test failed:', err);
  process.exit(1);
});
