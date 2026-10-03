'use strict';

const assert = require('assert');
const express = require('express');
const runtimeRoutes = require('../src/routes/runtime');
const { prisma } = require('../src/services/runtimeStorage');

const app = express();
app.use(express.json());
app.use('/api/runtime', runtimeRoutes);

// Helper for making supertest-style HTTP requests using fetch or http
const http = require('http');

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

async function runRouteTests() {
  console.log('[Test] Starting runtime Express route integration tests...');

  try {
    // 1. Test POST /api/runtime/runs with valid payload
    const validRunId = 'run-api-test-' + Date.now();
    const validPayload = {
      run_id: validRunId,
      language: 'python',
      command: 'python app.py',
      environment: 'test',
      events: [
        {
          event_id: 'evt-api-1-' + Date.now(),
          language: 'python',
          library: 'hashlib',
          operation: 'hash',
          algorithm: 'SHA-256',
          call_file: 'app.py',
          call_line: 12,
          call_function: 'do_hash',
        },
        {
          event_id: 'evt-api-2-' + Date.now(),
          language: 'python',
          library: 'cryptography',
          operation: 'keygen',
          algorithm: 'RSA',
          key_size: 2048,
          call_file: 'app.py',
          call_line: 28,
          call_function: 'do_rsa',
        },
      ],
    };

    const resPost = await makeRequest(app, 'POST', '/api/runtime/runs', validPayload);
    assert.strictEqual(resPost.statusCode, 201);
    assert.strictEqual(resPost.body.success, true);
    assert.strictEqual(resPost.body.event_count, 2);
    console.log('✔ POST /api/runtime/runs (valid) passed');

    // 2. Test POST /api/runtime/runs with invalid language -> 400
    const invalidLangRes = await makeRequest(app, 'POST', '/api/runtime/runs', {
      language: 'ruby',
    });
    assert.strictEqual(invalidLangRes.statusCode, 400);
    assert(invalidLangRes.body.error.includes('Invalid or missing language'));
    console.log('✔ POST /api/runtime/runs (invalid language rejection) passed');

    // 3. Test POST /api/runtime/runs with invalid operation -> 400
    const invalidOpRes = await makeRequest(app, 'POST', '/api/runtime/runs', {
      language: 'python',
      events: [{ operation: 'invalid_op', algorithm: 'SHA-256' }],
    });
    assert.strictEqual(invalidOpRes.statusCode, 400);
    assert(invalidOpRes.body.error.includes('invalid or missing operation'));
    console.log('✔ POST /api/runtime/runs (invalid operation rejection) passed');

    // 4. Test GET /api/runtime/runs
    const resList = await makeRequest(app, 'GET', '/api/runtime/runs');
    assert.strictEqual(resList.statusCode, 200);
    assert(Array.isArray(resList.body.runs));
    console.log('✔ GET /api/runtime/runs passed');

    // 5. Test GET /api/runtime/runs/:run_id
    const resDetail = await makeRequest(app, 'GET', `/api/runtime/runs/${validRunId}`);
    assert.strictEqual(resDetail.statusCode, 200);
    assert.strictEqual(resDetail.body.run.id, validRunId);
    console.log('✔ GET /api/runtime/runs/:run_id passed');

    // 6. Test GET /api/runtime/runs/:run_id/events
    const resEvents = await makeRequest(app, 'GET', `/api/runtime/runs/${validRunId}/events`);
    assert.strictEqual(resEvents.statusCode, 200);
    assert.strictEqual(resEvents.body.count, 2);
    console.log('✔ GET /api/runtime/runs/:run_id/events passed');

    // 7. Test GET /api/runtime/runs/:run_id/report
    const resReport = await makeRequest(app, 'GET', `/api/runtime/runs/${validRunId}/report`);
    assert.strictEqual(resReport.statusCode, 200);
    assert.strictEqual(resReport.body.summary.total_events, 2);
    assert(resReport.body.summary.unique_algorithms.includes('RSA'));
    console.log('✔ GET /api/runtime/runs/:run_id/report passed');

    console.log('ALL runtime API route tests passed successfully!');
  } finally {
    await prisma.$disconnect();
  }
}

runRouteTests().catch((err) => {
  console.error('Route Test failed:', err);
  process.exit(1);
});
