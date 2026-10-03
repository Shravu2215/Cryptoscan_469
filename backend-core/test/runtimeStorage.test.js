'use strict';

const assert = require('assert');
const {
  createRun,
  bulkInsertEvents,
  getRunById,
  listRuns,
  getEventsByRunId,
  prisma,
} = require('../src/services/runtimeStorage');

async function runTests() {
  console.log('[Test] Starting runtimeStorage DAO integration tests...');

  try {
    // 1. Create a run
    const runData = {
      id: 'test-run-dao-' + Date.now(),
      language: 'node',
      command: 'node app.js',
      environment: 'test',
    };
    const createdRun = await createRun(runData);
    assert.strictEqual(createdRun.id, runData.id);
    assert.strictEqual(createdRun.language, 'node');
    assert.strictEqual(createdRun.eventCount, 0);
    console.log('✔ createRun passed');

    // 2. Bulk insert events
    const sampleEvents = [
      {
        event_id: 'evt-dao-1-' + Date.now(),
        language: 'node',
        library: 'node:crypto',
        operation: 'hash',
        algorithm: 'SHA-256',
        call_file: 'app.js',
        call_line: 10,
        call_function: 'doHash',
      },
      {
        event_id: 'evt-dao-2-' + Date.now(),
        language: 'node',
        library: 'node:crypto',
        operation: 'encrypt',
        algorithm: 'AES',
        key_size: 256,
        mode: 'GCM',
        call_file: 'app.js',
        call_line: 25,
        call_function: 'doEncrypt',
      },
    ];

    const bulkRes = await bulkInsertEvents(createdRun.id, sampleEvents);
    assert.strictEqual(bulkRes.count, 2);
    console.log('✔ bulkInsertEvents passed');

    // 3. Read back run with events
    const fetchedRun = await getRunById(createdRun.id, true);
    assert.strictEqual(fetchedRun.eventCount, 2);
    assert.strictEqual(fetchedRun.events.length, 2);
    const algos = fetchedRun.events.map(e => e.algorithm);
    assert(algos.includes('SHA-256'));
    assert(algos.includes('AES'));
    console.log('✔ getRunById with events passed');

    // 4. List runs
    const runs = await listRuns(null, 10, 0);
    assert(runs.length > 0);
    console.log('✔ listRuns passed');

    console.log('ALL runtimeStorage DAO tests passed successfully!');
  } finally {
    await prisma.$disconnect();
  }
}

runTests().catch((err) => {
  console.error('DAO Test failed:', err);
  process.exit(1);
});
