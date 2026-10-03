'use strict';

const assert = require('assert');
const { generateSchedule } = require('../../src/services/quantumRisk/scheduler/index');

async function runTest() {
  const tasks = [
    { taskId: 'A', durationMonths: 2, peopleNeeded: 1, exposureWeightPerMonth: 10, dependsOn: [] },
    { taskId: 'B', durationMonths: 1, peopleNeeded: 1, exposureWeightPerMonth: 9, dependsOn: [] },
    { taskId: 'C', durationMonths: 1, peopleNeeded: 1, exposureWeightPerMonth: 8, dependsOn: [] },
    { taskId: 'D', durationMonths: 1, peopleNeeded: 1, exposureWeightPerMonth: 1, dependsOn: ['A'] },
  ];

  const input = {
    tasks,
    teamCapacity: 1,
    horizonMonths: 12,
    timeLimitSeconds: 10,
  };

  if (!process.env.PYTHON_BIN) {
    process.env.PYTHON_BIN = process.platform === 'win32' ? 'python' : 'python3';
  }

  const result = await generateSchedule(input);

  if (result.solverStatus === 'ERROR' && result.message === 'Scheduler runtime unavailable') {
    console.log('SOLVER TEST SKIPPED: Scheduler runtime (Python/ortools) is unavailable.');
    return;
  }
  
  console.log('SOLVER TEST RAN');

  assert(['OPTIMAL', 'FEASIBLE'].includes(result.solverStatus));

  // Verify optimized exposure <= baseline
  assert(result.totalExposure <= result.baselineTotalExposure);
  
  // In our specific handcrafted case, CP-SAT should definitively beat the greedy baseline
  assert(result.totalExposure < result.baselineTotalExposure);

  // Helper to verify capacity and dependencies
  const verifySchedule = (rows, label) => {
    const byId = new Map(rows.map(r => [r.taskId, r]));
    const capacityUsed = new Array(input.horizonMonths + 1).fill(0);
    
    for (const t of tasks) {
      const row = byId.get(t.taskId);
      assert(row, `Task ${t.taskId} missing in ${label}`);
      
      // Capacity
      for (let m = row.startMonth; m < row.endMonth; m++) {
        capacityUsed[m] += t.peopleNeeded;
        assert(capacityUsed[m] <= input.teamCapacity, `Capacity exceeded in ${label} month ${m}`);
      }
      
      // Dependencies
      for (const dep of t.dependsOn) {
        const depRow = byId.get(dep);
        assert(row.startMonth >= depRow.endMonth, `Dependency failed in ${label}: ${t.taskId} depends on ${dep}`);
      }
    }
  };

  verifySchedule(result.ganttRows, 'CP-SAT');
  verifySchedule(result.baseline.ganttRows, 'Baseline');

  console.log('PASS test/quantumRisk/scheduler.test.js');
}

if (require.main === module) {
  runTest().catch((err) => {
    console.error('FAIL test/quantumRisk/scheduler.test.js');
    console.error(err);
    process.exit(1);
  });
}