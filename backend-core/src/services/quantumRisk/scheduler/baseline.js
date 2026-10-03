'use strict';

/**
 * Severity-ordered greedy baseline schedule.
 *
 * Produces a baseline schedule WITHOUT invoking the CP-SAT solver,
 * by ordering tasks greedily from highest to lowest exposureWeightPerMonth
 * and packing them into months respecting capacity and dependency order.
 *
 * Used as the baseline comparison point for sensitivity analysis.
 */

/**
 * Build a greedy baseline schedule.
 *
 * @param {object} params
 * @param {Array}  params.tasks          ScheduleInput tasks array
 * @param {number} params.teamCapacity   People available per month
 * @param {number} params.horizonMonths  Maximum schedule horizon
 * @returns {object}  ScheduleResult-shaped object with solverStatus:'BASELINE'
 */
function buildBaselineSchedule({ tasks, teamCapacity, horizonMonths }) {
  if (!tasks || tasks.length === 0) {
    return {
      solverStatus: 'BASELINE',
      waves: [],
      ganttRows: [],
      totalExposure: 0,
      message: 'No tasks provided',
    };
  }

  // Sort by exposure weight descending (greedy: highest urgency first)
  const sorted = [...tasks].sort((a, b) => (b.exposureWeightPerMonth || 0) - (a.exposureWeightPerMonth || 0));

  // Topological sort to respect dependencies while keeping exposure ordering
  const taskById = new Map(tasks.map((t) => [t.taskId, t]));
  const inDegree = new Map(tasks.map((t) => [t.taskId, 0]));
  for (const t of tasks) {
    for (const dep of (t.dependsOn || [])) {
      inDegree.set(t.taskId, (inDegree.get(t.taskId) || 0) + 1);
    }
  }

  // Track earliest possible start per task (determined by dependency end times)
  const earliestStart = new Map(tasks.map((t) => [t.taskId, 0]));
  const scheduleResult = new Map(); // taskId -> { startMonth, endMonth }
  const remaining = new Set(sorted.map((t) => t.taskId));

  // Month-level capacity tracking
  const capacityUsed = new Array(horizonMonths + 1).fill(0);

  function canSchedule(taskId, start) {
    const task = taskById.get(taskId);
    const duration = task.durationMonths || 1;
    const needed = task.peopleNeeded || 0;
    if (start + duration > horizonMonths) return false;
    for (let m = start; m < start + duration; m++) {
      if ((capacityUsed[m] || 0) + needed > teamCapacity) return false;
    }
    return true;
  }

  function commitSchedule(taskId, start) {
    const task = taskById.get(taskId);
    const duration = task.durationMonths || 1;
    const needed = task.peopleNeeded || 0;
    const end = start + duration;
    for (let m = start; m < end; m++) {
      capacityUsed[m] = (capacityUsed[m] || 0) + needed;
    }
    scheduleResult.set(taskId, { startMonth: start, endMonth: end });
  }

  // Iteratively schedule tasks when all deps are resolved
  let maxIterations = tasks.length * tasks.length + tasks.length;
  while (remaining.size > 0 && maxIterations-- > 0) {
    let progress = false;
    for (const taskId of [...remaining]) {
      const task = taskById.get(taskId);
      const deps = task.dependsOn || [];
      // Check all deps scheduled
      if (deps.some((d) => !scheduleResult.has(d))) continue;

      // Earliest start is max of dependency ends
      const depEnd = deps.reduce((max, d) => {
        const res = scheduleResult.get(d);
        return res ? Math.max(max, res.endMonth) : max;
      }, earliestStart.get(taskId) || 0);

      // Find first month where it fits
      let scheduled = false;
      for (let m = depEnd; m < horizonMonths; m++) {
        if (canSchedule(taskId, m)) {
          commitSchedule(taskId, m);
          remaining.delete(taskId);
          scheduled = true;
          progress = true;
          break;
        }
      }
      if (!scheduled) {
        // Cannot fit within horizon — schedule at end (infeasible marker)
        commitSchedule(taskId, Math.max(0, horizonMonths - (task.durationMonths || 1)));
        remaining.delete(taskId);
        progress = true;
      }
    }
    if (!progress) break; // Circular dependency or unresolvable — bail
  }

  const ganttRows = [];
  const deadlineMisses = [];
  let totalExposure = 0;
  for (const task of tasks) {
    const res = scheduleResult.get(task.taskId) || { startMonth: 0, endMonth: task.durationMonths || 1 };
    ganttRows.push({ taskId: task.taskId, startMonth: res.startMonth, endMonth: res.endMonth });
    totalExposure += (task.exposureWeightPerMonth || 0) * res.endMonth;
    if (task.deadlineMonth !== undefined && task.deadlineMonth !== null && res.endMonth > task.deadlineMonth) {
      deadlineMisses.push(task.taskId);
    }
  }

  // Build waves grouped by startMonth
  const wavesDict = new Map();
  for (const row of ganttRows) {
    if (!wavesDict.has(row.startMonth)) wavesDict.set(row.startMonth, []);
    wavesDict.get(row.startMonth).push(row);
  }
  const waves = [...wavesDict.entries()]
    .sort(([a], [b]) => a - b)
    .map(([sm, rows], idx) => ({
      wave: idx + 1,
      startMonth: sm,
      endMonth: Math.max(...rows.map((r) => r.endMonth)),
      taskIds: rows.map((r) => r.taskId),
    }));

  return {
    solverStatus: 'BASELINE',
    waves,
    ganttRows,
    deadlineMisses,
    totalExposure: Math.round(totalExposure * 10000) / 10000,
    message: 'Greedy baseline (severity-ordered, no CP-SAT)',
  };
}

module.exports = { buildBaselineSchedule };