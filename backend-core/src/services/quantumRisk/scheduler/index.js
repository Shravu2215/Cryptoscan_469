'use strict';

/**
 * Scheduler feature entry point.
 *
 * generateSchedule({ tasks, teamCapacity, horizonMonths, timeLimitSeconds })
 *   -> ScheduleResult (from model.py via runner.js)
 *
 * buildBaselineSchedule({ tasks, teamCapacity, horizonMonths })
 *   -> greedy baseline ScheduleResult (pure JS, no Python)
 */

const { runScheduler } = require('./runner');
const { buildBaselineSchedule } = require('./baseline');

/**
 * Run the CP-SAT scheduler.
 * @param {object} input  { tasks, teamCapacity, horizonMonths, timeLimitSeconds? }
 * @returns {Promise<object>} ScheduleResult
 */
async function generateSchedule(input) {
  const result = await runScheduler(input);
  const baseline = buildBaselineSchedule(input);
  const totalExposure = result.totalExposure || 0;
  const baselineTotalExposure = baseline.totalExposure || 0;
  const improvementPct = baselineTotalExposure > 0 ? ((baselineTotalExposure - totalExposure) / baselineTotalExposure) * 100 : 0;
  
  return {
    waves: result.waves || [],
    ganttRows: result.ganttRows || [],
    totalExposure,
    baselineTotalExposure,
    improvementPct,
    solverStatus: result.solverStatus,
    message: result.message,
    baseline: {
      waves: baseline.waves,
      ganttRows: baseline.ganttRows,
      deadlineMisses: baseline.deadlineMisses || []
    }
  };
}

module.exports = { generateSchedule, buildBaselineSchedule };