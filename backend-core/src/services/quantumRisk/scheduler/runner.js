'use strict';

/**
 * Python scheduler process boundary.
 * Spawns model.py as a child process, pipes JSON in via stdin, reads JSON from stdout.
 */

const { execFile } = require('child_process');
const path = require('path');

const MODEL_PATH = path.resolve(__dirname, 'model.py');

/**
 * Run the CP-SAT scheduler for the given input.
 * @param {object} scheduleInput  ScheduleInput (tasks, teamCapacity, horizonMonths, timeLimitSeconds)
 * @returns {Promise<object>}     ScheduleResult from model.py
 */
function runScheduler(scheduleInput) {
  return new Promise((resolve, reject) => {
    const pythonBin = process.env.PYTHON_BIN || 'python3';
    const child = execFile(
      pythonBin,
      [MODEL_PATH],
      { timeout: (scheduleInput.timeLimitSeconds || 10) * 1000 + 5000, maxBuffer: 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          return resolve({ solverStatus: 'ERROR', message: 'Scheduler runtime unavailable' });
        }
        let result;
        try {
          result = JSON.parse(stdout);
        } catch (_) {
          return resolve({ solverStatus: 'ERROR', message: 'Scheduler runtime unavailable' });
        }
        return resolve(result);
      },
    );
    child.stdin.write(JSON.stringify(scheduleInput));
    child.stdin.end();
  });
}

module.exports = { runScheduler };