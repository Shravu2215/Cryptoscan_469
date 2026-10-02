'use strict';

const { Queue } = require('bullmq');
const Redis = require('ioredis');

const QUEUE_NAME = 'scanQueue';
const MAX_CONCURRENT_SCANS_PER_USER = Number(process.env.MAX_CONCURRENT_SCANS_PER_USER || 2);

let _redisConnection = null;
let _scanQueue = null;

function getRedisConnectionOptions() {
  const url = process.env.REDIS_URL || 'redis://localhost:6379';
  const parsed = new URL(url);
  return {
    host: parsed.hostname || 'localhost',
    port: Number(parsed.port) || 6379,
    password: parsed.password || undefined,
    username: parsed.username || undefined,
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
    // Stop retrying on connection failure so the process event-loop is not
    // held open when Redis is unavailable (e.g. during unit tests).
    // BullMQ will surface the error through its normal error path.
    retryStrategy: () => null,
  };
}

function getRedisConnection() {
  if (!_redisConnection) {
    _redisConnection = new Redis(getRedisConnectionOptions());
    _redisConnection.on('error', (err) => {
      // Suppress ECONNREFUSED noise — the caller catches the thrown error.
      if (err.code !== 'ECONNREFUSED') {
        console.error('[ScanQueue:Redis] Connection error:', err.message);
      }
    });
  }
  return _redisConnection;
}

function getScanQueue() {
  if (!_scanQueue) {
    // Share the single Redis connection with BullMQ so there is only one
    // ioredis client and closeScanQueue() reliably tears it down.
    _scanQueue = new Queue(QUEUE_NAME, {
      connection: getRedisConnection(),
      defaultJobOptions: {
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 1000,
        },
        removeOnComplete: 1000,
        removeOnFail: 5000,
      },
    });
  }
  return _scanQueue;
}

async function getActiveAndWaitingCountForUser(userId) {
  if (!userId) return 0;
  const queue = getScanQueue();
  const jobs = await queue.getJobs(['active', 'waiting', 'delayed']);
  return jobs.filter((job) => job.data && job.data.userId === userId).length;
}

async function enqueueScan({ scanId, userId }) {
  const queue = getScanQueue();
  return await queue.add(
    'scan',
    { scanId, userId },
    {
      jobId: scanId, // Idempotency: using scanId as jobId
    }
  );
}

async function closeScanQueue() {
  if (_scanQueue) {
    await _scanQueue.close();
    _scanQueue = null;
  }
  if (_redisConnection) {
    _redisConnection.disconnect();
    _redisConnection = null;
  }
}

module.exports = {
  QUEUE_NAME,
  MAX_CONCURRENT_SCANS_PER_USER,
  getScanQueue,
  getActiveAndWaitingCountForUser,
  enqueueScan,
  closeScanQueue,
};
