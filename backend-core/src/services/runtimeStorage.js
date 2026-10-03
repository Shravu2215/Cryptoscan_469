'use strict';

/**
 * Runtime Storage DAO / Repository Module.
 * Manages persistence for RuntimeRun and RuntimeEvent models using Prisma.
 */

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const memoryRuns = new Map();
const memoryEvents = new Map(); // runId -> array of events

/**
 * Creates a new RuntimeRun record.
 */
async function createRun(data) {
  const runObj = {
    id: data.id || 'run-' + Date.now(),
    scanId: data.scanId || null,
    language: data.language || 'unknown',
    command: data.command || null,
    environment: data.environment || 'test',
    startedAt: data.startedAt ? new Date(data.startedAt) : new Date(),
    finishedAt: data.finishedAt ? new Date(data.finishedAt) : null,
    eventCount: data.eventCount || 0,
    createdAt: new Date(),
  };

  try {
    return await prisma.runtimeRun.create({
      data: {
        id: data.id || undefined,
        scanId: data.scanId || null,
        language: data.language || 'unknown',
        command: data.command || null,
        environment: data.environment || 'test',
        startedAt: data.startedAt ? new Date(data.startedAt) : new Date(),
        finishedAt: data.finishedAt ? new Date(data.finishedAt) : null,
        eventCount: data.eventCount || 0,
      },
    });
  } catch (err) {
    memoryRuns.set(runObj.id, runObj);
    console.warn('[RuntimeStorage] PostgreSQL DB unreachable; falling back to in-memory storage:', err.message);
    return runObj;
  }
}

/**
 * Bulk-inserts runtime events for a given runId.
 */
async function bulkInsertEvents(runId, events) {
  if (!events || events.length === 0) return { count: 0 };

  const records = events.map((e) => ({
    eventId: e.event_id || e.eventId,
    runId: runId,
    timestamp: e.timestamp ? new Date(e.timestamp) : new Date(),
    language: e.language || 'unknown',
    library: e.library || 'unknown',
    operation: e.operation || 'other',
    algorithm: e.algorithm || 'UNKNOWN',
    keySize: e.key_size !== undefined ? e.key_size : (e.keySize || null),
    mode: e.mode || null,
    padding: e.padding || null,
    curve: e.curve || null,
    callFile: e.call_file || e.callFile || '',
    callLine: parseInt(e.call_line || e.callLine || 0, 10),
    callFunction: e.call_function || e.callFunction || '',
    matchedFindingId: e.matched_finding_id || e.matchedFindingId || null,
  }));

  try {
    const result = await prisma.runtimeEvent.createMany({
      data: records,
    });

    await prisma.runtimeRun.update({
      where: { id: runId },
      data: {
        eventCount: { increment: result.count },
        finishedAt: new Date(),
      },
    });

    return result;
  } catch (err) {
    const existing = memoryEvents.get(runId) || [];
    memoryEvents.set(runId, existing.concat(records));

    const run = memoryRuns.get(runId);
    if (run) {
      run.eventCount = (run.eventCount || 0) + records.length;
      run.finishedAt = new Date();
    }
    return { count: records.length };
  }
}

/**
 * Fetches a run by ID with optional event inclusion.
 */
async function getRunById(runId, includeEvents = false) {
  try {
    return await prisma.runtimeRun.findUnique({
      where: { id: runId },
      include: {
        events: includeEvents,
        scan: true,
      },
    });
  } catch (err) {
    const run = memoryRuns.get(runId);
    if (!run) return null;
    const result = { ...run };
    if (includeEvents) {
      result.events = memoryEvents.get(runId) || [];
    }
    return result;
  }
}

/**
 * Lists runs, optionally filtered by scanId.
 */
async function listRuns(scanId = null, limit = 50, offset = 0) {
  try {
    const where = scanId ? { scanId } : {};
    return await prisma.runtimeRun.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
      include: {
        scan: {
          select: { id: true, repoId: true, status: true },
        },
      },
    });
  } catch (err) {
    let list = Array.from(memoryRuns.values());
    if (scanId) {
      list = list.filter((r) => r.scanId === scanId);
    }
    return list.slice(offset, offset + limit);
  }
}

/**
 * Retrieves paginated events for a run.
 */
async function getEventsByRunId(runId, limit = 100, offset = 0) {
  try {
    return await prisma.runtimeEvent.findMany({
      where: { runId },
      orderBy: { timestamp: 'asc' },
      take: limit,
      skip: offset,
    });
  } catch (err) {
    const events = memoryEvents.get(runId) || [];
    return events.slice(offset, offset + limit);
  }
}

/**
 * Updates matchedFindingId for a set of events.
 */
async function updateEventFindingMatch(eventId, matchedFindingId) {
  try {
    return await prisma.runtimeEvent.update({
      where: { eventId },
      data: { matchedFindingId },
    });
  } catch (err) {
    for (const events of memoryEvents.values()) {
      const match = events.find((e) => e.eventId === eventId);
      if (match) {
        match.matchedFindingId = matchedFindingId;
        return match;
      }
    }
    return null;
  }
}

module.exports = {
  prisma,
  createRun,
  bulkInsertEvents,
  getRunById,
  listRuns,
  getEventsByRunId,
  updateEventFindingMatch,
};
