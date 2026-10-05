'use strict';

const crypto = require('crypto');
const cors = require('cors');
const express = require('express');
const { verifyAccessToken } = require('../utils/tokenService');
const { isJtiDenylisted } = require('../utils/redisClient');
const prisma = require('../utils/prismaClient');
const { classifyEvents, probePublicTls } = require('../services/runtimeAnalysis');
const {
  saveRepo, getRepo, saveScan, getScan, saveFindings, getFindings,
  saveRuntimeRun, getRuntimeRun, updateRuntimeRun, saveRuntimeEvent, getRuntimeEvents
} = require('../utils/devStore');

const router = express.Router();
const MAX_BODY_BYTES = 64 * 1024;
const MAX_BATCH_EVENTS = 100;
const MAX_SESSION_EVENTS = 10000;
const EVENT_FIELDS = new Set([
  'source', 'algorithm', 'operation', 'keyInfo', 'callerScript', 'hostOrigin',
  'scheme', 'port', 'crossOrigin', 'count', 'timestamp',
]);
const KEY_INFO_FIELDS = new Set([
  'keySize', 'modulusLength', 'curve', 'mode', 'hash', 'format', 'version', 'cipherSuite', 'bits', 'expiresAt',
]);
const SOURCES = new Set(['crypto', 'network', 'library', 'wasm', 'tls']);
const OPERATIONS = new Set([
  'digest', 'generateKey', 'importKey', 'exportKey', 'encrypt', 'decrypt', 'sign',
  'verify', 'deriveKey', 'deriveBits', 'wrapKey', 'unwrapKey', 'random', 'network',
  'wallet', 'load', 'library', 'wasm', 'handshake', 'protocol', 'certificate', 'signature', 'key_exchange',
]);
const SAFE_LIBRARIES = new Set(['CryptoJS', 'forge', 'sjcl', 'jsrsasign', 'elliptic', 'tweetnacl', 'ethers', 'web3']);
const ingestCors = cors({
  origin: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CryptoScan-Token', 'X-CryptoScan-Origin'],
  maxAge: 600,
});

router.use(ingestCors);

function hashToken(value) {
  return crypto.createHash('sha256').update(value).digest();
}

async function strictAuth(req, res, next) {
  const authorization = req.headers.authorization || '';
  if (!authorization.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required.' });
  try {
    const payload = verifyAccessToken(authorization.slice(7));
    if (!payload || !payload.id || (payload.jti && await isJtiDenylisted(payload.jti))) {
      return res.status(401).json({ error: 'Invalid or revoked access token.' });
    }
    req.user = { id: payload.id, email: payload.email, role: payload.role || 'Developer' };
    return next();
  } catch (_) {
    return res.status(401).json({ error: 'Invalid or expired access token.' });
  }
}

function optionalAuth(req, res, next) {
  return req.headers.authorization ? strictAuth(req, res, next) : next();
}

function safeOrigin(value, protocols = ['http:', 'https:']) {
  try {
    const parsed = new URL(value);
    if (!protocols.includes(parsed.protocol) || parsed.username || parsed.password) return null;
    return parsed.origin;
  } catch (_) {
    return null;
  }
}

function getCallerScript(value) {
  if (typeof value !== 'string' || value.length > 1000) return null;
  const lineMatch = value.match(/:(\d+)(?::\d+)?$/);
  if (!lineMatch) return null;
  const line = Number(lineMatch[1]);
  if (!Number.isSafeInteger(line) || line < 0) return null;
  const source = value.slice(0, lineMatch.index).replace(/[?#].*$/, '');
  if (source === 'unknown' || source.startsWith('inline:')) return `unknown:${line}`;
  try {
    const parsed = new URL(source);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return null;
    return `${parsed.origin}${parsed.pathname}:${line}`.slice(0, 700);
  } catch (_) {
    const relative = source.replace(/\\/g, '/');
    if (!/^[A-Za-z0-9._~/-]+\.py$/i.test(relative) || relative.split('/').includes('..')) return null;
    return `python://${relative}:${line}`.slice(0, 700);
  }
}

function normalizeKeyInfo(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if (Object.keys(value).some(key => !KEY_INFO_FIELDS.has(key))) return null;
  const info = {};
  for (const name of ['keySize', 'modulusLength', 'bits']) {
    if (value[name] !== undefined) {
      const number = Number(value[name]);
      if (!Number.isSafeInteger(number) || number < 1 || number > 65536) return null;
      info[name] = number;
    }
  }
  for (const name of ['curve', 'mode', 'hash', 'format', 'version', 'cipherSuite', 'expiresAt']) {
    if (value[name] !== undefined) {
      if (typeof value[name] !== 'string' || value[name].length > 100 || !/^[A-Za-z0-9._:+() /_-]+$/.test(value[name])) return null;
      info[name] = value[name];
    }
  }
  return info;
}

function normalizeEvent(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  if (Object.keys(input).some(key => !EVENT_FIELDS.has(key))) return null;
  if (!SOURCES.has(input.source) || !OPERATIONS.has(input.operation)) return null;
  if (typeof input.algorithm !== 'string' || input.algorithm.length > 100 || !/^[A-Za-z0-9_.:+() /-]+$/.test(input.algorithm)) return null;
  if (input.source === 'library' && !SAFE_LIBRARIES.has(input.algorithm)) return null;
  if (input.source === 'network' && input.algorithm !== 'NETWORK') return null;
  if (input.source === 'wasm' && input.algorithm !== 'WASM') return null;
  const keyInfo = normalizeKeyInfo(input.keyInfo || {});
  if (!keyInfo) return null;
  const callerScript = getCallerScript(input.callerScript);
  if (!callerScript) return null;
  const scheme = input.scheme === undefined ? '' : input.scheme;
  if (!['', 'http', 'https', 'ws', 'wss'].includes(scheme)) return null;
  const hostOrigin = input.hostOrigin === undefined || input.hostOrigin === '' ? '' : safeOrigin(input.hostOrigin, ['http:', 'https:', 'ws:', 'wss:']);
  if (input.hostOrigin && !hostOrigin) return null;
  const port = input.port === undefined ? 0 : Number(input.port);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) return null;
  if (input.source === 'network' && (!scheme || !hostOrigin)) return null;
  if (typeof input.crossOrigin !== 'boolean' && input.crossOrigin !== undefined) return null;
  const count = input.count === undefined ? 1 : Number(input.count);
  if (!Number.isSafeInteger(count) || count < 1 || count > 1000000) return null;
  const timestamp = input.timestamp ? new Date(input.timestamp) : new Date();
  if (!Number.isFinite(timestamp.getTime()) || (input.timestamp && (typeof input.timestamp !== 'string' || input.timestamp.length > 40))) return null;
  return {
    source: input.source,
    algorithm: input.algorithm,
    operation: input.operation,
    keyInfo,
    keyInfoJson: JSON.stringify(Object.fromEntries(Object.entries(keyInfo).sort(([a], [b]) => a.localeCompare(b)))),
    callerScript,
    hostOrigin: hostOrigin || '',
    scheme,
    port,
    crossOrigin: Boolean(input.crossOrigin),
    count,
    timestamp,
  };
}

function verifyIngestToken(run, token) {
  if (!token || !/^[A-Za-z0-9_-]{32,100}$/.test(token)) return false;
  const supplied = hashToken(token);
  const expected = Buffer.from(run.ingestTokenHash, 'hex');
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

async function findSession(id) {
  const shadow = getRuntimeRun(id) || null;
  try {
    const run = await prisma.runtimeRun.findUnique({ where: { id } });
    if (run) return shadow && shadow.status === 'stopped' && run.status !== 'stopped' ? shadow : run;
  } catch (_) {}
  return shadow;
}

async function findAuthorizedSession(req, res) {
  const run = await findSession(req.params.id);
  if (!run) {
    res.status(404).json({ error: 'Runtime session not found.' });
    return null;
  }
  const ingestToken = req.get('x-cryptoscan-token');
  if (ingestToken && verifyIngestToken(run, ingestToken)) return run;
  if (req.user && req.user.id === run.userId) return run;
  res.status(401).json({ error: 'Runtime session authorization required.' });
  return null;
}

function eventIdentity(runId, event) {
  const identity = [
    runId, event.source, event.algorithm, event.operation, event.keyInfoJson,
    event.callerScript, event.hostOrigin, event.scheme, event.port, event.crossOrigin,
  ];
  return crypto.createHash('sha256').update(JSON.stringify(identity)).digest('hex');
}

function eventRecord(runId, event) {
  const line = Number(event.callerScript.match(/:(\d+)$/)?.[1]) || 0;
  return {
    eventId: eventIdentity(runId, event),
    runId,
    timestamp: event.timestamp,
    language: event.source === 'crypto' ? 'browser' : event.source,
    library: event.source,
    operation: event.operation,
    algorithm: event.algorithm,
    keySize: event.keyInfo.keySize || event.keyInfo.modulusLength || null,
    mode: event.keyInfo.mode || null,
    padding: null,
    curve: event.keyInfo.curve || null,
    callFile: event.callerScript,
    callLine: line,
    callFunction: event.operation,
    source: event.source,
    keyInfo: event.keyInfoJson,
    callerScript: event.callerScript,
    hostOrigin: event.hostOrigin,
    scheme: event.scheme,
    port: event.port,
    crossOrigin: event.crossOrigin,
    count: event.count,
  };
}

async function storeAggregates(runId, events) {
  if (!events.length) return;
  const latestEventAt = events.reduce((latest, event) => event.timestamp > latest ? event.timestamp : latest, events[0].timestamp);
  const increment = events.reduce((total, event) => total + event.count, 0);
  try {
    await prisma.$transaction(async tx => {
      const session = await tx.runtimeRun.findFirst({ where: { id: runId, status: 'recording' } });
      if (!session) throw Object.assign(new Error('Runtime session is not recording.'), { status: 409 });
      if (session.eventCount + increment > 1000000000) throw Object.assign(new Error('Runtime event limit reached.'), { status: 413 });
      const distinctCount = await tx.runtimeEvent.count({ where: { runId } });
      const batchKeys = new Set(events.map(event => eventIdentity(runId, event)));
      if (distinctCount + batchKeys.size > MAX_SESSION_EVENTS) throw Object.assign(new Error('Runtime session aggregate limit reached.'), { status: 413 });
      const locked = await tx.runtimeRun.updateMany({
        where: { id: runId, status: 'recording' },
        data: { eventCount: { increment }, lastEventAt: latestEventAt },
      });
      if (locked.count !== 1) throw Object.assign(new Error('Runtime session is not recording.'), { status: 409 });
      for (const event of events) {
        const record = eventRecord(runId, event);
        await tx.runtimeEvent.upsert({
          where: { eventId: record.eventId },
          create: record,
          update: { count: { increment: event.count } },
        });
      }
    });
    const shadowRun = getRuntimeRun(runId);
    if (shadowRun) {
      shadowRun.eventCount = (shadowRun.eventCount || 0) + increment;
      shadowRun.lastEventAt = latestEventAt;
      updateRuntimeRun(runId, shadowRun);
    }
    for (const event of events) saveRuntimeEvent(eventRecord(runId, event));
  } catch (dbErr) {
    if (dbErr.status) throw dbErr;
    const run = getRuntimeRun(runId);
    if (!run) throw Object.assign(new Error('Runtime session not found.'), { status: 404 });
    if (run.status !== 'recording') throw Object.assign(new Error('Runtime session is not recording.'), { status: 409 });
    run.eventCount = (run.eventCount || 0) + increment;
    run.lastEventAt = latestEventAt;
    updateRuntimeRun(runId, run);
    for (const event of events) {
      saveRuntimeEvent(eventRecord(runId, event));
    }
  }
}

function findingFromClassification(run, event, finding, suffix = '') {
  const callerScript = event.callerScript || `tls://${new URL(run.targetOrigin).host}:0`;
  const line = Number(callerScript.match(/:(\d+)$/)?.[1]) || null;
  const filePath = line ? callerScript.slice(0, callerScript.lastIndexOf(':')) : callerScript;
  const algorithm = finding.algorithm || event.algorithm || 'Observed operation';
  const id = crypto.createHash('sha256')
    .update([run.id, event.eventId || event.algorithm, suffix, algorithm, event.operation].join('|'))
    .digest('hex').slice(0, 32);
  return {
    id,
    scanId: run.scanId,
    filePath: filePath || 'unknown',
    lineNumber: line,
    algorithm,
    library: event.library || event.source || 'Runtime observation',
    usage: event.operation || 'observed',
    operation: event.operation || null,
    callSite: callerScript,
    keySize: event.keySize || null,
    mode: event.mode || null,
    curve: event.curve || null,
    hash: event.hash || null,
    observedAt: event.timestamp || new Date(),
    quantumStatus: String(finding.quantumRisk || 'Safe').includes('Broken') ? 'Quantum Vulnerable'
      : String(finding.quantumRisk || '').includes('Weakened') ? 'Quantum Weakened'
        : String(finding.quantumRisk || '').includes('Risk') ? 'Classical Risk' : 'Quantum Safe',
    severity: String(finding.severity || 'Informational').toUpperCase(),
    description: `Observed during this session: ${finding.description || algorithm + ' ' + (event.operation || 'operation') + ' observed.'}`,
    recommendation: finding.recommendation || 'Review this observed operation.',
    confidence: 'Observed|runtime',
    detection: 'RUNTIME',
    detection_method: 'runtime',
    language: event.language || 'JavaScript',
    source: 'runtime',
    sessionId: run.id,
    count: event.count || 1,
  };
}

function tlsProbeEvents(run, probe) {
  const origin = new URL(run.targetOrigin);
  const callerScript = `tls://${origin.host}:0`;
  const base = { source: 'tls', callerScript, hostOrigin: run.targetOrigin, scheme: 'https', port: Number(origin.port || 443), crossOrigin: false, count: 1 };
  const events = [];
  if (probe.negotiatedVersion) {
    events.push({ ...base, algorithm: 'TLS', operation: 'load', keyInfo: { version: probe.negotiatedVersion, cipherSuite: probe.cipherSuite || '' }, timestamp: new Date().toISOString() });
  }
  for (const version of probe.acceptedProtocols || []) {
    events.push({ ...base, algorithm: version, operation: 'protocol', keyInfo: {}, timestamp: new Date().toISOString() });
  }
  if (probe.certificateKeyType) {
    events.push({
      ...base,
      algorithm: probe.certificateKeyType,
      operation: 'certificate',
      keyInfo: {
        ...(probe.certificateKeySize ? { keySize: probe.certificateKeySize } : {}),
        ...(probe.certificateCurve ? { curve: probe.certificateCurve } : {}),
        ...(probe.expiresAt ? { expiresAt: probe.expiresAt } : {}),
      },
      timestamp: new Date().toISOString(),
    });
  }
  if (probe.signatureAlgorithm) {
    events.push({ ...base, algorithm: probe.signatureAlgorithm, operation: 'signature', keyInfo: {}, timestamp: new Date().toISOString() });
  }
  if (probe.ecdhe) {
    events.push({ ...base, algorithm: 'ECDHE', operation: 'key_exchange', keyInfo: {}, timestamp: new Date().toISOString() });
  }
  return events.map(event => ({ ...event, keyInfoJson: JSON.stringify(event.keyInfo), count: 1 }));
}

router.post('/sessions', strictAuth, async (req, res, next) => {
  try {
    if (!req.body || Object.keys(req.body).some(key => key !== 'targetUrl') || typeof req.body.targetUrl !== 'string') {
      return res.status(400).json({ error: 'Provide only targetUrl.' });
    }
    const targetOrigin = safeOrigin(req.body.targetUrl);
    if (!targetOrigin) return res.status(400).json({ error: 'targetUrl must be an http or https URL without credentials.' });
    const parsedTarget = new URL(req.body.targetUrl);
    const cryptoscanOrigin = safeOrigin(req.get('x-cryptoscan-origin') || req.get('origin') || req.get('referer')) || 'http://localhost:3000';

    const id = crypto.randomUUID();
    const ingestToken = crypto.randomBytes(32).toString('base64url');
    const startedAt = new Date();
    const userId = req.user && req.user.id ? req.user.id : 'usr_demo';

    let run = null;
    const repoData = {
      name: `Runtime ${parsedTarget.hostname}`,
      filePath: `runtime-session://${id}`,
      uploadedBy: userId,
      businessCriticality: 'Not tagged',
    };

    try {
      run = await prisma.$transaction(async tx => {
        const repo = await tx.repo.create({ data: repoData });
        const scan = await tx.scan.create({ data: { repoId: repo.id, status: 'RUNNING' } });
        return tx.runtimeRun.create({
          data: {
            id,
            scanId: scan.id,
            userId,
            ingestTokenHash: hashToken(ingestToken).toString('hex'),
            targetOrigin,
            cryptoscanOrigin,
            status: 'ready',
            language: 'browser',
            command: null,
            environment: 'browser',
            startedAt,
          },
        });
      });
    } catch (dbErr) {
      console.warn('PostgreSQL unavailable during session creation, using devStore:', dbErr.message);
      const repo = saveRepo({
        id: 'repo-runtime-' + id.slice(0, 8),
        name: repoData.name,
        filePath: repoData.filePath,
        uploadedBy: userId,
        businessCriticality: 'Not tagged',
      });
      const scan = saveScan({
        id: 'scan-runtime-' + id.slice(0, 8),
        repoId: repo.id,
        status: 'RUNNING',
        createdAt: startedAt,
      });
      run = saveRuntimeRun({
        id,
        scanId: scan.id,
        userId,
        ingestTokenHash: hashToken(ingestToken).toString('hex'),
        targetOrigin,
        cryptoscanOrigin,
        status: 'ready',
        language: 'browser',
        command: null,
        environment: 'browser',
        startedAt,
        eventCount: 0,
      });
    }
    const localRepoId = 'repo-runtime-' + id.slice(0, 8);
    saveRepo({
      id: localRepoId,
      name: repoData.name,
      filePath: repoData.filePath,
      uploadedBy: userId,
      businessCriticality: 'Not tagged',
    });
    saveScan({
      id: run.scanId,
      repoId: localRepoId,
      repoName: repoData.name,
      status: 'RUNNING',
      createdAt: startedAt,
    });
    saveRuntimeRun({
      id,
      scanId: run.scanId,
      userId,
      ingestTokenHash: hashToken(ingestToken).toString('hex'),
      targetOrigin,
      cryptoscanOrigin,
      status: 'ready',
      language: 'browser',
      command: null,
      environment: 'browser',
      startedAt,
      eventCount: 0,
    });
    const ingestUrl = `${req.protocol}://${req.get('host')}/api/runtime/sessions/${id}/events`;
    return res.status(201).json({ id, ingestToken, startedAt: run.startedAt, scanId: run.scanId, targetOrigin, cryptoscanOrigin, ingestUrl });
  } catch (error) {
    next(error);
  }
});

router.post('/sessions/:id/start', async (req, res, next) => {
  try {
    const run = await findSession(req.params.id);
    if (!run || !verifyIngestToken(run, req.get('x-cryptoscan-token'))) return res.status(401).json({ error: 'Invalid runtime session token.' });
    if (run.status === 'recording') return res.json({ id: run.id, status: run.status });
    if (run.status !== 'ready') return res.status(409).json({ error: 'Runtime session cannot be started.' });
    try {
      await prisma.runtimeRun.update({ where: { id: run.id }, data: { status: 'recording' } });
    } catch (_) {}
    updateRuntimeRun(run.id, { status: 'recording' });
    return res.json({ id: run.id, status: 'recording' });
  } catch (error) {
    next(error);
  }
});

router.post('/sessions/:id/events', async (req, res, next) => {
  try {
    const bodySize = Math.max(Number(req.headers['content-length'] || 0), Buffer.byteLength(JSON.stringify(req.body || {})));
    if (bodySize > MAX_BODY_BYTES) return res.status(413).json({ error: 'Runtime event batch exceeds 64 KB.' });
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body) || Object.keys(req.body).some(key => key !== 'events')) {
      return res.status(400).json({ error: 'Runtime payload may contain only events.' });
    }
    if (!Array.isArray(req.body.events) || req.body.events.length > MAX_BATCH_EVENTS) {
      return res.status(400).json({ error: `events must contain at most ${MAX_BATCH_EVENTS} aggregated metadata records.` });
    }
    const run = await findSession(req.params.id);
    if (!run || !verifyIngestToken(run, req.get('x-cryptoscan-token'))) return res.status(401).json({ error: 'Invalid runtime session token.' });
    if (run.status !== 'recording') return res.status(409).json({ error: 'Runtime session is not recording.' });
    const events = req.body.events.map(normalizeEvent);
    if (events.some(event => !event)) return res.status(400).json({ error: 'Event contains unknown fields or invalid metadata.' });
    await storeAggregates(run.id, events);
    let eventCount = run.eventCount;
    let lastEventAt = run.lastEventAt;
    try {
      const updated = await prisma.runtimeRun.findUnique({ where: { id: run.id }, select: { eventCount: true, lastEventAt: true } });
      if (updated) {
        eventCount = updated.eventCount;
        lastEventAt = updated.lastEventAt;
      }
    } catch (_) {}
    const devRun = getRuntimeRun(run.id);
    if (devRun) {
      eventCount = devRun.eventCount;
      lastEventAt = devRun.lastEventAt;
    }
    return res.json({ accepted: events.reduce((total, event) => total + event.count, 0), eventCount, lastEventAt });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.status ? error.message : 'Runtime event ingestion failed.' });
  }
});

router.get('/sessions/:id', optionalAuth, sendStatus);

router.get('/sessions/:id/findings', optionalAuth, async (req, res, next) => {
  try {
    const run = await findSession(req.params.id);
    if (!run || !(verifyIngestToken(run, req.get('x-cryptoscan-token')) || (req.user && req.user.id === run.userId))) {
      return res.status(401).json({ error: 'Runtime session authorization required.' });
    }
    if (run.status !== 'stopped') return res.status(409).json({ error: 'Runtime analysis has not stopped.' });
    let scan;
    let repoName = 'Runtime Analysis';
    try {
      scan = await prisma.scan.findUnique({ where: { id: run.scanId }, include: { repo: true } });
      if (scan && scan.repo) repoName = scan.repo.name;
    } catch (_) {}
    if (!scan) scan = getScan(run.scanId);
    if (!scan) return res.status(404).json({ error: 'Runtime scan not found.' });

    let findings = [];
    try {
      findings = await prisma.finding.findMany({ where: { sessionId: run.id }, orderBy: { createdAt: 'asc' } });
    } catch (_) {}
    if (!findings || findings.length === 0) {
      findings = getFindings(run.scanId) || [];
    }

    return res.json({
      sessionId: run.id,
      scanId: scan.id,
      repoId: scan.repoId,
      repoName: repoName || scan.repoName || 'Runtime Analysis',
      status: scan.status,
      eventCount: run.eventCount || 0,
      findings,
    });
  } catch (error) {
    next(error);
  }
});

async function sendStatus(req, res, next) {
  try {
    const run = await findSession(req.params.id);
    if (!run || !(verifyIngestToken(run, req.get('x-cryptoscan-token')) || (req.user && req.user.id === run.userId))) {
      return res.status(401).json({ error: 'Runtime session authorization required.' });
    }
    return res.json({
      id: run.id,
      scanId: run.scanId,
      status: run.status,
      startedAt: run.startedAt,
      lastEventAt: run.lastEventAt,
      stoppedAt: run.stoppedAt,
      eventCount: run.eventCount || 0,
    });
  } catch (error) {
    next(error);
  }
}

router.post('/sessions/:id/stop', optionalAuth, async (req, res, next) => {
  try {
    const initial = await findSession(req.params.id);
    if (!initial || !(verifyIngestToken(initial, req.get('x-cryptoscan-token')) || (req.user && req.user.id === initial.userId))) {
      return res.status(401).json({ error: 'Runtime session authorization required.' });
    }
    if (initial.status === 'stopped') return res.json({ id: initial.id, scanId: initial.scanId, status: 'stopped', eventCount: initial.eventCount });
    try {
      await prisma.runtimeRun.updateMany({
        where: { id: initial.id, status: { in: ['ready', 'recording'] } },
        data: { status: 'analyzing' },
      });
    } catch (_) {}
    updateRuntimeRun(initial.id, { status: 'analyzing' });

    try {
      let probe = null;
      try { probe = await probePublicTls(initial.targetOrigin); } catch (_) {}
      const tlsEvents = probe && probe.probeSucceeded ? tlsProbeEvents(initial, probe) : [];
      if (tlsEvents.length) {
        let tlsStoredInPrisma = false;
        try {
          await prisma.$transaction(async tx => {
            for (const event of tlsEvents) {
              const record = eventRecord(initial.id, event);
              await tx.runtimeEvent.upsert({ where: { eventId: record.eventId }, create: record, update: { count: { increment: event.count } } });
            }
          });
          tlsStoredInPrisma = true;
        } catch (_) {
          for (const event of tlsEvents) {
            saveRuntimeEvent(eventRecord(initial.id, event));
          }
        }
        if (tlsStoredInPrisma) {
          for (const event of tlsEvents) saveRuntimeEvent(eventRecord(initial.id, event));
        }
      }

      let aggregates = [];
      try {
        aggregates = await prisma.runtimeEvent.findMany({ where: { runId: initial.id }, orderBy: { timestamp: 'asc' } });
      } catch (_) {}
      if (!aggregates || aggregates.length === 0) {
        aggregates = getRuntimeEvents(initial.id);
      }

      const classifierEvents = aggregates.map(event => ({
        source: event.source,
        algorithm: event.algorithm,
        operation: event.operation,
        keyInfo: JSON.parse(event.keyInfo || '{}'),
        callerScript: event.callerScript,
        hostOrigin: event.hostOrigin,
        targetOrigin: initial.targetOrigin,
        scheme: event.scheme,
        port: event.port,
        crossOrigin: event.crossOrigin,
        count: event.count,
        timestamp: event.timestamp,
        language: event.language,
        library: event.library,
        mode: event.mode,
        curve: event.curve,
        hash: JSON.parse(event.keyInfo || '{}').hash || null,
        eventId: event.eventId,
      }));
      const classified = await classifyEvents(classifierEvents);
      const findings = [];
      for (const item of classified) {
        const event = item.event;
        const keyInfo = event.keyInfo || {};
        const eventForFinding = {
          ...event,
          mode: event.mode || keyInfo.mode,
          curve: event.curve || keyInfo.curve,
          hash: event.hash || keyInfo.hash,
          keySize: keyInfo.keySize || keyInfo.modulusLength || event.keySize,
        };
        const outputs = Array.isArray(item.finding) ? item.finding : [item.finding];
        outputs.forEach((finding, index) => findings.push(findingFromClassification(initial, eventForFinding, finding, String(index))));
      }
      if (probe && Array.isArray(probe.certificateFindings)) {
        for (const finding of probe.certificateFindings) {
          findings.push(findingFromClassification(initial, {
            source: 'tls', algorithm: finding.algorithm, operation: 'certificate',
            callerScript: `tls://${new URL(initial.targetOrigin).host}:0`,
            hostOrigin: initial.targetOrigin, timestamp: new Date(), count: 1,
          }, finding, 'certificate-analysis'));
        }
      }

      const stoppedAt = new Date();
      try {
        await prisma.$transaction(async tx => {
          if (findings.length) await tx.finding.createMany({ data: findings, skipDuplicates: true });
          await tx.runtimeRun.update({ where: { id: initial.id }, data: { status: 'stopped', stoppedAt, finishedAt: stoppedAt } });
          await tx.scan.update({ where: { id: initial.scanId }, data: { status: 'COMPLETED', completedAt: stoppedAt } });
        });
      } catch (dbErr) {
        console.warn('PostgreSQL unavailable during runtime stop, using devStore:', dbErr.message);
        try {
          await prisma.runtimeRun.update({ where: { id: initial.id }, data: { status: 'stopped', stoppedAt, finishedAt: stoppedAt } });
          await prisma.scan.update({ where: { id: initial.scanId }, data: { status: 'COMPLETED', completedAt: stoppedAt } });
        } catch (_) {}
      }
      saveFindings(initial.scanId, findings);
      updateRuntimeRun(initial.id, { status: 'stopped', stoppedAt, finishedAt: stoppedAt });
      const devScan = getScan(initial.scanId);
      if (devScan) {
        devScan.status = 'COMPLETED';
        devScan.completedAt = stoppedAt;
        saveScan(devScan);
      }
      return res.json({ id: initial.id, scanId: initial.scanId, status: 'stopped', eventCount: initial.eventCount, findingCount: findings.length });
    } catch (error) {
      try {
        await prisma.runtimeRun.update({ where: { id: initial.id }, data: { status: 'recording' } });
      } catch (_) {}
      updateRuntimeRun(initial.id, { status: 'recording' });
      throw error;
    }
  } catch (error) {
    next(error);
  }
});

router.validation = Object.freeze({ normalizeEvent, normalizeKeyInfo, getCallerScript });
module.exports = router;