'use strict';

const crypto = require('crypto');
const express = require('express');
const { requireAuth } = require('../middleware/auth');
const prisma = require('../utils/prismaClient');
const { runtimeEventToFinding } = require('../services/runtimeFinding');

const router = express.Router();
const MAX_BODY_BYTES = 64 * 1024;
const MAX_EVENTS_PER_BATCH = 100;
const ALGORITHM_PATTERN = /^(?:Math\.random|CSPRNG|crypto\.getRandomValues|secrets|os\.urandom|uuid\.uuid4|SSLContext|Python random\.(?:random|randint|randrange|choice|choices|uniform|getrandbits|randbytes|shuffle|sample|triangular|normalvariate|gauss|lognormvariate|expovariate|vonmisesvariate|gammavariate|betavariate|paretovariate|weibullvariate)|MD5|SHA-1|SHA-256|SHA-384|SHA-512|SHA3(?:-256|-384|-512)?|SHA-3(?:-256|-384|-512)?|Keccak-256|AES(?:-(?:GCM|CBC|CTR|ECB))?|RSA(?:-(?:OAEP|PSS))?|RSASSA-PKCS1-v1_5|ECDSA|ECDH|Ed25519|Ed448|secp256k1|ECDSA secp256k1|HMAC(?:-(?:MD5|SHA-(?:1|256|384|512)))?|HKDF|PBKDF2|eth_sendTransaction|personal_sign|eth_signTypedData(?:_v\d+)?|eth_requestAccounts|JWT (?:HS256|RS256|none))$/;
const OPERATIONS = new Set([
  'digest', 'generateKey', 'importKey', 'encrypt', 'decrypt', 'sign', 'verify',
  'deriveKey', 'deriveBits', 'random', 'wallet', 'hash', 'hmac', 'tls', 'other',
]);
const EVENT_FIELDS = new Set(['algorithm', 'operation', 'keyInfo', 'callSite', 'timestamp', 'count', 'language']);
const KEY_INFO_FIELDS = new Set(['keySize', 'curve', 'mode', 'hash', 'padding']);
const KEY_INFO_VALUES = {
  curve: new Set(['P-256', 'P-384', 'P-521', 'secp256k1', 'Ed25519', 'Ed448']),
  mode: new Set(['GCM', 'CBC', 'CTR', 'ECB']),
  hash: new Set(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384', 'SHA3-512']),
  padding: new Set(['RSA-PSS', 'RSA-OAEP', 'RSASSA-PKCS1-v1_5']),
};

function tokenDigest(token) {
  return crypto.createHash('sha256').update(token).digest();
}

function isCallSite(value) {
  if (/^unknown:\d+$/.test(value)) return true;
  const match = value.match(/^(.+):(\d+)$/);
  if (!match) return false;
  const source = match[1];
  const extension = /\.(?:cjs|html|js|jsx|mjs|py|ts|tsx|wasm)$/i;
  if (/^https?:\/\//i.test(source) || /^file:\/\//i.test(source)) {
    try {
      const parsed = new URL(source);
      return !parsed.username && !parsed.password && extension.test(parsed.pathname);
    } catch (_) {
      return false;
    }
  }
  return !/[?#\r\n\0]/.test(source)
    && (/^(?:[A-Za-z]:[\\/]|\/|\.\.?[\\/])/.test(source) || /^[A-Za-z0-9._~-]/.test(source))
    && extension.test(source);
}

function normalizeEvent(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  if (Object.keys(input).some(key => !EVENT_FIELDS.has(key))) return null;
  if (typeof input.algorithm !== 'string' || input.algorithm.length < 1 || input.algorithm.length > 100 || !ALGORITHM_PATTERN.test(input.algorithm)) return null;
  if (typeof input.operation !== 'string' || !OPERATIONS.has(input.operation)) return null;
  if (typeof input.callSite !== 'string' || input.callSite.length > 600) return null;
  if (!input.keyInfo || typeof input.keyInfo !== 'object' || Array.isArray(input.keyInfo)) return null;
  if (Object.keys(input.keyInfo).some(key => !KEY_INFO_FIELDS.has(key))) return null;
  const count = input.count === undefined ? 1 : Number(input.count);
  if (!Number.isSafeInteger(count) || count < 1 || count > 1000000) return null;
  if (input.timestamp !== undefined && (typeof input.timestamp !== 'string' || input.timestamp.length > 40 || !Number.isFinite(Date.parse(input.timestamp)))) return null;
  if (input.language !== undefined && !['JavaScript', 'Python'].includes(input.language)) return null;

  const keyInfo = {};
  if (input.keyInfo.keySize !== undefined) {
    const keySize = Number(input.keyInfo.keySize);
    if (!Number.isSafeInteger(keySize) || keySize < 1 || keySize > 65536) return null;
    keyInfo.keySize = keySize;
  }
  for (const field of ['curve', 'mode', 'hash', 'padding']) {
    if (input.keyInfo[field] !== undefined) {
      if (typeof input.keyInfo[field] !== 'string' || !KEY_INFO_VALUES[field].has(input.keyInfo[field])) return null;
      keyInfo[field] = input.keyInfo[field];
    }
  }
  const callSite = input.callSite.replace(/[?#].*$/, '').replace(/[\r\n\0]/g, '').slice(0, 500) || 'unknown:0';
  if (!isCallSite(callSite)) return null;
  return {
    algorithm: input.algorithm.trim(),
    operation: input.operation,
    keyInfo,
    keyInfoJson: JSON.stringify(keyInfo),
    callSite,
    count,
    timestamp: input.timestamp ? new Date(input.timestamp) : new Date(),
    language: input.language || 'JavaScript',
  };
}

async function getOwnedSession(id, userId) {
  return prisma.runtimeSession.findFirst({ where: { id, userId } });
}

router.post('/', requireAuth, async (req, res, next) => {
  try {
    const id = crypto.randomUUID();
    const ingestToken = crypto.randomBytes(32).toString('base64url');
    const repo = await prisma.$transaction(async tx => {
      const createdRepo = await tx.repo.create({
        data: {
          name: `Runtime Analysis ${id.slice(0, 8)}`,
          filePath: `runtime-session:${id}`,
          uploadedBy: req.user.id,
          businessCriticality: 'Not tagged',
        },
      });
      const scan = await tx.scan.create({ data: { repoId: createdRepo.id, status: 'RUNNING' } });
      await tx.runtimeSession.create({
        data: {
          id,
          userId: req.user.id,
          scanId: scan.id,
          ingestTokenHash: tokenDigest(ingestToken).toString('hex'),
        },
      });
      return { scanId: scan.id };
    });
    const ingestUrl = `${req.protocol}://${req.get('host')}/api/runtime/sessions/${id}/events`;
    return res.status(201).json({ id, ingestToken, status: 'recording', startedAt: new Date().toISOString(), scanId: repo.scanId, ingestUrl });
  } catch (err) {
    next(err);
  }
});

router.post('/:id/events', async (req, res, next) => {
  try {
    const bodySize = Math.max(Number(req.headers['content-length'] || 0), Buffer.byteLength(JSON.stringify(req.body || {})));
    if (bodySize > MAX_BODY_BYTES) return res.status(413).json({ error: 'Runtime event batch exceeds 64 KB.' });
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body) || Object.keys(req.body).some(key => key !== 'events')) {
      return res.status(400).json({ error: 'Runtime payload may contain only the events array.' });
    }
    const events = req.body && req.body.events;
    if (!Array.isArray(events) || events.length > MAX_EVENTS_PER_BATCH) {
      return res.status(400).json({ error: `events must be an array with at most ${MAX_EVENTS_PER_BATCH} items.` });
    }
    const token = req.get('x-cryptoscan-token') || '';
    if (!/^[A-Za-z0-9_-]{32,100}$/.test(token)) return res.status(401).json({ error: 'Invalid ingest token.' });
    const session = await prisma.runtimeSession.findUnique({ where: { id: req.params.id } });
    if (!session || session.status !== 'recording') return res.status(404).json({ error: 'Recording session not found.' });
    const suppliedDigest = tokenDigest(token);
    const expectedDigest = Buffer.from(session.ingestTokenHash, 'hex');
    if (suppliedDigest.length !== expectedDigest.length || !crypto.timingSafeEqual(suppliedDigest, expectedDigest)) {
      return res.status(401).json({ error: 'Invalid ingest token.' });
    }
    const normalized = events.map(normalizeEvent);
    if (normalized.some(event => !event)) return res.status(400).json({ error: 'Event contains invalid or non-metadata fields.' });

    const increment = normalized.reduce((total, event) => total + event.count, 0);
    const accepted = await prisma.$transaction(async tx => {
      const sessionUpdate = await tx.runtimeSession.updateMany({
        where: { id: session.id, status: 'recording' },
        data: { eventCount: { increment } },
      });
      if (sessionUpdate.count !== 1) return false;
      for (const event of normalized) {
        await tx.runtimeObservedEvent.upsert({
          where: {
            sessionId_algorithm_operation_keyInfo_callSite: {
              sessionId: session.id,
              algorithm: event.algorithm,
              operation: event.operation,
              keyInfo: event.keyInfoJson,
              callSite: event.callSite,
            },
          },
          create: {
            sessionId: session.id,
            algorithm: event.algorithm,
            operation: event.operation,
            keyInfo: event.keyInfoJson,
            callSite: event.callSite,
            language: event.language,
            count: event.count,
            timestamp: event.timestamp,
          },
          update: { count: { increment: event.count } },
        });
      }
      return true;
    });
    if (!accepted) return res.status(409).json({ error: 'Runtime session is no longer recording.' });
    const latest = await prisma.runtimeSession.findUnique({ where: { id: session.id }, select: { eventCount: true } });
    return res.json({ accepted: increment, eventCount: latest.eventCount });
  } catch (err) {
    next(err);
  }
});

router.get('/:id', requireAuth, async (req, res, next) => {
  try {
    const session = await getOwnedSession(req.params.id, req.user.id);
    if (!session) return res.status(404).json({ error: 'Runtime session not found.' });
    return res.json({ id: session.id, scanId: session.scanId, status: session.status, startedAt: session.startedAt, stoppedAt: session.stoppedAt, eventCount: session.eventCount });
  } catch (err) {
    next(err);
  }
});

router.post('/:id/stop', requireAuth, async (req, res, next) => {
  try {
    const result = await prisma.$transaction(async tx => {
      const session = await tx.runtimeSession.findFirst({ where: { id: req.params.id, userId: req.user.id } });
      if (!session) return null;
      if (session.status === 'stopped') return { scanId: session.scanId, eventCount: session.eventCount, findingCount: null };
      const stoppedAt = new Date();
      const claimed = await tx.runtimeSession.updateMany({
        where: { id: session.id, userId: req.user.id, status: 'recording' },
        data: { status: 'stopped', stoppedAt },
      });
      if (claimed.count !== 1) return { scanId: session.scanId, eventCount: session.eventCount, findingCount: null };
      const events = await tx.runtimeObservedEvent.findMany({ where: { sessionId: session.id }, orderBy: { id: 'asc' } });
      const findings = events.map(event => runtimeEventToFinding(session.id, {
        algorithm: event.algorithm,
        operation: event.operation,
        keyInfo: JSON.parse(event.keyInfo),
        callSite: event.callSite,
        count: event.count,
        timestamp: event.timestamp,
        language: event.language,
        scanId: session.scanId,
      })).filter(Boolean);
      if (findings.length) await tx.finding.createMany({ data: findings });
      await tx.scan.update({ where: { id: session.scanId }, data: { status: 'COMPLETED', completedAt: stoppedAt } });
      return { scanId: session.scanId, eventCount: session.eventCount, findingCount: findings.length };
    });
    if (!result) return res.status(404).json({ error: 'Runtime session not found.' });
    return res.json({ status: 'stopped', ...result });
  } catch (err) {
    next(err);
  }
});

router.normalizeEvent = normalizeEvent;
router.isCallSite = isCallSite;
module.exports = router;