'use strict';
const crypto = require('crypto');
const prisma = require('../utils/prismaClient');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(value, Object.keys(value).sort());
async function appendAuditLog(data) {
  try {
    const previous = await prisma.auditLog.findFirst({ orderBy: [{ createdAt: 'desc' }, { id: 'desc' }] });
    const record = { ...data, userId: data.userId || null, requestHash: data.requestHash || null, previousHash: previous?.entryHash || null };
    return await prisma.auditLog.create({ data: { ...record, entryHash: hash(canonical(record)) } });
  } catch (err) {
    // Database unavailable in local dev fallback — silent skip
    return null;
  }
}
function auditMiddleware(req, res, next) {
  res.on('finish', () => {
    if (req.method === 'GET' || req.path === '/health' || res.statusCode >= 500) return;
    const body = { ...req.body }; delete body.password; delete body.token; delete body.accessToken;
    appendAuditLog({ userId: req.user?.id, action: `${req.method} ${req.path}`, method: req.method, path: req.path, statusCode: res.statusCode, requestHash: hash(canonical(body)) }).catch(() => {});
  });
  next();
}
module.exports = { appendAuditLog, auditMiddleware };
