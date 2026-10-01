'use strict';
const crypto = require('crypto');
const prisma = require('../utils/prismaClient');
const { isDev, logStructuredError, serviceUnavailable } = require('../utils/failClosed');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(value, Object.keys(value).sort());
async function appendAuditLog(data) {
  try {
    const previous = await prisma.auditLog.findFirst({ orderBy: [{ createdAt: 'desc' }, { id: 'desc' }] });
    const record = { ...data, userId: data.userId || null, requestHash: data.requestHash || null, previousHash: previous?.entryHash || null };
    return await prisma.auditLog.create({ data: { ...record, entryHash: hash(canonical(record)) } });
  } catch (err) {
    if (!isDev) throw serviceUnavailable('audit_log.write_failed', err, { action: data.action });
    logStructuredError('audit_log.write_failed', err, { action: data.action }, 'warning');
    return null;
  }
}
function auditMiddleware(req, res, next) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) || req.path === '/health') return next();

  const send = res.send.bind(res);
  let auditAttempted = false;
  res.send = body => {
    if (auditAttempted) return send(body);
    auditAttempted = true;

    const requestBody = { ...req.body };
    delete requestBody.password;
    delete requestBody.token;
    delete requestBody.accessToken;
    const auditEntry = {
      userId: req.user?.id,
      action: `${req.method} ${req.path}`,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      requestHash: hash(canonical(requestBody)),
    };

    appendAuditLog(auditEntry).then(() => send(body)).catch(() => {
      if (isDev) return send(body);
      res.statusCode = 503;
      res.type('application/json');
      return send(JSON.stringify({ error: { code: 'SERVICE_UNAVAILABLE', message: 'Audit logging unavailable' } }));
    });
    return res;
  };
  next();
}
module.exports = { appendAuditLog, auditMiddleware };
