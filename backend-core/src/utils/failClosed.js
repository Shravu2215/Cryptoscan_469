'use strict';

const isDev = process.env.NODE_ENV === 'development';

function logStructuredError(event, err, context = {}, level = 'error') {
  const log = {
    level,
    event,
    ...context,
    error: {
      name: err?.name || 'Error',
      code: err?.code || null,
      message: err?.message || String(err),
    },
  };
  (level === 'error' ? console.error : console.warn)(JSON.stringify(log));
}

function serviceUnavailable(event, err, context = {}) {
  logStructuredError(event, err, context);
  const wrapped = new Error('Service temporarily unavailable');
  wrapped.status = 503;
  wrapped.code = 'SERVICE_UNAVAILABLE';
  wrapped.logged = true;
  wrapped.cause = err;
  return wrapped;
}

function sendError(res, err, event) {
  if (!err?.logged) logStructuredError(event, err);
  const status = err?.status || 500;
  const code = err?.code || 'INTERNAL_SERVER_ERROR';
  const message = status === 503 ? 'Service temporarily unavailable' : 'Internal server error';
  return res.status(status).json({ error: { code, message } });
}

module.exports = { isDev, logStructuredError, serviceUnavailable, sendError };