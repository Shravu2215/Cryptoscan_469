/**
 * CSRF Protection Middleware for Cookie-based Endpoints
 * (P0-7 Security requirement)
 *
 * Validates the presence of custom X-Requested-With header on state-changing requests.
 */

module.exports = function csrfCheck(req, res, next) {
  const customHeader = req.headers['x-requested-with'];
  if (!customHeader || customHeader !== 'CryptoScan') {
    return res.status(403).json({
      error: {
        code: 'CSRF_REJECTED',
        message: 'Forbidden: Missing or invalid X-Requested-With header.',
      },
    });
  }
  next();
};
