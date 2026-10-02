'use strict';
/**
 * repoSecurity.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Input-validation helpers for hostile-repository hardening (Req 5).
 *
 * Env knobs (all optional, sane defaults apply):
 *   ALLOWED_GIT_HOSTS   – comma-separated extra HTTPS hosts (default: github.com)
 *   SSRF_BLOCK_METADATA – set "false" to skip cloud-metadata IP block (dev only)
 */

const { URL } = require('url');
const dns = require('dns').promises;
const net = require('net');

// ── Allowed HTTPS hosts for Git clone URLs ────────────────────────────────────
const ALLOWED_GIT_HOSTS = new Set(
  (process.env.ALLOWED_GIT_HOSTS || 'github.com,gitlab.com,bitbucket.org')
    .split(',')
    .map(h => h.trim().toLowerCase())
    .filter(Boolean)
);

// ── Private / loopback / link-local / cloud-metadata IP ranges ───────────────
// Blocks SSRF to localhost, RFC-1918 ranges, IPv6 loopback, and AWS/GCP/Azure
// instance-metadata endpoints (169.254.169.254, fd00::ec2, etc.)
const BLOCKED_CIDRS = [
  // Loopback
  { start: ipToLong('127.0.0.0'),   end: ipToLong('127.255.255.255') },
  // RFC-1918 private
  { start: ipToLong('10.0.0.0'),    end: ipToLong('10.255.255.255')  },
  { start: ipToLong('172.16.0.0'),  end: ipToLong('172.31.255.255')  },
  { start: ipToLong('192.168.0.0'), end: ipToLong('192.168.255.255') },
  // Link-local / cloud metadata (AWS IMDSv1/v2, GCP, Azure)
  { start: ipToLong('169.254.0.0'), end: ipToLong('169.254.255.255') },
  // Carrier-grade NAT
  { start: ipToLong('100.64.0.0'),  end: ipToLong('100.127.255.255') },
];

function ipToLong(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isPrivateIPv4(ip) {
  if (!net.isIPv4(ip)) return false;
  const n = ipToLong(ip);
  return BLOCKED_CIDRS.some(r => n >= r.start && n <= r.end);
}

function isPrivateIPv6(ip) {
  if (!net.isIPv6(ip)) return false;
  const lower = ip.toLowerCase();
  // ::1 loopback
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
  // fc00::/7 unique-local (includes fd00::)
  const first16 = parseInt(lower.split(':')[0] || '0', 16);
  if ((first16 & 0xfe00) === 0xfc00) return true;
  // fe80::/10 link-local
  if ((first16 & 0xffc0) === 0xfe80) return true;
  return false;
}

/**
 * Validates a git URL:
 *  - Must be https://
 *  - Host must be in ALLOWED_GIT_HOSTS
 *  - Resolves host to IP and blocks private/SSRF ranges
 *  - Path must look like /owner/repo (or /owner/repo.git)
 *
 * @param {string} rawUrl
 * @returns {Promise<{owner:string, repo:string, safeUrl:string}>}
 * @throws {Error} with a user-safe message on any violation
 */
async function validateGitUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    throw new Error('Repository URL is required');
  }

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new Error('Repository URL is not a valid URL');
  }

  if (parsed.protocol !== 'https:') {
    throw new Error('Only HTTPS repository URLs are allowed');
  }

  const host = parsed.hostname.toLowerCase();
  if (!ALLOWED_GIT_HOSTS.has(host)) {
    throw new Error(
      `Repository host "${host}" is not allowed. Allowed hosts: ${[...ALLOWED_GIT_HOSTS].join(', ')}`
    );
  }

  // DNS-resolve the host and verify it doesn't resolve to a private IP
  if (process.env.SSRF_BLOCK_METADATA !== 'false') {
    try {
      const results = await dns.lookup(host, { all: true, family: 0 });
      for (const { address, family } of results) {
        if ((family === 4 && isPrivateIPv4(address)) || (family === 6 && isPrivateIPv6(address))) {
          throw new Error('Repository URL resolves to a private or reserved IP address (SSRF blocked)');
        }
      }
    } catch (err) {
      if (err.message.includes('SSRF')) throw err;
      // DNS failure is not a reason to reject — fall through; the actual fetch
      // will fail naturally if the host is unreachable.
    }
  }

  // Extract and validate owner/repo from path
  const parts = parsed.pathname.split('/').filter(Boolean);
  if (parts.length < 2) {
    throw new Error('Repository URL must contain an owner and a repository name (e.g. https://github.com/owner/repo)');
  }
  
  const decodedParts = parts.map(p => decodeURIComponent(p));
  if (decodedParts.some(p => p === '.' || p === '..')) {
    throw new Error('Repository URL contains path traversal sequences');
  }

  const owner = decodedParts[0];
  const repoName = decodedParts[1].trim().replace(/\.git$/i, '').replace(/\.*$/, '');

  const SAFE_SEGMENT = /^[A-Za-z0-9_.-]{1,100}$/;
  if (!SAFE_SEGMENT.test(owner) || !SAFE_SEGMENT.test(repoName)) {
    throw new Error('Repository owner or name contains disallowed characters');
  }
  
  if (owner === '..' || repoName === '..') {
    throw new Error('Repository URL contains path traversal sequences');
  }

  const safeUrl = `https://${host}/${owner}/${repoName}`;
  return { owner, repo: repoName, host, safeUrl };
}

/**
 * Sanitizes a user-supplied repository name for safe use in the database and
 * API responses.  Strips control chars, limits length.
 */
function sanitizeRepoName(name) {
  if (!name || typeof name !== 'string') return 'unnamed-repo';
  return name
    .replace(/[\x00-\x1f\x7f]/g, '') // strip control characters
    .replace(/[<>"'`]/g, '')          // strip HTML/JS injection chars
    .trim()
    .slice(0, 200)                    // hard cap
    || 'unnamed-repo';
}

/**
 * Sanitizes a file path coming from scanner output before it is stored in the
 * DB or returned in API responses.  Strips path traversal and null bytes.
 */
function sanitizeFilePath(filePath) {
  if (!filePath || typeof filePath !== 'string') return '';
  return filePath
    .replace(/\0/g, '')               // null bytes
    .replace(/\.\.[/\\]/g, '')        // path traversal
    .replace(/^[/\\]+/, '')           // leading slashes
    .replace(/[\x00-\x1f\x7f]/g, '') // control chars
    .trim()
    .slice(0, 500);
}

/**
 * Caps code snippet length to prevent huge payloads in API responses and
 * log injection.
 */
function sanitizeSnippet(snippet, maxLen) {
  maxLen = maxLen || Number(process.env.MAX_SNIPPET_LENGTH) || 500;
  if (!snippet || typeof snippet !== 'string') return '';
  return snippet.slice(0, maxLen);
}

module.exports = {
  validateGitUrl,
  sanitizeRepoName,
  sanitizeFilePath,
  sanitizeSnippet,
  isPrivateIPv4,
  isPrivateIPv6,
};
