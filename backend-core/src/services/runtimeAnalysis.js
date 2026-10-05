'use strict';

const { spawn } = require('child_process');
const dns = require('dns').promises;
const net = require('net');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../../');
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;

function runPythonJson(script, payload, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const python = process.env.PYTHON_EXECUTABLE || (process.platform === 'win32' ? 'python' : 'python3');
    const child = spawn(python, [path.join(ROOT, script)], {
      cwd: ROOT,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      stdout += chunk;
      if (Buffer.byteLength(stdout) > MAX_OUTPUT_BYTES) child.kill();
    });
    child.stderr.on('data', chunk => {
      stderr += chunk;
      if (Buffer.byteLength(stderr) > 16 * 1024) stderr = stderr.slice(-16 * 1024);
    });
    child.on('error', error => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on('close', code => {
      clearTimeout(timeout);
      if (timedOut) return reject(new Error('Runtime analysis timed out.'));
      if (code !== 0) return reject(new Error(stderr.trim() || 'Runtime analysis process failed.'));
      try {
        resolve(JSON.parse(stdout));
      } catch (_) {
        reject(new Error('Runtime analysis returned invalid metadata.'));
      }
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

function isPublicAddress(address) {
  const version = net.isIP(address);
  if (version === 4) {
    const octets = address.split('.').map(Number);
    const [a, b] = octets;
    return !(
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && octets[2] === 0) ||
      (a === 192 && b === 0 && octets[2] === 2) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && octets[2] === 100))) ||
      (a === 203 && b === 0 && octets[2] === 113)
    );
  }
  if (version === 6) {
    const normalized = address.toLowerCase();
    if (normalized.startsWith('::ffff:')) return isPublicAddress(normalized.slice(7));
    return !(
      normalized === '::' || normalized === '::1' ||
      normalized.startsWith('fc') || normalized.startsWith('fd') ||
      /^fe[89ab]/.test(normalized) || normalized.startsWith('ff') ||
      normalized.startsWith('2001:db8:')
    );
  }
  return false;
}

async function resolvePublicAddress(hostname) {
  if (net.isIP(hostname)) return isPublicAddress(hostname) ? hostname : null;
  const addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(item => !isPublicAddress(item.address))) return null;
  return addresses[0].address;
}

async function classifyEvents(events) {
  return runPythonJson('scanner/runtime_classifier.py', { events });
}

async function probePublicTls(targetOrigin) {
  const target = new URL(targetOrigin);
  if (target.protocol !== 'https:' || target.hostname === 'localhost' || target.hostname.endsWith('.localhost')) return null;
  const address = await resolvePublicAddress(target.hostname);
  if (!address) return null;
  return runPythonJson('scanner/runtime_tls_probe.py', {
    host: target.hostname,
    port: Number(target.port || 443),
    address,
  }, 18000);
}

module.exports = { classifyEvents, isPublicAddress, probePublicTls, resolvePublicAddress };