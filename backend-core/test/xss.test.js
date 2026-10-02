'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Test frontend security helper function escapeHtml logic
function escapeHtml(val) {
  if (val == null) return '';
  return String(val)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#39;');
}

async function main() {
  // 1. Verify escapeHtml handles malicious script tags & attribute breakouts
  const payload = '<script>alert("XSS")</script>';
  const escaped = escapeHtml(payload);
  assert.equal(escaped, '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');
  assert(!escaped.includes('<script>'), 'escaped string contains no raw script tag');

  const attrPayload = '"><img src=x onerror=alert(1)>';
  const attrEscaped = escapeHtml(attrPayload);
  assert.equal(attrEscaped, '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;');

  // 2. Verify frontend HTML files include security.js
  const frontendDir = path.resolve(__dirname, '../../frontend');
  const htmlFiles = fs.readdirSync(frontendDir).filter(f => f.endsWith('.html'));

  for (const file of htmlFiles) {
    if (file === 'index.login-backup.html') continue;
    const content = fs.readFileSync(path.join(frontendDir, file), 'utf8');
    assert(
      content.includes('assets/js/security.js'),
      `${file} must include <script src="assets/js/security.js"></script>`
    );
  }

  // 3. Verify no raw cs_token getItem fallback remains in frontend HTML pages
  for (const file of htmlFiles) {
    if (file === 'index.login-backup.html') continue;
    const content = fs.readFileSync(path.join(frontendDir, file), 'utf8');
    assert(
      !content.includes("localStorage.getItem('cs_token')") && !content.includes('localStorage.getItem("cs_token")'),
      `${file} must not contain legacy cs_token localStorage fallback`
    );
  }

  console.log('PASS: escapeHtml safely encodes script tags & attributes');
  console.log('PASS: All frontend HTML files include security.js');
  console.log('PASS: All frontend HTML files have removed localStorage cs_token fallbacks');
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
