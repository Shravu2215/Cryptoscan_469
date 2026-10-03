/**
 * Unit Tests for PQC Simulator — Mitigation Text & IoT Display
 *
 * Run in browser console or via Node.js with jsdom after loading pqcSizes.js.
 * These test the data engine only (no DOM rendering).
 *
 * Usage (Node.js):
 *   1. npm install jsdom
 *   2. node frontend/tests/pqcMitigationTests.js
 */

// ── Minimal shim if running under Node ──────────────────────────────────────
if (typeof window === 'undefined') {
  // Create a minimal window/document so pqcSizes.js can attach itself
  const { JSDOM } = require('jsdom');
  const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
  global.window = dom.window;
  global.document = dom.window.document;

  // Load the data engine
  const fs = require('fs');
  const path = require('path');
  const pqcSizesPath = path.resolve(__dirname, '..', 'assets', 'js', 'pqcSizes.js');
  const code = fs.readFileSync(pqcSizesPath, 'utf-8');
  eval(code);
}

const PQCSizes = window.PQCSizes;

let passed = 0;
let failed = 0;

function assert(condition, testName) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${testName}`);
  } else {
    failed++;
    console.error(`  ✗ FAIL: ${testName}`);
  }
}

function assertIncludes(str, sub, testName) {
  assert(str.includes(sub), `${testName} — expected "${sub}" in "${str.substring(0, 120)}…"`);
}

function assertNotIncludes(str, sub, testName) {
  assert(!str.includes(sub), `${testName} — should NOT contain "${sub}"`);
}

// ──────────────────────────────────────────────────────────────────────────────
console.log('\n=== QR Code Mitigation Tests ===');

// Test 1: ECC Level L → "Already at maximum capacity"
(function testQrLevelL() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', { qrEccLevel: 'L' });
  const qrRow = res.matrix.find(r => r.id === 'qr');
  assertIncludes(qrRow.mitigation, 'Already at maximum capacity', 'QR Level L: says "Already at maximum capacity"');
  assertNotIncludes(qrRow.mitigation, 'lower ECC', 'QR Level L: does NOT say "use lower ECC level"');
  assertIncludes(qrRow.mitigation, 'structured append', 'QR Level L: suggests structured append');
  assertIncludes(qrRow.mitigation, 'CBOR/zlib', 'QR Level L: suggests CBOR/zlib');
})();

// Test 2: ECC Level M → "Switch to ECC level L"
(function testQrLevelM() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', { qrEccLevel: 'M' });
  const qrRow = res.matrix.find(r => r.id === 'qr');
  assertIncludes(qrRow.mitigation, 'Switch to ECC level L', 'QR Level M: suggests switching to L');
  assertIncludes(qrRow.mitigation, '2953 B', 'QR Level M: mentions L capacity 2953');
})();

// Test 3: ECC Level Q → same as M
(function testQrLevelQ() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', { qrEccLevel: 'Q' });
  const qrRow = res.matrix.find(r => r.id === 'qr');
  assertIncludes(qrRow.mitigation, 'Switch to ECC level L', 'QR Level Q: suggests switching to L');
})();

// Test 4: ECC Level H → same as M
(function testQrLevelH() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', { qrEccLevel: 'H' });
  const qrRow = res.matrix.find(r => r.id === 'qr');
  assertIncludes(qrRow.mitigation, 'Switch to ECC level L', 'QR Level H: suggests switching to L');
})();

// ──────────────────────────────────────────────────────────────────────────────
console.log('\n=== IoT Mitigation Tests ===');

// Test 5: BLE_ATT → negotiate larger ATT MTU
(function testIotBleAtt() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', { iotProfile: 'BLE_ATT' });
  const iotRow = res.matrix.find(r => r.id === 'iot');
  assertIncludes(iotRow.mitigation, 'Negotiate a larger ATT MTU', 'BLE_ATT: mentions negotiate ATT MTU');
  assertIncludes(iotRow.mitigation, 'up to 512 B', 'BLE_ATT: mentions max 512 B MTU');
  assertIncludes(iotRow.mitigation, 'packets instead of', 'BLE_ATT: shows packet count comparison');
  assertIncludes(iotRow.mitigation, 'gateway verify', 'BLE_ATT: suggests gateway verification');
  // Verify packet counts are real numbers
  const pqcSig = 3309; // ML-DSA-65 sig
  const expectedFrags = Math.ceil(pqcSig / 20); // 166
  const expectedAtMax = Math.ceil(pqcSig / 512); // 7
  assertIncludes(iotRow.mitigation, `${expectedAtMax} packets instead of ${expectedFrags}`, 'BLE_ATT: correct packet counts');
})();

// Test 6: LoRaWAN → application-layer fragmentation
(function testIotLoRaWAN() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', { iotProfile: 'LoRaWAN_SF12' });
  const iotRow = res.matrix.find(r => r.id === 'iot');
  assertIncludes(iotRow.mitigation, 'application-layer fragmentation', 'LoRaWAN: mentions app-layer fragmentation');
  assertIncludes(iotRow.mitigation, 'hash/ID', 'LoRaWAN: suggests hash/ID off-device');
})();

// Test 7: IEEE_802_15_4 → 6LoWPAN fragmentation
(function testIotIeee() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', { iotProfile: 'IEEE_802_15_4' });
  const iotRow = res.matrix.find(r => r.id === 'iot');
  assertIncludes(iotRow.mitigation, '6LoWPAN fragmentation', 'IEEE 802.15.4: mentions 6LoWPAN fragmentation');
})();

// Test 8: CoAP_UDP → blockwise transfer
(function testIotCoap() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', { iotProfile: 'CoAP_UDP' });
  const iotRow = res.matrix.find(r => r.id === 'iot');
  assertIncludes(iotRow.mitigation, 'CoAP blockwise transfer', 'CoAP_UDP: mentions blockwise transfer');
  assertIncludes(iotRow.mitigation, 'RFC 7959', 'CoAP_UDP: mentions RFC 7959');
})();

// Test 9: DTLS_UDP → DTLS fragmentation
(function testIotDtls() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', { iotProfile: 'DTLS_UDP' });
  const iotRow = res.matrix.find(r => r.id === 'iot');
  assertIncludes(iotRow.mitigation, 'DTLS fragmentation', 'DTLS_UDP: mentions DTLS fragmentation');
  assertIncludes(iotRow.mitigation, '1280', 'DTLS_UDP: mentions path MTU 1280');
})();

// ──────────────────────────────────────────────────────────────────────────────
console.log('\n=== IoT Display Tests ===');

// Test 10: IoT BLE_ATT display shows "N packets needed" not "16545% limit"
(function testIotDisplay() {
  const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', { iotProfile: 'BLE_ATT' });
  const iotRow = res.matrix.find(r => r.id === 'iot');
  assertIncludes(iotRow.displayLabel, 'packets needed', 'IoT BLE_ATT: displayLabel says "packets needed"');
  assertNotIncludes(iotRow.displayLabel, '% limit', 'IoT BLE_ATT: displayLabel does NOT show % limit');
  assert(typeof iotRow.overLimitText === 'string', 'IoT BLE_ATT: overLimitText is present');
  assertIncludes(iotRow.overLimitText, 'x over limit', 'IoT BLE_ATT: overLimitText says "Nx over limit"');
  assert(iotRow.displayPct <= 100, 'IoT BLE_ATT: displayPct is capped ≤ 100');
})();

// Test 11: IoT where payload fits → normal % display
(function testIotFits() {
  // AES → AES-256-GCM is noPayloadImpact, so use Ed25519 → Falcon-512 (sig=666)
  // with CoAP_UDP limit 1152 → 666 fits
  const res = PQCSizes.computeSimulation('Ed25519', 'Falcon-512', 'pure', { iotProfile: 'CoAP_UDP' });
  const iotRow = res.matrix.find(r => r.id === 'iot');
  assert(iotRow.displayLabel.includes('% limit'), 'IoT CoAP fits: displayLabel shows normal % limit');
  assert(iotRow.overLimitText === null, 'IoT CoAP fits: overLimitText is null');
})();

// ──────────────────────────────────────────────────────────────────────────────
console.log('\n\n' + '='.repeat(50));
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.error('SOME TESTS FAILED');
  if (typeof process !== 'undefined') process.exit(1);
} else {
  console.log('ALL TESTS PASSED ✓');
}
