/**
 * Quick verification: print the matrix values for ECDSA P-256 → ML-DSA-65
 * with no user limits and no scanned evidence (simulating pqc-test-fixture.zip scan).
 */
if (typeof window === 'undefined') {
  const { JSDOM } = require('jsdom');
  const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
  global.window = dom.window;
  global.document = dom.window.document;
  const fs = require('fs');
  const path = require('path');
  eval(fs.readFileSync(path.resolve(__dirname, '..', 'assets', 'js', 'pqcSizes.js'), 'utf-8'));
}

const PQCSizes = window.PQCSizes;

console.log('=== ECDSA P-256 → ML-DSA-65 (no user limits, no scanned evidence) ===\n');
const res = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', {}, {});

console.log('KPIs:');
console.log(`  PK: ${res.kpis.pkBefore} → ${res.kpis.pkAfter} B (${res.kpis.pkMultiplier}x)`);
console.log(`  Sig: ${res.kpis.sigBefore} → ${res.kpis.sigAfter} B (${res.kpis.sigMultiplier}x)`);
console.log(`  Affected: ${res.kpis.affectedScenariosCount} of 6`);
console.log(`  Verdict: ${res.kpis.verdict}`);

console.log('\nMatrix rows:');
res.matrix.forEach(r => {
  const limitStr = r.limit != null ? `${r.limit.toLocaleString()} B` : 'N/A';
  console.log(`\n  [${r.id}] ${r.name}`);
  console.log(`    Before: ${r.beforeSize.toLocaleString()} B`);
  console.log(`    After:  ${r.afterSize.toLocaleString()} B`);
  console.log(`    Limit:  ${r.limitDisplay || limitStr}`);
  console.log(`    Status: ${r.status}`);
  console.log(`    Evidence: ${r.evidence}`);
  if (r.displayLabel) console.log(`    Display: ${r.displayLabel}`);
  if (r.overLimitText) console.log(`    Over: ${r.overLimitText}`);
  console.log(`    Breakdown: ${r.breakdown}`);
});

console.log('\n\n=== With user-entered cookie limit of 4096 ===\n');
const res2 = PQCSizes.computeSimulation('ECDSA P-256', 'ML-DSA-65', 'pure', { cookieLimit: 4096 }, {});
const jwt2 = res2.matrix.find(r => r.id === 'jwt');
console.log(`  [jwt] Status: ${jwt2.status}`);
console.log(`  [jwt] Evidence: ${jwt2.evidence}`);
console.log(`  Verdict: ${res2.kpis.verdict}`);
