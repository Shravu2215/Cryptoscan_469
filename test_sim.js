const fs = require('fs');
const pqcSizesCode = fs.readFileSync('frontend/assets/js/pqcSizes.js', 'utf8').replace('window.PQCSizes = ', 'const PQCSizes = ');
const simCode = fs.readFileSync('frontend/assets/js/pqcSimulator.js', 'utf8').replace('(function() {', '').replace('})();', '');

const raw = JSON.parse(fs.readFileSync('scan_demo_output.json', 'utf8'));
const scans = raw.scans || [raw];
const findings = scans[0].findings || [];
const classicalKey = 'ECDSA P-256';

const document = { addEventListener: () => {} };
const window = {};
eval(pqcSizesCode + ';' + simCode + ';');

const table = [];
for (const f of findings) {
  let fNorm = null;
  if (f.algorithm) fNorm = PQCSizes.normalizeAlgo(f.algorithm);
  if (!fNorm) {
    const lib = (f.library || f.category || '').toLowerCase().trim();
    fNorm = PQCSizes.normalizeAlgo(LIB_TO_ALGO[lib]) || PQCSizes.normalizeAlgo(lib);
  }
  if (!fNorm) {
    const snippet = (f.codeSnippet || f.rawCallSite || f.description || '');
    fNorm = PQCSizes.normalizeAlgo(snippet);
  }
  
  const included = findingMatchesAlgo(f, classicalKey);
  table.push({
    file: f.file || f.filePath,
    line: f.line || f.lineNumber,
    algorithm: f.algorithm || '-',
    normalized: fNorm || '-',
    included: included
  });
}
console.table(table.filter(t => t.included));
