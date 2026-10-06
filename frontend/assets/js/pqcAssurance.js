'use strict';

(() => {
  const byId = id => document.getElementById(id);
  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  const params = new URLSearchParams(location.search);
  const selectedFindingId = params.get('findingId') || '';
  const fromAlgorithm = params.get('from') || '';
  const toAlgorithm = params.get('to') || '';
  const requestedScanId = params.get('scanId') || '';
  const sourceLabel = params.get('source') || '';
  let currentScan = null;
  let candidates = [];
  let searchText = '';
  const evidenceByFinding = new Map();

  function dateLabel(value) {
    if (!value) return 'Not recorded';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }

  function scanList(data) {
    if (Array.isArray(data.scans) && data.scans.length) return data.scans;
    return data.activeScan ? [data.activeScan] : [];
  }

  function findCurrentScan(data) {
    const scans = scanList(data);
    if (requestedScanId) {
      return scans.find(scan => [scan.id, scan.scanId, scan.repoId].some(id => id != null && String(id) === requestedScanId)) || null;
    }
    if (data.activeScan) return data.activeScan;
    return scans.slice().sort((a, b) => new Date(b.scanDate || b.createdAt || 0) - new Date(a.scanDate || a.createdAt || 0))[0] || null;
  }

  function asNumber(value) {
    if (value === null || value === undefined || value === '') return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  function renderPosture(scan) {
    const summary = byId('assurance-summary');
    const assets = Array.isArray(scan?.cbom) ? scan.cbom : [];
    if (!assets.length) {
      byId('assurance-posture-score').textContent = 'Not yet verified';
      summary.innerHTML = ['PQC-safe', 'Hybrid', 'Still vulnerable', 'Unknown'].map(label =>
        `<article class="assurance-stat"><span>${label}</span><strong>Not yet verified</strong></article>`).join('');
      return;
    }

    const counts = { safe: 0, hybrid: 0, vulnerable: 0, unknown: 0 };
    assets.forEach(asset => {
      const algorithm = asset.algorithm || asset.name || '';
      const combined = `${algorithm} ${asset.library || ''}`;
      const rule = window.QuantumRules?.lookup(algorithm);
      const risk = String(asset.quantumRisk || '').toLowerCase();
      if (/\bhybrid\b/i.test(combined)) counts.hybrid += 1;
      else if (risk === 'quantum-ready' || rule?.quantumStatus === 'quantum-safe') counts.safe += 1;
      else if (risk === 'vulnerable' || (window.QuantumRules?.isQuantumVulnerable && window.QuantumRules.isQuantumVulnerable(asset))) counts.vulnerable += 1;
      else counts.unknown += 1;
    });
    const pct = count => `${Math.round((count / assets.length) * 100)}% (${count}/${assets.length})`;
    const score = Math.round(((counts.safe + counts.hybrid) / assets.length) * 100);
    byId('assurance-posture-score').textContent = `${score}% quantum-safe or hybrid · ${assets.length} observed CBOM assets`;
    summary.innerHTML = `
      <article class="assurance-stat"><span>PQC / quantum-safe</span><strong class="assurance-safe">${pct(counts.safe)}</strong></article>
      <article class="assurance-stat"><span>Hybrid</span><strong class="assurance-quantum">${pct(counts.hybrid)}</strong></article>
      <article class="assurance-stat"><span>Still vulnerable</span><strong class="assurance-danger">${pct(counts.vulnerable)}</strong></article>
      <article class="assurance-stat"><span>Not classified</span><strong>${pct(counts.unknown)}</strong></article>`;
  }

  function explicitMosca(finding) {
    const x = asNumber(finding?.dataLifetimeYears ?? finding?.sensitivityLifetimeYears ?? finding?.risk?.X);
    const y = asNumber(finding?.migrationTimeYears ?? finding?.risk?.Y);
    const z = asNumber(finding?.threatHorizonYears ?? finding?.risk?.Z);
    if (x === null || y === null || z === null) return null;
    return { x, y, z, met: x + y > z };
  }

  function sourceLinks(entry) {
    const sources = entry.sources || PQCAssuranceKnowledge.SOURCES || [];
    if (!sources.length) return '<p>Reference links are not yet configured for this replacement.</p>';
    return `<ul class="assurance-source-list">${sources.map(source =>
      `<li><a href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(source.label)}</a> <span>${escapeHtml(source.status || '')}</span></li>`).join('')}</ul>`;
  }

  function focusFinding(candidate) {
    if (selectedFindingId) return (candidate.findingIds || []).some(id => String(id) === selectedFindingId);
    const fromMatches = !fromAlgorithm || candidate.algorithm.toLowerCase() === fromAlgorithm.toLowerCase();
    const toMatches = !toAlgorithm || String(candidate.replacement || '').toLowerCase().includes(toAlgorithm.toLowerCase());
    return fromMatches && toMatches;
  }

  function purposeLabel(purpose) {
    const labels = {
      key_exchange: 'KEM / key establishment',
      digital_signature: 'Signature',
      integrity_hashing: 'Hash',
      hashing: 'Hash',
      data_encryption: 'Symmetric encryption',
      encryption: 'Symmetric encryption',
      password_hashing: 'Password hashing'
    };
    return labels[String(purpose || '').toLowerCase()] || 'Not recorded in finding';
  }

  function assuranceCheckNames(candidate) {
    const finding = candidate.rawFinding || {};
    const context = `${candidate.remediationClass || finding.remediationClass || ''} ${candidate.algorithm || ''} ${candidate.purpose || ''} ${candidate.replacement || ''}`;
    if (/SECRET_HYGIENE|hardcoded|secret|credential|api[_ -]?key|private[_ -]?key/i.test(context)) {
      return ['Build', 'Run-with-env', 'Missing-var-raises', 'Rescan'];
    }
    if (/SYMMETRIC_HASH_UPGRADE|hash|sha-?256|sha3/i.test(context)) {
      return ['Cryptographic hash known-answer test', 'Digest length / encoding contract', 'Collision-resistance assessment', 'Library / version / constant-time claim', 'Rescan'];
    }
    return ['Known-answer test', 'Round-trip', 'Tamper rejection', 'Library / version / constant-time claim', 'Rescan'];
  }

  function renderEvidence(candidate, index, checkState) {
    const finding = candidate.rawFinding || {};
    const findingId = finding.id || candidate.findingIds?.[0] || '';
    const state = checkState || evidenceByFinding.get(String(findingId));
    const checks = state?.checks || assuranceCheckNames(candidate).map(name => ({
      name,
      status: 'NOT_VERIFIED',
      reason: name === 'Rescan' ? 'A migrated source tree is not available for rescan.' : 'Run checks to request a backend execution.'
    }));
    return `
      <div class="assurance-live-head">
        <div><h4>Live evidence</h4><p>Checks run on demand by the backend. Unavailable checks remain unverified.</p></div>
        <button type="button" class="btn-action btn-primary-action" data-run-assurance="${index}" ${state?.status === 'RUNNING' ? 'disabled' : ''}>${state?.status === 'RUNNING' ? 'Checks running…' : 'Run assurance checks'}</button>
      </div>
      <div class="assurance-check-grid">
        ${checks.map((check, checkIndex) => {
          const status = String(check.status || 'NOT_VERIFIED').toUpperCase();
          const rawId = `raw-${index}-${checkIndex}`;
          return `<article class="assurance-check ${escapeHtml(status.toLowerCase())}">
            <div><strong>${escapeHtml(check.name)}</strong><span class="assurance-check-status">${escapeHtml(status.replace(/_/g, ' '))}</span></div>
            <p>${escapeHtml(check.reason || check.message || 'No result returned.')}</p>
            <small>${escapeHtml(check.durationMs == null ? 'Duration not available' : `${check.durationMs} ms`)} · ${escapeHtml(dateLabel(check.timestamp || state?.updatedAt))}</small>
            <details id="${rawId}"><summary>View raw log</summary><pre>${escapeHtml(check.rawLog || 'No raw log was returned for this check.')}</pre></details>
          </article>`;
        }).join('')}
      </div>
      ${state?.library ? `<p class="assurance-library">Library: ${escapeHtml(state.library.name)} ${escapeHtml(state.library.version || '')} · Constant-time claims: ${escapeHtml(state.library.constantTime || 'Not verified')}</p>` : ''}
      ${state?.error ? `<p class="assurance-warning">${escapeHtml(state.error)}</p>` : ''}`;
  }

  function renderFocusedCard(candidate, index, entry, target) {
    const finding = candidate.rawFinding || {};
    const purpose = `${candidate.purpose || finding.usage || ''}`;
    const isSecret = /SECRET_HYGIENE|hardcoded|secret|credential|api[_ -]?key|private[_ -]?key/i.test(`${candidate.remediationClass || ''} ${candidate.algorithm} ${purpose} ${target}`);
    const isSignature = /sign|auth|jwt|certificate/i.test(purpose);
    const isKem = /ML-KEM/i.test(target);
    const isSignaturePqc = /ML-DSA|SLH-DSA|FN-DSA/i.test(target);
    let why = entry.points?.[0] || entry.safeStatus || 'Use a reviewed, purpose-matched implementation.';
    let quantumOutlook = 'No stronger quantum-resistance claim is established for this recommendation; verify it against the cited standard.';

    if (isSecret) {
      why = 'Move the exposed value out of source control, restrict access, and rotate it.';
      quantumOutlook = 'This is secret handling, not a PQC algorithm upgrade; it does not make the underlying cryptography quantum-safe.';
    } else if (isKem && isSignature) {
      why = 'ML-KEM is for key establishment, not signatures. Choose a signature scheme such as ML-DSA or SLH-DSA for this operation.';
      quantumOutlook = 'Do not apply this key-establishment recommendation to a signature call.';
    } else if (isSignaturePqc && /encrypt|key.?exchange|key.?establish/i.test(purpose)) {
      why = 'A signature scheme does not replace encryption or key establishment. Choose a purpose-matched KEM for this operation.';
      quantumOutlook = 'Do not apply a signature recommendation to encryption or key establishment.';
    } else if (isKem) {
      why = 'ML-KEM is standardized for key establishment; its Module-LWE basis is different from RSA/ECDH.';
      quantumOutlook = 'No efficient quantum attack is currently known against standardized ML-KEM parameters; use a reviewed protocol/provider.';
    } else if (isSignaturePqc) {
      why = /SLH-DSA/i.test(target) ? 'SLH-DSA uses standardized hash-based signatures.' : 'ML-DSA uses standardized module-lattice signatures.';
      quantumOutlook = 'Shor’s algorithm breaks RSA/ECDSA, while no efficient quantum attack is currently known against standardized ML-DSA/SLH-DSA parameters.';
    } else if (/sha-?256|sha3/i.test(target)) {
      why = 'SHA-256 and SHA-3 are standardized hash functions; MD5/SHA-1 collision weaknesses are already practical classical risks.';
      quantumOutlook = 'Grover speeds generic search, but does not recreate the known MD5/SHA-1 collision break in these replacements.';
    } else if (/aes-?256|chacha20/i.test(target)) {
      why = 'Use the recommended strong symmetric cipher with an authenticated-encryption mode.';
      quantumOutlook = 'Grover gives a quadratic key-search speedup; AES-256 retains roughly 128-bit generic quantum search work.';
    }

    const source = entry.sources?.find(item =>
      (isKem && /FIPS 203/.test(item.label)) ||
      (isSignaturePqc && (/ML-DSA/i.test(target) ? /FIPS 204/.test(item.label) : /FIPS 205/.test(item.label))) ||
      (/sha-?256|sha3/i.test(target) && /FIPS 180-4/.test(item.label)) ||
      (/aes-?256|chacha20/i.test(target) && /800-38D/.test(item.label))
    );
    const file = finding.file || finding.filePath || candidate.affectedFiles?.[0] || 'Finding file not recorded';
    const line = finding.line || finding.lineNumber || '';
    const location = `${file}${line ? ` · line ${line}` : ''}`;

    return `
      <article id="assurance-${index}" class="pqc-assurance-card assurance-report-card assurance-focused-card selected">
        <header class="assurance-card-header">
          <div><div class="assurance-kicker">Selected CryptoTwin finding</div><h3>${escapeHtml(candidate.algorithm)} → ${escapeHtml(target)}</h3><p>${escapeHtml(location)} · ${escapeHtml(purposeLabel(purpose))}</p></div>
        </header>
        <section class="assurance-brief">
          <p><strong>Why this recommendation:</strong> ${escapeHtml(why)}</p>
          <p><strong>Quantum outlook:</strong> ${escapeHtml(quantumOutlook)}</p>
          <p><strong>Standard:</strong> ${source ? `<a href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(source.label)}</a>` : escapeHtml(entry.standard || 'Not established for this recommendation.')}</p>
        </section>
      </article>`;
  }

  function renderCard(candidate, index) {
    const target = toAlgorithm || candidate.replacement || 'No replacement specified';
    const entry = PQCAssuranceKnowledge.resolveAssuranceEntry(target, candidate.algorithm, candidate.purpose);
    if (sourceLabel === 'cryptotwin') return renderFocusedCard(candidate, index, entry, target);
    const finding = candidate.rawFinding || {};
    const findings = candidate.findings?.length ? candidate.findings : [finding];
    const selected = focusFinding(candidate);
    const locations = findings.map(item => `${item.file || item.filePath || 'unknown'}:${item.line || item.lineNumber || '—'}`);
    const mosca = explicitMosca(finding);
    const category = entry.securityCategory || 'Not established for this parameter set';
    const status = entry.nistStatus || 'Review standard status';
    const oldEffect = entry.current?.quantum || entry.oldQuantum || entry.quantum || 'Not established from the observed algorithm.';
    const oldClassicalEffect = entry.current?.classical || entry.classical || 'Not established from the observed algorithm.';
    const sourceData = sourceLinks(entry);
    const findingId = finding.id || candidate.findingIds?.[0] || '';
    const replacement = candidate.replacement || 'No replacement specified';
    return `
      <article id="assurance-${index}" class="pqc-assurance-card assurance-report-card${selected ? ' selected' : ''}" data-algorithm="${escapeHtml(candidate.algorithm)}">
        <header class="assurance-card-header">
          <div><div class="assurance-kicker">Finding-backed replacement</div><h3>${escapeHtml(candidate.algorithm)} <span aria-hidden="true">→</span> ${escapeHtml(replacement)}</h3><p>${escapeHtml(candidate.severity)} · ${escapeHtml(purposeLabel(candidate.purpose))} · ${findings.length} related finding${findings.length === 1 ? '' : 's'}</p></div>
          <div class="assurance-badges"><span class="badge-pill badge-pqc">NIST: ${escapeHtml(status)}</span><span class="badge-pill">${escapeHtml(category)}</span><span class="badge-pill">${escapeHtml(purposeLabel(candidate.purpose))}</span></div>
        </header>
        ${entry.isFallback ? '<p class="assurance-warning">No reviewed knowledge entry matches this replacement. Algorithm-specific assurance is not yet verified.</p>' : ''}
        <div class="assurance-columns">
          <section class="assurance-subcard"><h4>1 · Verdict</h4><p><strong>${escapeHtml(candidate.algorithm)} → ${escapeHtml(replacement)}</strong></p><p>${escapeHtml(entry.standard || 'Applicable standard not established.')}</p><p>${escapeHtml(category)} · ${escapeHtml(purposeLabel(candidate.purpose))}</p></section>
          <section class="assurance-subcard"><h4>2 · Why the old primitive is unsafe</h4><p><strong>Attack:</strong> ${escapeHtml(oldEffect)}</p><p><strong>Estimated effect:</strong> ${escapeHtml(oldClassicalEffect)}</p>
            <div class="assurance-hndl"><strong>Harvest now, decrypt later / Mosca</strong>${mosca
              ? `<p>Recorded data lifetime X=${mosca.x}y, migration time Y=${mosca.y}y, threat horizon Z=${mosca.z}y. X + Y ${mosca.met ? '>' : '≤'} Z.</p>`
              : '<p>Not yet verified: this finding does not include data shelf-life and threat-horizon values, so no finding-specific inequality is asserted.</p>'}</div></section>
        </div>
        <div class="assurance-columns">
          <section class="assurance-subcard"><h4>3 · Why the replacement is considered resilient</h4><ul>${(entry.points || []).map(point => `<li>${escapeHtml(point)}</li>`).join('')}</ul>
            <p><strong>Underlying problem:</strong> ${escapeHtml(entry.hardProblem || 'Not established for this exact replacement.')}</p><p><strong>Known best attacks / margin:</strong> ${escapeHtml(entry.bestAttack || 'No attack-cost or security-margin claim is asserted here; see the cited standard.')}</p><p><strong>Caveat:</strong> ${escapeHtml(entry.caveat || 'Implementation, side-channel, parameter-selection, and migration risks remain.')}</p></section>
          <section class="assurance-subcard"><h4>4 · Old vs new comparison</h4><div class="assurance-table-wrap"><table class="assurance-table"><thead><tr><th>Property</th><th>Observed</th><th>Replacement</th></tr></thead><tbody>
            <tr><th>Public key</th><td>${escapeHtml(entry.oldPublicKeySize || 'Not recorded')}</td><td>${escapeHtml(entry.publicKeySize || 'Not established')}</td></tr>
            <tr><th>Ciphertext / signature</th><td>${escapeHtml(entry.oldOutputSize || 'Not recorded')}</td><td>${escapeHtml(entry.outputSize || entry.sizes || 'Not established')}</td></tr>
            <tr><th>Operation time</th><td>Not measured</td><td>Not measured on this server</td></tr>
            <tr><th>Security category</th><td>${escapeHtml(entry.oldBits || 'Not established')}</td><td>${escapeHtml(category)}</td></tr>
            <tr><th>Standard</th><td>${escapeHtml(entry.oldStandard || 'Algorithm-specific legacy standard not inferred')}</td><td>${escapeHtml(entry.standard || 'Not established')}</td></tr>
          </tbody></table></div><p class="assurance-source-tag">Sizes shown as specification values where cited; no benchmark was run for these static facts.</p></section>
        </div>
        <div class="assurance-columns">
          <section class="assurance-subcard"><h4>5 · Migration impact for this code</h4><p><strong>Finding:</strong> ${escapeHtml(candidate.algorithm)} · ${escapeHtml(candidate.severity)}</p><p><strong>File and original line(s):</strong> ${locations.map(escapeHtml).join('<br>')}</p><p><strong>Language / library:</strong> ${escapeHtml(finding.language || 'Not recorded')} / ${escapeHtml(finding.library || 'Not recorded')}</p><p><strong>Replacement impact:</strong> ${escapeHtml(entry.impact || 'Not established from this finding; review the actual call site.')}</p></section>
          <section class="assurance-subcard"><h4>6 · Recommended migration path</h4><ul>${(entry.migrationPath || ['Use a reviewed provider implementation; preserve crypto-agility and test protocol compatibility.']).map(point => `<li>${escapeHtml(point)}</li>`).join('')}</ul><p>${escapeHtml(entry.transition || 'Follow the applicable final NIST guidance and organization policy.')}</p></section>
        </div>
        <section class="assurance-subcard"><h4>7 · Future resilience</h4><p>${escapeHtml(entry.futureResilience || 'Maintain crypto-agility. Reassess standards and implementations as cryptanalysis evolves.')}</p></section>
        <section class="assurance-subcard assurance-live" id="live-evidence-${index}" aria-live="polite">${renderEvidence(candidate, index)}</section>
        <section class="assurance-subcard assurance-sources"><h4>9 · Sources</h4>${sourceData}</section>
      </article>`;
  }

  function renderWholeScanTable() {
    const body = byId('whole-scan-body');
    body.innerHTML = candidates.map(candidate => {
      const finding = candidate.rawFinding || {};
      const findingId = finding.id || candidate.findingIds?.[0] || '';
      const url = `pqc-assurance.html?scanId=${encodeURIComponent(currentScan?.id || currentScan?.scanId || '')}&findingId=${encodeURIComponent(findingId)}&source=whole-scan`;
      return `<tr><td>${escapeHtml(candidate.algorithm)}</td><td>${escapeHtml(candidate.replacement || 'Not specified')}</td><td>${escapeHtml(purposeLabel(candidate.purpose))}</td><td>${escapeHtml(candidate.severity)}</td><td>${escapeHtml(finding.file || finding.filePath || 'unknown')}:${escapeHtml(finding.line || finding.lineNumber || '—')}</td><td><a href="${url}">Assurance</a></td></tr>`;
    }).join('') || '<tr><td colspan="6">No replacement findings were recorded for this scan.</td></tr>';
  }

  function renderCards() {
    const query = searchText.trim().toLowerCase();
    let visible = candidates.filter(candidate => !query || `${candidate.algorithm} ${candidate.replacement} ${candidate.purpose} ${(candidate.affectedFiles || []).join(' ')}`.toLowerCase().includes(query));
    const focusRequested = selectedFindingId || fromAlgorithm || toAlgorithm;
    if (focusRequested) {
      visible = visible.filter(focusFinding);
    }
    const host = byId('assurance-report-list');
    if (!candidates.length) {
      host.innerHTML = '<div class="assurance-empty"><strong>No migration findings in this scan</strong><p>Run a repository scan. This view does not invent sample findings or replacement measurements.</p><a class="btn-action btn-primary-action" href="scan.html">Go to Scan</a></div>';
      return;
    }
    if (!visible.length) {
      host.innerHTML = '<div class="assurance-empty"><strong>No matching replacement</strong><p>The requested finding or algorithm pair is not present in the selected scan.</p></div>';
      return;
    }
    host.innerHTML = visible.map(candidate => renderCard(candidate, candidates.indexOf(candidate))).join('');
  }

  function requestApi(url, options) {
    const base = (window.Auth && window.Auth.API_BASE) || ((location.hostname === 'localhost' || location.hostname === '127.0.0.1') ? location.origin : 'https://cryptoscan-demo-api.onrender.com');
    const absoluteUrl = `${base}${url}`;
    return (window.Auth && window.Auth.apiFetch ? window.Auth.apiFetch(absoluteUrl, options) : fetch(absoluteUrl, options))
      .then(async response => {
        if (!response) throw new Error('Authentication is required to run assurance checks.');
        const body = await response.json();
        if (!response.ok) throw new Error(body.error || 'Assurance check request failed.');
        return body;
      });
  }

  async function runChecks(index) {
    const candidate = candidates[index];
    if (!candidate || !currentScan) return;
    const finding = candidate.rawFinding || {};
    const findingId = String(finding.id || candidate.findingIds?.[0] || '');
    const running = { status: 'RUNNING', checks: assuranceCheckNames(candidate).map(name => ({ name, status: 'RUNNING', reason: 'Backend check queued.' })) };
    evidenceByFinding.set(findingId, running);
    byId(`live-evidence-${index}`).innerHTML = renderEvidence(candidate, index, running);
    try {
      const started = await requestApi('/api/cryptotwin/assurance-checks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanId: currentScan.id || currentScan.scanId,
          findingId,
          algorithm: candidate.algorithm,
          replacement: candidate.replacement,
          purpose: candidate.purpose
        })
      });
      let state = running;
      for (let attempt = 0; attempt < 120; attempt += 1) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        state = await requestApi(`/api/cryptotwin/assurance-checks/${encodeURIComponent(started.checkRunId)}`);
        evidenceByFinding.set(findingId, state);
        byId(`live-evidence-${index}`).innerHTML = renderEvidence(candidate, index, state);
        if (state.status === 'DONE' || state.status === 'FAILED') return;
      }
      throw new Error('Assurance checks did not finish within 120 seconds.');
    } catch (error) {
      const failed = { status: 'FAILED', error: error.message, checks: [{ name: 'Backend request', status: 'FAIL', reason: error.message }] };
      evidenceByFinding.set(findingId, failed);
      byId(`live-evidence-${index}`).innerHTML = renderEvidence(candidate, index, failed);
    }
  }

  function renderPage() {
    const data = window.CryptoEngine?.getData ? window.CryptoEngine.getData() : {};
    document.body.classList.toggle('assurance-focused', sourceLabel === 'cryptotwin');
    currentScan = findCurrentScan(data);
    const scanId = currentScan?.id || currentScan?.scanId || '';
    if (requestedScanId && !currentScan) {
      byId('assurance-scan-meta').textContent = `Scan ${requestedScanId} is not loaded in this browser session.`;
      byId('assurance-selection-note').textContent = 'Open the scan in CryptoTwin or Findings first, then reopen PQC Assurance.';
      candidates = [];
    } else {
      const collected = MigrationPlanData.collectFindings(data, scanId || undefined);
      candidates = MigrationPlanData.buildCandidates(collected.findings);
      byId('assurance-scan-meta').textContent = `${currentScan?.repoName || currentScan?.name || 'Current scan'} · ${scanId || 'scan ID not recorded'} · Last scan: ${dateLabel(currentScan?.scanDate || currentScan?.completedAt || currentScan?.timestamp)}`;
      if (selectedFindingId || fromAlgorithm || toAlgorithm) {
        byId('assurance-selection-note').textContent = sourceLabel === 'cryptotwin'
          ? 'Short, finding-specific migration assurance.'
          : `Focused view${selectedFindingId ? ` · finding ${selectedFindingId}` : ''}${fromAlgorithm || toAlgorithm ? ` · ${fromAlgorithm || '—'} → ${toAlgorithm || '—'}` : ''}${sourceLabel ? ` · opened from ${sourceLabel}` : ''}.`;
      } else {
        byId('assurance-selection-note').textContent = 'Showing all replacement candidates derived from the selected scan and shared CryptoScan rules.';
      }
    }
    renderPosture(currentScan);
    byId('assurance-count').textContent = `${candidates.length} replacement candidate${candidates.length === 1 ? '' : 's'} from this scan's findings.`;
    renderCards();
    renderWholeScanTable();
  }

  document.addEventListener('DOMContentLoaded', () => {
    byId('assurance-search').addEventListener('input', event => {
      searchText = event.target.value;
      renderCards();
    });
    document.querySelectorAll('[data-assurance-view]').forEach(button => {
      button.addEventListener('click', () => {
        document.querySelectorAll('[data-assurance-view]').forEach(tab => tab.classList.toggle('active', tab === button));
        const wholeScan = button.dataset.assuranceView === 'whole-scan';
        byId('replacements-view').hidden = wholeScan;
        byId('whole-scan-view').hidden = !wholeScan;
      });
    });
    document.addEventListener('click', event => {
      const button = event.target.closest('[data-run-assurance]');
      if (button) runChecks(Number(button.dataset.runAssurance));
    });
    window.addEventListener('cryptoscan_data_updated', renderPage);
    window.addEventListener('zchange', renderPage);
    renderPage();
  });
})();
