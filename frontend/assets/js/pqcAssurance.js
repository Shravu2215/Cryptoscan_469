'use strict';

(() => {
  const byId = id => document.getElementById(id);
  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  let candidates = [];
  let visibleCandidates = [];
  let activeFilter = 'all';
  let searchText = '';
  let selectedAlgorithm = new URLSearchParams(location.search).get('algo') || '';

  function classification(candidate) {
    const entry = PQCAssuranceKnowledge.resolveAssuranceEntry(candidate.replacement || 'None specified', candidate.algorithm, candidate.purpose);
    if (candidate.isClassicallyWeak || entry.classicallyBroken) return 'classical';
    if (candidate.quantumVulnerable) return 'quantum';
    const rule = window.QuantumRules?.lookup(candidate.algorithm);
    return rule?.quantumStatus === 'quantum-safe' ? 'safe' : 'review';
  }

  function priorityText(priority) {
    return priority === 1 ? 'Priority 1 · Immediate' : priority === 2 ? 'Priority 2 · High' : 'Priority 3 · Planned';
  }

  function renderSummary() {
    const counts = { classical: 0, quantum: 0, safe: 0 };
    candidates.forEach(candidate => {
      if (candidate.isClassicallyWeak || PQCAssuranceKnowledge.resolveAssuranceEntry(candidate.replacement || 'None specified', candidate.algorithm).classicallyBroken) counts.classical++;
      if (candidate.quantumVulnerable) counts.quantum++;
      if (classification(candidate) === 'safe') counts.safe++;
    });
    const total = candidates.length;
    const ready = total ? Math.round((counts.safe / total) * 100) : 0;
    byId('assurance-summary').innerHTML = `
      <article class="assurance-stat"><span>Algorithms assessed</span><strong>${total}</strong></article>
      <article class="assurance-stat"><span>Classically broken</span><strong class="assurance-danger">${counts.classical}</strong></article>
      <article class="assurance-stat"><span>Quantum-vulnerable</span><strong class="assurance-quantum">${counts.quantum}</strong></article>
      <article class="assurance-stat"><span>Already safe</span><strong class="assurance-safe">${counts.safe}</strong></article>
      <article class="assurance-stat" title="PQC readiness = already-safe algorithms ÷ all algorithms assessed × 100. Classically broken and quantum-vulnerable counts are not considered ready."><span>PQC readiness <abbr title="Already safe / total assessed × 100">ⓘ</abbr></span><strong>${ready}%</strong></article>`;
  }

  function renderCard(candidate, index) {
    const kind = classification(candidate);
    const entry = PQCAssuranceKnowledge.resolveAssuranceEntry(candidate.replacement || 'None specified', candidate.algorithm, candidate.purpose);
    const mosca = candidate.mosca || MigrationPlanData.computeMosca(candidate.rawFinding, candidate.fileCount);
    const raw = candidate.rawFinding || {};
    const selected = selectedAlgorithm && candidate.algorithm.toLowerCase() === selectedAlgorithm.toLowerCase();
    const old = entry.current || {};
    const replacement = candidate.replacement || 'None specified';
    const statusOld = candidate.isClassicallyWeak || entry.classicallyBroken ? 'Harmful · Legacy-Broken' : (candidate.quantumVulnerable ? 'Quantum-Broken' : 'Classically Safe');
    const statusNew = replacement === 'None specified' ? 'No replacement specified' : (entry.isFallback ? 'Unverified · Review required' : 'Quantum-Safe / Quantum-Resilient');
    const latencyImpact = candidate.purpose === 'digital_signature' && (candidate.algorithm.includes('RSA') || candidate.algorithm.includes('EC'))
      ? 'High' : (candidate.purpose === 'key_exchange' ? 'Medium' : 'Low');
    const effort = raw.cryptoAgilityScore < 40 ? 'High' : (raw.cryptoAgilityScore < 80 ? 'Medium' : 'Low');
    const latencyEstimate = raw.latencyImpactMs == null ? '' : ` · ${escapeHtml(raw.latencyImpactMs)} ms baseline estimate`;
    const oldClassical = old.classical || entry.oldClassical;
    const oldQuantum = old.quantum || entry.oldQuantum;
    const moscaVerdict = mosca.isMet ? 'X + Y > Z · Inequality met' : `X + Y ≤ Z · ${mosca.categoryLabel || 'Within current timeline'}`;
    const fileNames = candidate.affectedFiles instanceof Set ? Array.from(candidate.affectedFiles) : (candidate.affectedFiles || []);
    const cardId = `assurance-${index}`;
    return `
      <article id="${cardId}" class="pqc-assurance-card assurance-report-card${selected ? ' selected' : ''}" data-algorithm="${escapeHtml(candidate.algorithm)}" data-kind="${kind}">
        <header class="assurance-card-header">
          <div><div class="assurance-kicker">${escapeHtml(priorityText(candidate.priority))}</div><h3>${escapeHtml(candidate.algorithm)} <span aria-hidden="true">→</span> ${escapeHtml(replacement)}</h3><p>${escapeHtml(entry.category)} · ${candidate.fileCount} affected file${candidate.fileCount === 1 ? '' : 's'}</p></div>
          <div class="assurance-badges"><span class="badge-pill ${candidate.severity === 'CRITICAL' || candidate.severity === 'HIGH' ? 'assurance-danger-badge' : 'badge-pqc'}">${escapeHtml(candidate.severity)}</span>${candidate.isClassicallyWeak || entry.classicallyBroken ? '<span class="badge-pill assurance-danger-badge">Legacy-Broken</span>' : ''}${candidate.quantumVulnerable ? '<span class="badge-pill badge-pqc">Quantum-Vulnerable</span>' : ''}${kind === 'safe' ? '<span class="badge-pill assurance-safe-badge">Already safe</span>' : (kind === 'review' ? '<span class="badge-pill assurance-danger-badge">Review</span>' : '')}</div>
        </header>
        ${entry.isFallback ? '<p class="assurance-warning">No reviewed knowledge entry matches this replacement yet. This card is based on the real Migration Plan finding; replacement assurance requires review.</p>' : ''}
        <div class="assurance-columns">
          <section class="assurance-subcard"><h4>Before vs after</h4><div class="assurance-table-wrap"><table class="assurance-table"><thead><tr><th>Property</th><th>Observed · ${escapeHtml(candidate.algorithm)}</th><th>Recommended · ${escapeHtml(replacement)}</th></tr></thead><tbody>
            <tr><th>Classical security</th><td>${escapeHtml(oldClassical)}</td><td>${escapeHtml(entry.safeStatus)}</td></tr>
            <tr><th>Quantum threat</th><td>${escapeHtml(oldQuantum)}</td><td>${escapeHtml(entry.quantum)}</td></tr>
            <tr><th>Effective strength</th><td>${escapeHtml(entry.oldBits)}</td><td>${escapeHtml(entry.newBits)}</td></tr>
            <tr><th>Status</th><td><span class="assurance-status old">${escapeHtml(statusOld)}</span></td><td><span class="assurance-status new">${escapeHtml(statusNew)}</span></td></tr>
          </tbody></table></div></section>
          <section class="assurance-subcard"><h4>Why this replacement</h4>${entry.contextNote ? `<p class="assurance-warning">${escapeHtml(entry.contextNote)}</p>` : ''}<ul>${entry.points.map(point => `<li>${escapeHtml(point)}</li>`).join('')}</ul><p class="assurance-standard"><strong>Standard / status:</strong> ${escapeHtml(entry.standard)}</p></section>
        </div>
        <div class="assurance-columns">
          <section class="assurance-subcard"><h4>CRQC outlook</h4><p><strong>Old:</strong> ${escapeHtml(oldQuantum)}</p><p><strong>Recommended:</strong> ${escapeHtml(entry.quantum)}</p><p class="assurance-standard">${escapeHtml(entry.transition)}</p></section>
          <section class="assurance-subcard"><h4>Migration trade-offs</h4><dl class="assurance-dl"><dt>Size</dt><dd>${escapeHtml(entry.sizes)}</dd><dt>Latency</dt><dd>${escapeHtml(latencyImpact)} Migration Plan impact${latencyEstimate} · ${escapeHtml(entry.latency)}</dd><dt>Effort</dt><dd>${escapeHtml(effort)} Migration Plan effort · ${escapeHtml(entry.effort)}</dd></dl></section>
        </div>
        <section class="assurance-subcard assurance-mosca"><h4>Mosca's inequality <span title="Values and verdict are reused from the Migration Plan candidate; no independent recomputation.">ⓘ</span></h4><div class="assurance-mosca-values"><span>X <b>${escapeHtml(mosca.moscaX)}</b></span><span>Y <b>${escapeHtml(mosca.moscaY)}</b></span><span>Z <b>${escapeHtml(mosca.moscaZ)}</b></span><strong>${escapeHtml(moscaVerdict)}</strong></div><p>${escapeHtml(mosca.message || '')}</p></section>
        <details class="assurance-snippet"><summary>Implementation snippet</summary><div class="assurance-code-grid"><div><span>Before</span><pre><code>${escapeHtml(entry.before)}</code></pre></div><div><span>After · illustrative</span><pre><code>${escapeHtml(entry.after)}</code></pre></div></div></details>
        <footer class="assurance-card-footer"><span>${escapeHtml(fileNames.slice(0, 3).join(', ') || 'Finding location not recorded')}${fileNames.length > 3 ? ` · +${fileNames.length - 3} more` : ''}</span><a class="btn-action assurance-verify" href="verification.html?algo=${encodeURIComponent(candidate.algorithm)}">Verify scan</a></footer>
      </article>`;
  }

  function renderCards() {
    const query = searchText.trim().toLowerCase();
    visibleCandidates = candidates.filter(candidate => {
      const kind = classification(candidate);
      const classical = candidate.isClassicallyWeak || PQCAssuranceKnowledge.resolveAssuranceEntry(candidate.replacement || 'None specified', candidate.algorithm).classicallyBroken;
      const filterMatch = activeFilter === 'all' || (activeFilter === 'classical' && classical) || (activeFilter === 'quantum' && candidate.quantumVulnerable);
      const queryMatch = !query || `${candidate.algorithm} ${candidate.replacement} ${candidate.purpose}`.toLowerCase().includes(query);
      return filterMatch && queryMatch;
    });
    const host = byId('assurance-report-list');
    if (!candidates.length) {
      host.innerHTML = '<div class="assurance-empty"><strong>No migration findings to assess</strong><p>Run a repository scan. This report only lists algorithms present in the shared Migration Plan data.</p><a class="btn-action btn-primary-action" href="scan.html">Go to Scan &amp; Runtime</a></div>';
      return;
    }
    if (!visibleCandidates.length) {
      host.innerHTML = '<div class="assurance-empty"><strong>No algorithms match this filter</strong><p>Try another category or clear the search.</p></div>';
      return;
    }
    host.innerHTML = visibleCandidates.map(renderCard).join('');
    if (selectedAlgorithm) {
      const selected = Array.from(host.querySelectorAll('.assurance-report-card')).find(card => card.dataset.algorithm.toLowerCase() === selectedAlgorithm.toLowerCase());
      if (selected) requestAnimationFrame(() => selected.scrollIntoView({ behavior: 'smooth', block: 'center' }));
    }
  }

  function reportData() {
    return {
      reportBasis: 'assessed from observed scan findings',
      algorithms: visibleCandidates.map(candidate => {
        const knowledge = PQCAssuranceKnowledge.resolveAssuranceEntry(candidate.replacement || 'None specified', candidate.algorithm, candidate.purpose);
        const plain = { ...candidate, affectedFiles: candidate.affectedFiles instanceof Set ? Array.from(candidate.affectedFiles) : candidate.affectedFiles };
        delete plain.rawFinding;
        return { ...plain, knowledge };
      })
    };
  }

  async function copyReport() {
    const text = JSON.stringify(reportData(), null, 2);
    try { await navigator.clipboard.writeText(text); byId('copy-report').textContent = 'Copied'; setTimeout(() => { byId('copy-report').textContent = 'Copy assurance report'; }, 1800); }
    catch (_) { byId('report-feedback').textContent = 'Clipboard access was unavailable.'; }
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(reportData(), null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'pqc-assurance-report.json';
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function setFilter(filter) {
    activeFilter = filter;
    document.querySelectorAll('[data-assurance-filter]').forEach(button => button.classList.toggle('active', button.dataset.assuranceFilter === filter));
    renderCards();
  }

  function init() {
    const host = byId('assurance-report-list');
    host.innerHTML = '<div class="assurance-skeleton" aria-label="Loading scan findings"><i></i><i></i><i></i></div>';
    requestAnimationFrame(() => {
      const source = MigrationPlanData.collectFindings();
      candidates = MigrationPlanData.buildCandidates(source.findings);
      renderSummary();
      renderCards();
      byId('assurance-count').textContent = `${candidates.length} algorithm${candidates.length === 1 ? '' : 's'} · assessed from observed scan findings`;
      if (selectedAlgorithm && !candidates.some(candidate => candidate.algorithm.toLowerCase() === selectedAlgorithm.toLowerCase())) {
        byId('assurance-selection-note').textContent = `No current Migration Plan finding matches “${selectedAlgorithm}”.`;
      }
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-assurance-filter]').forEach(button => button.addEventListener('click', () => setFilter(button.dataset.assuranceFilter)));
    byId('assurance-search').addEventListener('input', event => { searchText = event.target.value; renderCards(); });
    byId('copy-report').addEventListener('click', copyReport);
    byId('export-report').addEventListener('click', exportJson);
    window.addEventListener('cryptoscan_data_updated', init);
    window.addEventListener('zchange', init);
    init();
  });
})();
