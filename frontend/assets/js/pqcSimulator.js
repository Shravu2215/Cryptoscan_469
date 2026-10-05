/**
 * CryptoScan PQC Impact Simulator — UI Controller
 * Integrates PQCSizes data engine, CryptoEngine scan findings,
 * interactive controls, bar chart rendering, and export functions.
 */

(function() {
  'use strict';

  let currentScanData = null;
  let allScanFindings = [];
  let userCustomLimits = {};
  let currentSimResult = null;
  let isLogScale = false;

  document.addEventListener('DOMContentLoaded', () => {
    init();
  });

  function init() {
    loadScanData();
    setupControls();
    checkUrlParamsAndRun();
    bindEvents();
  }

  function loadScanData() {
    try {
      if (typeof CryptoEngine !== 'undefined') {
        currentScanData = CryptoEngine.getData();
        const active = currentScanData && currentScanData.activeScan;
        if (active && ((active.findings && active.findings.length > 0) || (active.results && active.results.length > 0))) {
          allScanFindings = active.findings || active.results || [];
        } else if (currentScanData && currentScanData.scans && currentScanData.scans.length > 0) {
          const scanWithFindings = currentScanData.scans.find(s => (s.findings && s.findings.length > 0) || (s.results && s.results.length > 0));
          const scan = scanWithFindings || currentScanData.scans[0];
          allScanFindings = scan.findings || scan.results || [];
        } else if (currentScanData && currentScanData.activeScan) {
          allScanFindings = currentScanData.activeScan.findings || [];
        }
      }
    } catch(e) {
      console.warn('Could not load scan findings:', e);
      allScanFindings = [];
    }
  }

  function setupControls() {
    const curSelect = document.getElementById('pqc-sel-classical');
    const replSelect = document.getElementById('pqc-sel-pqc');
    if (!curSelect || !replSelect) return;

    // Standard classical options
    const defaultClassicalAlgos = ['ECDSA P-256', 'RSA-2048', 'RSA-3072', 'RSA-4096', 'ECDSA P-384', 'Ed25519', 'ECDH P-256', 'X25519', 'AES-128', 'DES', 'MD5', 'SHA-1'];

    // Collect additional distinct algorithms discovered in scan findings
    const scanAlgos = new Set();
    allScanFindings.forEach(f => {
      if (f.algorithm) {
        const norm = PQCSizes.normalizeAlgo(f.algorithm);
        if (norm) scanAlgos.add(norm);
      }
    });

    const combined = Array.from(new Set([...scanAlgos, ...defaultClassicalAlgos])).filter(Boolean);

    curSelect.innerHTML = combined.map(a => {
      const isFromScan = scanAlgos.has(a);
      return `<option value="${a}">${a}${isFromScan ? ' (Scanned)' : ''}</option>`;
    }).join('');

    updateReplacementDropdown();
  }

  function updateReplacementDropdown() {
    const curSelect = document.getElementById('pqc-sel-classical');
    const replSelect = document.getElementById('pqc-sel-pqc');
    if (!curSelect || !replSelect) return;

    const curAlgo = curSelect.value || 'ECDSA P-256';
    const mode = getSelectedMode();
    const valids = PQCSizes.getValidReplacements(curAlgo, mode);

    replSelect.innerHTML = (valids && valids.length > 0 ? valids : ['ML-DSA-65', 'ML-DSA-44', 'Falcon-512']).map(r => `<option value="${r}">${r}</option>`).join('');
  }

  function getSelectedMode() {
    const activeSeg = document.querySelector('.pqc-seg-btn.active');
    return activeSeg ? activeSeg.getAttribute('data-mode') : 'pure';
  }

  function checkUrlParamsAndRun() {
    const params = new URLSearchParams(window.location.search);
    const urlAlgo = params.get('algorithm') || params.get('algo');
    const urlRepl = params.get('replacement') || params.get('repl');
    const urlMode = params.get('mode');
    const urlSource = params.get('source');

    if (urlSource === 'migration-plan') {
      const backBtn = document.getElementById('pqc-back-link');
      if (backBtn) backBtn.style.display = 'inline-flex';
    }

    if (urlAlgo) {
      const curSelect = document.getElementById('pqc-sel-classical');
      const norm = PQCSizes.normalizeAlgo(urlAlgo) || urlAlgo;
      if (curSelect && norm) {
        let matchedOpt = Array.from(curSelect.options).find(o => o.value && o.value.toLowerCase() === norm.toLowerCase());
        if (!matchedOpt) {
          const newOpt = document.createElement('option');
          newOpt.value = norm;
          newOpt.textContent = `${norm} (Selected)`;
          curSelect.appendChild(newOpt);
          matchedOpt = newOpt;
        }
        curSelect.value = matchedOpt.value;
      }
    }

    if (urlMode) {
      document.querySelectorAll('.pqc-seg-btn').forEach(btn => {
        if (btn.getAttribute('data-mode') === urlMode.toLowerCase()) {
          btn.classList.add('active');
        } else {
          btn.classList.remove('active');
        }
      });
    }

    updateReplacementDropdown();

    if (urlRepl) {
      const replSelect = document.getElementById('pqc-sel-pqc');
      const normRepl = PQCSizes.normalizeAlgo(urlRepl) || urlRepl;
      if (replSelect && normRepl) {
        let matchedOpt = Array.from(replSelect.options).find(o => o.value && (o.value.toLowerCase() === normRepl.toLowerCase() || o.value.toLowerCase() === urlRepl.toLowerCase()));
        if (matchedOpt) {
          replSelect.value = matchedOpt.value;
        }
      }
    }

    // Run simulation
    runSimulation();
  }

  function bindEvents() {
    // Mode toggle
    document.querySelectorAll('.pqc-seg-btn').forEach(btn => {
      btn.addEventListener('click', function() {
        document.querySelectorAll('.pqc-seg-btn').forEach(b => b.classList.remove('active'));
        this.classList.add('active');
        updateReplacementDropdown();
        runSimulation();
      });
    });

    // Dropdown changes
    const curSelect = document.getElementById('pqc-sel-classical');
    if (curSelect) {
      curSelect.addEventListener('change', () => {
        updateReplacementDropdown();
        runSimulation();
      });
    }

    const replSelect = document.getElementById('pqc-sel-pqc');
    if (replSelect) {
      replSelect.addEventListener('change', () => {
        runSimulation();
      });
    }

    // Run Simulation Button
    const runBtn = document.getElementById('btn-run-sim');
    if (runBtn) {
      runBtn.addEventListener('click', () => runSimulationWithReveal());
    }

    // Log-scale toggle
    const scaleCheckbox = document.getElementById('pqc-scale-toggle');
    if (scaleCheckbox) {
      scaleCheckbox.addEventListener('change', (e) => {
        isLogScale = e.target.checked;
        if (currentSimResult) renderComparisonChart(currentSimResult);
      });
    }

    // Collapsible limits header
    const limitsHeader = document.getElementById('pqc-limits-header');
    const limitsBody = document.getElementById('pqc-limits-body');
    if (limitsHeader && limitsBody) {
      limitsHeader.addEventListener('click', () => {
        const isHidden = limitsBody.style.display === 'none';
        limitsBody.style.display = isHidden ? 'grid' : 'none';
        const arrow = document.getElementById('pqc-limits-arrow');
        if (arrow) arrow.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0deg)';
      });
    }

    // Limit form input listeners
    const limitInputs = ['limit-cookie', 'limit-header', 'limit-tls', 'limit-qr-ecc', 'limit-iot', 'limit-jwt-claims'];
    limitInputs.forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener('input', () => onLimitChanged());
        el.addEventListener('change', () => onLimitChanged());
      }
    });

    // Reset limits button
    const resetBtn = document.getElementById('btn-reset-limits');
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        userCustomLimits = {};
        document.getElementById('limit-cookie').value = 4096;
        document.getElementById('limit-header').value = 8192;
        document.getElementById('limit-tls').value = 14600;
        document.getElementById('limit-qr-ecc').value = 'L';
        document.getElementById('limit-iot').value = 'BLE_ATT';
        document.getElementById('limit-jwt-claims').value = 200;
        runSimulation();
      });
    }

    // Export JSON
    const exportBtn = document.getElementById('btn-export-json');
    if (exportBtn) {
      exportBtn.addEventListener('click', exportSimulationJson);
    }

    // Copy Summary
    const copyBtn = document.getElementById('btn-copy-summary');
    if (copyBtn) {
      copyBtn.addEventListener('click', copySummaryToClipboard);
    }
  }

  function onLimitChanged() {
    // Only include keys the user actually changed from the defaults.
    // This lets classifyScenario distinguish user-entered limits from defaults.
    const DEFAULTS = PQCSizes.DEFAULT_LIMITS;
    const newLimits = {};

    const cookieVal = parseInt(document.getElementById('limit-cookie')?.value || 4096, 10);
    if (cookieVal !== DEFAULTS.cookieLimit) newLimits.cookieLimit = cookieVal;

    const headerVal = parseInt(document.getElementById('limit-header')?.value || 8192, 10);
    if (headerVal !== DEFAULTS.headerLineLimit) newLimits.headerLineLimit = headerVal;

    const tlsVal = parseInt(document.getElementById('limit-tls')?.value || 14600, 10);
    if (tlsVal !== DEFAULTS.tlsInitCwnd) newLimits.tlsInitCwnd = tlsVal;

    const qrVal = document.getElementById('limit-qr-ecc')?.value || 'L';
    if (qrVal !== DEFAULTS.qrEccLevel) newLimits.qrEccLevel = qrVal;

    const iotVal = document.getElementById('limit-iot')?.value || 'BLE_ATT';
    if (iotVal !== DEFAULTS.iotProfile) newLimits.iotProfile = iotVal;

    const jwtVal = parseInt(document.getElementById('limit-jwt-claims')?.value || 200, 10);
    if (jwtVal !== DEFAULTS.jwtClaimsPayload) newLimits.jwtClaimsPayload = jwtVal;

    userCustomLimits = newLimits;
    runSimulation();
  }

  function runSimulation() {
    const curSelect = document.getElementById('pqc-sel-classical');
    const replSelect = document.getElementById('pqc-sel-pqc');
    if (!curSelect || !replSelect) return;

    const classicalKey = curSelect.value;
    const pqcKey = replSelect.value;
    const mode = getSelectedMode();

    // Evidence from scanned files: only populate if the finding actually
    // contains a parsed size-limit value (e.g. large_client_header_buffers).
    // Crypto algorithm detection findings (ssl_ciphers, ECDSA usage, etc.)
    // do NOT contain limit data and must NOT produce "Confirmed issue".
    const scannedEvidence = {};
    allScanFindings.forEach(f => {
      const norm = PQCSizes.normalizeAlgo(f.algorithm);
      if (norm === classicalKey && f.parsedLimit) {
        // Only include evidence when the finding actually parsed a real limit
        const ev = { file: f.filePath || f.file, line: f.lineNumber || f.line, parsedLimit: f.parsedLimit, source: 'scanned config' };
        if (f.parsedLimit.type === 'cookie' || f.parsedLimit.type === 'jwt') scannedEvidence.jwt = ev;
        if (f.parsedLimit.type === 'header') scannedEvidence.header = ev;
        if (f.parsedLimit.type === 'tls' || f.parsedLimit.type === 'initcwnd') scannedEvidence.tls = ev;
      }
    });

    currentSimResult = PQCSizes.computeSimulation(classicalKey, pqcKey, mode, userCustomLimits, scannedEvidence);

    renderKPIs(currentSimResult);
    renderComparisonChart(currentSimResult);
    renderMatrixTable(currentSimResult);
    renderAffectedFiles(classicalKey);
  }

  // ─── Animated Before vs After Reveal ────────────────────────────────────────

  function runSimulationWithReveal() {
    const runBtn = document.getElementById('btn-run-sim');
    if (!runBtn) { runSimulation(); return; }

    const curSelect = document.getElementById('pqc-sel-classical');
    const replSelect = document.getElementById('pqc-sel-pqc');
    if (!curSelect || !replSelect) { runSimulation(); return; }

    const classicalKey = curSelect.value;
    const pqcKey = replSelect.value;
    const mode = getSelectedMode();

    // ── 1. Button loading state ────────────────────────────────────────────────
    runBtn.disabled = true;
    runBtn.innerHTML = `
      <svg class="pqc-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;">
        <path stroke-linecap="round" stroke-linejoin="round" d="M4 12a8 8 0 018-8v8H4z"/>
      </svg>
      Simulating…`;

    setTimeout(() => {
      // ── 2. Compute ─────────────────────────────────────────────────────────
      runSimulation();

      // ── 3. Restore button ──────────────────────────────────────────────────
      runBtn.disabled = false;
      runBtn.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;">
          <path stroke-linecap="round" stroke-linejoin="round" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
          <path stroke-linecap="round" stroke-linejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        Run Simulation`;

      if (!currentSimResult) return;

      // ── 4. Inject Before vs After reveal panel above the KPI grid ──────────
      renderBeforeAfterReveal(currentSimResult);
    }, 900);
  }

  function renderBeforeAfterReveal(res) {
    const kpis = res.kpis;

    // Remove any previous reveal
    const prev = document.getElementById('pqc-bva-panel');
    if (prev) prev.remove();

    const verdictColor = kpis.verdict === 'Breaking' ? '#ef4444'
                        : kpis.verdict === 'Review'   ? '#f59e0b'
                        : '#22c55e';

    const panel = document.createElement('div');
    panel.id = 'pqc-bva-panel';
    panel.className = 'pqc-bva-panel pqc-bva-enter';
    panel.innerHTML = `
      <div class="pqc-bva-header">
        <span class="pqc-bva-tag before-tag">⏪ BEFORE</span>
        <span class="pqc-bva-title">${res.classicalKey} → ${res.pqcKey}</span>
        <span class="pqc-bva-tag after-tag">AFTER ⏩</span>
      </div>

      <div class="pqc-bva-body">
        <!-- BEFORE column -->
        <div class="pqc-bva-col before-col">
          <div class="pqc-bva-algo-pill before-pill">${res.classicalKey}</div>
          <div class="pqc-bva-metric">
            <span class="pqc-bva-metric-label">Public Key</span>
            <span class="pqc-bva-metric-val before-val">${kpis.pkBefore.toLocaleString()} B</span>
          </div>
          <div class="pqc-bva-metric">
            <span class="pqc-bva-metric-label">Signature / CT</span>
            <span class="pqc-bva-metric-val before-val">${kpis.sigBefore.toLocaleString()} B</span>
          </div>
          <div class="pqc-bva-metric">
            <span class="pqc-bva-metric-label">Quantum Safe</span>
            <span class="pqc-bva-metric-val" style="color:#ef4444; font-weight:800;">✗ No</span>
          </div>
        </div>

        <!-- Divider -->
        <div class="pqc-bva-divider">
          <div class="pqc-bva-arrow-wrap">
            <div class="pqc-bva-arrow-icon">⚡</div>
            <div class="pqc-bva-delta-badge" style="background:${verdictColor}">${kpis.verdict}</div>
          </div>
        </div>

        <!-- AFTER column -->
        <div class="pqc-bva-col after-col">
          <div class="pqc-bva-algo-pill after-pill">${res.pqcKey}</div>
          <div class="pqc-bva-metric">
            <span class="pqc-bva-metric-label">Public Key</span>
            <span class="pqc-bva-metric-val after-val">${kpis.pkAfter.toLocaleString()} B</span>
            <span class="pqc-bva-multiplier">${kpis.pkMultiplier}×</span>
          </div>
          <div class="pqc-bva-metric">
            <span class="pqc-bva-metric-label">Signature / CT</span>
            <span class="pqc-bva-metric-val after-val">${kpis.sigAfter.toLocaleString()} B</span>
            <span class="pqc-bva-multiplier">${kpis.sigMultiplier}×</span>
          </div>
          <div class="pqc-bva-metric">
            <span class="pqc-bva-metric-label">Quantum Safe</span>
            <span class="pqc-bva-metric-val" style="color:#22c55e; font-weight:800;">✓ Yes</span>
          </div>
        </div>
      </div>

      <!-- Animated size bars -->
      <div class="pqc-bva-bars">
        <div class="pqc-bva-bar-row">
          <span class="pqc-bva-bar-lbl">PK Size (before)</span>
          <div class="pqc-bva-bar-track"><div class="pqc-bva-bar-fill before-fill" data-target="6"></div></div>
          <span class="pqc-bva-bar-sz">${kpis.pkBefore} B</span>
        </div>
        <div class="pqc-bva-bar-row">
          <span class="pqc-bva-bar-lbl">PK Size (after)</span>
          <div class="pqc-bva-bar-track"><div class="pqc-bva-bar-fill after-fill" data-target="100"></div></div>
          <span class="pqc-bva-bar-sz">${kpis.pkAfter} B</span>
        </div>
        <div class="pqc-bva-bar-row">
          <span class="pqc-bva-bar-lbl">Sig Size (before)</span>
          <div class="pqc-bva-bar-track"><div class="pqc-bva-bar-fill before-fill" data-target="${Math.max(2, Math.round((kpis.sigBefore/kpis.sigAfter)*100))}"></div></div>
          <span class="pqc-bva-bar-sz">${kpis.sigBefore} B</span>
        </div>
        <div class="pqc-bva-bar-row">
          <span class="pqc-bva-bar-lbl">Sig Size (after)</span>
          <div class="pqc-bva-bar-track"><div class="pqc-bva-bar-fill after-fill" data-target="100"></div></div>
          <span class="pqc-bva-bar-sz">${kpis.sigAfter} B</span>
        </div>
      </div>

      <button class="pqc-bva-close" id="pqc-bva-close" title="Dismiss">✕ Dismiss</button>
    `;

    // Insert before the KPI grid
    const kpiGrid = document.querySelector('.pqc-kpi-grid');
    if (kpiGrid) kpiGrid.parentNode.insertBefore(panel, kpiGrid);
    else document.querySelector('.pqc-sim-container').prepend(panel);

    // Trigger entrance animation
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        panel.classList.remove('pqc-bva-enter');
        panel.classList.add('pqc-bva-visible');

        // Animate bars after panel slides in
        setTimeout(() => {
          panel.querySelectorAll('.pqc-bva-bar-fill').forEach(bar => {
            bar.style.width = bar.getAttribute('data-target') + '%';
          });
        }, 350);
      });
    });

    // Dismiss button
    document.getElementById('pqc-bva-close').addEventListener('click', () => {
      panel.classList.add('pqc-bva-exit');
      setTimeout(() => panel.remove(), 400);
    });
  }

  function renderKPIs(res) {
    const kpis = res.kpis;

    const pkVal = document.getElementById('kpi-pk-val');
    const pkBadge = document.getElementById('kpi-pk-badge');
    if (pkVal && pkBadge) {
      pkVal.textContent = `${kpis.pkBefore.toLocaleString()} B ➔ ${kpis.pkAfter.toLocaleString()} B`;
      pkBadge.textContent = `${kpis.pkMultiplier}x`;
      pkBadge.className = `pqc-kpi-badge ${parseFloat(kpis.pkMultiplier) > 5 ? 'badge-amber' : 'badge-safe'}`;
    }

    const sigVal = document.getElementById('kpi-sig-val');
    const sigBadge = document.getElementById('kpi-sig-badge');
    if (sigVal && sigBadge) {
      sigVal.textContent = `${kpis.sigBefore.toLocaleString()} B ➔ ${kpis.sigAfter.toLocaleString()} B`;
      sigBadge.textContent = `${kpis.sigMultiplier}x`;
      sigBadge.className = `pqc-kpi-badge ${parseFloat(kpis.sigMultiplier) > 10 ? 'badge-crit' : (parseFloat(kpis.sigMultiplier) > 2 ? 'badge-amber' : 'badge-safe')}`;
    }

    const countVal = document.getElementById('kpi-risk-count');
    const countBadge = document.getElementById('kpi-risk-badge');
    if (countVal && countBadge) {
      countVal.textContent = `${kpis.affectedScenariosCount} of 6`;
      countBadge.textContent = kpis.affectedScenariosCount > 0 ? 'Issues Found' : 'Clean';
      countBadge.className = `pqc-kpi-badge ${kpis.affectedScenariosCount > 0 ? 'badge-amber' : 'badge-safe'}`;
    }

    const verdictVal = document.getElementById('kpi-verdict-val');
    const verdictBadge = document.getElementById('kpi-verdict-badge');
    if (verdictVal && verdictBadge) {
      verdictVal.textContent = kpis.verdict;
      verdictBadge.textContent = kpis.verdict === 'Breaking' ? 'Action Required' : (kpis.verdict === 'Review' ? 'Review Protocol' : 'Compliant');
      verdictBadge.className = `pqc-kpi-badge ${kpis.verdict === 'Breaking' ? 'badge-crit' : (kpis.verdict === 'Review' ? 'badge-amber' : 'badge-safe')}`;
    }
  }

  function renderComparisonChart(res) {
    const container = document.getElementById('pqc-bars-container');
    if (!container) return;

    if (res.isNoPayloadImpact) {
      container.innerHTML = `<div style="padding:24px; text-align:center; color:var(--text-m); font-size:13px;">${res.summaryMessage}</div>`;
      return;
    }

    const kpis = res.kpis;
    const curJwt = res.curJwt.base64Bytes;
    const pqcJwt = res.pqcJwt.base64Bytes;

    const items = [
      { label: 'Public Key Size', classical: kpis.pkBefore, pqc: kpis.pkAfter, mult: kpis.pkMultiplier },
      { label: 'Signature / Ciphertext Size', classical: kpis.sigBefore, pqc: kpis.sigAfter, mult: kpis.sigMultiplier },
      { label: 'Encoded JWT Token Size', classical: curJwt, pqc: pqcJwt, mult: (pqcJwt / curJwt).toFixed(1) }
    ];

    container.innerHTML = items.map(item => {
      let cVal = item.classical;
      let pVal = item.pqc;
      let maxVal = Math.max(cVal, pVal);

      let cPct, pPct;
      if (isLogScale) {
        const logC = Math.log10(Math.max(1, cVal));
        const logP = Math.log10(Math.max(1, pVal));
        const maxLog = Math.log10(Math.max(10, maxVal));
        cPct = Math.min(100, Math.max(5, (logC / maxLog) * 100));
        pPct = Math.min(100, Math.max(5, (logP / maxLog) * 100));
      } else {
        cPct = Math.min(100, Math.max(2, (cVal / maxVal) * 100));
        pPct = Math.min(100, Math.max(2, (pVal / maxVal) * 100));
      }

      return `
        <div class="pqc-bar-group">
          <div class="pqc-bar-label">
            <span>${item.label}</span>
            <span class="badge ${parseFloat(item.mult) > 5 ? 'badge-crit' : 'badge-amber'}">${item.mult}x larger</span>
          </div>
          <div class="pqc-bar-track-wrap">
            <div class="pqc-bar-row">
              <span class="pqc-bar-tag">${res.classicalKey}</span>
              <div class="pqc-bar-track">
                <div class="pqc-bar-fill classical" style="width: ${cPct}%;">
                  ${cVal.toLocaleString()} B
                </div>
              </div>
            </div>
            <div class="pqc-bar-row">
              <span class="pqc-bar-tag">${res.pqcKey}</span>
              <div class="pqc-bar-track">
                <div class="pqc-bar-fill pqc" style="width: ${pPct}%;">
                  ${pVal.toLocaleString()} B
                </div>
              </div>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  function renderMatrixTable(res) {
    const tbody = document.getElementById('pqc-matrix-tbody');
    if (!tbody) return;

    if (res.isNoPayloadImpact) {
      tbody.innerHTML = `<tr><td colspan="7" style="padding:24px; text-align:center; color:var(--text-m);">${res.summaryMessage}</td></tr>`;
      return;
    }

    tbody.innerHTML = res.matrix.map(row => {
      const statusTooltip = row.status === 'Confirmed issue' ?
        'Concrete repo evidence or user-entered limit override breached.' :
        (row.status === 'Estimated risk' ? 'Computed against default limits only. Endpoint may break depending on server config.' :
        (row.status === 'Informational' ? 'No hard limit defined. Shown for awareness.' : 'Payload size fits comfortably within protocol limits.'));

      // IoT row uses special display: "N packets needed" instead of "16545% limit"
      const headroomLabel = row.displayLabel || (row.isInformational ? '' : `${row.usedPct}% limit`);
      const headroomBarPct = row.displayPct != null ? row.displayPct : (row.isInformational ? 0 : Math.min(100, row.usedPct));
      const overLimitNote = row.overLimitText ? `<div style="font-size:10px; color:var(--red); font-weight:700; margin-top:2px;">${row.overLimitText}</div>` : '';

      // Limit column: show N/A for cert chain informational row
      const limitDisplay = row.limitDisplay || (row.limit != null ? `${row.limit.toLocaleString()} B` : 'N/A');

      // Status column: for informational, show the evidence as the label
      const statusBadge = row.isInformational
        ? `<span class="badge badge-amber" title="${statusTooltip}">Informational</span>`
        : `<span class="badge ${row.badgeClass}" title="${statusTooltip}">${row.status}</span>`;

      // Headroom bar: hide for informational rows
      const headroomHtml = row.isInformational
        ? `<div style="font-size:11px; font-weight:600; color:var(--text-s); text-align:center;">—</div>`
        : `<div style="font-size:11px; font-weight:600; text-align:right;">${headroomLabel}</div>
            <div class="pqc-headroom-bar">
              <div class="pqc-headroom-fill" style="width: ${headroomBarPct}%; background:${row.status === 'Confirmed issue' ? 'var(--red)' : (row.status === 'Estimated risk' ? 'var(--amber)' : 'var(--green)')};"></div>
            </div>
            ${overLimitNote}`;

      return `
        <tr class="pqc-matrix-row" onclick="toggleAccordion('${row.id}')">
          <td>
            <div style="font-weight:700; color:var(--text-h);">${row.name}</div>
            <div style="font-size:11px; color:var(--text-s);">${row.desc}</div>
          </td>
          <td style="font-family:'JetBrains Mono',monospace;">${row.beforeSize.toLocaleString()} B</td>
          <td style="font-family:'JetBrains Mono',monospace; font-weight:700; color:${(row.status === 'Confirmed issue' || row.status === 'Estimated risk') ? 'var(--red)' : 'var(--text-h)'};">
            ${row.afterSize.toLocaleString()} B
          </td>
          <td style="font-family:'JetBrains Mono',monospace; color:var(--text-m);">${limitDisplay}</td>
          <td style="width:140px;">
            ${headroomHtml}
          </td>
          <td>
            ${statusBadge}
            <div style="font-size:10.5px; color:var(--text-s); margin-top:2px; max-width:180px;">${row.evidence}</div>
          </td>
          <td style="font-size:12px; color:var(--text-b); max-width:260px;">
            ${row.mitigation}
          </td>
        </tr>
        <tr class="pqc-row-accordion" id="acc-${row.id}">
          <td colspan="7">
            <div class="pqc-accordion-content">
              <strong>Calculation Breakdown:</strong> ${row.breakdown}
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  window.toggleAccordion = function(id) {
    const acc = document.getElementById(`acc-${id}`);
    if (acc) {
      acc.classList.toggle('open');
    }
  };

  // ── Library-to-algorithm mapping for MANIFEST findings ────────────────────
  // When a manifest finding lists a library name (e.g. "elliptic"), we need
  // to know which normalized algorithm it corresponds to.
  const LIB_TO_ALGO = {
    'elliptic': 'ECDSA P-256', 'secp256k1': 'ECDSA P-256',
    'ecdsa': 'ECDSA P-256', 'node-forge': 'RSA-2048',
    'jsrsasign': 'RSA-2048', 'pyopenssl': 'RSA-2048',
    'pycryptodome': 'AES-128', 'cryptography': 'RSA-2048',
    'bouncycastle': 'RSA-2048', 'bcprov': 'RSA-2048',
    'tweetnacl': 'Ed25519', 'ed25519': 'Ed25519',
    'libsodium': 'Ed25519', 'nacl': 'Ed25519',
    'noble-curves': 'ECDSA P-256', '@noble/curves': 'ECDSA P-256'
  };

  function findingMatchesAlgo(f, classicalKey) {
    let fNorm = null;
    if (f.algorithm) {
      fNorm = PQCSizes.normalizeAlgo(f.algorithm);
    }
    if (!fNorm) {
      const lib = (f.library || f.category || '').toLowerCase().trim();
      fNorm = PQCSizes.normalizeAlgo(LIB_TO_ALGO[lib]) || PQCSizes.normalizeAlgo(lib);
    }
    if (!fNorm) {
      const snippet = (f.codeSnippet || f.rawCallSite || f.description || '');
      fNorm = PQCSizes.normalizeAlgo(snippet);
    }

    const selNorm = PQCSizes.normalizeAlgo(classicalKey);
    
    if (!fNorm || !selNorm) return false;

    // Check if in the same family
    const fFamily = (PQCSizes.ALGO_DATABASE[fNorm] || {}).family;
    const selFamily = (PQCSizes.ALGO_DATABASE[selNorm] || {}).family;

    if (fFamily && selFamily && fFamily === selFamily) {
        return true;
    }
    
    return fNorm === selNorm;
  }

  function renderAffectedFiles(classicalKey) {
    const container = document.getElementById('pqc-affected-files-list');
    if (!container) return;

    // Filter to findings matching the selected algorithm
    const rawMatches = allScanFindings.filter(f => findingMatchesAlgo(f, classicalKey));

    // Deduplicate by file + line + algorithm + detection
    const seen = new Set();
    const matches = rawMatches.filter(f => {
      const key = `${f.filePath || f.file}|${f.lineNumber || f.line}|${f.algorithm}|${f.detection || f.detection_method || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // === TEMPORARY DEBUG: console.table proof ===
    const debugTable = allScanFindings.map(f => {
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
      return {
        file: f.filePath || f.file || '?',
        line: f.lineNumber || f.line || '?',
        algorithm: f.algorithm || '-',
        normalized: fNorm || 'null',
        included: findingMatchesAlgo(f, classicalKey)
      };
    });
    console.group(`[PQC Filter] Selected: ${classicalKey}`);
    console.table(debugTable);
    console.log(`Matched ${matches.length} of ${allScanFindings.length} findings`);
    console.groupEnd();
    // === END DEBUG ===

    if (matches.length === 0) {
      container.innerHTML = `
        <div style="padding:16px; background:var(--bg-main); border-radius:var(--r-sm); font-size:13px; color:var(--text-m);">
          No scanned file uses <strong>${classicalKey}</strong>. Showing manual simulation.
        </div>
      `;
      return;
    }

    // Detection badge color map
    const DETECT_COLORS = {
      AST: 'badge-safe', REGEX: 'badge-amber', MANIFEST: 'badge-amber',
      CERTIFICATE: 'badge-crit', CONFIG: 'badge-crit', INFRA: 'badge-crit',
      RUNTIME: 'badge-crit'
    };

    const header = `<div style="font-size:12px; font-weight:700; color:var(--text-m); margin-bottom:8px;">${matches.length} file${matches.length !== 1 ? 's' : ''} affected</div>`;

    const rows = matches.map(f => {
      const path = f.filePath || f.file || 'unknown';
      const line = f.lineNumber || f.line || 1;
      const algo = f.algorithm || classicalKey;
      const lang = f.language || (path.endsWith('.py') ? 'Python' : (path.endsWith('.js') ? 'JavaScript' : (path.endsWith('.json') ? 'JSON' : 'code')));
      const detection = (f.detection || f.detection_method || 'REGEX').toUpperCase();
      const badgeClass = DETECT_COLORS[detection] || 'badge-amber';
      const snippet = f.codeSnippet || f.rawCallSite || f.description || algo;

      return `
        <div class="pqc-file-item">
          <div style="flex:1; min-width:0;">
            <div style="font-weight:700; color:var(--text-h);">${path} : line ${line}</div>
            <div style="font-size:11px; color:var(--text-m); font-family:monospace; margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${snippet}</div>
          </div>
          <div style="display:flex; gap:6px; align-items:center; flex-shrink:0;">
            <span class="badge ${badgeClass}" style="font-size:10px;">${detection}</span>
            <span class="badge badge-safe" style="font-size:10px;">${lang}</span>
          </div>
        </div>
      `;
    }).join('');

    container.innerHTML = header + rows;
  }

  function exportSimulationJson() {
    if (!currentSimResult) return;
    const jsonStr = JSON.stringify(currentSimResult, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pqc_impact_simulation_${currentSimResult.classicalKey}_to_${currentSimResult.pqcKey}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function copySummaryToClipboard() {
    if (!currentSimResult) return;
    const res = currentSimResult;
    const k = res.kpis;
    const summary = `CryptoScan PQC Impact Simulation Summary:
Current Algorithm: ${res.classicalKey}
PQC Replacement: ${res.pqcKey} (Mode: ${res.mode})
Public Key Size: ${k.pkBefore} B -> ${k.pkAfter} B (${k.pkMultiplier}x)
Signature/CT Size: ${k.sigBefore} B -> ${k.sigAfter} B (${k.sigMultiplier}x)
Affected Protocol Scenarios: ${k.affectedScenariosCount} of 6
Overall Compatibility Verdict: ${k.verdict}
Note: Results are size-based estimates, not a live interoperability test.`;

    navigator.clipboard.writeText(summary).then(() => {
      alert('Simulation summary copied to clipboard!');
    }).catch(err => {
      console.error('Copy failed:', err);
    });
  }
})();
