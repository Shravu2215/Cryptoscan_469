/**
 * CryptoTwin Frontend JavaScript Module
 * Handles target scan selection, fire drill execution polling,
 * interactive breach simulation node rendering, drawer detail view,
 * test matrix filtering, AI diagnosis timeline diff view, and report exports.
 */

class CryptoTwinApp {
  constructor() {
    this.currentScanId = null;
    this.currentRunId = null;
    this.activeRunData = null;
    this.pollInterval = null;
    this.activeTestTab = 'ALL';
    this.activeTestFilter = 'ALL';

    this.init();
  }

  async init() {
    this.bindEvents();
    await this.loadScans();
  }

  bindEvents() {
    const scanSelect = document.getElementById('ct-scan-select');
    if (scanSelect) {
      scanSelect.addEventListener('change', (e) => {
        this.currentScanId = e.target.value;
        this.loadLastRunForScan();
      });
    }

    const btnRun = document.getElementById('ct-btn-run');
    if (btnRun) {
      btnRun.addEventListener('click', () => this.startFireDrill());
    }

    const btnReset = document.getElementById('ct-btn-reset');
    if (btnReset) {
      btnReset.addEventListener('click', () => this.resetTwin());
    }

    const testFilter = document.getElementById('ct-test-filter');
    if (testFilter) {
      testFilter.addEventListener('change', (e) => {
        this.activeTestFilter = e.target.value;
        this.renderTestTable();
      });
    }

    const tabBtns = document.querySelectorAll('.ct-tab-btn');
    tabBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        tabBtns.forEach(b => b.classList.remove('active'));
        e.target.classList.add('active');
        this.activeTestTab = e.target.dataset.tab;
        this.renderTestTable();
      });
    });

    const drawerClose = document.getElementById('ct-drawer-close');
    const drawerOverlay = document.getElementById('ct-drawer-overlay');
    if (drawerClose && drawerOverlay) {
      drawerClose.addEventListener('click', () => this.closeDrawer());
      drawerOverlay.addEventListener('click', () => this.closeDrawer());
    }

    const btnExport = document.getElementById('ct-btn-export');
    if (btnExport) {
      btnExport.addEventListener('click', () => this.exportReport());
    }

    const btnAddMigration = document.getElementById('ct-btn-add-migration');
    if (btnAddMigration) {
      btnAddMigration.addEventListener('click', () => {
        window.location.href = `migration-plan.html?scanId=${this.currentScanId || ''}`;
      });
    }
  }

  getAuthHeader() {
    const token = localStorage.getItem('cs_token');
    return token ? { 'Authorization': `Bearer ${token}` } : {};
  }

  async loadScans() {
    try {
      const select = document.getElementById('ct-scan-select');
      select.innerHTML = '<option value="" disabled selected>Loading scans...</option>';

      let scans = [];
      try {
        const res = await fetch('/api/scans', { headers: this.getAuthHeader() });
        if (res.ok) {
          scans = await res.json();
        }
      } catch (e) {
        console.warn('Failed to fetch scans from DB API, attempting fallback', e);
      }

      if (!scans || scans.length === 0) {
        // Fallback demo/sample scan
        scans = [
          { id: 'pqc-test-fixture-multilang', name: 'pqc-test-fixture-multilang.zip', status: 'COMPLETED', createdAt: new Date().toISOString() }
        ];
      }

      // Check URL query param scanId
      const urlParams = new URLSearchParams(window.location.search);
      const paramScanId = urlParams.get('scanId');

      select.innerHTML = '';
      scans.forEach((scan, index) => {
        const opt = document.createElement('option');
        opt.value = scan.id;
        const name = scan.repo?.name || scan.name || scan.id;
        opt.textContent = `${name} (${new Date(scan.createdAt).toLocaleDateString()})`;
        if (paramScanId && scan.id === paramScanId) {
          opt.selected = true;
        } else if (!paramScanId && index === 0) {
          opt.selected = true;
        }
        select.appendChild(opt);
      });

      this.currentScanId = select.value;
      if (this.currentScanId) {
        await this.loadLastRunForScan();
      }
    } catch (err) {
      console.error('Error loading scans:', err);
    }
  }

  async loadLastRunForScan() {
    if (!this.currentScanId) return;
    try {
      const res = await fetch(`/api/cryptotwin/runs?scanId=${this.currentScanId}`, { headers: this.getAuthHeader() });
      if (res.ok) {
        const runs = await res.json();
        if (runs && runs.length > 0) {
          this.activeRunData = runs[0];
          this.currentRunId = this.activeRunData.id;
          this.updateUIFromRunData(this.activeRunData);
        } else {
          this.resetUIState();
        }
      } else {
        this.resetUIState();
      }
    } catch (e) {
      console.warn('Could not load past run for scan, resetting UI state', e);
      this.resetUIState();
    }
  }

  resetUIState() {
    this.activeRunData = null;
    this.currentRunId = null;
    document.getElementById('kpi-weaknesses-count').textContent = '0';
    document.getElementById('kpi-attack-paths-count').textContent = '0';
    document.getElementById('kpi-tests-run-count').textContent = '0';
    document.getElementById('kpi-tests-passed-count').textContent = '0';
    document.getElementById('kpi-fixes-applied-count').textContent = '0';
    document.getElementById('kpi-confidence-pct').textContent = '-- %';
    
    const verdictEl = document.getElementById('ct-verdict-badge');
    verdictEl.className = 'ct-verdict-badge verdict-not-run';
    verdictEl.textContent = 'NOT RUN';

    this.resetStepper();
    
    document.getElementById('ct-chain-before').innerHTML = '<div style="color:var(--text-m); font-size:13px; text-align:center; padding:20px;">No fire drill run yet. Select a scan and click "Run CryptoTwin Fire Drill".</div>';
    document.getElementById('ct-chain-after').innerHTML = '<div style="color:var(--text-m); font-size:13px; text-align:center; padding:20px;">No fire drill run yet. Select a scan and click "Run CryptoTwin Fire Drill".</div>';
    document.getElementById('ct-test-table-body').innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-m); padding:24px;">No test results yet. Run a CryptoTwin fire drill to execute tests.</td></tr>';
    document.getElementById('ct-ai-timeline').innerHTML = '<div style="color:var(--text-m); font-size:13px; text-align:center; padding:20px; background:var(--bg-main); border-radius:var(--r-md);">AI loop timeline will appear here during/after fire drill execution.</div>';
    
    document.getElementById('ct-report-blockers').textContent = '0';
    document.getElementById('ct-report-closed-paths').textContent = '0 / 0';
    document.getElementById('ct-report-confidence').textContent = '-- %';
  }

  resetStepper() {
    const items = document.querySelectorAll('.ct-step-item');
    items.forEach(item => {
      item.className = 'ct-step-item pending';
    });
  }

  async startFireDrill() {
    if (!this.currentScanId) {
      alert('Please select a target scan repository first.');
      return;
    }

    const btnRun = document.getElementById('ct-btn-run');
    btnRun.disabled = true;
    btnRun.innerHTML = `
      <svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px; height:16px; animation: spin 1s linear infinite;">
        <circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-dashoffset="10"/>
      </svg>
      Running Twin Sandbox...
    `;

    try {
      const res = await fetch('/api/cryptotwin/runs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.getAuthHeader()
        },
        body: JSON.stringify({ scanId: this.currentScanId, maxFixIterations: 3 })
      });

      if (!res.ok) {
        throw new Error('Failed to create CryptoTwin run');
      }

      const run = await res.json();
      this.currentRunId = run.id;
      this.activeRunData = run;
      this.updateUIFromRunData(run);

      // Start Polling
      if (this.pollInterval) clearInterval(this.pollInterval);
      this.pollInterval = setInterval(() => this.pollRunProgress(), 1500);

    } catch (e) {
      console.error('Error starting CryptoTwin drill:', e);
      alert('Failed to start CryptoTwin Fire Drill: ' + e.message);
      btnRun.disabled = false;
      btnRun.innerHTML = 'Run CryptoTwin Fire Drill';
    }
  }

  async pollRunProgress() {
    if (!this.currentRunId) return;
    try {
      const res = await fetch(`/api/cryptotwin/runs/${this.currentRunId}`, { headers: this.getAuthHeader() });
      if (!res.ok) return;

      const run = await res.json();
      this.activeRunData = run;
      this.updateUIFromRunData(run);

      if (run.status === 'COMPLETED' || run.status === 'FAILED') {
        clearInterval(this.pollInterval);
        this.pollInterval = null;

        const btnRun = document.getElementById('ct-btn-run');
        btnRun.disabled = false;
        btnRun.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px; height:16px;">
            <path stroke-linecap="round" stroke-linejoin="round" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
            <path stroke-linecap="round" stroke-linejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          Run CryptoTwin Fire Drill
        `;
      }
    } catch (e) {
      console.warn('Error polling CryptoTwin run state:', e);
    }
  }

  async resetTwin() {
    if (!this.currentRunId) {
      this.resetUIState();
      return;
    }
    if (confirm('Are you sure you want to reset this Twin sandbox run?')) {
      try {
        await fetch(`/api/cryptotwin/runs/${this.currentRunId}/reset`, {
          method: 'POST',
          headers: this.getAuthHeader()
        });
      } catch (_) {}
      this.resetUIState();
    }
  }

  updateUIFromRunData(run) {
    if (!run) return;

    // Update Top KPIs
    document.getElementById('kpi-weaknesses-count').textContent = run.weaknessCount || (run.attackPaths ? run.attackPaths.length : 0);
    document.getElementById('kpi-attack-paths-count').textContent = run.attackPaths ? run.attackPaths.length : 0;
    document.getElementById('kpi-tests-run-count').textContent = run.testsRun || (run.tests ? run.tests.length : 0);
    document.getElementById('kpi-tests-passed-count').textContent = run.testsPassed || 0;
    document.getElementById('kpi-fixes-applied-count').textContent = run.fixesApplied || 0;
    
    const confidencePct = run.migrationConfidence != null ? `${run.migrationConfidence}%` : '-- %';
    document.getElementById('kpi-confidence-pct').textContent = confidencePct;

    // Verdict Badge
    const verdictEl = document.getElementById('ct-verdict-badge');
    const verdict = run.verdict || 'NOT RUN';
    verdictEl.textContent = verdict;
    if (verdict === 'PRODUCTION READY') {
      verdictEl.className = 'ct-verdict-badge verdict-ready';
    } else if (verdict === 'PRODUCTION NOT READY') {
      verdictEl.className = 'ct-verdict-badge verdict-not-ready';
    } else if (run.status === 'RUNNING') {
      verdictEl.className = 'ct-verdict-badge verdict-running';
      verdictEl.textContent = 'DRILL IN PROGRESS...';
    } else {
      verdictEl.className = 'ct-verdict-badge verdict-not-run';
    }

    // Pipeline Stepper Stages
    this.updateStepperStages(run.stages || []);

    // Breach Simulation Node Chain
    this.renderBreachSimulation(run.attackPaths || []);

    // Test Suite Table
    this.renderTestTable();

    // AI Diagnosis Timeline
    this.renderAITimeline(run.aiIterations || []);

    // Final Report Summary Card
    document.getElementById('ct-report-blockers').textContent = run.remainingBlockers || (verdict === 'PRODUCTION NOT READY' ? (run.tests ? run.tests.filter(t => t.status === 'FAILED').length : 1) : 0);
    const closedPathsCount = run.attackPaths ? run.attackPaths.filter(p => p.status === 'BLOCKED').length : 0;
    const totalPathsCount = run.attackPaths ? run.attackPaths.length : 0;
    document.getElementById('ct-report-closed-paths').textContent = `${closedPathsCount} / ${totalPathsCount}`;
    document.getElementById('ct-report-confidence').textContent = confidencePct;
    document.getElementById('ct-report-sub').textContent = `Run ID: ${run.id || 'N/A'} • Status: ${run.status || 'READY'}`;
  }

  updateStepperStages(stages) {
    const stageMap = {
      'WEAKNESS_FOUND': 'weakness-found',
      'RISK_ANALYSIS': 'risk-analysis',
      'MIGRATION_REC': 'migration-rec',
      'TWIN_CREATED': 'twin-created',
      'MIGRATION_APPLIED': 'migration-applied',
      'TESTS_RUNNING': 'tests-running',
      'AI_DIAGNOSE': 'ai-diagnose',
      'RETEST': 'retest',
      'VERDICT': 'verdict'
    };

    stages.forEach(st => {
      const stageKey = stageMap[st.name];
      if (!stageKey) return;
      const el = document.querySelector(`.ct-step-item[data-stage="${stageKey}"]`);
      if (el) {
        el.className = `ct-step-item ${st.status.toLowerCase()}`;
      }
    });
  }

  renderBreachSimulation(attackPaths) {
    const colBefore = document.getElementById('ct-chain-before');
    const colAfter = document.getElementById('ct-chain-after');

    if (!attackPaths || attackPaths.length === 0) {
      colBefore.innerHTML = '<div style="color:var(--text-m); font-size:13px; text-align:center; padding:20px;">No attack paths simulated for this scan.</div>';
      colAfter.innerHTML = '<div style="color:var(--text-m); font-size:13px; text-align:center; padding:20px;">No attack paths simulated for this scan.</div>';
      return;
    }

    let beforeHtml = '';
    let afterHtml = '';

    attackPaths.forEach((path, pathIdx) => {
      beforeHtml += `<div style="font-size:12px; font-weight:700; color:var(--text-h); margin-bottom:8px;">Path #${pathIdx + 1}: ${path.title}</div>`;
      afterHtml += `<div style="font-size:12px; font-weight:700; color:var(--text-h); margin-bottom:8px;">Path #${pathIdx + 1}: ${path.title} (Migrated)</div>`;

      path.nodes.forEach((node, nodeIdx) => {
        // Before Node
        beforeHtml += `
          <div class="ct-chain-node vulnerable" onclick="cryptoTwinApp.openDrawer('${path.id}', ${nodeIdx}, 'BEFORE')">
            <div>
              <div class="ct-node-name">${node.name}</div>
              <div class="ct-node-meta">${node.algorithm || ''} • ${node.file || 'System'}</div>
            </div>
            <span class="ct-status-pill pill-failed">${node.role || 'EXPOSED'}</span>
          </div>
        `;

        if (nodeIdx < path.nodes.length - 1) {
          beforeHtml += `<div class="ct-chain-connector">↓</div>`;
        }

        // After Node
        const isBlocked = node.isBrokenLink || node.status === 'BLOCKED';
        const isDownstream = nodeIdx > 0 && path.nodes[0].isBrokenLink;
        const nodeClass = isBlocked ? 'blocked' : (isDownstream ? 'protected' : 'vulnerable');
        const pillClass = isBlocked ? 'pill-passed' : (isDownstream ? 'pill-skipped' : 'pill-failed');
        const statusText = isBlocked ? 'BLOCKED LINK' : (isDownstream ? 'PROTECTED' : 'EXPOSED');

        afterHtml += `
          <div class="ct-chain-node ${nodeClass}" onclick="cryptoTwinApp.openDrawer('${path.id}', ${nodeIdx}, 'AFTER')">
            <div>
              <div class="ct-node-name">${node.name} ${isBlocked ? '✓' : ''}</div>
              <div class="ct-node-meta">${isBlocked ? (node.pqcReplacement || 'Quantum Shielded') : node.algorithm} • ${node.file || 'System'}</div>
            </div>
            <span class="ct-status-pill ${pillClass}">${statusText}</span>
          </div>
        `;

        if (nodeIdx < path.nodes.length - 1) {
          afterHtml += `<div class="ct-chain-connector">${isBlocked ? '✕ [BROKEN CHAIN]' : '↓'}</div>`;
        }
      });

      if (pathIdx < attackPaths.length - 1) {
        beforeHtml += `<div style="height:16px; border-bottom:1px dashed var(--border-color); margin-bottom:16px;"></div>`;
        afterHtml += `<div style="height:16px; border-bottom:1px dashed var(--border-color); margin-bottom:16px;"></div>`;
      }
    });

    colBefore.innerHTML = beforeHtml;
    colAfter.innerHTML = afterHtml;
  }

  openDrawer(pathId, nodeIndex, mode) {
    if (!this.activeRunData || !this.activeRunData.attackPaths) return;
    const path = this.activeRunData.attackPaths.find(p => p.id === pathId);
    if (!path || !path.nodes[nodeIndex]) return;

    const node = path.nodes[nodeIndex];
    document.getElementById('drawer-title').textContent = `${node.name} (${mode} Migration)`;

    const body = document.getElementById('drawer-body');
    body.innerHTML = `
      <div style="background:var(--bg-card); padding:16px; border-radius:var(--r-md); border:1px solid var(--border-color);">
        <div style="font-size:11px; font-weight:700; color:var(--text-m); text-transform:uppercase;">Source File & Line</div>
        <div style="font-family:'JetBrains Mono', monospace; font-size:13px; font-weight:600; color:var(--text-h); margin-top:4px;">
          ${node.file || 'Not specified'}:${node.line || '1'}
        </div>
      </div>

      <div style="background:var(--bg-card); padding:16px; border-radius:var(--r-md); border:1px solid var(--border-color);">
        <div style="font-size:11px; font-weight:700; color:var(--text-m); text-transform:uppercase;">Detected Algorithm</div>
        <div style="font-size:14px; font-weight:700; color:var(--ct-red); margin-top:4px;">
          ${node.algorithm || 'Classical Cryptography'}
        </div>
      </div>

      <div style="background:var(--bg-card); padding:16px; border-radius:var(--r-md); border:1px solid var(--border-color);">
        <div style="font-size:11px; font-weight:700; color:var(--text-m); text-transform:uppercase;">Why It Matters</div>
        <div style="font-size:13px; color:var(--text-h); margin-top:6px; line-height:1.5;">
          ${node.whyItMatters || 'Classical algorithms like RSA/ECC can be broken by quantum computers (Shor\'s Algorithm), exposing private keys and enabling session hijack/decryption.'}
        </div>
      </div>

      <div style="background:var(--ct-green-bg); padding:16px; border-radius:var(--r-md); border:1px solid rgba(16, 185, 129, 0.4);">
        <div style="font-size:11px; font-weight:700; color:var(--ct-green); text-transform:uppercase;">Proposed PQC / Hybrid Replacement</div>
        <div style="font-family:'JetBrains Mono', monospace; font-size:14px; font-weight:700; color:var(--ct-green); margin-top:6px;">
          ${node.pqcReplacement || 'ML-KEM-768 / Hybrid ECDH+Kyber'}
        </div>
      </div>
    `;

    document.getElementById('ct-drawer-overlay').classList.add('active');
    document.getElementById('ct-drawer').classList.add('active');
  }

  closeDrawer() {
    document.getElementById('ct-drawer-overlay').classList.remove('active');
    document.getElementById('ct-drawer').classList.remove('active');
  }

  renderTestTable() {
    const tbody = document.getElementById('ct-test-table-body');
    if (!this.activeRunData || !this.activeRunData.tests || this.activeRunData.tests.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-m); padding:24px;">No test results available.</td></tr>';
      return;
    }

    let tests = this.activeRunData.tests;

    // Filter Category
    if (this.activeTestTab !== 'ALL') {
      tests = tests.filter(t => t.category.toUpperCase() === this.activeTestTab);
    }

    // Filter Status
    if (this.activeTestFilter !== 'ALL') {
      tests = tests.filter(t => t.status === this.activeTestFilter);
    }

    if (tests.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-m); padding:24px;">No tests matching selected filters.</td></tr>';
      return;
    }

    let html = '';
    tests.forEach(test => {
      const statusPill = test.status === 'PASSED' ? '<span class="ct-status-pill pill-passed">PASSED</span>' :
                         (test.status === 'FAILED' ? '<span class="ct-status-pill pill-failed">FAILED</span>' :
                         '<span class="ct-status-pill pill-skipped">SKIPPED</span>');

      html += `
        <tr>
          <td style="font-weight:700;">${test.name}</td>
          <td><span style="font-size:11px; padding:2px 8px; border-radius:4px; background:var(--bg-main); font-weight:600;">${test.category}</span></td>
          <td>${test.phase || 'POST-MIGRATION'}</td>
          <td>${statusPill}</td>
          <td style="font-family:'JetBrains Mono', monospace; font-size:12px;">${test.durationMs ? `${test.durationMs}ms` : '12ms'}</td>
          <td style="color:var(--text-m); font-size:12px;">${test.reason || 'Executing normally'}</td>
        </tr>
      `;
    });

    tbody.innerHTML = html;
  }

  renderAITimeline(iterations) {
    const container = document.getElementById('ct-ai-timeline');
    if (!iterations || iterations.length === 0) {
      container.innerHTML = '<div style="color:var(--text-m); font-size:13px; text-align:center; padding:20px; background:var(--bg-main); border-radius:var(--r-md);">No AI auto-fix iterations required. All tests passed on initial migration run!</div>';
      return;
    }

    let html = '';
    iterations.forEach((item, index) => {
      const statusClass = item.retestResult === 'PASSED' ? 'pill-passed' : 'pill-failed';
      html += `
        <div class="ct-iteration-card">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div style="font-size:14px; font-weight:700; color:var(--text-h);">
              Iteration #${index + 1}: ${item.symptom || 'Test Failure Diagnosed'}
            </div>
            <span class="ct-status-pill ${statusClass}">${item.retestResult || 'RETESTED'}</span>
          </div>

          <div style="font-size:13px; color:var(--text-m);">
            <strong>AI Identified Root Cause:</strong> ${item.rootCause || 'Algorithm parameter mismatch during hybrid key exchange payload packing.'}
          </div>

          ${item.codeDiff ? `
            <div>
              <div style="font-size:11px; font-weight:700; color:var(--text-m); text-transform:uppercase; margin-bottom:6px;">Applied Patch (Code Diff)</div>
              <pre class="ct-diff-box"><code>${item.codeDiff}</code></pre>
            </div>
          ` : ''}
        </div>
      `;
    });

    container.innerHTML = html;
  }

  exportReport() {
    if (!this.activeRunData) {
      alert('No CryptoTwin run data to export.');
      return;
    }
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(this.activeRunData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `CryptoTwin_Report_${this.currentRunId}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }
}

// Global instance
window.cryptoTwinApp = new CryptoTwinApp();
