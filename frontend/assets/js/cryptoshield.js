/**
 * CryptoShield Frontend JavaScript Module
 * Handles Crypto Asset Identity display, Access Policy management,
 * Access Control simulation, Blast Radius visualization, CryptoTwin test recovery integration,
 * Human Approval workflows, and Audit Trail viewing.
 */

class CryptoShieldApp {
  constructor() {
    this.activeTab = 'dashboard';
    this.init();
  }

  async init() {
    this.bindEvents();
    await this.loadDashboard();
    await this.loadAssets();
  }

  // ---- Helpers ----
  getAuthHeader() {
    const token = localStorage.getItem('cs_token');
    return token ? { 'Authorization': `Bearer ${token}` } : {};
  }

  showToast(message, type = 'success') {
    const existing = document.getElementById('cs-toast');
    if (existing) existing.remove();

    const color = type === 'success' ? 'var(--cs-green)' :
                  type === 'error'   ? 'var(--cs-red)'   :
                  type === 'warn'    ? 'var(--cs-amber)'  : 'var(--cs-purple)';
    const toast = document.createElement('div');
    toast.id = 'cs-toast';
    toast.innerHTML = message;
    toast.style.cssText = `
      position:fixed; bottom:24px; right:24px; z-index:9999;
      background:var(--bg-card); border:1px solid ${color};
      color:var(--text-h); padding:14px 20px; border-radius:12px;
      font-size:13px; font-weight:600; max-width:420px;
      box-shadow:0 8px 32px rgba(0,0,0,0.2);
      animation:csToastIn 0.3s ease; border-left:4px solid ${color};
    `;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
  }

  // ---- Tab Navigation ----
  bindEvents() {
    const tabs = document.querySelectorAll('.cs-nav-tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', (e) => {
        tabs.forEach(t => t.classList.remove('active'));
        e.target.classList.add('active');
        this.switchTab(e.target.dataset.tab);
      });
    });

    const btnSimModal = document.getElementById('cs-btn-sim-modal');
    const modalClose = document.getElementById('cs-modal-close');
    const modalOverlay = document.getElementById('cs-modal-overlay');

    if (btnSimModal && modalOverlay) {
      btnSimModal.addEventListener('click', () => {
        // clear previous result
        const res = document.getElementById('cs-sim-result');
        if (res) res.remove();
        modalOverlay.classList.add('active');
      });
    }
    if (modalClose && modalOverlay) {
      modalClose.addEventListener('click', () => modalOverlay.classList.remove('active'));
    }
    // close modal on overlay click outside modal box
    if (modalOverlay) {
      modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) modalOverlay.classList.remove('active');
      });
    }

    const formPolicy = document.getElementById('cs-form-policy');
    if (formPolicy) {
      formPolicy.addEventListener('submit', (e) => this.handleCreatePolicy(e));
    }

    const formSim = document.getElementById('cs-form-sim');
    if (formSim) {
      formSim.addEventListener('submit', (e) => this.handleSimulateAccess(e));
    }
  }

  switchTab(tabName) {
    this.activeTab = tabName;
    document.querySelectorAll('.cs-tab-panel').forEach(p => p.style.display = 'none');
    const targetPanel = document.getElementById(`tab-view-${tabName}`);
    if (targetPanel) targetPanel.style.display = 'block';

    if (tabName === 'dashboard') this.loadDashboard();
    if (tabName === 'assets')    this.loadAssets();
    if (tabName === 'policies')  this.loadPolicies();
    if (tabName === 'events')    this.loadEvents();
    if (tabName === 'alerts')    this.loadAlerts();
    if (tabName === 'plans')     this.loadPlans();
    if (tabName === 'audit')     this.loadAudits();
  }

  // ---- Dashboard ----
  async loadDashboard() {
    try {
      const res = await fetch('/api/cryptoshield/dashboard', { headers: this.getAuthHeader() });
      if (!res.ok) return;
      const data = await res.json();

      const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
      set('dash-assets-count',   data.protectedAssets   || 0);
      set('dash-critical-count', data.criticalAssets     || 0);
      set('dash-blocked-count',  data.unauthorizedAttempts || 0);
      set('dash-policies-count', data.activePolicies     || 0);

      const pill = document.getElementById('dash-status-pill');
      if (pill) {
        if (data.systemStatus === 'ATTENTION_REQUIRED') {
          pill.className = 'cs-pill cs-pill-misuse';
          pill.textContent = '⚠ ATTENTION REQUIRED';
        } else {
          pill.className = 'cs-pill cs-pill-protected';
          pill.textContent = '✓ ALL SYSTEMS PROTECTED';
        }
      }
    } catch (e) {
      console.warn('Error loading CryptoShield dashboard:', e);
    }
  }

  // ---- Assets ----
  async loadAssets() {
    try {
      const res = await fetch('/api/cryptoshield/assets', { headers: this.getAuthHeader() });
      if (!res.ok) return;
      const assets = await res.json();

      const tbody = document.getElementById('cs-assets-tbody');
      const selectPolicy = document.getElementById('pol-asset-id');
      const selectSim = document.getElementById('sim-asset-id');

      let optHtml = '';
      let rowHtml = '';

      assets.forEach(asset => {
        optHtml += `<option value="${asset.assetId}">${asset.assetId} — ${asset.algorithm}</option>`;
        const pill = asset.status === 'PROTECTED'
          ? `<span class="cs-pill cs-pill-protected">PROTECTED</span>`
          : asset.status === 'SUSPECTED_MISUSE'
            ? `<span class="cs-pill cs-pill-misuse">SUSPECTED MISUSE</span>`
            : `<span class="cs-pill cs-pill-blocked">BLOCKED</span>`;

        rowHtml += `
          <tr>
            <td style="font-weight:700; color:var(--text-h);">${asset.assetId}</td>
            <td><span style="font-size:11px; padding:2px 8px; border-radius:4px; background:var(--bg-main); border:1px solid var(--border-color); font-weight:600;">${asset.assetType}</span></td>
            <td>${asset.application}</td>
            <td>${asset.environment}</td>
            <td style="font-family:'JetBrains Mono',monospace; font-size:12px; color:var(--cs-purple);">${asset.fingerprint}</td>
            <td style="font-weight:700; color:${asset.criticality === 'CRITICAL' ? 'var(--cs-red)' : asset.criticality === 'HIGH' ? 'var(--cs-amber)' : 'var(--text-m)'};">${asset.criticality}</td>
            <td>${pill}</td>
            <td>
              <button class="cs-btn-sm cs-btn-purple" onclick="cryptoShieldApp.showBlastRadius('${asset.assetId}')">
                Blast Radius
              </button>
            </td>
          </tr>`;
      });

      if (tbody) tbody.innerHTML = rowHtml || '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--text-m);">No assets registered.</td></tr>';
      if (selectPolicy) selectPolicy.innerHTML = optHtml;
      if (selectSim) selectSim.innerHTML = optHtml;
    } catch (e) {
      console.warn('Error loading assets:', e);
    }
  }

  // ---- Policies ----
  async loadPolicies() {
    try {
      const res = await fetch('/api/cryptoshield/policies', { headers: this.getAuthHeader() });
      if (!res.ok) return;
      const policies = await res.json();
      const tbody = document.getElementById('cs-policies-tbody');
      let html = '';
      policies.forEach(p => {
        const ops = (p.allowedOperations || []).map(op =>
          `<span style="font-size:10px;padding:2px 7px;border-radius:4px;background:var(--cs-purple-bg);color:var(--cs-purple);font-weight:700;margin-right:4px;">${op}</span>`
        ).join('');
        html += `
          <tr>
            <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-m);">${p.id}</td>
            <td style="font-weight:700;">${p.assetId}</td>
            <td>${p.allowedService}</td>
            <td>${ops}</td>
            <td>${p.environment}</td>
            <td><span class="cs-pill cs-pill-protected">${p.status}</span></td>
          </tr>`;
      });
      if (tbody) tbody.innerHTML = html || '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--text-m);">No access policies defined. Create one above.</td></tr>';
    } catch (e) {
      console.warn('Error loading policies:', e);
    }
  }

  async handleCreatePolicy(event) {
    event.preventDefault();
    const assetId = document.getElementById('pol-asset-id').value;
    const allowedService = document.getElementById('pol-allowed-app').value.trim();
    const environment = document.getElementById('pol-env').value;
    const allowedOperations = Array.from(document.querySelectorAll('input[name="op"]:checked')).map(c => c.value);

    if (!allowedService) { this.showToast('Allowed Application is required.', 'error'); return; }
    if (!allowedOperations.length) { this.showToast('Select at least one allowed operation.', 'warn'); return; }

    const btn = event.target.querySelector('button[type="submit"]');
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }

    try {
      const res = await fetch('/api/cryptoshield/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...this.getAuthHeader() },
        body: JSON.stringify({ assetId, allowedService, allowedOperations, environment })
      });
      if (!res.ok) throw new Error((await res.json()).error || 'Failed to create policy');
      this.showToast(`✓ Access Policy saved for <strong>${allowedService}</strong> on <strong>${assetId}</strong>`, 'success');
      document.getElementById('cs-form-policy').reset();
      await this.loadPolicies();
      await this.loadDashboard();
    } catch (err) {
      this.showToast(`Policy Error: ${err.message}`, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Save Access Policy'; }
    }
  }

  // ---- Security Events & Access Simulation ----
  async handleSimulateAccess(event) {
    event.preventDefault();
    const assetId = document.getElementById('sim-asset-id').value;
    const requestingApplication = document.getElementById('sim-app-name').value;
    const requestedOperation = document.getElementById('sim-op-name').value;
    const environment = document.getElementById('sim-env-name').value;

    const btn = event.target.querySelector('button[type="submit"]');
    if (btn) { btn.disabled = true; btn.textContent = 'Evaluating…'; }

    // Remove old result
    const oldResult = document.getElementById('cs-sim-result');
    if (oldResult) oldResult.remove();

    try {
      const res = await fetch('/api/cryptoshield/simulate-access', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...this.getAuthHeader() },
        body: JSON.stringify({ assetId, requestingApplication, requestedOperation, environment })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Access simulation failed.');

      const ev = data.event;
      const isAllowed = ev.decision === 'ALLOWED';
      const resultDiv = document.createElement('div');
      resultDiv.id = 'cs-sim-result';
      resultDiv.style.cssText = `
        background: ${isAllowed ? 'var(--cs-green-bg)' : 'var(--cs-red-bg)'};
        border: 2px solid ${isAllowed ? 'var(--cs-green-border)' : 'var(--cs-red-border)'};
        border-radius: 12px; padding: 18px 20px;
      `;
      resultDiv.innerHTML = `
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:10px;">
          <span style="font-size:24px;">${isAllowed ? '✓' : '🚨'}</span>
          <div>
            <div style="font-size:18px; font-weight:800; color:${isAllowed ? 'var(--cs-green)' : 'var(--cs-red)'};">
              ${isAllowed ? 'ACCESS ALLOWED' : 'ACCESS BLOCKED'}
            </div>
            <div style="font-size:11px; font-weight:700; color:var(--text-m); text-transform:uppercase; margin-top:2px;">
              ${isAllowed ? 'Simulated' : 'Detected'} Security Event
            </div>
          </div>
        </div>
        <div style="font-size:13px; color:var(--text-h); background:var(--bg-card); padding:12px; border-radius:8px; margin-bottom:8px;">
          <strong>Decision Reason:</strong> ${ev.reason}
        </div>
        <div style="display:flex; gap:12px; flex-wrap:wrap; font-size:12px; color:var(--text-m);">
          <span>Asset: <strong style="color:var(--text-h);">${ev.assetId}</strong></span>
          <span>Operation: <strong style="color:var(--text-h);">${ev.requestedOperation}</strong></span>
          <span>Severity: <strong style="color:${ev.severity === 'CRITICAL' ? 'var(--cs-red)' : 'var(--cs-amber)'};">${ev.severity}</strong></span>
        </div>
      `;
      event.target.appendChild(resultDiv);

      this.loadDashboard();
      this.loadEvents();

      if (!isAllowed) {
        this.showToast(`🚨 Unauthorized access attempt blocked for <strong>${assetId}</strong>`, 'error');
      } else {
        this.showToast(`✓ Access allowed for <strong>${requestingApplication}</strong>`, 'success');
      }
    } catch (err) {
      this.showToast(`Simulation Error: ${err.message}`, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Evaluate Access Policy'; }
    }
  }

  async loadEvents() {
    try {
      const res = await fetch('/api/cryptoshield/events', { headers: this.getAuthHeader() });
      if (!res.ok) return;
      const events = await res.json();
      const tbody = document.getElementById('cs-events-tbody');
      let html = '';
      events.forEach(e => {
        const pill = e.decision === 'ALLOWED'
          ? `<span class="cs-pill cs-pill-protected">ALLOWED</span>`
          : `<span class="cs-pill cs-pill-blocked">BLOCKED</span>`;
        html += `
          <tr>
            <td style="font-size:12px;color:var(--text-m);">${new Date(e.timestamp).toLocaleString()}</td>
            <td style="font-weight:700;">${e.assetId}</td>
            <td>${e.requestingApplication}</td>
            <td><span style="font-size:11px;padding:2px 7px;border-radius:4px;background:var(--bg-main);font-weight:700;">${e.requestedOperation}</span></td>
            <td>${e.environment}</td>
            <td>${pill}</td>
            <td style="font-weight:700;color:${e.severity === 'CRITICAL' ? 'var(--cs-red)' : e.severity === 'HIGH' ? 'var(--cs-amber)' : 'var(--text-m)'};">${e.severity}</td>
            <td style="font-size:12px;color:var(--text-m);max-width:260px;">${e.reason}</td>
          </tr>`;
      });
      if (tbody) tbody.innerHTML = html || '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--text-m);">No security access events recorded yet. Run an access simulation to create one.</td></tr>';
    } catch (e) {
      console.warn('Error loading events:', e);
    }
  }

  // ---- Alerts ----
  async loadAlerts() {
    try {
      const res = await fetch('/api/cryptoshield/alerts', { headers: this.getAuthHeader() });
      if (!res.ok) return;
      const alerts = await res.json();
      const container = document.getElementById('cs-alerts-list');

      if (!alerts || alerts.length === 0) {
        container.innerHTML = `
          <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:32px;text-align:center;">
            <div style="font-size:32px;margin-bottom:8px;">✓</div>
            <div style="font-size:14px;font-weight:700;color:var(--cs-green);">No Active Misuse Alerts</div>
            <div style="font-size:12px;color:var(--text-m);margin-top:4px;">All crypto access requests are policy-compliant.</div>
          </div>`;
        return;
      }

      let html = '';
      alerts.forEach(alt => {
        html += `
          <div style="background:var(--bg-card);border:1px solid var(--cs-red-border);border-left:4px solid var(--cs-red);padding:18px 20px;border-radius:12px;">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px;">
              <div>
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
                  <span class="cs-pill cs-pill-blocked">${alt.severity} MISUSE</span>
                  <span style="font-size:14px;font-weight:800;color:var(--text-h);">${alt.title}</span>
                </div>
                <div style="font-size:12px;color:var(--text-m);">Target Asset: <strong style="color:var(--text-h);">${alt.assetId}</strong> — ${alt.description}</div>
              </div>
              <div style="display:flex;gap:10px;flex-wrap:wrap;">
                <button class="cs-btn-sm cs-btn-red" onclick="cryptoShieldApp.showBlastRadiusPanel('${alt.assetId}')">
                  🔍 Blast Radius
                </button>
                <button class="cs-btn-sm cs-btn-purple" onclick="cryptoShieldApp.testRecovery('${alt.assetId}')">
                  🛡 Test Recovery in CryptoTwin
                </button>
              </div>
            </div>
          </div>`;
      });
      container.innerHTML = html;
    } catch (e) {
      console.warn('Error loading alerts:', e);
    }
  }

  // ---- Blast Radius (inline panel) ----
  async showBlastRadius(assetId) {
    // Navigate to assets tab and show blast radius
    const tabs = document.querySelectorAll('.cs-nav-tab');
    tabs.forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.cs-nav-tab').forEach(t => {
      if (t.dataset.tab === 'assets') t.classList.add('active');
    });
    this.switchTab('assets');
    await this.showBlastRadiusPanel(assetId);
  }

  async showBlastRadiusPanel(assetId) {
    try {
      const res = await fetch(`/api/cryptoshield/blast-radius/${assetId}`, { headers: this.getAuthHeader() });
      if (!res.ok) throw new Error('Failed to calculate blast radius');
      const data = await res.json();

      // Remove existing blast radius panel
      const existing = document.getElementById('cs-blast-panel');
      if (existing) existing.remove();

      const chainHtml = data.potentialBlastRadius.map((node, i) => `
        <div style="display:flex;align-items:center;gap:10px;">
          ${i > 0 ? '<div style="width:2px;height:16px;background:var(--cs-red-border);margin-left:10px;"></div>' : ''}
        </div>
        <div class="cs-chain-node" style="border-left:3px solid ${i === 0 ? 'var(--cs-red)' : 'var(--border-color)'};">
          ${i === 0 ? '🔑 ' : `${i+1}. `}${node}
        </div>
      `).join('');

      const recHtml = data.recommendedResponse.map(r => `
        <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--border-light);">
          <span style="font-size:12px;font-weight:700;color:var(--cs-purple);min-width:20px;">${r.split('.')[0]}.</span>
          <span style="font-size:13px;color:var(--text-h);">${r.replace(/^\d+\.\s*/, '')}</span>
        </div>`).join('');

      const panel = document.createElement('div');
      panel.id = 'cs-blast-panel';
      panel.style.cssText = 'margin-top:20px;';
      panel.innerHTML = `
        <div class="cs-panel" style="border:2px solid var(--cs-red-border);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
            <div>
              <div style="font-size:16px;font-weight:800;color:var(--cs-red);">⚠ Potential Blast Radius — ${assetId}</div>
              <div style="font-size:12px;color:var(--text-m);margin-top:2px;">Not a confirmed breach — this is a simulated worst-case impact model.</div>
            </div>
            <button onclick="document.getElementById('cs-blast-panel').remove()" style="background:none;border:none;cursor:pointer;color:var(--text-m);font-size:18px;">✕</button>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;flex-wrap:wrap;">
            <div>
              <div style="font-size:12px;font-weight:700;color:var(--text-m);text-transform:uppercase;margin-bottom:10px;">Dependency Chain</div>
              <div class="cs-chain-box">${chainHtml}</div>
            </div>
            <div>
              <div style="font-size:12px;font-weight:700;color:var(--text-m);text-transform:uppercase;margin-bottom:10px;">6-Step Recovery Recommendation</div>
              <div style="background:var(--bg-main);border-radius:10px;padding:14px 16px;">${recHtml}</div>
            </div>
          </div>
          <div style="display:flex;gap:10px;margin-top:16px;flex-wrap:wrap;">
            <button class="cs-btn-sm cs-btn-purple" onclick="cryptoShieldApp.testRecovery('${assetId}')">
              🛡 Test Recovery in CryptoTwin
            </button>
          </div>
        </div>`;

      const assetsPanel = document.getElementById('tab-view-assets');
      if (assetsPanel) assetsPanel.appendChild(panel);
      panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (err) {
      this.showToast(`Blast Radius Error: ${err.message}`, 'error');
    }
  }

  // ---- Recovery Plans ----
  async loadPlans() {
    try {
      const res = await fetch('/api/cryptoshield/recovery-plans', { headers: this.getAuthHeader() });
      if (!res.ok) return;
      const plans = await res.json();
      const container = document.getElementById('cs-plans-list');

      if (!plans || plans.length === 0) {
        container.innerHTML = `
          <div class="cs-panel" style="text-align:center;padding:32px;">
            <div style="font-size:32px;margin-bottom:10px;">🛡</div>
            <div style="font-size:16px;font-weight:700;color:var(--text-h);">No Active Recovery Plans</div>
            <div style="font-size:12px;color:var(--text-m);margin-top:6px;margin-bottom:18px;">
              Investigate an alert or run a blast radius analysis to generate a CryptoTwin-backed recovery plan.
            </div>
            <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap;">
              ${['Payment-Key-01','Authentication-Key-01'].map(id => `
                <button class="cs-btn-sm cs-btn-purple" onclick="cryptoShieldApp.testRecovery('${id}')">
                  Test Recovery for ${id}
                </button>`).join('')}
            </div>
          </div>`;
        return;
      }

      container.innerHTML = plans.map(plan => {
        const tv = plan.cryptoTwinValidation || {};
        const approvalPill = plan.approvalStatus === 'APPROVED'
          ? `<span class="cs-pill cs-pill-protected">✓ APPROVED</span>`
          : plan.approvalStatus === 'DECLINED'
            ? `<span class="cs-pill cs-pill-blocked">✕ DECLINED</span>`
            : `<span class="cs-pill cs-pill-misuse">⏳ PENDING HUMAN APPROVAL</span>`;

        const twinSection = tv.verdict ? `
          <div style="background:var(--cs-purple-bg);border:1px solid rgba(139,92,246,0.3);padding:14px 16px;border-radius:10px;">
            <div style="font-size:11px;font-weight:700;color:var(--text-m);text-transform:uppercase;margin-bottom:6px;">CryptoTwin Validation Results</div>
            <div style="display:flex;gap:20px;flex-wrap:wrap;font-size:13px;">
              <span>Verdict: <strong style="color:${tv.verdict==='SAFE_TO_DEPLOY'?'var(--cs-green)':'var(--cs-amber)'};">${tv.verdict}</strong></span>
              <span>Confidence: <strong style="color:var(--cs-purple);">${tv.confidence}%</strong></span>
              <span>Tests Run: <strong>${tv.testsRun}</strong></span>
              <span>Passed: <strong style="color:var(--cs-green);">${tv.testsPassed}</strong></span>
              ${tv.criticalFailures > 0 ? `<span>Critical Failures: <strong style="color:var(--cs-red);">${tv.criticalFailures}</strong></span>` : ''}
            </div>
          </div>` : `
          <div style="background:var(--bg-main);border:1px dashed var(--border-color);padding:14px;border-radius:10px;text-align:center;">
            <div style="font-size:13px;color:var(--text-m);">CryptoTwin validation not yet run.</div>
          </div>`;

        const approvalBtns = plan.approvalStatus === 'PENDING' ? `
          <div style="display:flex;justify-content:flex-end;gap:10px;flex-wrap:wrap;">
            <button class="cs-btn-sm cs-btn-green" onclick="cryptoShieldApp.approvePlan('${plan.id}','APPROVE')" ${!plan.cryptoTwinValidation ? 'disabled title="Run CryptoTwin validation first"' : ''}>
              ✓ APPROVE RECOVERY PLAN
            </button>
            <button class="cs-btn-sm cs-btn-red" onclick="cryptoShieldApp.approvePlan('${plan.id}','DECLINE')">
              ✕ DECLINE
            </button>
          </div>` : `
          <div style="font-size:12px;color:var(--text-m);text-align:right;">
            Reviewed by <strong>${plan.approvedBy || 'SecOps Lead'}</strong> on ${new Date(plan.approvedAt).toLocaleString()} — No real credentials modified.
          </div>`;

        return `
          <div class="cs-panel" style="border-left:4px solid ${plan.approvalStatus==='APPROVED'?'var(--cs-green)':plan.approvalStatus==='DECLINED'?'var(--cs-red)':'var(--cs-amber)'};">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;flex-wrap:wrap;gap:10px;">
              <div>
                <div style="font-size:16px;font-weight:800;color:var(--text-h);">Security Recovery Plan — ${plan.assetId}</div>
                <div style="font-size:12px;color:var(--text-m);margin-top:2px;">ID: ${plan.id} • Created ${new Date(plan.createdAt).toLocaleString()}</div>
              </div>
              ${approvalPill}
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:14px;">
              <div style="background:var(--bg-main);padding:14px;border-radius:10px;border:1px solid var(--border-color);">
                <div style="font-size:11px;font-weight:700;color:var(--text-m);text-transform:uppercase;">Identified Issue</div>
                <div style="font-size:13px;font-weight:600;color:var(--text-h);margin-top:4px;">${plan.issue}</div>
              </div>
              <div style="background:var(--cs-red-bg);padding:14px;border-radius:10px;border:1px solid var(--cs-red-border);">
                <div style="font-size:11px;font-weight:700;color:var(--text-m);text-transform:uppercase;">Potential Impact</div>
                <div style="font-size:13px;font-weight:600;color:var(--cs-red);margin-top:4px;">${plan.potentialImpact}</div>
              </div>
              <div style="background:var(--bg-main);padding:14px;border-radius:10px;border:1px solid var(--border-color);">
                <div style="font-size:11px;font-weight:700;color:var(--text-m);text-transform:uppercase;">Production Action</div>
                <div style="font-size:13px;font-weight:700;color:var(--text-s);margin-top:4px;">NOT EXECUTED (Awaiting Human Approval)</div>
              </div>
            </div>
            <div style="background:var(--bg-main);padding:14px;border-radius:10px;border:1px solid var(--border-color);margin-bottom:14px;font-size:13px;">
              <strong>Recommended Action:</strong> ${plan.recommendedAction}
            </div>
            ${twinSection}
            <div style="margin-top:14px;">${approvalBtns}</div>
          </div>`;
      }).join('');
    } catch (e) {
      console.warn('Error loading plans:', e);
    }
  }

  async testRecovery(assetId) {
    const btnEls = document.querySelectorAll(`button[onclick*="testRecovery('${assetId}')"]`);
    btnEls.forEach(b => { b.disabled = true; b.textContent = '⏳ Running CryptoTwin…'; });

    try {
      const res = await fetch('/api/cryptoshield/test-recovery', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...this.getAuthHeader() },
        body: JSON.stringify({ assetId })
      });
      if (!res.ok) throw new Error((await res.json()).error || 'Test recovery failed');
      this.showToast(`✓ CryptoTwin validation complete for <strong>${assetId}</strong>. Recovery plan generated.`, 'success');
      // Navigate to plans tab
      document.querySelectorAll('.cs-nav-tab').forEach(t => {
        t.classList.toggle('active', t.dataset.tab === 'plans');
      });
      this.switchTab('plans');
    } catch (err) {
      this.showToast(`CryptoTwin Recovery Error: ${err.message}`, 'error');
    } finally {
      btnEls.forEach(b => { b.disabled = false; b.textContent = '🛡 Test Recovery in CryptoTwin'; });
    }
  }

  async approvePlan(planId, action) {
    const btns = document.querySelectorAll(`button[onclick*="approvePlan('${planId}'"]`);
    btns.forEach(b => b.disabled = true);
    try {
      const res = await fetch(`/api/cryptoshield/recovery-plans/${planId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...this.getAuthHeader() },
        body: JSON.stringify({ action })
      });
      if (!res.ok) throw new Error((await res.json()).error || 'Approval failed');
      this.showToast(
        action === 'APPROVE'
          ? `✓ Recovery plan approved. Audit event recorded. No real credentials modified.`
          : `Recovery plan declined. Audit event recorded.`,
        action === 'APPROVE' ? 'success' : 'warn'
      );
      await this.loadPlans();
      await this.loadDashboard();
      await this.loadAudits();
    } catch (err) {
      this.showToast(`Approval Error: ${err.message}`, 'error');
      btns.forEach(b => b.disabled = false);
    }
  }

  // ---- Audit Trail ----
  async loadAudits() {
    try {
      const res = await fetch('/api/cryptoshield/audit', { headers: this.getAuthHeader() });
      if (!res.ok) return;
      const audits = await res.json();
      const tbody = document.getElementById('cs-audit-tbody');
      let html = '';
      audits.forEach(a => {
        const resultColor = a.result === 'SUCCESS' || a.result === 'ALLOWED' || a.result === 'APPROVE'
          ? 'var(--cs-green)' : a.result === 'BLOCKED' || a.result === 'DECLINE'
          ? 'var(--cs-red)' : 'var(--cs-amber)';
        html += `
          <tr>
            <td style="font-size:12px;color:var(--text-m);white-space:nowrap;">${new Date(a.timestamp).toLocaleString()}</td>
            <td style="font-weight:700;font-size:12px;">${a.action.replace(/_/g,' ')}</td>
            <td>${a.user || 'System'}</td>
            <td style="font-weight:600;color:var(--cs-purple);">${a.assetId || '--'}</td>
            <td><span style="font-size:11px;font-weight:700;color:${resultColor};">${a.result}</span></td>
            <td style="font-size:12px;color:var(--text-m);">${a.details || ''}</td>
          </tr>`;
      });
      if (tbody) tbody.innerHTML = html || '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--text-m);">No audit log entries yet.</td></tr>';
    } catch (e) {
      console.warn('Error loading audits:', e);
    }
  }
}

// ---- Toast animation ----
(function injectToastStyle() {
  const style = document.createElement('style');
  style.textContent = `
    @keyframes csToastIn {
      from { opacity:0; transform:translateY(16px); }
      to   { opacity:1; transform:translateY(0); }
    }
    .cs-btn-sm {
      padding: 7px 14px; border-radius: 8px; font-size: 12px;
      font-weight: 700; cursor: pointer; border: 1px solid transparent;
      transition: all 0.2s ease; white-space: nowrap;
    }
    .cs-btn-sm:disabled { opacity:0.5; cursor:not-allowed; }
    .cs-btn-purple { background: var(--cs-purple-bg); color: var(--cs-purple); border-color: rgba(139,92,246,0.35); }
    .cs-btn-purple:hover:not(:disabled) { background: var(--cs-purple); color: #fff; }
    .cs-btn-green  { background: var(--cs-green-bg);  color: var(--cs-green);  border-color: var(--cs-green-border); }
    .cs-btn-green:hover:not(:disabled)  { background: var(--cs-green);  color: #fff; }
    .cs-btn-red    { background: var(--cs-red-bg);    color: var(--cs-red);    border-color: var(--cs-red-border); }
    .cs-btn-red:hover:not(:disabled)    { background: var(--cs-red);    color: #fff; }
    .cs-pill { cursor: default; }
    .cs-tab-panel { animation: csToastIn 0.2s ease; }
  `;
  document.head.appendChild(style);
})();

// ---- Init ----
document.addEventListener('DOMContentLoaded', () => {
  window.cryptoShieldApp = new CryptoShieldApp();
});
