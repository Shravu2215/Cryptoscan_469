'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  
  const state = {
    scans: [],
    scanId: '',
    tasks: [],
    sensitivityData: null,
    activeVariationIndex: -1, // -1 means base
    running: false
  };

  const VARIATIONS = [
    { label: 'Capacity +2 devs', teamCapacityShift: 2 },
    { label: 'Capacity -2 devs', teamCapacityShift: -2 },
    { label: 'Deadline +1 yr', deadlineShiftMonths: 12 },
    { label: 'Deadline -1 yr', deadlineShiftMonths: -12 },
  ];

  function make(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined) el.textContent = text;
    return el;
  }

  function setStatus(message, kind = '') {
    const status = $('page-status');
    status.textContent = message || '';
    if (kind) status.dataset.kind = kind;
    else delete status.dataset.kind;
  }

  async function apiRequest(path, method = 'GET', body) {
    const url = `${window.Auth.API_BASE}/scan/${encodeURIComponent(state.scanId)}/quantum-risk${path}`;
    const response = await window.Auth.apiFetch(url, {
      method,
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    if (!response) throw new Error('Session expired.');
    let payload;
    try { payload = await response.json(); } catch (_) { payload = {}; }
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
    return payload;
  }

  function loadScans() {
    const data = window.CryptoEngine ? window.CryptoEngine.getData() : {};
    const source = Array.isArray(data.scans) ? data.scans.slice() : [];
    if (data.activeScan) source.unshift(data.activeScan);
    const seen = new Set();
    state.scans = source.filter((scan) => {
      const id = scan.scanId || scan.id;
      if (!id || seen.has(id)) return false;
      seen.add(id);
      scan.scanId = id;
      return true;
    });
    if (['localhost', '127.0.0.1'].includes(window.location.hostname) && !seen.has('dev-quantum-sample')) {
      state.scans.push({ scanId: 'dev-quantum-sample', repoName: 'Development sample CBOM' });
    }
    
    const select = $('scan-select');
    select.replaceChildren();
    for (const scan of state.scans) {
      const option = make('option');
      option.value = scan.scanId;
      option.textContent = scan.repoName || scan.name || scan.scanId;
      select.append(option);
    }
    
    if (state.scans.length > 0) {
      state.scanId = state.scans[0].scanId;
      select.value = state.scanId;
      fetchTasks();
    }
  }

  async function fetchTasks() {
    try {
      setStatus('Loading tasks...');
      const payload = await apiRequest('/schedule');
      state.tasks = payload.tasks || [];
      setStatus(`Loaded ${state.tasks.length} tasks. Ready to run analysis.`, 'success');
    } catch (e) {
      setStatus(`Failed to load tasks: ${e.message}`, 'error');
    }
  }

  async function runSensitivity() {
    if (state.running || !state.tasks.length) return;
    
    const capacity = parseInt($('capacity-input').value, 10);
    const horizon = parseInt($('horizon-input').value, 10);
    if (isNaN(capacity) || capacity < 1) return setStatus('Invalid capacity', 'error');
    if (isNaN(horizon) || horizon < 1) return setStatus('Invalid horizon', 'error');
    
    state.running = true;
    $('run-sensitivity').disabled = true;
    setStatus('Running sensitivity analysis (CP-SAT)...');
    
    try {
      const variations = VARIATIONS.map(v => ({
        label: v.label,
        teamCapacity: v.teamCapacityShift ? Math.max(1, capacity + v.teamCapacityShift) : undefined,
        deadlineShiftMonths: v.deadlineShiftMonths
      }));
      
      const payload = await apiRequest('/schedule/sensitivity', 'POST', {
        tasks: state.tasks,
        teamCapacity: capacity,
        horizonMonths: horizon,
        variations
      });
      
      state.sensitivityData = payload;
      state.activeVariationIndex = -1;
      
      if (payload.meta && payload.meta.note) {
        $('assumptions').textContent = payload.meta.note;
      }
      
      renderTabs();
      renderActiveVariation();
      setStatus('Analysis complete.', 'success');
    } catch (e) {
      setStatus(`Analysis failed: ${e.message}`, 'error');
    } finally {
      state.running = false;
      $('run-sensitivity').disabled = false;
    }
  }

  function renderTabs() {
    const container = $('variation-tabs');
    container.replaceChildren();
    if (!state.sensitivityData) return;
    
    const baseBtn = make('button', 'ms-preset-btn', 'Baseline');
    baseBtn.type = 'button';
    baseBtn.setAttribute('aria-pressed', state.activeVariationIndex === -1 ? 'true' : 'false');
    baseBtn.addEventListener('click', () => {
      state.activeVariationIndex = -1;
      renderTabs();
      renderActiveVariation();
    });
    container.append(baseBtn);
    
    state.sensitivityData.variations.forEach((v, idx) => {
      const btn = make('button', 'ms-preset-btn', v.label);
      btn.type = 'button';
      btn.setAttribute('aria-pressed', state.activeVariationIndex === idx ? 'true' : 'false');
      btn.addEventListener('click', () => {
        state.activeVariationIndex = idx;
        renderTabs();
        renderActiveVariation();
      });
      container.append(btn);
    });
  }

  function renderActiveVariation() {
    const data = state.sensitivityData;
    if (!data) return;
    
    const base = data.base;
    const active = state.activeVariationIndex === -1 ? base : data.variations[state.activeVariationIndex];
    
    // Update strip
    $('val-exposure').textContent = active.totalExposure.toFixed(4);
    $('val-makespan').textContent = `${active.makespanMonths} mo`;
    $('val-waves').textContent = active.waveCount;
    $('val-status').textContent = active.solverStatus;
    
    if (state.activeVariationIndex !== -1) {
      const imp = active.improvementPct;
      const dExp = $('delta-exposure');
      dExp.textContent = imp > 0 ? `-${imp}%` : (imp < 0 ? `+${Math.abs(imp)}%` : '0%');
      dExp.className = `ms-strip-delta ${imp > 0 ? 'ms-delta-pos' : (imp < 0 ? 'ms-delta-neg' : 'ms-delta-neu')}`;
      
      const dMake = active.makespanMonths - base.makespanMonths;
      const dSpan = $('delta-makespan');
      dSpan.textContent = dMake > 0 ? `+${dMake} mo` : (dMake < 0 ? `${dMake} mo` : '0');
      dSpan.className = `ms-strip-delta ${dMake < 0 ? 'ms-delta-pos' : (dMake > 0 ? 'ms-delta-neg' : 'ms-delta-neu')}`;
      
      const dWv = active.waveCount - base.waveCount;
      const dWaves = $('delta-waves');
      dWaves.textContent = dWv > 0 ? `+${dWv}` : (dWv < 0 ? `${dWv}` : '0');
      dWaves.className = `ms-strip-delta ${dWv < 0 ? 'ms-delta-pos' : (dWv > 0 ? 'ms-delta-neg' : 'ms-delta-neu')}`;
    } else {
      $('delta-exposure').textContent = 'Base';
      $('delta-exposure').className = 'ms-strip-delta ms-delta-neu';
      $('delta-makespan').textContent = 'Base';
      $('delta-makespan').className = 'ms-strip-delta ms-delta-neu';
      $('delta-waves').textContent = 'Base';
      $('delta-waves').className = 'ms-strip-delta ms-delta-neu';
    }
    
    $('delta-status').textContent = '';
    
    renderGantt(active.ganttRows || [], active.makespanMonths, active.changedTaskIds || []);
  }

  function renderGantt(rows, makespan, changedIds) {
    const container = $('gantt-chart');
    container.replaceChildren();
    
    if (rows.length === 0) {
      $('gantt-empty').hidden = false;
      return;
    }
    $('gantt-empty').hidden = true;
    
    const horizon = Math.max(makespan, 12);
    // Create grid: 1 column for label, `horizon` columns for months
    container.style.gridTemplateColumns = `120px repeat(${horizon}, 1fr)`;
    
    // Header
    const hdr = make('div', 'ms-gantt-header');
    hdr.append(make('div', 'ms-gantt-label'));
    for (let i = 1; i <= horizon; i++) {
      hdr.append(make('div', 'ms-gantt-month', `M${i}`));
    }
    container.append(hdr);
    
    // Rows
    const changedSet = new Set(changedIds);
    // Sort rows by startMonth then endMonth
    const sorted = [...rows].sort((a, b) => a.startMonth - b.startMonth || a.endMonth - b.endMonth);
    
    sorted.forEach((row, idx) => {
      const gridRow = idx + 2;
      
      // Look up task details for human-readable label
      const taskDef = state.tasks.find(t => t.taskId === row.taskId) || {};
      const alg = taskDef.algorithm || 'Unknown';
      const file = taskDef.filePath ? taskDef.filePath.split('/').pop() : row.taskId.substring(0, 8);
      const displayText = `${alg} (${file})`;

      const label = make('div', 'ms-gantt-label', displayText);
      label.style.gridRow = gridRow;
      label.title = taskDef.filePath ? `${alg} in ${taskDef.filePath}` : row.taskId;
      
      const bar = make('div', 'ms-gantt-bar', `${row.endMonth - row.startMonth}m`);
      if (changedSet.has(row.taskId)) bar.classList.add('changed');
      
      const startCol = Math.max(1, row.startMonth + 1) + 1; // +1 for label col
      const endCol = row.endMonth + 1 + 1; // span to end
      bar.style.gridRow = gridRow;
      bar.style.gridColumn = `${startCol} / ${endCol}`;
      
      container.append(label, bar);
    });
  }

  // Init
  $('scan-select').addEventListener('change', (e) => {
    state.scanId = e.target.value;
    state.sensitivityData = null;
    $('gantt-chart').replaceChildren();
    $('gantt-empty').hidden = false;
    $('variation-tabs').replaceChildren();
    fetchTasks();
  });
  
  $('run-sensitivity').addEventListener('click', runSensitivity);
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadScans);
  } else {
    loadScans();
  }
})();
