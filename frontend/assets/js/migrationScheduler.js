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

  function clearResults() {
    state.sensitivityData = null;
    state.activeVariationIndex = -1;
    $('scenario-rows').replaceChildren();
    const emptyScenario = make('tr');
    const emptyCell = make('td', 'ms-empty', 'Run analysis to compare scenarios.');
    emptyCell.colSpan = 5;
    emptyScenario.append(emptyCell);
    $('scenario-rows').append(emptyScenario);
    $('gantt-chart').replaceChildren();
    $('gantt-empty').textContent = 'Run analysis to see the wave-grouped schedule.';
    $('gantt-empty').hidden = false;
    $('assessment-warning').hidden = true;
    $('assumptions').textContent = '';
    ['val-exposure', 'val-makespan', 'val-waves', 'val-status'].forEach((id) => {
      $(id).textContent = '—';
    });
    ['delta-exposure', 'delta-makespan', 'delta-waves', 'delta-status'].forEach((id) => {
      $(id).textContent = 'Waiting for analysis';
      $(id).className = 'ms-strip-delta ms-delta-neu';
    });
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
    } else {
      $('run-sensitivity').disabled = true;
      setStatus('No repository scans are available.', 'error');
    }
  }

  async function fetchTasks() {
    $('run-sensitivity').disabled = true;
    state.tasks = [];
    clearResults();
    renderFilters();
    try {
      setStatus('Loading tasks...');
      const payload = await apiRequest('/schedule');
      state.tasks = Array.isArray(payload.tasks) ? payload.tasks : [];
      const totalRisk = state.tasks.reduce((sum, task) => sum + getRiskProbability(task), 0);
      $('assessment-warning').hidden = totalRisk > 0;
      renderFilters();
      if (state.tasks.length === 0) {
        setStatus('No migration tasks were found for this scan.', 'error');
        return;
      }
      $('run-sensitivity').disabled = false;
      setStatus(`Loaded ${state.tasks.length} tasks. Ready to run analysis.`, 'success');
    } catch (e) {
      setStatus(`Failed to load tasks: ${e.message}`, 'error');
    }
  }

  async function runSensitivity() {
    if (state.running) return;
    if (!state.scanId) return setStatus('Select a repository scan first.', 'error');
    if (!state.tasks.length) return setStatus('No migration tasks are available for this scan.', 'error');
    
    const capacity = parseInt($('capacity-input').value, 10);
    const horizon = parseInt($('horizon-input').value, 10);
    if (!Number.isInteger(capacity) || capacity < 1 || capacity > 100) return setStatus('Team capacity must be between 1 and 100.', 'error');
    if (!Number.isInteger(horizon) || horizon < 1 || horizon > 120) return setStatus('Horizon must be between 1 and 120 months.', 'error');
    
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
      
      renderComparisonTable();
      renderActiveVariation();
    } catch (e) {
      setStatus(`Analysis failed: ${e.message}`, 'error');
    } finally {
      state.running = false;
      $('run-sensitivity').disabled = state.tasks.length === 0;
    }
  }

  function getRiskProbability(task) {
    const probability = Number(task.exposureWeightPerMonth);
    return Number.isFinite(probability) ? Math.min(1, Math.max(0, probability)) : 0;
  }

  function getRiskBand(task) {
    const suppliedBand = String(task.riskBand || '').toUpperCase();
    if (['LOW', 'MODERATE', 'HIGH', 'CRITICAL'].includes(suppliedBand)) return suppliedBand;
    if (suppliedBand === 'MEDIUM') return 'MODERATE';
    const probability = getRiskProbability(task);
    if (probability >= 0.75) return 'CRITICAL';
    if (probability >= 0.5) return 'HIGH';
    if (probability >= 0.2) return 'MODERATE';
    return 'LOW';
  }

  function renderFilters() {
    [
      { id: 'filter-service', label: 'All services', field: 'service' },
      { id: 'filter-family', label: 'All families', field: 'family' },
    ].forEach(({ id, label, field }) => {
      const select = $(id);
      const selectedValue = select.value;
      select.replaceChildren(new Option(label, ''));
      const values = [...new Set(state.tasks.map((task) => task[field]).filter(Boolean).map(String))]
        .sort((a, b) => a.localeCompare(b));
      values.forEach((value) => select.add(new Option(value, value)));
      if (values.includes(selectedValue)) select.value = selectedValue;
    });
  }

  function renderComparisonTable() {
    const body = $('scenario-rows');
    body.replaceChildren();
    const data = state.sensitivityData;
    if (!data || !data.base) {
      const empty = make('tr');
      const cell = make('td', 'ms-empty', 'Run analysis to compare scenarios.');
      cell.colSpan = 5;
      empty.append(cell);
      body.append(empty);
      return;
    }

    const scenarios = [
      { result: data.base, label: 'Baseline', hint: 'Reference schedule', index: -1 },
      ...(data.variations || []).map((result, index) => ({
        result,
        label: result.label || `Variation ${index + 1}`,
        hint: '',
        index,
      })),
    ];

    scenarios.forEach(({ result, label, hint, index }) => {
      const row = make('tr', 'ms-scenario-row');
      row.tabIndex = 0;
      row.setAttribute('aria-current', state.activeVariationIndex === index ? 'true' : 'false');
      const nameCell = make('td');
      nameCell.append(make('span', 'ms-scenario-name', label));
      if (hint) nameCell.append(make('span', 'ms-scenario-hint', hint));
      row.append(nameCell);
      row.append(make('td', '', Number.isFinite(result.makespanMonths) ? `${result.makespanMonths} mo` : '—'));
      row.append(make('td', '', Number.isFinite(result.waveCount) ? String(result.waveCount) : '—'));
      row.append(make('td', '', Number.isFinite(result.totalExposure) ? `${result.totalExposure.toFixed(4)} risk-mo` : '—'));
      const statusCell = make('td');
      statusCell.append(make('span', 'ms-status-pill', result.solverStatus || 'Unavailable'));
      row.append(statusCell);
      const selectScenario = () => {
        state.activeVariationIndex = index;
        renderComparisonTable();
        renderActiveVariation();
      };
      row.addEventListener('click', selectScenario);
      row.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          selectScenario();
        }
      });
      body.append(row);
    });
  }

  function setDelta(id, text, direction = 0) {
    const element = $(id);
    element.textContent = text;
    element.className = `ms-strip-delta ${direction < 0 ? 'ms-delta-pos' : (direction > 0 ? 'ms-delta-neg' : 'ms-delta-neu')}`;
  }

  function renderActiveVariation() {
    const data = state.sensitivityData;
    if (!data || !data.base) return;

    const base = data.base;
    const active = state.activeVariationIndex === -1 ? base : (data.variations || [])[state.activeVariationIndex];
    if (!active) return;
    const schedulable = ['OPTIMAL', 'FEASIBLE'].includes(active.solverStatus);
    const baselineSchedulable = ['OPTIMAL', 'FEASIBLE'].includes(base.solverStatus);
    $('val-exposure').textContent = schedulable && Number.isFinite(active.totalExposure)
      ? `${active.totalExposure.toFixed(4)} risk-mo` : '—';
    $('val-makespan').textContent = schedulable && Number.isFinite(active.makespanMonths)
      ? `${active.makespanMonths} mo` : '—';
    $('val-waves').textContent = schedulable && Number.isFinite(active.waveCount)
      ? String(active.waveCount) : '—';
    $('val-status').textContent = active.solverStatus || 'Unavailable';

    if (state.activeVariationIndex === -1) {
      setDelta('delta-exposure', '0.0000 risk-mo vs baseline');
      setDelta('delta-makespan', '0 mo vs baseline');
      setDelta('delta-waves', '0 vs baseline');
      setDelta('delta-status', 'Reference solver result');
    } else if (!schedulable || !baselineSchedulable
      || !Number.isFinite(active.totalExposure) || !Number.isFinite(base.totalExposure)
      || !Number.isFinite(active.makespanMonths) || !Number.isFinite(base.makespanMonths)
      || !Number.isFinite(active.waveCount) || !Number.isFinite(base.waveCount)) {
      ['delta-exposure', 'delta-makespan', 'delta-waves', 'delta-status'].forEach((id) => setDelta(id, 'N/A vs baseline'));
    } else {
      const exposureDelta = active.totalExposure - base.totalExposure;
      const makespanDelta = active.makespanMonths - base.makespanMonths;
      const waveDelta = active.waveCount - base.waveCount;
      const signed = (value, digits = 0) => `${value > 0 ? '+' : ''}${value.toFixed(digits)}`;
      setDelta('delta-exposure', `${signed(exposureDelta, 4)} risk-mo vs baseline`, exposureDelta);
      setDelta('delta-makespan', `${signed(makespanDelta)} mo vs baseline`, makespanDelta);
      setDelta('delta-waves', `${signed(waveDelta)} vs baseline`, waveDelta);
      setDelta('delta-status', active.solverStatus === base.solverStatus
        ? 'Same as baseline' : `${base.solverStatus} vs baseline`);
    }

    if (schedulable) {
      const label = state.activeVariationIndex === -1 ? 'Baseline' : active.label;
      setStatus(`${label} schedule computed successfully.`, 'success');
    } else {
      setStatus(`${active.solverStatus || 'Schedule unavailable'}: ${active.message || 'Review the team capacity, horizon, and task constraints.'}`, 'error');
    }
    renderComparisonTableSelection();
    renderCurrentGantt();
  }

  function renderCurrentGantt() {
    const data = state.sensitivityData;
    if (!data || !data.base) return;
    const active = state.activeVariationIndex === -1 ? data.base : (data.variations || [])[state.activeVariationIndex];
    if (!active) return;
    renderGantt(active.ganttRows || [], active.makespanMonths, active.changedTaskIds || [], active.message);
  }

  function renderComparisonTableSelection() {
    [...$('scenario-rows').querySelectorAll('.ms-scenario-row')].forEach((row, index) => {
      row.setAttribute('aria-current', (index - 1) === state.activeVariationIndex ? 'true' : 'false');
    });
  }

  function renderGantt(rows, makespan, changedIds, message = '') {
    const container = $('gantt-chart');
    container.replaceChildren();
    const taskById = new Map(state.tasks.map((task) => [task.taskId, task]));
    const changedSet = new Set(changedIds);
    const query = $('gantt-search').value.trim().toLowerCase();
    const service = $('filter-service').value;
    const family = $('filter-family').value;
    const risk = $('filter-risk').value;
    const matches = (row) => {
      const task = taskById.get(row.taskId) || { taskId: row.taskId };
      const searchable = [task.taskId, task.algorithm, task.filePath, task.service, task.family].filter(Boolean).join(' ').toLowerCase();
      return (!query || searchable.includes(query))
        && (!service || String(task.service || '') === service)
        && (!family || String(task.family || '') === family)
        && (!risk || getRiskBand(task) === risk);
    };
    const fullRows = Array.isArray(rows) ? rows : [];
    const filteredRows = fullRows.filter(matches);
    if (!filteredRows.length) {
      $('gantt-empty').textContent = fullRows.length
        ? 'No tasks match the current search and filters.'
        : (message || 'No schedule data available. Run analysis first.');
      $('gantt-empty').hidden = false;
      return;
    }
    $('gantt-empty').hidden = true;

    const maxMonth = Math.max(
      12,
      Number.isFinite(makespan) ? makespan : 0,
      ...fullRows.map((row) => Number(row.endMonth) || 0)
    );
    container.style.setProperty('--ms-month-count', maxMonth);
    const header = make('div', 'ms-gantt-header');
    header.append(make('div', 'ms-wave-label', 'Wave / start month'));
    for (let month = 1; month <= maxMonth; month += 1) {
      header.append(make('div', 'ms-gantt-month', `M${month}`));
    }
    container.append(header);

    const grouped = new Map();
    filteredRows.forEach((row) => {
      const startMonth = Number(row.startMonth) || 0;
      if (!grouped.has(startMonth)) grouped.set(startMonth, []);
      grouped.get(startMonth).push(row);
    });
    const startMonths = [...grouped.keys()].sort((a, b) => a - b);
    const fullStartMonths = [...new Set(fullRows.map((row) => Number(row.startMonth) || 0))].sort((a, b) => a - b);

    startMonths.forEach((startMonth) => {
      const waveRows = grouped.get(startMonth).sort((a, b) => a.endMonth - b.endMonth);
      const endMonth = Math.max(...waveRows.map((row) => Number(row.endMonth) || startMonth + 1));
      const probabilities = waveRows.map((row) => getRiskProbability(taskById.get(row.taskId) || {}));
      const probability = Math.max(...probabilities);
      const hue = Math.round(140 * (1 - probability));
      const waveIndex = fullStartMonths.indexOf(startMonth) + 1;
      const wave = make('details', 'ms-wave');
      const summary = make('summary', 'ms-wave-summary');
      const label = make('span', 'ms-wave-label');
      label.append(make('span', '', `Wave ${waveIndex}`));
      label.append(make('small', '', `Month ${startMonth + 1} · ${waveRows.length} ${waveRows.length === 1 ? 'task' : 'tasks'}`));
      summary.append(label);

      const bar = make('span', 'ms-wave-bar', `${endMonth - startMonth} mo · peak risk ${(probability * 100).toFixed(0)}%`);
      bar.style.gridColumn = `${Math.max(0, startMonth) + 2} / ${Math.max(startMonth + 1, endMonth) + 2}`;
      bar.style.setProperty('--risk-hue', hue);
      bar.title = `Wave ${waveIndex}: month ${startMonth + 1} to ${endMonth}, peak risk probability ${(probability * 100).toFixed(1)}%`;
      summary.append(bar);
      wave.append(summary);

      const details = make('div', 'ms-wave-tasks');
      waveRows.forEach((row) => {
        const task = taskById.get(row.taskId) || { taskId: row.taskId };
        const fullName = `${task.algorithm || 'Migration task'}${task.filePath ? ` — ${task.filePath}` : ` — ${task.taskId}`}`;
        const item = make('div', 'ms-task-detail');
        const name = make('span', 'ms-task-name', fullName);
        name.title = fullName;
        item.append(name);
        item.append(make('span', 'ms-task-meta', task.service || 'Service not specified'));
        item.append(make('span', 'ms-task-meta', task.family || 'Family not specified'));
        const riskTag = make('span', 'ms-risk-tag', `${getRiskBand(task)} · ${(getRiskProbability(task) * 100).toFixed(1)}%${changedSet.has(row.taskId) ? ' · Adjusted' : ''}`);
        item.append(riskTag);
        details.append(item);
      });
      wave.append(details);
      container.append(wave);
    });
  }

  // Init
  $('scan-select').addEventListener('change', (e) => {
    state.scanId = e.target.value;
    fetchTasks();
  });
  
  $('run-sensitivity').addEventListener('click', runSensitivity);
  $('run-sensitivity').disabled = true;
  $('gantt-search').addEventListener('input', renderCurrentGantt);
  ['filter-service', 'filter-family', 'filter-risk'].forEach((id) => {
    $(id).addEventListener('change', renderCurrentGantt);
  });
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadScans);
  } else {
    loadScans();
  }
})();
