'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const DEFAULT_IDS = new Set(['scenario-optimistic-v1', 'scenario-median-v1', 'scenario-pessimistic-v1']);
  const COLORS = [
    { at: 0, rgb: [0, 32, 76] },
    { at: 0.25, rgb: [59, 113, 133] },
    { at: 0.5, rgb: [142, 170, 128] },
    { at: 0.75, rgb: [216, 195, 108] },
    { at: 1, rgb: [255, 241, 168] },
  ];
  const state = {
    scans: [],
    scanId: '',
    scenarios: [],
    selectedScenarioIds: new Set(),
    scenarioBases: new Map(),
    assets: [],
    results: null,
    shiftedByScenario: null,
    sweepCache: new Map(),
    overrides: {},
    devSample: false,
    running: false,
    editorTarget: null,
    editorBaseId: null,
    editorModel: null,
    sortKey: 'algorithm',
    sortDirection: 1,
    sweepTimer: null,
  };

  function make(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
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
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response) throw new Error('Your session has expired. Sign in again to continue.');
    let payload;
    try { payload = await response.json(); } catch (_) { payload = {}; }
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
    return payload;
  }

  function localScans() {
    const data = window.CryptoEngine ? window.CryptoEngine.getData() : {};
    const source = Array.isArray(data.scans) ? data.scans.slice() : [];
    if (data.activeScan) source.unshift(data.activeScan);
    const seen = new Set();
    const scans = source.filter((scan) => {
      const id = scan.scanId || scan.id;
      if (!id || seen.has(id)) return false;
      seen.add(id);
      scan.scanId = id;
      return true;
    });
    if (isDevelopmentBrowser() && !seen.has('dev-quantum-sample')) {
      scans.push({ scanId: 'dev-quantum-sample', repoName: 'Development sample CBOM', status: 'sample' });
    }
    return scans;
  }

  function scanLabel(scan) {
    const name = scan.repoName || scan.name || scan.repoId || 'Repository';
    const date = scan.scanDate || scan.timestamp;
    return date ? `${name} · ${date}` : name;
  }

  function renderScanOptions() {
    const select = $('scan-select');
    select.replaceChildren();
    for (const scan of state.scans) {
      const option = make('option');
      option.value = scan.scanId;
      option.textContent = scanLabel(scan);
      select.append(option);
    }
    select.value = state.scanId;
    select.disabled = state.scans.length === 0;
    $('run-assessment').disabled = state.scans.length === 0 || state.running;
    $('load-sample').hidden = !isDevelopmentBrowser();
    $('load-sample').disabled = state.scans.length === 0 || state.running;
  }

  function isDevelopmentBrowser() {
    return ['localhost', '127.0.0.1'].includes(window.location.hostname) || window.location.port === '3000';
  }

  function scenarioDisplayName(scenario) {
    return scenario.displayName || scenario.name;
  }

  function addScenarioCard(scenario) {
    const card = make('article', 'qtm-scenario-card');
    const top = make('div', 'qtm-scenario-top');
    const title = make('div', 'qtm-scenario-title');
    const checkbox = make('input', 'qtm-scenario-select');
    checkbox.type = 'checkbox';
    checkbox.checked = state.selectedScenarioIds.has(scenario.id);
    checkbox.setAttribute('aria-label', `Include ${scenarioDisplayName(scenario)} scenario`);
    checkbox.addEventListener('change', () => {
      if (checkbox.checked && !state.selectedScenarioIds.has(scenario.id) && state.selectedScenarioIds.size >= 10) {
        checkbox.checked = false;
        setStatus('Choose no more than 10 scenarios.', 'error');
        return;
      }
      if (checkbox.checked) state.selectedScenarioIds.add(scenario.id);
      else state.selectedScenarioIds.delete(scenario.id);
      setStatus('');
    });
    title.append(checkbox, make('span', '', scenarioDisplayName(scenario)));
    top.append(title);
    if (!DEFAULT_IDS.has(scenario.id)) top.append(make('span', 'qtm-badge', 'CUSTOM'));
    if (String(scenario.source || '').trim().toUpperCase().startsWith('ASSUMPTION')) {
      top.append(make('span', 'qtm-assumption', 'ASSUMPTION'));
    }
    const meta = make('div', 'qtm-scenario-meta');
    const sourceWrap = make('div');
    sourceWrap.append(make('strong', '', 'Source'), make('p', '', scenario.source || 'Not provided'));
    const citationWrap = make('div');
    citationWrap.append(make('strong', '', 'Citation note'), make('p', '', scenario.citationNote || 'Not provided'));
    meta.append(sourceWrap, citationWrap);
    const actions = make('div', 'qtm-scenario-actions');
    const edit = make('button', 'qtm-button', scenario.id && !DEFAULT_IDS.has(scenario.id) ? 'Edit assumptions' : 'Edit assumptions');
    edit.type = 'button';
    edit.addEventListener('click', () => openScenarioEditor(scenario));
    actions.append(edit);
    if (scenario.id && !DEFAULT_IDS.has(scenario.id)) {
      const reset = make('button', 'qtm-button', 'Reset to default');
      reset.type = 'button';
      reset.addEventListener('click', () => resetCustomScenario(scenario));
      const remove = make('button', 'qtm-button qtm-button-danger', 'Delete');
      remove.type = 'button';
      remove.addEventListener('click', () => deleteScenario(scenario));
      actions.append(reset, remove);
    }
    card.append(top, meta, actions);
    return card;
  }

  function renderScenarioCards() {
    const container = $('scenario-cards');
    container.replaceChildren(...state.scenarios.map(addScenarioCard));
    renderTableScenarioOptions();
  }

  async function loadScenarios() {
    const payload = await apiRequest('/scenarios');
    state.scenarios = payload.scenarios || [];
    if (!state.selectedScenarioIds.size) {
      state.selectedScenarioIds = new Set(state.scenarios.map((scenario) => scenario.id).slice(0, 10));
    }
    renderScenarioCards();
  }

  function defaultScenarioById(id) {
    return state.scenarios.find((scenario) => scenario.id === id && DEFAULT_IDS.has(id));
  }

  function openScenarioEditor(scenario, forceCreate = false, resetName) {
    const isCustom = !DEFAULT_IDS.has(scenario.id);
    const shouldEdit = isCustom && !forceCreate;
    const baselineId = shouldEdit
      ? (state.scenarioBases.get(scenario.id) || 'scenario-median-v1')
      : scenario.id;
    const baseline = defaultScenarioById(baselineId) || defaultScenarioById('scenario-median-v1') || scenario;
    state.editorTarget = shouldEdit ? scenario.id : null;
    state.editorBaseId = baseline.id;
    state.editorModel = JSON.parse(JSON.stringify(shouldEdit ? scenario : baseline));
    buildEditorForm({
      displayName: resetName || (shouldEdit ? scenarioDisplayName(scenario) : `${scenarioDisplayName(baseline)} custom`),
      source: state.editorModel.source,
      citationNote: state.editorModel.citationNote,
    });
    $('scenario-editor').hidden = false;
    $('scenario-editor').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function addLabeledInput(parent, labelText, value, options = {}) {
    const label = make('label', 'qtm-field');
    label.append(make('span', '', labelText));
    const input = make('input');
    input.type = options.type || 'text';
    input.value = value === undefined || value === null ? '' : String(value);
    input.required = Boolean(options.required);
    if (options.maxLength) input.maxLength = options.maxLength;
    if (options.min !== undefined) input.min = String(options.min);
    if (options.step !== undefined) input.step = String(options.step);
    label.append(input);
    parent.append(label);
    return input;
  }

  function rebuildFamilyEditor(container) {
    container.replaceChildren();
    for (const [family, timeline] of Object.entries(state.editorModel.familyTimelines)) {
      const row = make('div', 'qtm-family-row');
      row.append(make('div', 'qtm-family-name', family));
      const distributionLabel = make('label', 'qtm-field');
      distributionLabel.append(make('span', '', 'Distribution'));
      const distribution = make('select');
      for (const type of ['triangular', 'normal', 'lognormal']) {
        const option = make('option', '', type);
        option.value = type;
        distribution.append(option);
      }
      distribution.value = timeline.distribution;
      distribution.addEventListener('change', () => {
        const old = timeline.params;
        let params;
        if (distribution.value === 'triangular') {
          const center = Number.isFinite(old.mean) ? old.mean : ((old.min || 0) + (old.mode || 0) + (old.max || 0)) / 3;
          params = { min: Math.max(0, center - 5), mode: Math.max(0, center), max: Math.max(0, center + 5) };
        } else {
          const mean = Number.isFinite(old.mean) ? old.mean : (old.min + old.mode + old.max) / 3;
          params = { mean: Math.max(distribution.value === 'lognormal' ? 0.001 : 0, mean), sd: Number.isFinite(old.sd) && old.sd > 0 ? old.sd : 2 };
        }
        state.editorModel.familyTimelines[family] = { distribution: distribution.value, params };
        rebuildFamilyEditor(container);
      });
      distributionLabel.append(distribution);
      row.append(distributionLabel);
      const keys = timeline.distribution === 'triangular' ? ['min', 'mode', 'max'] : ['mean', 'sd'];
      for (const key of keys) {
        const field = make('label', 'qtm-param-field');
        field.append(make('span', '', key));
        const input = make('input');
        input.type = 'number';
        input.step = 'any';
        input.required = true;
        input.min = '0';
        input.value = String(timeline.params[key]);
        input.addEventListener('input', () => { timeline.params[key] = input.value === '' ? NaN : Number(input.value); });
        field.append(input);
        row.append(field);
      }
      if (keys.length === 2) row.append(make('span', 'qtm-family-spacer'));
      container.append(row);
    }
  }

  function buildEditorForm(initial) {
    const host = $('scenario-editor');
    host.replaceChildren();
    const form = make('form', 'qtm-scenario-form');
    form.noValidate = true;
    form.append(make('h3', '', state.editorTarget ? `Edit ${scenarioDisplayName(state.editorModel)}` : `Clone ${scenarioDisplayName(state.editorModel)}`));
    const fields = make('div', 'qtm-editor-fields');
    const nameInput = addLabeledInput(fields, 'Scenario name', initial.displayName, { required: true, maxLength: 60 });
    const sourceInput = addLabeledInput(fields, 'Source', initial.source, { required: true, maxLength: 500 });
    const citationInput = addLabeledInput(fields, 'Citation note', initial.citationNote, { required: true, maxLength: 2000 });
    form.append(fields);
    const familyEditor = make('div', 'qtm-family-editor');
    rebuildFamilyEditor(familyEditor);
    form.append(familyEditor);
    const message = make('p', 'qtm-editor-error');
    message.setAttribute('role', 'alert');
    form.append(message);
    const actions = make('div', 'qtm-editor-actions');
    if (state.editorTarget) {
      const reset = make('button', 'qtm-button', 'Reset to default');
      reset.type = 'button';
      reset.addEventListener('click', () => {
        const name = `${nameInput.value.trim() || 'Custom'} reset`.slice(0, 60);
        openScenarioEditor(defaultScenarioById(state.editorBaseId) || defaultScenarioById('scenario-median-v1'), true, name);
      });
      actions.append(reset);
    }
    const cancel = make('button', 'qtm-button', 'Cancel');
    cancel.type = 'button';
    cancel.addEventListener('click', closeScenarioEditor);
    const save = make('button', 'qtm-button qtm-button-primary', 'Save assumptions');
    save.type = 'submit';
    actions.append(cancel, save);
    form.append(actions);
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const patch = {
        name: nameInput.value.trim(),
        source: sourceInput.value.trim(),
        citationNote: citationInput.value.trim(),
        familyTimelines: state.editorModel.familyTimelines,
      };
      const validationMessage = validateEditorPatch(patch);
      if (validationMessage) {
        message.textContent = validationMessage;
        return;
      }
      save.disabled = true;
      message.textContent = '';
      try {
        const payload = state.editorTarget
          ? await apiRequest(`/scenarios/${encodeURIComponent(state.editorTarget)}`, 'PUT', { patch })
          : await apiRequest('/scenarios', 'POST', { basedOn: state.editorBaseId, patch });
        const saved = payload.scenario;
        const existingIndex = state.scenarios.findIndex((scenario) => scenario.id === saved.id);
        if (existingIndex >= 0) state.scenarios[existingIndex] = saved;
        else state.scenarios.push(saved);
        if (!state.editorTarget) state.scenarioBases.set(saved.id, state.editorBaseId);
        state.sweepCache.clear();
        state.selectedScenarioIds.add(saved.id);
        closeScenarioEditor();
        renderScenarioCards();
        setStatus('Scenario assumptions saved.', 'success');
      } catch (error) {
        message.textContent = error.message;
      } finally {
        save.disabled = false;
      }
    });
    host.append(form);
  }

  function validateEditorPatch(patch) {
    if (!patch.name || patch.name.length > 60) return 'Enter a scenario name of at most 60 characters.';
    if (!patch.source) return 'Source is required.';
    if (!patch.citationNote) return 'Citation note is required.';
    for (const [family, timeline] of Object.entries(patch.familyTimelines)) {
      const params = timeline.params;
      if (timeline.distribution === 'triangular') {
        if (![params.min, params.mode, params.max].every(Number.isFinite) || params.min < 0 || !(params.min <= params.mode && params.mode <= params.max)) {
          return `${family}: enter non-negative values where min <= mode <= max.`;
        }
      } else if (!Number.isFinite(params.mean) || !Number.isFinite(params.sd) || params.sd <= 0 || params.mean < 0 || (timeline.distribution === 'lognormal' && params.mean === 0)) {
        return `${family}: enter a valid mean and standard deviation greater than zero.`;
      }
    }
    return '';
  }

  function closeScenarioEditor() {
    $('scenario-editor').hidden = true;
    $('scenario-editor').replaceChildren();
    state.editorTarget = null;
    state.editorBaseId = null;
    state.editorModel = null;
  }

  async function resetCustomScenario(scenario) {
    const basedOnId = state.scenarioBases.get(scenario.id) || 'scenario-median-v1';
    const baseline = defaultScenarioById(basedOnId) || defaultScenarioById('scenario-median-v1');
    const patch = {
      name: `${scenarioDisplayName(scenario)} reset`.slice(0, 60),
      familyTimelines: JSON.parse(JSON.stringify(baseline.familyTimelines)),
      source: baseline.source,
      citationNote: baseline.citationNote,
    };
    try {
      const payload = await apiRequest('/scenarios', 'POST', { basedOn: baseline.id, patch });
      state.scenarios.push(payload.scenario);
      state.scenarioBases.set(payload.scenario.id, baseline.id);
      state.selectedScenarioIds.add(payload.scenario.id);
      renderScenarioCards();
      setStatus('A fresh default-based scenario was created.', 'success');
    } catch (error) {
      setStatus(error.message, 'error');
    }
  }

  async function deleteScenario(scenario) {
    if (!window.confirm(`Delete scenario "${scenarioDisplayName(scenario)}"?`)) return;
    try {
      await apiRequest(`/scenarios/${encodeURIComponent(scenario.id)}`, 'DELETE');
      state.scenarios = state.scenarios.filter((item) => item.id !== scenario.id);
      state.selectedScenarioIds.delete(scenario.id);
      state.scenarioBases.delete(scenario.id);
      state.sweepCache.clear();
      if (state.results) {
        delete state.results.byScenario[scenario.id];
        delete state.results.summary[scenario.id];
        state.runScenarioIds = state.runScenarioIds.filter((id) => id !== scenario.id);
      }
      renderScenarioCards();
      renderResults();
      setStatus('Custom scenario deleted.', 'success');
    } catch (error) {
      setStatus(error.message, 'error');
    }
  }

  function renderTableScenarioOptions() {
    const select = $('table-scenario');
    const previous = select.value;
    select.replaceChildren();
    const ids = state.runScenarioIds || [];
    for (const id of ids) {
      const scenario = state.scenarios.find((item) => item.id === id);
      if (!scenario) continue;
      const option = make('option', '', scenarioDisplayName(scenario));
      option.value = id;
      select.append(option);
    }
    if (ids.includes(previous)) select.value = previous;
  }

  function visibleScenarioIds() {
    if (state.results) return state.runScenarioIds || Object.keys(state.results.byScenario || {});
    return [];
  }

  function assessmentsFor(scenarioId) {
    if (state.shiftedByScenario && state.shiftedByScenario[scenarioId]) return state.shiftedByScenario[scenarioId];
    return state.results?.byScenario?.[scenarioId] || [];
  }

  function summarizeLocally(assessments) {
    const expected = assessments.reduce((sum, assessment) => sum + assessment.pMoscaViolated, 0);
    return {
      assetsAtHighOrCritical: assessments.filter((assessment) => ['HIGH', 'CRITICAL'].includes(assessment.riskBand)).length,
      expectedAssetsViolated: expected,
      meanP: assessments.length ? expected / assessments.length : 0,
      ciWidth: assessments.length ? assessments.reduce((sum, assessment) => sum + (assessment.pMoscaViolatedCI95.upper - assessment.pMoscaViolatedCI95.lower), 0) / assessments.length : 0,
    };
  }

  function renderSummary() {
    const strip = $('summary-strip');
    strip.replaceChildren();
    for (const scenarioId of visibleScenarioIds()) {
      const scenario = state.scenarios.find((item) => item.id === scenarioId);
      const assessments = assessmentsFor(scenarioId);
      const summary = summarizeLocally(assessments);
      const card = make('article', 'qtm-summary-card');
      card.append(make('div', 'qtm-summary-name', scenario ? scenarioDisplayName(scenario) : scenarioId));
      const values = make('div', 'qtm-summary-numbers');
      const metrics = [
        ['HIGH/CRIT', String(summary.assetsAtHighOrCritical)],
        ['Expected violated', summary.expectedAssetsViolated.toFixed(3)],
        ['Mean p', summary.meanP.toFixed(3)],
      ];
      for (const [label, value] of metrics) {
        const item = make('div');
        item.append(make('strong', '', value), make('span', '', label));
        values.append(item);
      }
      card.append(values, make('p', 'qtm-mc-note', `Mean 95% Monte Carlo interval width: ${summary.ciWidth.toFixed(3)}`));
      strip.append(card);
    }
  }

  function rowGroups() {
    const mode = $('row-mode').value;
    const groups = new Map();
    for (const asset of state.assets) {
      let key;
      let label;
      if (mode === 'family') {
        key = asset.family;
        label = asset.family;
      } else if (mode === 'asset') {
        key = asset.assetId;
        label = `${asset.algorithm} · ${asset.filePath}${asset.lineNumber ? `:${asset.lineNumber}` : ''}`;
      } else {
        key = asset.service || 'Unknown service';
        label = key;
      }
      if (!groups.has(key)) groups.set(key, { label, assets: [] });
      groups.get(key).assets.push(asset);
    }
    return [...groups.values()].sort((left, right) => left.label.localeCompare(right.label));
  }

  function meanOf(values) {
    return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
  }

  function probabilityColor(value) {
    const p = Math.max(0, Math.min(1, value));
    let left = COLORS[0];
    let right = COLORS[COLORS.length - 1];
    for (let index = 1; index < COLORS.length; index += 1) {
      if (p <= COLORS[index].at) {
        left = COLORS[index - 1];
        right = COLORS[index];
        break;
      }
    }
    const ratio = (p - left.at) / (right.at - left.at || 1);
    const rgb = left.rgb.map((channel, index) => Math.round(channel + (right.rgb[index] - channel) * ratio));
    return { color: `rgb(${rgb[0]} ${rgb[1]} ${rgb[2]})`, text: p < 0.29 ? '#fff' : '#17282c' };
  }

  function renderHeatmap() {
    const container = $('heatmap-container');
    container.replaceChildren();
    const scenarioIds = visibleScenarioIds();
    const groups = rowGroups();
    if (!scenarioIds.length || !groups.length) {
      container.append(make('p', 'qtm-empty', 'Run an assessment to populate the heatmap.'));
      return;
    }
    const grid = make('div', 'qtm-heatmap-grid');
    grid.setAttribute('role', 'grid');
    grid.style.gridTemplateColumns = `minmax(150px, 220px) repeat(${scenarioIds.length}, minmax(102px, 1fr))`;
    grid.append(make('div', 'qtm-heat-corner', `${$('row-mode').selectedOptions[0].textContent} / scenario`));
    for (const scenarioId of scenarioIds) {
      const scenario = state.scenarios.find((item) => item.id === scenarioId);
      grid.append(make('div', 'qtm-heat-column', scenario ? scenarioDisplayName(scenario) : scenarioId));
    }
    const metric = $('metric-mode').value;
    for (const group of groups) {
      grid.append(make('div', 'qtm-heat-row', group.label));
      for (const scenarioId of scenarioIds) {
        const byAsset = new Map(assessmentsFor(scenarioId).map((assessment) => [assessment.assetId, assessment]));
        const matched = group.assets.map((asset) => ({ asset, assessment: byAsset.get(asset.assetId) })).filter((entry) => entry.assessment);
        if (!matched.length) {
          const blank = make('span', 'qtm-heat-cell', '—');
          blank.setAttribute('aria-label', `${group.label}, no result for ${scenarioId}`);
          grid.append(blank);
          continue;
        }
        const probability = meanOf(matched.map(({ assessment }) => assessment[metric]));
        const ciLower = meanOf(matched.map(({ assessment }) => assessment[metric === 'pMoscaViolated' ? 'pMoscaViolatedCI95' : 'pBreakBeforeMigrationCI95'].lower));
        const ciUpper = meanOf(matched.map(({ assessment }) => assessment[metric === 'pMoscaViolated' ? 'pMoscaViolatedCI95' : 'pBreakBeforeMigrationCI95'].upper));
        const p10 = meanOf(matched.map(({ assessment }) => assessment.p10));
        const p50 = meanOf(matched.map(({ assessment }) => assessment.p50));
        const p90 = meanOf(matched.map(({ assessment }) => assessment.p90));
        const x = meanOf(matched.map(({ assessment }) => assessment.dataLifetimeYears));
        const y = meanOf(matched.map(({ assessment }) => assessment.migrationTimeYears));
        const risks = matched.map(({ assessment }) => assessment.riskBand);
        const riskBand = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'MINIMAL'].find((band) => risks.includes(band)) || 'MINIMAL';
        const lowConfidence = matched.some(({ assessment }) => assessment.lowConfidenceFamily);
        const scenario = state.scenarios.find((item) => item.id === scenarioId);
        const label = `${group.label} under ${scenario ? scenarioDisplayName(scenario) : scenarioId}: ${metric} ${probability.toFixed(3)}; 95% CI ${ciLower.toFixed(3)} to ${ciUpper.toFixed(3)}; Z p10/p50/p90 ${p10.toFixed(1)}/${p50.toFixed(1)}/${p90.toFixed(1)} years; X ${x.toFixed(1)} years; Y ${y.toFixed(1)} years; risk ${riskBand}; low confidence family ${lowConfidence ? 'yes' : 'no'}.`;
        const cell = make('button', 'qtm-heat-cell', probability.toFixed(3));
        cell.type = 'button';
        cell.setAttribute('role', 'gridcell');
        cell.setAttribute('aria-label', label);
        cell.title = label;
        const color = probabilityColor(probability);
        cell.style.backgroundColor = color.color;
        cell.style.color = color.text;
        grid.append(cell);
      }
    }
    container.append(grid);
  }

  function selectedTableScenario() {
    const selected = $('table-scenario').value;
    return visibleScenarioIds().includes(selected) ? selected : visibleScenarioIds()[0];
  }

  function valueForSort(asset, assessment, key) {
    if (key === 'x') return assessment.dataLifetimeYears;
    if (key === 'y') return assessment.migrationTimeYears;
    if (key === 'pMoscaViolated' || key === 'pBreakBeforeMigration') return assessment[key];
    if (key === 'riskBand') return assessment.riskBand;
    return asset[key] || '';
  }

  function renderAssetsTable() {
    const body = $('asset-rows');
    body.replaceChildren();
    const scenarioId = selectedTableScenario();
    if (!scenarioId || !state.assets.length) {
      const row = make('tr');
      const cell = make('td', '', state.assets.length ? 'Run an assessment to see asset results.' : 'No assets available for this scan.');
      cell.colSpan = 8;
      row.append(cell);
      body.append(row);
      return;
    }
    const results = new Map(assessmentsFor(scenarioId).map((assessment) => [assessment.assetId, assessment]));
    const sorted = state.assets.slice().sort((left, right) => {
      const leftResult = results.get(left.assetId);
      const rightResult = results.get(right.assetId);
      const leftValue = valueForSort(left, leftResult || {}, state.sortKey);
      const rightValue = valueForSort(right, rightResult || {}, state.sortKey);
      const comparison = typeof leftValue === 'number' && typeof rightValue === 'number'
        ? leftValue - rightValue
        : String(leftValue).localeCompare(String(rightValue));
      return comparison * state.sortDirection;
    });
    for (const asset of sorted) {
      const assessment = results.get(asset.assetId);
      if (!assessment) continue;
      const row = make('tr');
      row.append(make('td', '', `${asset.algorithm} · ${asset.filePath}${asset.lineNumber ? `:${asset.lineNumber}` : ''}`));
      row.append(make('td', '', asset.family));
      row.append(make('td', '', asset.usage));
      row.append(makeOverrideCell(asset, assessment, 'dataLifetimeYears', assessment.dataLifetimeYears, isSignatureUsageForUi(asset.usage)));
      row.append(makeOverrideCell(asset, assessment, 'migrationTimeYears', assessment.migrationTimeYears, false));
      row.append(make('td', '', assessment.pMoscaViolated.toFixed(3)));
      row.append(make('td', '', assessment.pBreakBeforeMigration.toFixed(3)));
      const riskCell = make('td');
      const pill = make('span', 'qtm-risk-pill', assessment.riskBand);
      pill.dataset.risk = assessment.riskBand;
      riskCell.append(pill);
      if (assessment.lowConfidenceFamily) riskCell.append(make('span', 'qtm-low-confidence', 'Low confidence family'));
      row.append(riskCell);
      body.append(row);
    }
  }

  function isSignatureUsageForUi(usage) {
    return /(signature|auth|jwt|certificate)/i.test(String(usage || ''));
  }

  function makeOverrideCell(asset, assessment, field, currentValue, disabled) {
    const cell = make('td');
    const input = make('input');
    input.type = 'number';
    input.min = '0';
    input.step = '0.5';
    input.value = String(state.overrides[asset.assetId]?.[field] ?? currentValue);
    input.setAttribute('aria-label', `${asset.algorithm} ${field === 'dataLifetimeYears' ? 'X data lifetime' : 'Y migration time'} override in years`);
    input.title = disabled ? 'X is fixed at zero for signature and authentication use.' : 'Changing this value reruns the assessment.';
    input.disabled = disabled;
    input.addEventListener('change', () => {
      const value = Number(input.value);
      if (!Number.isFinite(value) || value < 0) {
        setStatus('Overrides must be non-negative numbers.', 'error');
        return;
      }
      state.overrides[asset.assetId] = { ...(state.overrides[asset.assetId] || {}), [field]: value };
      scheduleOverrideRun();
    });
    cell.append(input);
    return cell;
  }

  function renderResults() {
    const empty = $('empty-state');
    const noRun = $('no-run-state');
    const hasResults = visibleScenarioIds().some((id) => (state.results?.byScenario?.[id] || []).length > 0);
    empty.hidden = !state.results || state.assets.length !== 0;
    noRun.hidden = !state.results || state.assets.length === 0 || hasResults;
    renderSummary();
    renderTableScenarioOptions();
    renderHeatmap();
    renderAssetsTable();
  }

  async function loadScenarioList() {
    const payload = await apiRequest('/scenarios');
    state.scenarios = payload.scenarios || [];
    state.selectedScenarioIds = new Set(state.scenarios.map((scenario) => scenario.id).slice(0, 10));
    renderScenarioCards();
  }

  async function loadPersistedResults() {
    const payload = await apiRequest('/threat-model');
    state.results = payload;
    state.assets = payload.assets || [];
    state.runScenarioIds = Object.keys(payload.byScenario || {}).filter((id) => (payload.byScenario[id] || []).length > 0);
    state.shiftedByScenario = null;
    renderResults();
  }

  async function loadScan(scanId) {
    if (!scanId) return;
    state.scanId = scanId;
    state.results = null;
    state.assets = [];
    state.runScenarioIds = [];
    state.shiftedByScenario = null;
    state.overrides = {};
    state.devSample = false;
    renderScanOptions();
    setStatus('Loading scenarios and saved assessment…');
    try {
      await loadScenarioList();
      await loadPersistedResults();
      setStatus('');
    } catch (error) {
      setStatus(error.message, 'error');
      renderResults();
    }
  }

  function readRunSettings() {
    const iterations = Number($('iterations-input').value);
    const seed = Number($('seed-input').value);
    if (!Number.isInteger(iterations) || iterations < 1 || iterations > 100000) throw new Error('Iterations must be from 1 to 100000.');
    if (!Number.isInteger(seed) || seed < -2147483648 || seed > 2147483647) throw new Error('Seed must be a signed 32-bit integer.');
    return { iterations, seed };
  }

  async function runAssessment() {
    if (state.running) return;
    if (!state.scanId) return setStatus('Select a scan before running an assessment.', 'error');
    const scenarioIds = [...state.selectedScenarioIds];
    if (!scenarioIds.length) return setStatus('Select at least one scenario.', 'error');
    if (scenarioIds.length > 10) return setStatus('Select no more than 10 scenarios.', 'error');
    let settings;
    try { settings = readRunSettings(); } catch (error) { return setStatus(error.message, 'error'); }
    state.running = true;
    $('run-assessment').disabled = true;
    $('load-sample').disabled = true;
    setStatus('Running seeded Monte Carlo assessment…');
    try {
      const payload = await apiRequest('/threat-model/run', 'POST', {
        scenarioIds,
        iterations: settings.iterations,
        seed: settings.seed,
        overrides: state.overrides,
        ...(state.devSample ? { devSample: true } : {}),
      });
      state.results = payload;
      state.assets = payload.assets || [];
      state.runScenarioIds = Object.keys(payload.byScenario || {}).filter((id) => (payload.byScenario[id] || []).length > 0);
      state.shiftedByScenario = null;
      $('arrival-shift').value = '0';
      updateShiftLabel(0);
      renderResults();
      setStatus(payload.message || 'Assessment saved for this scan.', payload.assets?.length ? 'success' : '');
    } catch (error) {
      setStatus(error.message, 'error');
    } finally {
      state.running = false;
      renderScanOptions();
    }
  }

  function scheduleOverrideRun() {
    if (state.sweepTimer) clearTimeout(state.sweepTimer);
    state.sweepTimer = setTimeout(() => runAssessment(), 350);
  }

  function updateShiftLabel(value) {
    const label = $('shift-label');
    if (value < 0) label.textContent = `Quantum arrives ${Math.abs(value)} ${Math.abs(value) === 1 ? 'year' : 'years'} earlier than the scenario assumes`;
    else if (value > 0) label.textContent = `Quantum arrives ${value} ${value === 1 ? 'year' : 'years'} later than the scenario assumes`;
    else label.textContent = 'Scenario baseline';
  }

  async function applyArrivalShift() {
    const shift = Number($('arrival-shift').value);
    updateShiftLabel(shift);
    if (!state.results || !state.assets.length || shift === 0) {
      state.shiftedByScenario = null;
      renderResults();
      return;
    }
    let settings;
    try { settings = readRunSettings(); } catch (error) { return setStatus(error.message, 'error'); }
    const metric = $('metric-mode').value;
    const rows = $('row-mode').value;
    const scenarioIds = visibleScenarioIds();
    const shifted = {};
    setStatus('Recalculating arrival-shift sensitivity…');
    try {
      await Promise.all(scenarioIds.map(async (scenarioId) => {
        const cacheKey = [state.scanId, scenarioId, shift, settings.iterations, settings.seed, state.devSample, JSON.stringify(state.overrides)].join('|');
        let assessments = state.sweepCache.get(cacheKey);
        if (!assessments) {
          const payload = await apiRequest('/threat-model/sweep', 'POST', {
            scenarioId,
            shifts: [shift],
            metric,
            rows,
            iterations: settings.iterations,
            seed: settings.seed,
            overrides: state.overrides,
            ...(state.devSample ? { devSample: true } : {}),
          });
          const shiftedId = Object.keys(payload.byScenario || {})[0];
          assessments = payload.byScenario[shiftedId] || [];
          state.sweepCache.set(cacheKey, assessments);
        }
        shifted[scenarioId] = assessments;
      }));
      state.shiftedByScenario = shifted;
      renderResults();
      setStatus('Arrival-shift sensitivity updated.', 'success');
    } catch (error) {
      setStatus(error.message, 'error');
    }
  }

  function onShiftInput() {
    updateShiftLabel(Number($('arrival-shift').value));
    if (state.sweepTimer) clearTimeout(state.sweepTimer);
    state.sweepTimer = setTimeout(applyArrivalShift, 250);
  }

  function onSort(event) {
    const button = event.target.closest('[data-sort]');
    if (!button) return;
    const key = button.dataset.sort;
    if (state.sortKey === key) state.sortDirection *= -1;
    else { state.sortKey = key; state.sortDirection = 1; }
    renderAssetsTable();
  }

  async function bootstrap() {
    if (!window.Auth || !(await window.Auth.requireAuth())) return;
    const devButton = $('load-sample');
    devButton.hidden = !isDevelopmentBrowser();
    state.scans = localScans();
    const requestedScan = new URLSearchParams(window.location.search).get('scanId');
    const data = window.CryptoEngine ? window.CryptoEngine.getData() : {};
    const preferred = data.activeScan?.scanId || data.activeScan?.id || state.scans[0]?.scanId || '';
    state.scanId = state.scans.some((scan) => scan.scanId === requestedScan) ? requestedScan : preferred;
    renderScanOptions();
    if (!state.scanId) {
      setStatus('No local scan is available. Run a repository scan, then return here.', 'error');
      $('empty-state').hidden = false;
      $('empty-state').textContent = 'No scan is available in the current browser session.';
      return;
    }
    await loadScan(state.scanId);
  }

  $('scan-select').addEventListener('change', () => loadScan($('scan-select').value));
  $('run-assessment').addEventListener('click', runAssessment);
  $('load-sample').addEventListener('click', () => {
    if (!isDevelopmentBrowser()) return;
    state.devSample = true;
    runAssessment();
  });
  $('row-mode').addEventListener('change', renderHeatmap);
  $('metric-mode').addEventListener('change', () => {
    renderHeatmap();
    if (Number($('arrival-shift').value) !== 0) onShiftInput();
  });
  $('arrival-shift').addEventListener('input', onShiftInput);
  $('table-scenario').addEventListener('change', renderAssetsTable);
  document.querySelector('.qtm-assets-table thead').addEventListener('click', onSort);
  document.addEventListener('DOMContentLoaded', () => { bootstrap().catch((error) => setStatus(error.message, 'error')); });
})();