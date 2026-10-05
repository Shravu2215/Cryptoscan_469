'use strict';

const ports = new Set();
let runtimeState = null;
let flushTimer = null;
let statusTimer = null;
let flushing = false;
let polling = false;
const MAX_PENDING = 10000;
const ALLOWED_SOURCES = new Set(['crypto', 'network', 'library', 'wasm']);
const ALLOWED_OPERATIONS = new Set([
  'digest', 'generateKey', 'importKey', 'exportKey', 'encrypt', 'decrypt', 'sign', 'verify',
  'deriveKey', 'deriveBits', 'wrapKey', 'unwrapKey', 'random', 'network', 'wallet', 'load', 'library', 'wasm',
]);
const KEY_FIELDS = new Set(['keySize', 'modulusLength', 'curve', 'mode', 'hash', 'format']);
const LIBRARIES = new Set(['CryptoJS', 'forge', 'sjcl', 'jsrsasign', 'elliptic', 'tweetnacl', 'ethers', 'web3']);

function publicState(state = runtimeState) {
  if (!state) return { status: 'idle', eventCount: 0, lastFlushAt: null, lastError: null };
  return {
    id: state.id,
    scanId: state.scanId,
    status: state.status,
    startedAt: state.startedAt,
    targetOrigin: state.targetOrigin,
    cryptoscanOrigin: state.cryptoscanOrigin,
    eventCount: state.eventCount || 0,
    lastEventAt: state.lastEventAt || null,
    lastFlushAt: state.lastFlushAt || null,
    lastError: state.lastError || null,
  };
}

async function loadState() {
  if (runtimeState) return runtimeState;
  const saved = await chrome.storage.session.get('runtimeState');
  runtimeState = saved.runtimeState || null;
  return runtimeState;
}

async function saveState() {
  if (runtimeState) await chrome.storage.session.set({ runtimeState });
  broadcastState();
}

function broadcastState() {
  const message = { type: 'CS_STATE', state: publicState() };
  for (const port of ports) {
    stateForSender(port.sender).then(state => {
      try { port.postMessage({ type: 'CS_STATE', state }); } catch (_) { ports.delete(port); }
    }).catch(() => ports.delete(port));
  }
}

async function stateForSender(sender) {
  await loadState();
  if (!runtimeState) return publicState();
  if (sender && typeof sender.url === 'string' && sender.url.startsWith(`chrome-extension://${chrome.runtime.id}/`)) return publicState();
  if (!sender || !sender.tab || sender.tab.id === undefined) return { status: 'idle', eventCount: 0 };
  const tab = await chrome.tabs.get(sender.tab.id).catch(() => null);
  const origin = tab && normalizeOrigin(tab.url);
  if (!tab || ![runtimeState.targetOrigin, runtimeState.cryptoscanOrigin].includes(origin)) return { status: 'idle', eventCount: 0 };
  return {
    ...publicState(),
    recordingEnabled: origin === runtimeState.targetOrigin,
    controlsEnabled: true,
  };
}

function log(stage, metadata = {}) {
  console.log('[CryptoScan]', stage, metadata);
}

function normalizeOrigin(value, protocols = ['http:', 'https:']) {
  try {
    const parsed = new URL(value);
    if (!protocols.includes(parsed.protocol) || parsed.username || parsed.password) return null;
    return parsed.origin;
  } catch (_) { return null; }
}

function normalizeCaller(value) {
  if (typeof value !== 'string' || value.length > 1000) return null;
  if (/^unknown:\d+$/.test(value)) return value;
  const match = value.match(/^(.*):(\d+)$/);
  if (!match) return null;
  try {
    const parsed = new URL(match[1]);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return null;
    return `${parsed.origin}${parsed.pathname}:${Number(match[2])}`.slice(0, 700);
  } catch (_) { return null; }
}

function normalizeEvent(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const allowed = new Set(['source', 'algorithm', 'operation', 'keyInfo', 'callerScript', 'hostOrigin', 'scheme', 'port', 'crossOrigin', 'count', 'timestamp']);
  if (Object.keys(input).some(key => !allowed.has(key))) return null;
  if (!ALLOWED_SOURCES.has(input.source) || !ALLOWED_OPERATIONS.has(input.operation)) return null;
  if (typeof input.algorithm !== 'string' || input.algorithm.length > 100 || !/^[A-Za-z0-9_.:+() /-]+$/.test(input.algorithm)) return null;
  if (input.source === 'library' && !LIBRARIES.has(input.algorithm)) return null;
  if (input.source === 'network' && input.algorithm !== 'NETWORK') return null;
  if (input.source === 'wasm' && input.algorithm !== 'WASM') return null;
  if (!input.keyInfo || typeof input.keyInfo !== 'object' || Array.isArray(input.keyInfo)) return null;
  if (Object.keys(input.keyInfo).some(key => !KEY_FIELDS.has(key))) return null;
  const keyInfo = {};
  for (const name of ['keySize', 'modulusLength']) {
    if (input.keyInfo[name] !== undefined) {
      const size = Number(input.keyInfo[name]);
      if (!Number.isSafeInteger(size) || size < 1 || size > 65536) return null;
      keyInfo[name] = size;
    }
  }
  for (const name of ['curve', 'mode', 'hash', 'format']) {
    if (input.keyInfo[name] !== undefined) {
      if (typeof input.keyInfo[name] !== 'string' || input.keyInfo[name].length > 80 || !/^[A-Za-z0-9._:+() /-]+$/.test(input.keyInfo[name])) return null;
      keyInfo[name] = input.keyInfo[name];
    }
  }
  const callerScript = normalizeCaller(input.callerScript);
  if (!callerScript) return null;
  const scheme = input.scheme || '';
  if (!['', 'http', 'https', 'ws', 'wss'].includes(scheme)) return null;
  const hostOrigin = input.hostOrigin ? normalizeOrigin(input.hostOrigin, ['http:', 'https:', 'ws:', 'wss:']) : '';
  if (input.hostOrigin && !hostOrigin) return null;
  const port = Number(input.port || 0);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) return null;
  if (input.source === 'network' && (!scheme || !hostOrigin)) return null;
  if (input.crossOrigin !== undefined && typeof input.crossOrigin !== 'boolean') return null;
  const count = Number(input.count || 1);
  if (!Number.isSafeInteger(count) || count < 1 || count > 1000000) return null;
  const timestamp = typeof input.timestamp === 'string' && Number.isFinite(Date.parse(input.timestamp))
    ? new Date(input.timestamp).toISOString()
    : new Date().toISOString();
  return {
    source: input.source,
    algorithm: input.algorithm,
    operation: input.operation,
    keyInfo,
    callerScript,
    hostOrigin,
    scheme,
    port,
    crossOrigin: Boolean(input.crossOrigin),
    count,
    timestamp,
  };
}

function eventKey(event) {
  return JSON.stringify([
    event.source, event.algorithm, event.operation, event.keyInfo, event.callerScript,
    event.hostOrigin, event.scheme, event.port, event.crossOrigin,
  ]);
}

function noteError(error) {
  if (runtimeState) {
    runtimeState.lastError = String(error && error.message || 'Network operation failed.').slice(0, 240);
    saveState().catch(() => {});
  }
  log('request failed', { message: runtimeState && runtimeState.lastError });
}

function backendUrl(pathname) {
  const url = new URL(runtimeState.ingestUrl);
  return `${url.origin}${pathname}`;
}

async function authorizedFetch(url, options = {}) {
  return fetch(url, {
    ...options,
    credentials: 'omit',
    headers: { ...(options.headers || {}), 'X-CryptoScan-Token': runtimeState.ingestToken },
  });
}

function ensureTimers() {
  if (!flushTimer) flushTimer = setInterval(() => { flushEvents().catch(noteError); }, 1000);
  if (!statusTimer) statusTimer = setInterval(() => { pollStatus().catch(noteError); }, 1000);
}

function clearTimersIfIdle() {
  if (ports.size || !runtimeState || !['ready', 'recording', 'analyzing'].includes(runtimeState.status)) return;
  clearInterval(flushTimer);
  clearInterval(statusTimer);
  flushTimer = null;
  statusTimer = null;
}

async function handleEvents(sender, inputs) {
  await loadState();
  if (!runtimeState || runtimeState.status !== 'recording' || !Array.isArray(inputs)) return;
  if (sender && sender.tab && sender.tab.id !== undefined) {
    const tab = await chrome.tabs.get(sender.tab.id).catch(() => null);
    if (!tab || normalizeOrigin(tab.url) !== runtimeState.targetOrigin) return;
  }
  const normalized = inputs.map(normalizeEvent);
  if (normalized.some(event => !event)) return;
  for (const event of normalized) {
    const key = eventKey(event);
    const existing = runtimeState.pendingEvents.find(item => eventKey(item) === key);
    if (existing) existing.count += event.count;
    else if (runtimeState.pendingEvents.length < MAX_PENDING) runtimeState.pendingEvents.push(event);
    runtimeState.eventCount += event.count;
    runtimeState.lastEventAt = event.timestamp;
  }
  if (!runtimeState.firstEventLogged && normalized.length) {
    runtimeState.firstEventLogged = true;
    log('first event', { source: normalized[0].source, algorithm: normalized[0].algorithm });
  }
  await saveState();
}

async function flushEvents(force = false) {
  await loadState();
  if (flushing || !runtimeState || (!force && runtimeState.status !== 'recording') || !runtimeState.pendingEvents.length) return true;
  flushing = true;
  const batch = runtimeState.pendingEvents.splice(0, 50);
  try {
    const response = await authorizedFetch(runtimeState.ingestUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: batch }),
    });
    if (!response.ok) throw new Error(`Ingest HTTP ${response.status}`);
    const result = await response.json();
    runtimeState.lastFlushAt = new Date().toISOString();
    runtimeState.lastError = null;
    runtimeState.serverEventCount = Number(result.eventCount) || runtimeState.serverEventCount || 0;
    await saveState();
    log('flush ok', { count: batch.length, eventCount: runtimeState.eventCount });
    return true;
  } catch (error) {
    runtimeState.pendingEvents = batch.concat(runtimeState.pendingEvents);
    runtimeState.lastError = String(error && error.message || 'Ingest failed.').slice(0, 240);
    await saveState();
    log('flush failed', { message: runtimeState.lastError });
    return false;
  } finally {
    flushing = false;
  }
}

async function pollStatus() {
  await loadState();
  if (!runtimeState || !['ready', 'recording', 'analyzing'].includes(runtimeState.status)) return;
  try {
    const response = await authorizedFetch(backendUrl(`/api/runtime/sessions/${encodeURIComponent(runtimeState.id)}`));
    if (!response.ok) throw new Error(`Status HTTP ${response.status}`);
    const status = await response.json();
    runtimeState.serverEventCount = Number(status.eventCount) || 0;
    runtimeState.lastEventAt = status.lastEventAt || runtimeState.lastEventAt;
    if (status.status === 'recording' && runtimeState.status === 'ready') runtimeState.status = 'recording';
    if (status.status === 'stopped') runtimeState.status = 'stopped';
    runtimeState.lastError = null;
    await saveState();
  } catch (error) {
    noteError(error);
  }
}

async function startSession() {
  await loadState();
  if (!runtimeState || runtimeState.status !== 'ready') return { ok: false, error: 'No ready runtime session.' };
  const response = await authorizedFetch(backendUrl(`/api/runtime/sessions/${encodeURIComponent(runtimeState.id)}/start`), { method: 'POST' });
  if (!response.ok) throw new Error(`Start HTTP ${response.status}`);
  runtimeState.status = 'recording';
  runtimeState.lastError = null;
  await saveState();
  ensureTimers();
  log('recording started', { targetOrigin: runtimeState.targetOrigin });
  return { ok: true, state: publicState() };
}

async function stopSession() {
  await loadState();
  if (!runtimeState || !['ready', 'recording'].includes(runtimeState.status)) return { ok: false, error: 'No active runtime session.' };
  ensureTimers();
  if (runtimeState.status === 'recording' && runtimeState.targetTabId !== null) {
    await chrome.scripting.executeScript({
      target: { tabId: runtimeState.targetTabId, allFrames: true },
      world: 'MAIN',
      func: () => window.postMessage({ source: 'CryptoScanExtension', type: 'CS_HOOK_FLUSH' }, location.origin),
    }).catch(() => {});
    await new Promise(resolve => setTimeout(resolve, 120));
  }
  if (runtimeState.pendingEvents.length && !(await flushEvents(true))) {
    return { ok: false, error: runtimeState.lastError || 'Could not flush pending events.' };
  }
  runtimeState.status = 'analyzing';
  await saveState();
  try {
    log('stop requested', { sessionId: runtimeState.id });
    const response = await authorizedFetch(backendUrl(`/api/runtime/sessions/${encodeURIComponent(runtimeState.id)}/stop`), { method: 'POST' });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Stop HTTP ${response.status}`);
    runtimeState.status = 'stopped';
    runtimeState.lastError = null;
    await saveState();
    await openFindings(result.scanId);
    log('stop complete', { findingCount: result.findingCount, eventCount: result.eventCount });
    return { ok: true, result };
  } catch (error) {
    runtimeState.status = 'recording';
    runtimeState.lastError = String(error && error.message || 'Stop failed.').slice(0, 240);
    await saveState();
    return { ok: false, error: runtimeState.lastError };
  }
}

async function openFindings(scanId) {
  const url = `${runtimeState.cryptoscanOrigin}/findings.html?runtimeSession=${encodeURIComponent(runtimeState.id)}`;
  const existing = runtimeState.targetTabId === null || runtimeState.targetTabId === undefined
    ? null
    : await chrome.tabs.get(runtimeState.targetTabId).catch(() => null);
  if (existing) await chrome.tabs.update(existing.id, { url, active: true });
  else await chrome.tabs.create({ url, active: true });
}

async function receiveHandoff(bundle, sender) {
  const settings = await chrome.storage.local.get('cryptoscanOrigin');
  const senderOrigin = normalizeOrigin(sender && sender.url);
  const cryptoscanOrigin = normalizeOrigin(bundle && bundle.cryptoscanOrigin);
  const apiBase = normalizeOrigin(bundle && bundle.apiBase);
  let target;
  try { target = new URL(bundle.targetUrl); } catch (_) { return { ok: false, error: 'Invalid target URL.' }; }
  if (!settings.cryptoscanOrigin || senderOrigin !== settings.cryptoscanOrigin || cryptoscanOrigin !== settings.cryptoscanOrigin) return { ok: false, error: 'CryptoScan origin is not configured for this page.' };
  if (!apiBase || !['http:', 'https:'].includes(target.protocol) || target.username || target.password) return { ok: false, error: 'Invalid session URL or API origin.' };
  if (typeof bundle.authToken !== 'string' || bundle.authToken.length < 16 || bundle.authToken.length > 4096) return { ok: false, error: 'CryptoScan authentication is missing.' };
  let createResponse;
  let created = {};
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    createResponse = await fetch(`${apiBase}/api/runtime/sessions`, {
      method: 'POST',
      credentials: 'omit',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${bundle.authToken}`,
        'X-CryptoScan-Origin': cryptoscanOrigin,
      },
      body: JSON.stringify({ targetUrl: target.href }),
    });
    const body = await createResponse.text();
    try { created = JSON.parse(body); } catch (_) {}
  } catch (error) {
    return {
      ok: false,
      error: error && error.name === 'AbortError'
        ? 'Runtime backend timed out while preparing the session. Check that the backend service is running, then retry.'
        : 'Could not reach the CryptoScan backend from the extension.',
    };
  } finally {
    clearTimeout(timeout);
  }
  if (!createResponse.ok) {
    const message = createResponse.status === 503
      ? 'Runtime backend is unavailable (HTTP 503). Start or deploy the CryptoScan backend service, then retry.'
      : `Session prepare failed (HTTP ${createResponse.status}).`;
    return { ok: false, error: created.error || message };
  }
  const targetOrigin = normalizeOrigin(created.targetOrigin);
  const cryptoscanSessionOrigin = normalizeOrigin(created.cryptoscanOrigin);
  const ingest = (() => { try { return new URL(created.ingestUrl); } catch (_) { return null; } })();
  if (!created.id || typeof created.ingestToken !== 'string' || !/^[A-Za-z0-9_-]{32,100}$/.test(created.ingestToken)
    || targetOrigin !== target.origin || cryptoscanSessionOrigin !== cryptoscanOrigin
    || !ingest || !/\/api\/runtime\/sessions\/[^/]+\/events$/.test(ingest.pathname)) {
    return { ok: false, error: 'The backend returned an invalid runtime session.' };
  }
  runtimeState = {
    id: created.id,
    scanId: created.scanId,
    ingestToken: created.ingestToken,
    ingestUrl: ingest.href,
    targetOrigin,
    cryptoscanOrigin,
    cryptoscanTabId: sender.tab && sender.tab.id,
    targetTabId: null,
    status: 'ready',
    startedAt: created.startedAt,
    eventCount: 0,
    serverEventCount: 0,
    lastEventAt: null,
    lastFlushAt: null,
    lastError: null,
    firstEventLogged: false,
    pendingEvents: [],
  };
  await saveState();
  ensureTimers();
  const tab = await chrome.tabs.create({ url: target.href, active: true });
  runtimeState.targetTabId = tab.id;
  await saveState();
  log('handoff received', { sessionId: runtimeState.id, targetOrigin });
  return { ok: true, state: publicState(), targetTabId: tab.id };
}

async function configureOrigin(value) {
  const origin = normalizeOrigin(value);
  if (!origin) return { ok: false, error: 'Enter a valid http(s) origin without a path.' };
  await chrome.storage.local.set({ cryptoscanOrigin: origin });
  try { await chrome.scripting.unregisterContentScripts({ ids: ['cs-frontend-bridge'] }); } catch (_) {}
  await chrome.scripting.registerContentScripts([{
    id: 'cs-frontend-bridge',
    matches: [`${origin}/*`],
    js: ['frontend-bridge.js'],
    runAt: 'document_start',
  }]);
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    if (tab.id === undefined || normalizeOrigin(tab.url) !== origin) continue;
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['frontend-bridge.js'] }).catch(() => {});
  }
  await installMainHook();
  log('CryptoScan origin configured', { origin });
  return { ok: true, origin };
}

async function installMainHook() {
  try { await chrome.scripting.unregisterContentScripts({ ids: ['cs-main-world-hook'] }); } catch (_) {}
  await chrome.scripting.registerContentScripts([{
    id: 'cs-main-world-hook',
    matches: ['<all_urls>'],
    js: ['main-hook.js'],
    runAt: 'document_start',
    allFrames: true,
    world: 'MAIN',
  }]);
  log('main-world hooks registered', { allFrames: true });
}

async function selfTest() {
  await loadState();
  if (!runtimeState || runtimeState.status !== 'recording') return { ok: false, error: 'Start recording in the target widget first.' };
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || normalizeOrigin(tab.url) !== runtimeState.targetOrigin) return { ok: false, error: 'Open the active target tab while recording.' };
  const before = runtimeState.eventCount;
  await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    world: 'MAIN',
    func: async () => {
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode('cryptoscan observer self-test'));
      Math.random();
    },
  });
  await new Promise(resolve => setTimeout(resolve, 1200));
  const delta = runtimeState.eventCount - before;
  log('self-test complete', { delta });
  return { ok: true, observed: delta >= 2, delta };
}

async function handlePortMessage(port, message) {
  if (message.type === 'CS_FRONTEND_READY') {
    port.postMessage({ type: 'CS_STATE', state: await stateForSender(port.sender) });
    return;
  }
  if (message.type === 'CS_TARGET_READY') {
    const state = await stateForSender(port.sender);
    port.postMessage({ type: 'CS_STATE', state });
    return;
  }
  if (message.type === 'CS_EVENTS') {
    await handleEvents(port.sender, message.events);
    return;
  }
  const senderState = await stateForSender(port.sender);
  if (!senderState.targetOrigin || senderState.targetOrigin !== runtimeState?.targetOrigin) return;
  if (message.type === 'CS_START') {
    const result = await startSession().catch(error => ({ ok: false, error: error.message }));
    port.postMessage({ type: 'CS_ACTION_RESULT', action: 'start', ...result });
    return;
  }
  if (message.type === 'CS_STOP') {
    const result = await stopSession();
    port.postMessage({ type: 'CS_ACTION_RESULT', action: 'stop', ...result });
  }
}

chrome.runtime.onConnect.addListener(port => {
  if (!['cs-target', 'cs-popup', 'cs-frontend'].includes(port.name)) return;
  ports.add(port);
  loadState().then(() => {
    stateForSender(port.sender).then(state => port.postMessage({ type: 'CS_STATE', state }));
    ensureTimers();
  });
  port.onMessage.addListener(message => { handlePortMessage(port, message).catch(noteError); });
  port.onDisconnect.addListener(() => {
    void chrome.runtime.lastError;
    ports.delete(port);
    clearTimersIfIdle();
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message.type === 'CS_PING') {
      const config = await chrome.storage.local.get('cryptoscanOrigin');
      return { ok: Boolean(config.cryptoscanOrigin && normalizeOrigin(sender.url) === config.cryptoscanOrigin) };
    }
    if (message.type === 'CS_HANDOFF') return receiveHandoff(message.bundle, sender);
    if (message.type === 'CS_CONFIGURE_ORIGIN') return configureOrigin(message.origin);
    if (message.type === 'CS_GET_STATE') {
      await loadState();
      return { ok: true, state: await stateForSender(sender) };
    }
    if (message.type === 'CS_SELF_TEST') return selfTest();
    if (message.type === 'CS_START' || message.type === 'CS_STOP') {
      const senderState = await stateForSender(sender);
      if (!senderState.targetOrigin || senderState.targetOrigin !== runtimeState?.targetOrigin) return { ok: false, error: 'This origin cannot control the active session.' };
      return message.type === 'CS_START' ? startSession() : stopSession();
    }
    return { ok: false, error: 'Unknown CryptoScan message.' };
  })().then(sendResponse).catch(error => sendResponse({ ok: false, error: String(error.message || error).slice(0, 240) }));
  return true;
});

chrome.runtime.onInstalled.addListener(() => {
  installMainHook().catch(noteError);
  log('extension installed');
});

chrome.runtime.onStartup.addListener(() => {
  loadState().then(() => {
    if (runtimeState && ['ready', 'recording', 'analyzing'].includes(runtimeState.status)) ensureTimers();
  }).catch(noteError);
});
