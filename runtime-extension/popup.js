const $ = selector => document.querySelector(selector);

function send(message) {
  return new Promise(resolve => {
    chrome.runtime.sendMessage(message, response => {
      const error = chrome.runtime.lastError;
      resolve(error ? { ok: false, error: error.message } : (response || { ok: false, error: 'No response from service worker.' }));
    });
  });
}

function render(state) {
  const active = state && state.status === 'recording';
  $('#state').textContent = state ? state.status : 'No session';
  $('#state-dot').className = active ? 'recording' : '';
  $('#session-id').textContent = state && state.id ? `Session ${state.id}` : '';
  $('#count').textContent = String(state && state.eventCount || 0);
  $('#last-flush').textContent = state && state.lastFlushAt ? new Date(state.lastFlushAt).toLocaleTimeString() : 'Never';
  $('#last-error').hidden = !(state && state.lastError);
  $('#last-error').textContent = state && state.lastError ? state.lastError : '';
  $('#self-test').disabled = !active;
}

async function refresh() {
  const response = await send({ type: 'CS_GET_STATE' });
  if (response.ok) render(response.state);
}

async function loadConfig() {
  const config = await chrome.storage.local.get('cryptoscanOrigin');
  const originInput = $('#origin');
  if (document.activeElement !== originInput) originInput.value = config.cryptoscanOrigin || '';
  $('#connection').textContent = config.cryptoscanOrigin
    ? `Connected to ${config.cryptoscanOrigin}`
    : 'Configure the exact origin of your CryptoScan frontend.';
}

$('#connect').addEventListener('click', async () => {
  const button = $('#connect');
  button.disabled = true;
  const response = await send({ type: 'CS_CONFIGURE_ORIGIN', origin: $('#origin').value.trim() });
  button.disabled = false;
  $('#connection').textContent = response.ok ? `Connected to ${response.origin}` : (response.error || 'Could not register CryptoScan origin.');
  if (response.ok) $('#origin').value = response.origin;
  await refresh();
});

$('#self-test').addEventListener('click', async () => {
  const button = $('#self-test');
  button.disabled = true;
  $('#test-result').textContent = 'Running real WebCrypto and Math.random calls…';
  const response = await send({ type: 'CS_SELF_TEST' });
  $('#test-result').textContent = response.ok
    ? (response.observed ? `Self-test observed ${response.delta} events.` : 'No events arrived. Check that a target tab is recording.')
    : (response.error || 'Self-test failed.');
  await refresh();
  button.disabled = !response.ok || !response.observed;
});

loadConfig();
refresh();
setInterval(refresh, 1000);
