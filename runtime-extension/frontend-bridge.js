(() => {
  try {
    if (globalThis.__cryptoscanFrontendBridgeInstalled) return;
    globalThis.__cryptoscanFrontendBridgeInstalled = true;
    const reply = payload => window.postMessage({ source: 'CryptoScanExtension', ...payload }, location.origin);
    let port = null;
    const connectPort = () => {
      if (port) return;
      port = chrome.runtime.connect({ name: 'cs-frontend' });
      port.onMessage.addListener(message => {
        if (message.type === 'CS_STATE') reply({ type: 'CS_SESSION_STATE', state: message.state });
      });
      port.onDisconnect.addListener(() => {
        void chrome.runtime.lastError;
        port = null;
      });
      port.postMessage({ type: 'CS_FRONTEND_READY' });
    };
    connectPort();
    const send = message => new Promise(resolve => {
      chrome.runtime.sendMessage(message, response => {
        const error = chrome.runtime.lastError;
        resolve(error ? { ok: false, error: error.message } : (response || { ok: false, error: 'Extension worker did not respond.' }));
      });
    });

    window.addEventListener('message', async event => {
      try {
        if (event.source !== window || event.origin !== location.origin || !event.data) return;
        const data = event.data;
        if (data.source !== 'CryptoScanPage') return;
        if (data.type === 'CS_EXTENSION_PING') {
          const response = await send({ type: 'CS_PING' });
          reply({ type: 'CS_EXTENSION_PONG', installed: Boolean(response.ok), error: response.error || null });
          return;
        }
        if (data.type === 'CS_SESSION_HANDOFF') {
          const response = await send({ type: 'CS_HANDOFF', bundle: data.bundle });
          reply({ type: 'CS_SESSION_HANDOFF_RESULT', ...response });
          return;
        }
        if (data.type === 'CS_EXTENSION_STOP') {
          const response = await send({ type: 'CS_STOP' });
          reply({ type: 'CS_EXTENSION_STOP_RESULT', ...response });
        }
      } catch (_) {}
    });
    window.addEventListener('pageshow', event => {
      if (!event.persisted) return;
      connectPort();
      window.postMessage({ source: 'CryptoScanPage', type: 'CS_EXTENSION_PING' }, location.origin);
    });
    console.log('[CryptoScan] frontend bridge ready', { origin: location.origin });
  } catch (_) {}
})();
