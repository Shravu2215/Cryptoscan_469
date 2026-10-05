(() => {
  try {
    const port = chrome.runtime.connect({ name: 'cs-target' });
    let state = { status: 'idle', eventCount: 0 };
    let host = null;
    let root = null;
    let label = null;
    let count = null;
    let startButton = null;
    let stopButton = null;
    let panel = null;
    let stoppingLocally = false;

    function sendHookState() {
      try {
        window.postMessage({
          source: 'CryptoScanExtension',
          type: 'CS_HOOK_STATE',
          recording: state.status === 'recording' && state.recordingEnabled === true,
        }, location.origin);
      } catch (_) {}
    }

    function render() {
      if (!root) return;
      const status = stoppingLocally ? 'analyzing' : state.status;
      label.textContent = status === 'recording' ? 'Recording…'
        : status === 'ready' ? 'Ready'
          : status === 'analyzing' ? 'Analyzing…'
            : status === 'stopped' ? 'Stopped' : 'No session';
      count.textContent = `${Number(state.eventCount) || 0} events`;
      root.host.dataset.state = status;
      startButton.hidden = status !== 'ready';
      stopButton.hidden = !['ready', 'recording'].includes(status);
      startButton.disabled = status !== 'ready';
      stopButton.disabled = stoppingLocally || !['ready', 'recording'].includes(status);
      if (status === 'recording' || status === 'analyzing') root.statusRing.classList.add('active');
      else root.statusRing.classList.remove('active');
      sendHookState();
    }

    function createWidget() {
      if (host || window.top !== window) return;
      if (!document.documentElement) {
        document.addEventListener('DOMContentLoaded', createWidget, { once: true });
        return;
      }
      host = document.createElement('div');
      host.id = 'cryptoscan-runtime-observer';
      host.style.cssText = 'all:initial;position:fixed;right:18px;bottom:18px;z-index:2147483647;';
      const shadow = host.attachShadow({ mode: 'closed' });
      shadow.innerHTML = `
        <style>
          :host { all: initial; }
          * { box-sizing: border-box; font-family: system-ui, sans-serif; }
          .bubble { width: 66px; height: 66px; border-radius: 50%; border: 1px solid #b9c9c5; background: #f9fcfb; color: #153c34; box-shadow: 0 3px 18px #071e1838; cursor: grab; display: flex; flex-direction: column; align-items: center; justify-content: center; position: relative; user-select: none; }
          .brand { font-size: 9px; font-weight: 800; line-height: 1; }
          .mini { font-size: 10px; margin-top: 4px; }
          .ring { width: 9px; height: 9px; border-radius: 50%; border: 2px solid #c3d0cc; border-top-color: #da4635; position: absolute; top: 8px; right: 8px; }
          .ring.active { animation: spin .8s linear infinite; }
          @keyframes spin { to { transform: rotate(360deg); } }
          .panel { display: none; position: absolute; right: 0; bottom: 76px; width: 236px; background: #f9fcfb; color: #172521; border: 1px solid #b9c9c5; border-radius: 8px; padding: 12px; box-shadow: 0 5px 24px #071e1840; }
          .panel.open { display: block; }
          .panel-head { display: flex; justify-content: space-between; align-items: center; cursor: grab; font-size: 13px; font-weight: 700; }
          .state { font-size: 12px; margin: 9px 0 3px; font-weight: 700; }
          .count { color: #596b65; font-size: 12px; }
          .actions { display: flex; gap: 8px; margin-top: 12px; }
          button.action { flex: 1; border: 0; border-radius: 4px; padding: 8px; color: white; background: #176b57; font-size: 12px; font-weight: 700; cursor: pointer; }
          button.stop { background: #c6342c; }
          button.action[hidden] { display: none; }
          button.action:disabled { opacity: .55; cursor: default; }
          .error { display: none; margin-top: 8px; color: #a52c22; font-size: 11px; overflow-wrap: anywhere; }
          .error.visible { display: block; }
          .status-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 5px; background: #89958f; }
          :host([data-state="recording"]) .status-dot { background: #d33d31; }
          :host([data-state="analyzing"]) .status-dot { background: #c78a24; }
        </style>
        <button class="bubble" type="button" aria-label="CryptoScan runtime session" title="CryptoScan Runtime">
          <span class="brand">CS</span><span class="mini">0 events</span><span class="ring"></span>
        </button>
        <section class="panel" role="status">
          <div class="panel-head"><span>CryptoScan Runtime</span><span class="status-dot"></span></div>
          <div class="state">Ready</div>
          <div class="count">0 events</div>
          <div class="actions"><button class="action start">Start</button><button class="action stop">Stop</button></div>
          <div class="error"></div>
        </section>`;
      document.documentElement.appendChild(host);
      root = {
        host,
        bubble: shadow.querySelector('.bubble'),
        statusRing: shadow.querySelector('.ring'),
        panelHead: shadow.querySelector('.panel-head'),
        stateLabel: shadow.querySelector('.state'),
        countLabel: shadow.querySelector('.count'),
        error: shadow.querySelector('.error'),
      };
      label = root.stateLabel;
      count = root.countLabel;
      panel = shadow.querySelector('.panel');
      startButton = shadow.querySelector('.start');
      stopButton = shadow.querySelector('.stop');
      const mini = shadow.querySelector('.mini');
      const bubbleState = () => {
        mini.textContent = `${Number(state.eventCount) || 0} events`;
      };
      root.bubble.addEventListener('click', () => panel.classList.toggle('open'));
      root.panelHead.addEventListener('click', () => panel.classList.toggle('open'));
      startButton.addEventListener('click', () => port.postMessage({ type: 'CS_START' }));
      stopButton.addEventListener('click', () => {
        stoppingLocally = true;
        render();
        port.postMessage({ type: 'CS_STOP' });
      });
      const showError = message => {
        root.error.textContent = message || '';
        root.error.classList.toggle('visible', Boolean(message));
      };
      root.showError = showError;
      root.bubbleState = bubbleState;
      let drag = null;
      const beginDrag = event => {
        if (event.button !== 0) return;
        const bounds = host.getBoundingClientRect();
        drag = { x: event.clientX, y: event.clientY, left: bounds.left, top: bounds.top };
        event.preventDefault();
      };
      const moveDrag = event => {
        if (!drag) return;
        const left = Math.max(0, Math.min(window.innerWidth - host.offsetWidth, drag.left + event.clientX - drag.x));
        const top = Math.max(0, Math.min(window.innerHeight - host.offsetHeight, drag.top + event.clientY - drag.y));
        host.style.left = `${left}px`;
        host.style.top = `${top}px`;
        host.style.right = 'auto';
        host.style.bottom = 'auto';
      };
      const endDrag = () => { drag = null; };
      root.panelHead.addEventListener('pointerdown', beginDrag);
      root.bubble.addEventListener('pointerdown', beginDrag);
      window.addEventListener('pointermove', moveDrag);
      window.addEventListener('pointerup', endDrag);
      bubbleState();
      render();
    }

    function updateState(next) {
      state = next || { status: 'idle', eventCount: 0 };
      if (!host && window.top === window && state.targetOrigin === location.origin) createWidget();
      if (host && state.targetOrigin !== location.origin && window.top === window) {
        host.remove();
        host = null;
        root = null;
      }
      if (root) {
        root.bubbleState();
        render();
      }
    }

    port.onMessage.addListener(message => {
      try {
        if (message.type === 'CS_STATE') updateState(message.state);
        if (message.type === 'CS_ACTION_RESULT') {
          stoppingLocally = false;
          if (!message.ok && root) root.showError(message.error || 'Runtime action failed.');
          else if (root) root.showError('');
        }
      } catch (_) {}
    });

    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (!message || message.type !== 'CS_FLUSH_HOOKS') return;
      try {
        window.postMessage({ source: 'CryptoScanExtension', type: 'CS_HOOK_FLUSH' }, location.origin);
        sendResponse({ ok: true });
      } catch (_) { sendResponse({ ok: false }); }
    });

    window.addEventListener('message', event => {
      try {
        if (event.source !== window || event.origin !== location.origin || !event.data) return;
        if (event.data.source !== 'CryptoScanMainHook' || event.data.type !== 'CS_EVENTS' || !Array.isArray(event.data.events)) return;
        if (!['recording', 'analyzing'].includes(state.status) || !state.targetOrigin) return;
        port.postMessage({ type: 'CS_EVENTS', events: event.data.events });
      } catch (_) {}
    });

    port.postMessage({ type: 'CS_TARGET_READY' });
    chrome.runtime.sendMessage({ type: 'CS_GET_STATE' }, response => {
      if (chrome.runtime.lastError) return;
      if (response && response.state) updateState(response.state);
    });
  } catch (_) {}
})();
