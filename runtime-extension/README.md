# CryptoScan Runtime Observer (MV3)

Load `runtime-extension/` as an unpacked extension from `chrome://extensions` with Developer mode enabled. Open the extension popup and enter the exact CryptoScan frontend origin (for example, your deployed `https://<your-vercel-domain>` origin), then select **Connect**. This dynamically registers the CryptoScan page bridge for that exact origin; no Vercel wildcard is assumed.

The extension uses `<all_urls>` host permission because the observer must run on arbitrary user-selected target sites and the backend origin is supplied by each prepared session. All backend event/status/stop requests are made by the service worker. The target page receives only the isolated content widget and a main-world hook that emits metadata while the session is recording.

The popup displays session status, aggregate event count, last successful flush, and the last error. Self-test is enabled only during recording and invokes a real SHA-256 WebCrypto digest plus `Math.random` in the active tab.

The Agentic AI React/FastAPI test application was not found in this workspace. The extension is target-origin agnostic; verify it against that app after both projects are available and the backend migration is applied.
