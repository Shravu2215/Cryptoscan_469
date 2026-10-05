# Runtime Analysis Agents

The browser agent is served by backend-core at `/agent/cryptoscan-agent.js`. Include its session, ingest URL, and ingest token as script data attributes in the target page. The Python agent is the workspace-root `cryptoscan_agent.py`; call `start(session_id, ingest_url, token)` during application startup. Both agents send only aggregated algorithm, operation, key metadata, caller location, timestamp, and count.

Apply the browser script before the target page's application script:

```html
<script src="${CRYPTOSCAN_URL}/agent/cryptoscan-agent.js" data-session="${CRYPTOSCAN_SESSION}" data-ingest="${CRYPTOSCAN_INGEST}" data-token="${CRYPTOSCAN_TOKEN}"></script>
<script src="scripts/main.js"></script>
```

For FastAPI startup, install `cryptoscan_agent.py` on the Python import path and start it from environment configuration:

```python
import os
import cryptoscan_agent

cryptoscan_agent.start(
	os.getenv("CRYPTOSCAN_SESSION"),
	os.getenv("CRYPTOSCAN_INGEST"),
	os.getenv("CRYPTOSCAN_TOKEN"),
)
```

The TrustLend demo files referenced by the integration request are not present in this workspace, so no demo HTML or FastAPI business code was modified here. Apply the script to each target HTML page and the startup block to its `backend/main.py` when that demo is available. Run the `20261005_runtime_analysis` Prisma migration before starting the backend.

## Node extension (future)

A Node agent may later wrap `crypto.createHash`, `crypto.createCipheriv`, and `crypto.randomBytes`, preserving each original call and sending only algorithm/mode/key-size metadata and caller location. Node instrumentation is not implemented in this release.
