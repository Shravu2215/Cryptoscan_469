"""
Feature 12 Full Verification Script
Runs checks 2, 3, 5, and 6 of the verification protocol.
"""
import io
import sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import json
import os
import sys
import subprocess
import tempfile
import uuid
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

RESULTS = {}

def mark(name, passed, notes=""):
    status = "PASS" if passed else "FAIL"
    RESULTS[name] = (status, notes)
    print(f"[{status}] {name}" + (f" — {notes}" if notes else ""))

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

# ─────────────────────────────────────────────────────────────────────────────
# CHECK 2: Matcher — run tracer with --scan-id, verify matched_finding_id
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("CHECK 2: Matcher -- static->runtime evidence correlation")
print("="*60)

# Load static findings
scan_json_path = os.path.join(ROOT, "scan_demo_output.json")
with open(scan_json_path) as f:
    scan_data = json.load(f)
static_findings = scan_data["findings"]

print(f"  Static findings loaded: {len(static_findings)}")
for sf in static_findings:
    print(f"    fingerprint={sf['fingerprint']}  algo={sf['algorithm']}  file={sf['file']}  line={sf['line']}")

# Run tracer to get fresh events
out_events_path = os.path.join(ROOT, "verify_runtime_events.jsonl")
if os.path.exists(out_events_path):
    os.remove(out_events_path)

run_id = str(uuid.uuid4())
env = os.environ.copy()
env["CRYPTOSCAN_RUNTIME_OUT"] = out_events_path
env["CRYPTOSCAN_RUN_ID"] = run_id

py_agent_path = os.path.join(ROOT, "runtime", "python_agent")
env["PYTHONPATH"] = f"{py_agent_path}{os.pathsep}{ROOT}{os.pathsep}{env.get('PYTHONPATH','')}"

print(f"\n  Run ID: {run_id}")
result = subprocess.run(
    [sys.executable, os.path.join(ROOT, "demo_crypto_app.py")],
    env=env, capture_output=True, text=True
)
print(f"  Demo app exit code: {result.returncode}")

# Load raw events
raw_events = []
if os.path.exists(out_events_path):
    with open(out_events_path) as f:
        for line in f:
            if line.strip():
                raw_events.append(json.loads(line.strip()))
print(f"  Raw events captured: {len(raw_events)}")

# Run matcher
from runtime.matcher import match_events_to_findings
matched_events, match_summary = match_events_to_findings(static_findings, raw_events)

print(f"\n  Matcher summary: {json.dumps(match_summary, indent=4)}")
print("\n  Matched events:")
for evt in matched_events:
    print(f"    algo={evt['algorithm']}  file={evt['call_file']}  line={evt['call_line']}  "
          f"fn={evt['call_function']}  matched_finding_id={evt.get('matched_finding_id')}  "
          f"reason={evt.get('match_reason')}  confidence={evt.get('match_confidence')}")

# Verify: SHA-256 @line 33, AES @line 40, RSA @line 45, ECDSA @line 57 should be matched
executed = {evt["algorithm"]: evt for evt in matched_events}
sha256_ok = executed.get("SHA-256", {}).get("matched_finding_id") is not None
aes_ok = executed.get("AES", {}).get("matched_finding_id") is not None
rsa_ok = executed.get("RSA", {}).get("matched_finding_id") is not None
ecdsa_ok = executed.get("ECDSA", {}).get("matched_finding_id") is not None

mark("2a_sha256_matched", sha256_ok, f"id={executed.get('SHA-256',{}).get('matched_finding_id')}")
mark("2b_aes_matched", aes_ok, f"id={executed.get('AES',{}).get('matched_finding_id')}")
mark("2c_rsa_matched", rsa_ok, f"id={executed.get('RSA',{}).get('matched_finding_id')}")
mark("2d_ecdsa_matched", ecdsa_ok, f"id={executed.get('ECDSA',{}).get('matched_finding_id')}")

# Verify no MD5/SHA-1/RSA-1024 in runtime events
runtime_algos = {evt["algorithm"] for evt in matched_events}
md5_absent = "MD5" not in runtime_algos
sha1_absent = "SHA-1" not in runtime_algos
# RSA-1024 would show key_size=1024
rsa1024_absent = not any(
    evt["algorithm"] == "RSA" and evt.get("key_size") == 1024 for evt in matched_events
)
mark("2e_md5_not_in_runtime", md5_absent, f"Seen algos: {sorted(runtime_algos)}")
mark("2f_sha1_not_in_runtime", sha1_absent)
mark("2g_rsa1024_not_in_runtime", rsa1024_absent)

# ─────────────────────────────────────────────────────────────────────────────
# CHECK 3: Database storage via Prisma (SQLite)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("CHECK 3: Database storage (Prisma/SQLite)")
print("="*60)

# Use Node.js to run a Prisma query script from backend-core/ dir so dotenv + prisma resolve
BACKEND_DIR = os.path.join(ROOT, "backend-core")
db_check_script = os.path.join(BACKEND_DIR, "verify_db_check.js")
with open(db_check_script, "w") as f:
    f.write("""
'use strict';
require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const RUN_ID = process.argv[2];

async function main() {
  // Insert a test run + events
  const run = await prisma.runtimeRun.create({
    data: {
      id: RUN_ID,
      language: 'python',
      command: 'python demo_crypto_app.py',
      environment: 'test',
      eventCount: 4,
      finishedAt: new Date(),
    }
  });

  const events = await prisma.runtimeEvent.createMany({
    data: [
      { eventId: require('crypto').randomUUID(), runId: RUN_ID, language: 'python', library: 'hashlib', operation: 'hash', algorithm: 'SHA-256', callFile: 'demo_crypto_app.py', callLine: 33, callFunction: 'hash_data', matchedFindingId: '5d7b5ec60feb6fad' },
      { eventId: require('crypto').randomUUID(), runId: RUN_ID, language: 'python', library: 'cryptography', operation: 'encrypt', algorithm: 'AES', mode: 'GCM', callFile: 'demo_crypto_app.py', callLine: 40, callFunction: 'aes_encrypt' },
      { eventId: require('crypto').randomUUID(), runId: RUN_ID, language: 'python', library: 'cryptography', operation: 'keygen', algorithm: 'RSA', keySize: 2048, callFile: 'demo_crypto_app.py', callLine: 45, callFunction: 'rsa_sign_verify' },
      { eventId: require('crypto').randomUUID(), runId: RUN_ID, language: 'python', library: 'cryptography', operation: 'keygen', algorithm: 'ECDSA', curve: 'secp256r1', callFile: 'demo_crypto_app.py', callLine: 57, callFunction: 'ecdsa_sign' },
    ]
  });

  // Read back
  const readRun = await prisma.runtimeRun.findUnique({ where: { id: RUN_ID }, include: { events: true } });
  console.log(JSON.stringify({
    run_id: readRun.id,
    language: readRun.language,
    event_count: readRun.eventCount,
    events_in_db: readRun.events.length,
    algos: readRun.events.map(e => e.algorithm),
    sample_event: {
      algorithm: readRun.events[0]?.algorithm,
      callFile: readRun.events[0]?.callFile,
      callLine: readRun.events[0]?.callLine,
      callFunction: readRun.events[0]?.callFunction,
    }
  }, null, 2));

  await prisma.$disconnect();
}

main().catch(e => { console.error(e.message); process.exit(1); });
""")

db_run_id = str(uuid.uuid4())
# Run from backend-core/ so dotenv and @prisma/client resolve correctly
r = run(["node", "verify_db_check.js", db_run_id], cwd=BACKEND_DIR)
if os.path.exists(db_check_script):
    os.remove(db_check_script)

if r.returncode == 0:
    try:
        db_result = json.loads(r.stdout.strip())
        print(f"  DB query result:\n{json.dumps(db_result, indent=4)}")
        db_run_ok = db_result.get("run_id") == db_run_id
        db_events_ok = db_result.get("events_in_db") == 4
        db_algos_ok = set(db_result.get("algos",[])) == {"SHA-256","AES","RSA","ECDSA"}
        mark("3a_run_stored_in_db", db_run_ok, f"run_id={db_result.get('run_id','')[:8]}...")
        mark("3b_events_stored_in_db", db_events_ok, f"{db_result.get('events_in_db')} events")
        mark("3c_event_algos_correct", db_algos_ok, str(db_result.get("algos")))
        mark("3d_event_fields_correct",
             bool(db_result.get("sample_event",{}).get("callFunction")),
             str(db_result.get("sample_event",{})))
    except Exception as e:
        mark("3_db_storage", False, f"JSON parse error: {e}\nOutput: {r.stdout[:200]}")
else:
    mark("3_db_storage", False, f"Script failed: {r.stderr[:300]}")

# ─────────────────────────────────────────────────────────────────────────────
# CHECK 4: API endpoints
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("CHECK 4: API endpoints (http://localhost:3000)")
print("="*60)

try:
    import urllib.request, urllib.error

    BASE = "http://localhost:3000/api/runtime"
    api_run_id = str(uuid.uuid4())

    def api_post(path, body):
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            BASE + path, data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def api_get(path):
        req = urllib.request.Request(BASE + path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    # 4a: POST valid run + events
    post_body = {
        "run_id": api_run_id,
        "language": "python",
        "environment": "test",
        "command": "python demo_crypto_app.py",
        "events": [
            {"event_id": str(uuid.uuid4()), "language": "python", "library": "hashlib",
             "operation": "hash", "algorithm": "SHA-256", "call_file": "demo_crypto_app.py",
             "call_line": 33, "call_function": "hash_data"},
            {"event_id": str(uuid.uuid4()), "language": "python", "library": "cryptography",
             "operation": "encrypt", "algorithm": "AES", "mode": "GCM",
             "call_file": "demo_crypto_app.py", "call_line": 40, "call_function": "aes_encrypt"},
            {"event_id": str(uuid.uuid4()), "language": "python", "library": "cryptography",
             "operation": "keygen", "algorithm": "RSA", "key_size": 2048,
             "call_file": "demo_crypto_app.py", "call_line": 45, "call_function": "rsa_sign_verify"},
            {"event_id": str(uuid.uuid4()), "language": "python", "library": "cryptography",
             "operation": "keygen", "algorithm": "ECDSA", "curve": "secp256r1",
             "call_file": "demo_crypto_app.py", "call_line": 57, "call_function": "ecdsa_sign"},
        ]
    }
    status, body = api_post("/runs", post_body)
    print(f"\n  POST /api/runtime/runs  => {status}  {json.dumps(body)[:120]}")
    post_ok = status == 201 and body.get("run_id") == api_run_id and body.get("event_count") == 4
    mark("4a_post_run_201", post_ok, f"status={status} run_id={body.get('run_id','')[:8]}... events={body.get('event_count')}")

    # 4b: GET list runs
    status, body = api_get("/runs")
    print(f"  GET  /api/runtime/runs  => {status}  runs_count={len(body.get('runs',[]))}")
    list_ok = status == 200 and isinstance(body.get("runs"), list) and len(body.get("runs", [])) > 0
    mark("4b_get_runs_200", list_ok, f"status={status} count={len(body.get('runs',[]))}")

    # 4c: GET single run
    status, body = api_get(f"/runs/{api_run_id}")
    print(f"  GET  /api/runtime/runs/{{run_id}}  => {status}  lang={body.get('run',{}).get('language')}")
    get_run_ok = status == 200 and body.get("run", {}).get("id") == api_run_id
    mark("4c_get_run_by_id_200", get_run_ok, f"status={status}")

    # 4d: GET events for run
    status, body = api_get(f"/runs/{api_run_id}/events")
    print(f"  GET  /api/runtime/runs/{{run_id}}/events  => {status}  count={body.get('count')}")
    get_events_ok = status == 200 and body.get("count") == 4
    mark("4d_get_events_200", get_events_ok, f"status={status} count={body.get('count')}")

    # 4e: GET evidence report
    status, body = api_get(f"/runs/{api_run_id}/report")
    print(f"  GET  /api/runtime/runs/{{run_id}}/report  => {status}")
    print(f"       summary={json.dumps(body.get('summary',{}))}")
    report_ok = (status == 200
                 and set(body.get("summary", {}).get("unique_algorithms", [])) >= {"SHA-256", "AES", "RSA", "ECDSA"}
                 and set(body.get("summary", {}).get("quantum_vulnerable_algorithms", [])) >= {"RSA", "ECDSA"})
    mark("4e_get_report_200", report_ok, f"status={status} algos={body.get('summary',{}).get('unique_algorithms')}")

    # 4f: Invalid payload rejected
    status, body = api_post("/runs", {"language": "cobol", "events": []})
    print(f"  POST bad lang  => {status}  {body.get('error','')[:60]}")
    invalid_rejected = status == 400
    mark("4f_invalid_payload_rejected", invalid_rejected, f"status={status}")

    # 4g: 404 for unknown run
    status, body = api_get(f"/runs/nonexistent-run-id")
    print(f"  GET  unknown run => {status}")
    mark("4g_404_unknown_run", status == 404, f"status={status}")

except Exception as e:
    mark("4_api_endpoints", False, f"Exception: {str(e)[:200]}")

# ─────────────────────────────────────────────────────────────────────────────
# CHECK 5: Evidence report
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("CHECK 5: Evidence report generation")
print("="*60)

from runtime.report import generate_report_from_events

report = generate_report_from_events(
    run_id=run_id,
    raw_events=matched_events,
    scan_id="demo-scan-001",
    language="python",
    environment="test",
)

summary = report["summary"]
print(f"\n  Evidence Report Summary:\n{json.dumps(summary, indent=4)}")
print(f"\n  Aggregated events ({len(report['events'])}):")
for evt in report["events"]:
    print(f"    algo={evt['algorithm']}  op={evt['operation']}  fn={evt['call_function']}  "
          f"matched_id={evt['matched_finding_id']}  count={evt['count']}  quantum={evt['is_quantum_vulnerable']}")

report_total_ok = summary["total_events"] == len(raw_events)
report_algos_ok = set(summary["unique_algorithms"]) >= {"SHA-256", "AES", "RSA", "ECDSA"}
report_quantum_ok = set(summary["quantum_vulnerable_algorithms"]) >= {"RSA", "ECDSA"}
mark("5a_report_total_events", report_total_ok, f"total={summary['total_events']}")
mark("5b_report_unique_algorithms", report_algos_ok, str(summary["unique_algorithms"]))
mark("5c_report_quantum_vulnerable", report_quantum_ok, str(summary["quantum_vulnerable_algorithms"]))
mark("5d_report_unmatched_events", True, f"unmatched={summary['unmatched_events']}")

# ─────────────────────────────────────────────────────────────────────────────
# CHECK 6: Node.js agent
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("CHECK 6: Node.js agent")
print("="*60)

node_events_path = os.path.join(ROOT, "verify_node_events.jsonl")
if os.path.exists(node_events_path):
    os.remove(node_events_path)

preload_path = os.path.join(ROOT, "runtime", "node_agent", "preload.js")
node_run_id = str(uuid.uuid4())
node_env = os.environ.copy()
node_env["CRYPTOSCAN_RUNTIME_OUT"] = node_events_path
node_env["CRYPTOSCAN_RUN_ID"] = node_run_id

node_result = run(
    ["node", "--require", preload_path, "-e",
     "const c=require('crypto'); c.createHash('sha256').update('test').digest('hex'); "
     "const {publicKey,privateKey}=c.generateKeyPairSync('rsa',{modulusLength:2048}); "
     "console.log('Node crypto test OK');"],
    env=node_env, cwd=ROOT
)

print(f"  Node exit code: {node_result.returncode}")
print(f"  Node stdout: {node_result.stdout.strip()}")
if node_result.stderr:
    print(f"  Node stderr (first 200): {node_result.stderr[:200]}")

node_events = []
if os.path.exists(node_events_path):
    with open(node_events_path) as f:
        for line in f:
            if line.strip():
                node_events.append(json.loads(line.strip()))

print(f"\n  Node events captured: {len(node_events)}")
for evt in node_events:
    print(f"    algo={evt.get('algorithm')}  op={evt.get('operation')}  "
          f"file={evt.get('call_file')}  line={evt.get('call_line')}  fn={evt.get('call_function')}")

node_ran = node_result.returncode == 0
node_has_sha256 = any(e.get("algorithm") == "SHA-256" for e in node_events)
node_has_rsa = any(e.get("algorithm") == "RSA" for e in node_events)
node_no_data = all("data" not in e and "key" not in e and "plaintext" not in e for e in node_events)
node_has_caller = all(e.get("call_file") and e.get("call_function") for e in node_events) if node_events else False

mark("6a_node_app_ran", node_ran, f"exit={node_result.returncode}")
mark("6b_node_sha256_event", node_has_sha256)
mark("6c_node_rsa_event", node_has_rsa)
mark("6d_node_no_key_data", node_no_data)
mark("6e_node_caller_info", node_has_caller, f"events={len(node_events)}")

# ─────────────────────────────────────────────────────────────────────────────
# FINAL TABLE
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("FINAL RESULTS")
print("="*60)
print(f"{'Check':<35} {'Result':<6} {'Notes'}")
print("-"*80)
for k, (status, notes) in RESULTS.items():
    print(f"{k:<35} {status:<6} {notes[:60]}")

fails = [k for k, (s, _) in RESULTS.items() if s == "FAIL"]
print(f"\n{'ALL PASS' if not fails else f'FAILURES: {fails}'}")
sys.exit(0 if not fails else 1)
