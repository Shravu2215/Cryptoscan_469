"""
Re-scan pqc-test-fixture.zip via the live API and verify findings.
Run AFTER docker compose up -d confirms all containers Healthy.
"""
import subprocess, json, requests, time, sys

BASE = "http://localhost"
ZIP = r"C:\Users\ACER\Downloads\pqc-test-fixture.zip"

# ── 1. Login to get session cookie ───────────────────────────────────────────
print("Step 1: Login...")
sess = requests.Session()
r = sess.post(f"{BASE}/api/auth/login", json={"email": "admin@cryptoscan.dev", "password": "admin1234"})
if r.status_code not in (200, 201):
    print(f"  Login failed {r.status_code}: {r.text[:300]}")
    # Try demo credentials
    r = sess.post(f"{BASE}/api/auth/login", json={"email": "demo@cryptoscan.dev", "password": "demo1234"})
    if r.status_code not in (200, 201):
        print(f"  Demo login also failed. Running scanner directly instead.")
        # Run scanner directly on extracted fixture
        result = subprocess.run(
            ["python", "scanner/pipeline.py", r"C:\tmp\pqc-test-fixture\pqc-test-fixture"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print("Scanner error:", result.stderr[:500])
            sys.exit(1)
        data = json.loads(result.stdout)
        findings = data.get("findings", [])
        print(f"  Scanner direct: {len(findings)} findings")
        with open("scan_new_output.json", "w") as f:
            json.dump({"findings": findings}, f)
        verify_findings(findings)
        sys.exit(0)
print(f"  Logged in: {r.status_code}")

# ── 2. Upload zip ─────────────────────────────────────────────────────────────
print("Step 2: Upload zip...")
with open(ZIP, "rb") as fz:
    r2 = sess.post(f"{BASE}/api/repo/upload", files={"repository": ("pqc-test-fixture.zip", fz)})
if r2.status_code not in (200, 201):
    print(f"  Upload failed {r2.status_code}: {r2.text[:300]}")
    sys.exit(1)
data2 = r2.json()
repo_id = data2.get("repoId") or data2.get("id") or data2.get("repo", {}).get("id")
print(f"  Repo ID: {repo_id}")

# ── 3. Trigger scan ───────────────────────────────────────────────────────────
print("Step 3: Trigger scan...")
r3 = sess.post(f"{BASE}/api/scan/{repo_id}")
if r3.status_code not in (200, 201, 202):
    print(f"  Scan trigger failed {r3.status_code}: {r3.text[:300]}")
    sys.exit(1)
scan_id = r3.json().get("scanId") or r3.json().get("id")
print(f"  Scan ID: {scan_id}")

# ── 4. Poll for completion ────────────────────────────────────────────────────
print("Step 4: Waiting for scan to complete...")
for i in range(30):
    time.sleep(5)
    r4 = sess.get(f"{BASE}/api/scan/{scan_id}/findings")
    if r4.status_code == 200:
        d = r4.json()
        status = d.get("status", "?")
        findings = d.get("findings", [])
        print(f"  [{i*5}s] status={status}, findings={len(findings)}")
        if status == "COMPLETED":
            with open("scan_new_output.json", "w") as f:
                json.dump({"findings": findings}, f)
            print(f"  Scan complete! {len(findings)} findings saved to scan_new_output.json")
            break
    else:
        print(f"  Poll error {r4.status_code}")
else:
    print("  Timed out waiting for scan")
    sys.exit(1)
