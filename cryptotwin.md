You are working on my existing CryptoScan project (a Post-Quantum Cryptography security and migration platform).

Existing flow: Repository → CryptoScan → Findings → CBOM → Risk Analysis → Migration Plan → PQC Simulator → CryptoTwin → Human Approval.

GOAL: Add a NEW module called "CryptoShield" that sits right AFTER "CryptoTwin" in the sidebar and works as a native part of the app. It answers one question: "Who is allowed to use a cryptographic asset, and what happens if an unauthorized application tries to use it?"

It is NOT a SIEM, antivirus, or SOC dashboard. Keep it focused on crypto access control and misuse detection.

HARD RULES
- CryptoTwin already works. Do NOT rebuild, rewrite, or break it. Do NOT redesign the app.
- Reuse the existing design system, components, auth, API patterns, DB patterns, theme (dark/light), modals, tables, and sidebar mechanism.
- Never expose raw secrets/private keys in UI, logs, API responses, console, or DB. Show only safe fingerprints (SHA-256, shortened like 8f3a...9bd).
- A hash is only an identifier. Never use a hash as a key and never claim hashing alone protects a key.
- Never rotate, revoke, delete, or modify any real credential. All response actions are simulated or approval-based.
- Clearly label states: detected / simulated / suspected / confirmed. Never call a simulated event a "breach". Use "Potential Impact" / "Potential Blast Radius".
- Validate all API inputs, fail safely (deny by default), protect all CryptoShield routes with the existing auth/authorization, and audit-log every sensitive action.
- Use only dummy placeholder data. No realistic-looking secrets.
- Must stay compatible with on-premise deployment.

WORK IN PHASES. Finish each phase, tell me what you did, then continue.

PHASE 0: INSPECT (no code yet)
Inspect the full repo and report: frontend framework, backend framework, database, existing finding/CBOM models, CryptoTwin routes/components/services/state, authentication, UI component library, how the sidebar and routing work, and how API calls are structured.

PHASE 1: SHORT PLAN
Give a brief plan listing the files you will add or modify. Prefer modifying few files and reusing existing ones. Don't ask me to create files manually.

PHASE 2: DATA LAYER
Create safe "Crypto Asset Identity" records, reusing existing CryptoScan findings where possible instead of duplicating them. Fields: asset_id, asset_type, fingerprint, algorithm, application/service, environment, owner, source_file, source_line, criticality, allowed_services, status, created_at. Fingerprint using a one-way SHA-256 and never store the raw value.
Add models/tables for: access policies, security events, recovery plans, audit log.
Seed clearly labelled DEMO data if real runtime data isn't available:
Assets: Payment-Key-01, Authentication-Key-01, TLS-Certificate-01, API-Credential-01.
Services: Payment Service, Authentication Service, Notification Service, Unknown Service, Developer Tool.

PHASE 3: BACKEND APIs
Build validated, authenticated endpoints for: asset list/detail, policy create/update, access simulation, security events, alerts, blast radius, recovery plan create/approve/decline, audit log.
Policy engine logic:
IF application allowed AND operation allowed AND environment allowed → ALLOW.
Otherwise → BLOCK, create a security event (event_id, timestamp, asset_id, requesting_application, requested_operation, environment, decision, reason, severity), raise asset risk, create an alert.
Default for anything unknown = BLOCK.

PHASE 4: BLAST RADIUS + RECOMMENDATION
Use existing dependency data where available (example chain: Payment-Key-01 → Payment Service → Payment API → Transaction Service). Show "Potential Blast Radius" with affected components. Generate a recommended response:
1. Investigate the requesting application. 2. Verify if access is legitimate. 3. Review the affected asset. 4. Prepare a credential replacement/recovery plan. 5. Test using CryptoTwin. 6. Require human approval before any production change.
Never auto-execute anything.

PHASE 5: FRONTEND
Add "CryptoShield" to the sidebar right after CryptoTwin, using the same navigation pattern. Inside it, simple tabs/pages:
1. Dashboard: Protected Assets, Critical Assets, Unauthorized Attempts, Active Policies, and a Security Status indicator, computed from real data in the DB.
2. Protected Assets: table with Asset ID, Type, Application, Environment, Fingerprint, Risk, Status, View.
3. Access Policies: form with Asset, Allowed Application, Allowed Operations (Sign / Verify / Encrypt / Decrypt checkboxes), Environment, Save Policy.
4. Security Events + "Simulate Crypto Access" button. Modal with Application (Payment Service, Authentication Service, Unknown Service, Developer Tool), Asset, Operation. Label it clearly "Security Event Simulation" and state it is not a live banking network monitor. Show ✓ ALLOWED or 🚨 BLOCKED with the reason.
5. Alerts: crypto-only alerts (severity, asset, description, Investigate button).
6. Recovery Plans.
7. Audit Trail: Time, Action, User, Asset, Result.
Add loading, empty, and error states. Make the UI match the existing app exactly.

PHASE 6: CRYPTOTWIN INTEGRATION
Add a "Test Recovery in CryptoTwin" button on the alert/recovery view. It passes the security context (asset, affected service, issue) into the EXISTING CryptoTwin workflow, reusing its components, APIs, and state. Do NOT duplicate or modify CryptoTwin logic beyond a minimal entry point. Show the returned results (Authentication, Payment API, Database, Integration tests, Recovery Confidence, critical failures) inside the recovery plan.

PHASE 7: HUMAN APPROVAL
Show a SECURITY RECOVERY PLAN card: Asset, Issue, Potential Impact, Recommended Action, CryptoTwin Validation (PASSED/FAILED), Critical Test Failures, Production Action: NOT EXECUTED. Buttons: [APPROVE RECOVERY PLAN] [DECLINE].
Approval only records the approval, updates simulated status, and writes an audit event. It must NOT touch any real key. Block approval if CryptoTwin validation hasn't been run.

PHASE 8: AUDIT + VERIFY
Make sure every sensitive action (event detected, plan created, CryptoTwin validation, approve/decline, policy change) is audit-logged.
Then run a verification pass and report against this checklist:
✓ CryptoShield appears in sidebar after CryptoTwin
✓ CryptoTwin and all existing features still work
✓ Assets and fingerprints display with no raw secrets anywhere (UI, logs, API responses, demo data)
✓ Policies can be created and saved
✓ Authorized simulated access is ALLOWED; unauthorized is BLOCKED
✓ Security events and alerts are created
✓ Blast radius and recovery recommendation display
✓ "Test Recovery in CryptoTwin" works through the existing CryptoTwin
✓ Human approval works and changes no real credential
✓ Audit trail records everything
✓ Auth protects all CryptoShield routes; invalid inputs are rejected

PRODUCT STORY the UI should communicate:
CryptoScan finds the crypto assets and risks. CryptoShield controls who can use them and detects unauthorized usage. CryptoTwin safely tests the recovery before production. A human approves the final change.

Build this as a polished, working prototype, not static screens.

