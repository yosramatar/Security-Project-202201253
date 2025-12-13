# HealthCureAlpha Security Project Overview

## Detailed Reference (for engineers and auditors)

### 1. Scope of Work
- Completed an end-to-end security review covering infrastructure expansion, the clinical web portal, and operational runbooks.
- Implemented remediation for all high/medium application risks identified in the register.
- Added guardrails for day-to-day operations: security logging, SIEM integration path, secrets management, and automated regression testing.

### 2. System Architecture Snapshot
- **Frontend**: Single-page login/signup hub (`index.html`) plus role dashboards (`admin.html`, `doctor.html`, `nurse.html`, `patient.html`). Shared `frontend/js/auth.js` is the only active client script and handles authentication flows, session storage, MFA, logout, and change-password UX.
- **Backend**: Node.js HTTP server (`backend/server.js`) backed by SQLite. Supporting modules provide database access (`db.js`), security helpers (`security.js`), structured logging (`logger.js`), and deterministic seeding (`seed.js`).
- **Data**: Diagnoses and medication lists stored encrypted via AES-256-GCM; user credentials hashed with bcrypt on insert and transparently rehashed on login when work factor changes.
- **Operational Assets**: Documentation in `docs/` aligns technical changes with governance requirements (risk register, security strategy, secrets plan).

### 3. Key Backend Controls
- **Authentication & MFA**: Logins require password plus TOTP. Secrets are generated during signup/admin provisioning, encrypted at rest, and verified using `otplib`. Idle and absolute timeouts protect bearer tokens kept in-memory.
- **Session Lifecycle**: `server.js` enforces 30-minute idle / 12-hour absolute expiry, exposes logout, and invalidates sessions when accounts are disabled, banned, or password reset. Responses include `X-Session-Expires` so the frontend can mirror validity.
- **Input Validation**: `security.js` provides canonical validators for IDs, diagnosis notes, medication payloads, optional admin reasons, and JSON body size enforcement. Every write endpoint calls a validator before touching the database.
- **Audit Logging**: All auth actions stream into SQLite table `auth_events` and append-only log file `backend/logs/auth-events.log`. `logger.js` still produces structured events for broader security monitoring.
- **Security Headers**: Helmet middleware now standardises CSP, frame guard, referrer policy, COOP/CORP, HSTS, no-store cache hints, and tightens CORS to trusted local origins.

### 4. Frontend Safeguards
- `auth.js` is the single source of truth for API requests (`apiFetch`) and ensures Authorization headers, idle timeout refresh, and automatic logout on 401/403.
- `requireRole` gates dashboard entry and drives the user badge, logout controls, and change-password modal. Legacy standalone signup page has been removed to avoid divergent flows.
- Password UI includes strength meter, copy/paste suppression on sensitive fields, and explicit MFA verification step after signup.

### 5. Operational Tooling & Tests
- **Scripts**: `npm run security:test` (npm audit + ESLint SAST + Newman regression). `npm run security:postman` runs the standalone Newman suite. `npm run siem:test` exercises webhook delivery to a SIEM endpoint.
- **Test Suite**: Newman collection in `tests/security/healthcurealpha.postman_collection.json` covers signup, MFA verification, login failure states, yellowlist promotion, ban/unban, and audit log listing.
- **Logging Pipeline**: Structured auth events persist in both database and rolling file. Future SIEM forwarding uses `HCA_LOG_WEBHOOK` with graceful retry.

### 6. Governance & Documentation
- `docs/risk-register.md` tracks enterprise and application risks with status/owners.
- `docs/security-strategy.md` maps security improvements to data-centre and hybrid-cloud objectives.
- `docs/secrets-management.md` documents the Azure Key Vault implementation and rotation playbook.
- `docs/notes/security-headers.md` enumerates the exact headers now emitted by the backend.

### 7. Roadmap Highlights
- Production secrets to be consumed directly from Azure Key Vault using managed identities; local `.env` remains dev-only.
- Expand automated testing (role-based positive/negative cases, dynamic scans) and integrate into CI/CD gate.
- Extend audit events with correlation IDs and forward to enterprise SIEM once webhook endpoint is provisioned.

## Simplified Story (for stakeholders)

- **What changed?** We tightened the hospital’s web portal so only the right people get in, every action is logged, and sensitive records stay encrypted.
- **How do users log in now?** Every account uses strong passwords plus a 6-digit code from an authenticator app. If someone walks away, their session auto-expires.
- **Where are the records?** Medical notes and medications are stored locked-up; even if the database leaked, the contents are unreadable without the encryption key.
- **What happens when something goes wrong?** Security events are written to a live audit log and can be sent to the SIEM alarm system. Admins can freeze or restore accounts instantly.
- **How do we keep it healthy?** One command runs audits, linting, and API smoke tests. A documented risk register lists remaining tasks, and a secrets plan explains how production will rotate keys safely.
- **What’s next?** Move secrets into Azure Key Vault, hook the logs into the SIEM, and broaden automated testing so every release proves the controls still work.
