# Security Measures Implementation Record

This document collects the major security hardening actions completed for HealthCureAlpha, explains *why* each control matters, and notes the practical implementation details. The list focuses on the ten high-impact changes delivered during this iteration so stakeholders can trace risk reductions directly to code and tooling updates.

## Top 10 Implemented Controls

1. **Persistent, revocable sessions**
   - **Why**: Stops bearer tokens from providing indefinite access if a browser is left unattended or compromised.
   - **How**: `server.js` enforces a 30-minute idle timeout and a 12-hour absolute cap, persists sessions in SQLite, and exposes APIs so users or admins can revoke individual or bulk sessions. The auth modal surfaces session metadata and single-click revocation.
   - **Where**: `backend/server.js` (`persistSession`, `listUserSessions`, `handleRevokeOwnSessions`, `handleAdminRevokeUserSessions`), `frontend/js/auth.js` (session manager modal), `frontend/js/admin.js` (creation flow hooks the same policy).

2. **Mandatory multi-factor authentication (MFA)**
   - **Why**: Reduces credential theft risk by requiring a one-time code in addition to passwords.
   - **How**: Patients receive a TOTP secret during signup; admins provision staff with the same flow. Secrets are encrypted at rest and verified with `otplib` during login.
   - **Where**: `backend/server.js` (`handleSignup*`, `handleLogin`), `backend/security.js` (`generateTotpSecret`, `verifyTotpToken`).

3. **Strong password policy, storage, and reuse guardrails**
   - **Why**: Prevents offline cracking of leaked hashes and reduces credential stuffing by blocking weak or reused passwords.
   - **How**: Passwords must be 12–128 chars with mixed case, digits, and symbols, and must not appear in the local breach blacklist. Every change writes to `password_history`, disallowing the last five hashes. Bcrypt hashing remains enforced, with legacy SHA-256 transparently rehashed on login.
   - **Where**: `backend/security.js` (`validatePassword`, `isPasswordBreached`, `hashPassword`, `verifyPassword`, `needsPasswordRehash`), `backend/server.js` (`recordPasswordHistory`, `passwordUsedRecently`, change-password endpoints), `frontend/js/auth.js` and `frontend/js/admin.js` (client-side guidance).

4. **Encrypted patient health information (PHI)**
   - **Why**: Protects diagnoses and medications if the database or backups leak.
   - **How**: AES-256-GCM helpers wrap PHI fields; secrets derive from `HCA_ENC_KEY`. Fields decrypt only for authorised session views.
   - **Where**: `backend/security.js` (`encryptText`, `decryptText`), `backend/server.js` diagnosis/medication handlers.

5. **Centralised input validation**
   - **Why**: Eliminates inconsistent checks that can lead to injection, mass assignment, or unintended writes.
   - **How**: Shared validators normalise IDs, notes, medication arrays, optional admin reasons, and JSON body size thresholds before they reach SQL statements.
   - **Where**: `backend/security.js` (`validateDiagnosisPayload`, `validateMedicationPayload`, etc.), `backend/server.js` request handlers.

6. **Rate limiting and adaptive login lockout**
   - **Why**: Thwarts brute-force attacks and slows automated credential stuffing.
   - **How**: Per-IP rate buckets gate all requests; per-account lockouts trigger after 5 failed logins in 15 minutes, escalating to yellowlist status.
   - **Where**: `backend/security.js` (`checkRateLimit`, `registerLoginFailure`, `checkLoginAllowed`), `backend/server.js` login flow.

7. **Security header hardening**
   - **Why**: Mitigates clickjacking, script injection, and caching of sensitive responses.
   - **How**: Helmet applies a strict CSP, `frame-ancestors 'none'`, referrer policy `no-referrer`, HSTS (for production TLS), COOP/CORP, and disables caching for API responses.
   - **Where**: `backend/server.js` (`helmetMiddleware`), documented in `docs/notes/security-headers.md`.

8. **Comprehensive audit logging**
   - **Why**: Provides forensic evidence and trigger points for monitoring tooling.
   - **How**: Every auth event writes to the `auth_events` table and to `backend/logs/auth-events.log`. Logs carry timestamps, IP, user agent, user ID, and details for SIEM ingestion.
   - **Where**: `backend/server.js` (`recordAuthEvent`, `logSecurityEvent` usage), `backend/logger.js`.

9. **Automated security regression suite**
   - **Why**: Verifies the hardening stays intact as the code evolves and catches regressions quickly.
   - **How**: `npm run security:test` chains `npm audit`, ESLint SAST, and a Newman collection that covers signup, MFA, bans, yellowlisting, and recovery flows.
   - **Where**: `backend/package.json` scripts, `tests/security/healthcurealpha.postman_collection.json`.

10. **Documented secrets management and rotation**
    - **Why**: Ensures encryption keys and credentials leave developer machines and gain auditable rotation.
    - **How**: `docs/secrets-management.md` prescribes Azure Key Vault, managed identities, rotation cadence, and validation steps. `.env` use is limited to local development.
    - **Where**: `docs/secrets-management.md`, `.env` handling in `backend/server.js`.

## Supporting Safeguards

- **Account lifecycle controls**: Admin ban/disable/unban flows black/whitelist emails and invalidate sessions to enforce policy decisions immediately.
- **Payload size guard**: JSON bodies capped at 512 KB to prevent memory exhaustion attacks.
- **Frontend session enforcement**: `frontend/js/auth.js` mirrors expiry headers, blocks dashboards without a valid session, and drives change-password UX.

## Deferred or Environment-Specific Items

Some controls are intentionally scoped out or adjusted because this repository targets a localhost lab environment. These gaps are documented so production teams can plan follow-up work.

| Control | Status | Reason in Lab | Production Recommendation |
| --- | --- | --- | --- |
| TLS termination / HSTS validation | Partially implemented | Helmet sets HSTS headers and the dev server can serve HTTPS when `HCA_TLS_KEY_PATH`/`HCA_TLS_CERT_PATH` are provided, but the default lab still runs on HTTP. | Terminate HTTPS at the edge (gateway/load balancer) and keep HSTS enabled; enforce TLS-only traffic in infrastructure config.
| SameSite/HttpOnly cookies | Not applicable | Sessions rely on bearer tokens stored in memory/localStorage; no cookies are issued. | If shifting to cookies, add HttpOnly + SameSite=strict and CSRF tokens. Current bearer model already sends explicit Authorization headers.
| Continuous SIEM forwarding | Pending | No webhook endpoint exists in the lab. | Provide `HCA_LOG_WEBHOOK` via secret manager and enable the existing webhook publisher; monitor delivery metrics.
| CI/CD enforcement | Pending | Automation not part of the local repo scope. | Add `npm run security:test` as a required CI job with artefact retention and quality gates.
| Advanced bot protection (geo/IP analytics, CAPTCHA) | Deferred | Overkill for localhost testing. | Instrument risk-based controls once the app is exposed publicly.

This record should be revisited whenever new controls land or when the project transitions from a lab environment to production infrastructure so assumptions remain explicit and verifiable.
