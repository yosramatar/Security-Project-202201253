# Security Strategy & Recommendations

## Background
HealthCureAlpha is expanding its on-premises data center while onboarding cloud capacity for non-critical workloads. The organisation must preserve the confidentiality, integrity, and availability of protected health information (PHI) and maintain compliance with HIPAA, GDPR, and state privacy regulations. This document captures recommended security architecture controls, the web application hardening actions completed in this iteration, and next steps for validation.

## Data Center Expansion Controls
**Physical & Environmental**
- Dual power feeds, UPS + generator failover, and environmental monitoring (temperature, humidity, water leak) tied to alerting.
- Interlocking access controls (badge + biometric), visitor escort policy, and CCTV retention ≥ 90 days.
- Clean-agent fire suppression with zone isolation aligned to NFPA 75/76; quarterly safety system inspections.

**Network & Segmentation**
- Leaf–spine core with redundant firewalls enforcing zone-based segmentation (clinical, administrative, management, guest) and micro-segmentation for workloads with PHI.
- Inline IDS/IPS with TLS inspection for east-west traffic; network access control (802.1X) with posture checks before assets join trusted VLANs.
- Private management network for hypervisors, out-of-band management via hardened bastion hosts with MFA.

**Platform & Data Protection**
- Standardised host builds managed through infrastructure-as-code (Ansible/Terraform) with CIS benchmarks baseline.
- Full disk encryption for servers handling PHI, hardware security module (HSM) backed key escrow, and strict crypto key rotation process.
- Immutable backup targets (object-lock or WORM storage) and copy isolated in cloud provider with daily verification.

**Operations & Monitoring**
- Change management playbooks for expansion activities including back-out plans and stakeholder sign-off.
- Central logging (syslog + application) forwarded to SIEM with automated correlation rules for privileged actions and network anomalies.
- Quarterly incident response exercises (tabletop + technical) covering ransomware, data breach, and facility outage scenarios.

## Secure Cloud Integration
- Establish a hybrid connectivity design with redundant IPsec or Direct Connect links, segregated by workload sensitivity.
- Adopt landing zones with guardrails: mandatory encryption at rest, customer-managed keys, logging/monitoring enabled by default, and denied-by-default security groups.
- Enforce least-privilege IAM via role-based access, short-lived credentials (federated SSO + MFA), and continuous access reviews.
- Deploy cloud security posture management (CSPM) and data security posture management (DSPM) to detect misconfigurations, public exposures, or unencrypted data.
- Require business associate agreements (BAAs) and GDPR data processing addenda with cloud service providers; maintain data residency mapping.
- Implement automated cost governance (budgets + anomaly detection) to balance security investments with capacity scaling.

## Web Application Security Enhancements
**Implemented in this iteration**
1. **Session Hardening** – Server-side idle timeout (30 minutes) and 12-hour absolute lifetime with automatic cleanup; sessions persist in SQLite so users/admins can enumerate and revoke tokens on demand; logout endpoint and client synchronisation.
2. **Multi-Factor Authentication** – Patient and staff accounts now register TOTP secrets during signup/provisioning; logins require password + 6-digit code with encrypted secret storage.
3. **Password Policy & Storage Upgrade** – Passwords now require 12+ chars with mixed-case, digits, and symbols; requests hitting the local blacklist are rejected. Every change records the bcrypt hash in `password_history` to prevent reuse of the last five credentials, while legacy SHA-256 hashes still rehash transparently on successful login.
4. **Frontend Enforcement** – Shared `requireRole` helper plus a reusable change-password modal wired into every dashboard for consistent credential rotation UX.
5. **API Hygiene** – Centralised `apiFetch` wrapper adds Authorization headers, handles 401/403 responses, and normalises error handling for all dashboards.
6. **Input Protection** – Capped JSON payloads at 512 KB with audit logging for oversized requests to reduce DoS surface and centralised validation helpers for diagnosis/medication payloads.
7. **Response Security** – Helmet middleware applies CSP, frame guard, referrer policy, HSTS, COOP/CORP, and no-store cache directives across every response.
8. **Security Tooling** – Added `npm run security:test` meta-script (npm audit + ESLint SAST + Newman smoke) and expanded Newman coverage for MFA, bans, and yellowlist flows.
9. **Operations Utilities** – Introduced `.env` autoloading and `npm run siem:test` for validating SIEM webhook connectivity without touching application code.
10. **Secrets Management Plan** – Authored `docs/secrets-management.md` detailing Azure Key Vault rollout, rotation cadence, and integration steps for `HCA_ENC_KEY`, `HCA_BCRYPT_ROUNDS`, and future credentials.
11. **Account Lifecycle Controls** – Switched admin "delete" to a soft-disable with immediate session revocation, added reactivation flow, and surfaced status indicators in the admin UI to support policy-driven suspensions.
	12. **Transport Security Toggle** – Added optional HTTPS bootstrap controlled by `HCA_TLS_KEY_PATH`/`HCA_TLS_CERT_PATH` so lab environments can validate TLS locally before handing off to edge proxies.

**Planned Enhancements**
- Externalise encryption keys to a dedicated secret manager with rotation hooks (current `.env` only for developers; rollout plan captured in `docs/secrets-management.md`).
- Integrate the security scripts into CI with artefact capture, and extend Newman coverage to authenticated positive/negative RBAC scenarios.
- Expand structured security logging (trace IDs, request contexts) and forward to central SIEM once webhook endpoint is provisioned; leverage `npm run siem:test` during rollout.

## Security Testing & Validation
- **Manual Code Review**: Performed on authentication, session, and data retrieval paths; high-risk issues addressed above.
- **Automated Tooling Run (2025-12-11)**: `npm audit --omit=dev`, `npm run security:sast`, and the Newman smoke suite against `http://127.0.0.1:3000`. All checks passed; console transcript archived in project notes.
- **Recommended Automated Tests**: SAST (Semgrep or CodeQL), dependency scanning (npm audit + Snyk), container image scanning (if containerised), and automated linting for security rules.
- **Dynamic Testing**: Schedule OWASP ZAP baseline scan against staging once authentication stubs available; expand Newman coverage to authenticated positive/negative RBAC cases.
- **Resilience Validation**: Execute load test with realistic payload sizes post payload-limit change, and confirm graceful handling of 413 responses.
- **Regulatory Mapping**: Update HIPAA Security Rule matrix to reflect new controls (164.308(a)(5), 164.312(b), 164.312(c)), document evidence in compliance repository.

## Implementation Roadmap
- **Q1**: Complete identity hardening (MFA rollout, VPN replacement), expand SIEM ingestion, deploy CSPM, and operationalise bcrypt password storage with managed secrets + rotation evidence.
- **Q2**: Productionise hybrid cloud guardrails, shift encryption keys to secret manager, automate compliance evidence collection.
- **Q3**: Deliver tamper-evident audit trail, finish disaster recovery exercise, integrate periodic penetration testing.
- **Continuous**: Monitor metrics (mean time to detect/respond, session invalidation counts, failed login rates) and feed into quarterly risk committee reviews.

### TLS & KMS Hardening Plan
1. **Issue and Deploy Certificates** – Obtain ACME-issued server certificates (wildcard or SAN) via Azure Key Vault or ACM. Configure the reverse proxy/load balancer to terminate HTTPS on port 443 with automatic renewal hooks.
2. **Enforce HTTPS Everywhere** – Redirect HTTP to HTTPS, update CSP connect-src to the TLS endpoint, and configure Helmet HSTS preload once external TLS is verified. Document firewall rules to allow only encrypted ingress.
3. **Harden Service-to-Service Links** – For internal microservices, enable TLS for database and SIEM webhooks; store trust anchors alongside deployment manifests and validate certificates on connection.
4. **Externalise Secrets with KMS** – Move `HCA_ENC_KEY`, `HCA_BCRYPT_ROUNDS`, and future API secrets into Azure Key Vault with versioned secrets. Use managed identities so the Node backend retrieves secrets at startup without embedding credentials.
5. **Automate Rotation & Audit Trails** – Configure rotation policies (e.g., 90-day) in Key Vault, emit audit events to SIEM, and update the application to gracefully reload keys (signal handler or on schedule). Incorporate rotation evidence into compliance checklists.
