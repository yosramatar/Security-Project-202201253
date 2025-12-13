# HealthCureAlpha Risk Register

## Methodology
- **Impact** and **Likelihood** scored qualitatively (Low, Medium, High) based on confidentiality, integrity, availability, and regulatory exposure.
- **Inherent Risk** reflects exposure prior to additional controls. **Residual values** assume the mitigation plan is implemented.
- Ratings focus on HIPAA/GDPR alignment, patient safety, and service continuity for the data center expansion and supporting web services.

## Enterprise (Hospital) Risks
| ID | Asset / Process | Threat | Key Vulnerability | Impact | Likelihood | Inherent Risk | Mitigation Plan | Residual Impact | Residual Likelihood | Owner / Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ORG-01 | Core clinical systems & EHR platform | Unplanned outage during data center expansion | Single power path, limited capacity planning, no blue/green deployment | High | Medium | High | Implement dual power feeds, phased rollout with staging environment, pre/post change validation, automated rollback playbooks | Medium | Low | Infrastructure Ops – In progress |
| ORG-02 | Patient health information (PHI) | External compromise / credential theft | Legacy VPN with weak MFA enforcement for admins | High | Medium | High | Enforce phishing-resistant MFA, replace legacy VPN with zero trust network access, harden identity lifecycle (joiner-mover-leaver), continuous monitoring | Medium | Low | Security Operations – Planned Q1 |
| ORG-03 | Enterprise backup & archive | Ransomware encrypts primary & backup data | Backups stored online without immutability; irregular restore testing | High | Medium | High | Implement immutable/cloud-isolated backups, daily integrity checks, quarterly recovery testing, EDR with ransomware heuristics | Medium | Low | IT Continuity – In progress |
| ORG-04 | Hybrid cloud workloads | Misconfiguration exposes data in cloud migration | Lack of unified configuration baselines and IaC guardrails | High | Medium | High | Adopt infrastructure-as-code with policy-as-code scanning, least privilege IAM, continuous CSPM (Cloud Security Posture Management) | Medium | Low | Cloud Center of Excellence – Planned Q2 |
| ORG-05 | Physical data center | Natural disaster / fire | Single geographic site, incomplete BCP runbooks | High | Low | Medium | Establish secondary warm site, contract for rapid hardware replacement, update/run annual tabletop & full failover tests | Medium | Low | Business Continuity – In progress |
| ORG-06 | Workforce endpoints | Insider or careless user data leakage | Insufficient DLP monitoring, unmanaged personal devices | Medium | Medium | Medium | Deploy endpoint DLP with device posture checks, restrict PHI export, provide quarterly privacy awareness training | Medium | Low | HR & IS – Operational |
| ORG-07 | Network segmentation | Lateral movement after breach | Flat network for clinical/guest systems | High | Medium | High | Implement micro-segmentation, NAC with device profiling, network anomaly detection, strict east-west firewall policies | Medium | Low | Network Engineering – Not started |
| ORG-08 | Regulatory compliance program | Audit findings / fines | Manual evidence collection, fragmented control ownership | High | Medium | High | Centralize GRC tooling, assign control owners, continuous compliance monitoring, quarterly HIPAA/GDPR readiness reviews | Medium | Low | Compliance Office – Planned Q1 |
| ORG-09 | Third-party vendors | BAA / GDPR processor breach | Incomplete vendor due diligence, no continuous monitoring | High | Medium | High | Strengthen vendor risk assessments, require SOC 2 / HITRUST reports, continuous attack surface monitoring, contractual right to audit | Medium | Medium | Procurement & Legal – In progress |

## Web Application Risks
| ID | Component | Threat | Key Vulnerability | Impact | Likelihood | Inherent Risk | Mitigation Plan | Residual Impact | Residual Likelihood | Owner / Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| APP-01 | Session management | Token theft / session hijack | Long-lived bearer tokens stored client-side without idle timeout | High | Medium | High | Enforce 30-minute idle & 12-hour absolute timeout (implemented), add logout endpoint, client-side expiry tracking, forced re-auth on expiry | Medium | Low | Engineering – Complete |
| APP-02 | API tier | DoS via oversized payloads | No request body size limits | Medium | Medium | Medium | Cap JSON payload to 512 KB with graceful 413 responses and logging | Medium | Low | Engineering – Complete |
| APP-03 | Patient diagnosis retrieval | SQL injection / data leakage | Dynamic IN clause string concatenation | High | Medium | High | Use parameterized queries for appointment IDs (implemented) and extend secure coding guidelines | Medium | Low | Engineering – Complete |
| APP-04 | Authentication | Brute force login | Weak account lock-out logic, no geo/IP analytics | Medium | Medium | Medium | Maintain adaptive rate limiting (existing), enforce MFA (implemented), add login throttling audit, investigate risk-based reCAPTCHA for repeated failures | Medium | Low | Security Engineering – Planned Q1 |
| APP-05 | Audit logging | Incomplete security telemetry | Limited structured logging for API failures | Medium | Medium | Medium | Expand `security.log` events, forward to SIEM, establish alert thresholds for admin actions | Medium | Low | DevSecOps – Planned Q1 |
| APP-06 | Frontend security posture | Unauthorized dashboard access | Missing consistent role guard on SPA routes | High | Medium | High | Implement shared `requireRole` helper, auto redirect on 401, bind logout controls (implemented) | Medium | Low | Frontend Team – Complete |
| APP-07 | Secrets management | Encryption key compromise | Static crypto key embedded in code with dev default | High | Low | Medium | Implement Azure Key Vault per `docs/secrets-management.md`, enforce managed identity access, rotate every 90 days; `.env` limited to local dev | Medium | Low | Platform Engineering – In progress |
| APP-08 | Data integrity | Tampering/rollback of diagnosis | Lack of tamper-evident logging, no checksum | Medium | Low | Medium | Store append-only audit trail with hash chaining, enable DB WAL archiving and daily validation | Low | Low | Data Engineering – Planned Q3 |
| APP-09 | API access control | Escalation of privilege | Role checks scattered in codebase | High | Medium | High | Centralize RBAC middleware, unit tests for each endpoint, security test cases in CI | Medium | Low | Backend Team – In progress |

## Mitigation Summary
- High and medium risks have explicit action owners and target quarters; progress tracked in the Security PMO board.
- Completed items (session timeouts, bcrypt upgrade, payload caps, parameterized queries, frontend role guard, security regression scripts) reduce immediate exposure for the web portal.
- Planned controls emphasize alignment with HIPAA Security Rule safeguards (administrative, physical, technical) and GDPR accountability requirements.
- Security regression suite (`npm run security:test`) executed 2025-12-02; next step is CI integration so findings surface automatically.
- SIEM rollout prep: `npm run siem:test` provides a low-risk connectivity probe before enabling production forwarding.
- Soft-disable workflow prevents accidental data purges while supporting policy-driven suspensions and immediate session revocation.
- Residual risks remaining at Medium require executive visibility and inclusion in the quarterly risk committee agenda.
