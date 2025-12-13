# Secrets Management & Rotation Plan

## Objectives
- Eliminate long-lived secrets stored in source code or developer machines.
- Centralise management of application secrets (`HCA_ENC_KEY`, `HCA_BCRYPT_ROUNDS`, future DB/API credentials) in a hardened vault.
- Enable auditable rotation with minimal downtime for the HealthCureAlpha platform.

## Target Platform
HealthCureAlpha production workloads will use **Azure Key Vault** (AKV). The same approach can be adapted for AWS Secrets Manager or Hashicorp Vault if cloud strategy changes.

## Secret Inventory
| Secret | Purpose | Scope | Rotation Interval |
| --- | --- | --- | --- |
| `HCA_ENC_KEY` | AES-256-GCM key derivation for PHI at rest | Backend API | 90 days or upon incident |
| `HCA_BCRYPT_ROUNDS` | Bcrypt cost factor (tunable) | Backend API | Annual review |
| `HCA_ADMIN_PASSWORD` | Seed admin credential (bootstrap only) | Seeding script | Delete after initial provisioning |
| Future DB credentials | Primary DB access | Backend API | 60 days |
| SIEM webhook token (`HCA_LOG_WEBHOOK`) | Forward security events | Backend API | 90 days |

## Provisioning Workflow
1. **Create Key Vault**
   - `az keyvault create -g hca-sec -n hca-kv-prod --enable-soft-delete --enable-purge-protection`.
2. **Define Access Policies**
   - Grant `Get` permissions to the Kubernetes/VM managed identity hosting the backend.
   - Grant `Get/Set/Delete` to SecOps rotation group.
3. **Seed Secrets**
   ```bash
   az keyvault secret set --vault-name hca-kv-prod --name HCA-ENC-KEY --value "$(openssl rand -base64 48)"
   az keyvault secret set --vault-name hca-kv-prod --name HCA-BCRYPT-ROUNDS --value "12"
   ```
4. **Application Integration**
   - Use managed identity + `@azure/identity` in production start script: resolve secrets at boot, inject into `process.env` before starting the Node server.
   - Continue using `.env` for local development only.
5. **Rotation**
   - SecOps triggers rotation runbook (see below). New secrets are written with `--version`, old versions disabled after rollout validation.

## Rotation Runbook
1. Announce maintenance window (if required) and ensure canaries are monitoring.
2. Generate new secret material (`openssl rand -base64 48` for `HCA_ENC_KEY`).
3. `az keyvault secret set --vault-name hca-kv-prod --name HCA-ENC-KEY --value <NEW>`.
4. Deploy backend with configuration reload (Kubernetes rollout restart / systemd restart) so pods pick up new version.
5. Validate:
   - `npm run security:test` passes.
   - Change password + encrypted fields decrypt correctly.
6. Disable prior secret version: `az keyvault secret set-attributes --enabled false --id <SECRET_ID>`.
7. Update rotation tracker (Confluence/ServiceNow) with timestamp, operator, validation artefacts.

## Local Development Policy
- `.env` remains for developers; however, values must never be committed. Git ignore rules enforce this.
- Developers should regenerate `HCA_ENC_KEY` locally with `openssl rand -base64 48` when starting fresh work and rotate it whenever the dev database is reseeded.

## Audit & Compliance
- Key Vault diagnostic logs forwarded to SIEM.
- Quarterly review of access policies by Security team.
- Incident response checklist updated to include secret revocation steps.
