# Azure Key Vault Automation for HealthCureAlpha

## Overview

This project supports automated provisioning and rotation of secrets in Azure Key Vault for all backend cryptographic and password policy material.

## Prerequisites
- Azure subscription with Key Vault created (e.g. https://myvault.vault.azure.net/)
- Azure CLI or portal access to assign permissions
- The machine/service principal running scripts must have `set` and `get` secret permissions
- Node.js environment with `@azure/identity` and `@azure/keyvault-secrets` installed

## Provisioning Secrets

1. Set the environment variable:
   ```sh
   export HCA_KEYVAULT_URL="https://myvault.vault.azure.net/"
   ```
2. Run the provisioning script:
   ```sh
   npm run keyvault:provision
   ```
   This will create (or update) the following secrets:
   - `HCA_ENC_KEY` (random 48-byte base64)
   - `HCA_BCRYPT_ROUNDS` (default: 12)

## Rotating Secrets

To rotate the main encryption key:
```sh
npm run keyvault:rotate
```
This will generate a new random value for `HCA_ENC_KEY`.

> **Note:** After rotation, you must restart all backend services to pick up the new secret. If you rotate `HCA_ENC_KEY`, any data encrypted with the old key will become unreadable unless you implement a key versioning/migration strategy.

## Adding More Secrets
- Edit `backend/scripts/provision-keyvault-secrets.js` to add new secret names/values as needed.
- Update the backend code to load and use the new secrets at startup.

## Security Best Practices
- Never check secrets into source control.
- Use managed identities or service principals with least privilege.
- Document all rotations and keep an audit trail.
- Consider implementing key versioning for seamless crypto key rotation in production.
