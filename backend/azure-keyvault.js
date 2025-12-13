// backend/azure-keyvault.js
// Azure Key Vault integration for HealthCureAlpha
// Loads secrets at startup for use in config (HCA_ENC_KEY, HCA_BCRYPT_ROUNDS, etc.)

const { DefaultAzureCredential } = require("@azure/identity");
const { SecretClient } = require("@azure/keyvault-secrets");

/**
 * Loads secrets from Azure Key Vault.
 * @param {string} vaultUrl - The full URL to the Key Vault (e.g. https://myvault.vault.azure.net/)
 * @param {string[]} secretNames - Array of secret names to fetch
 * @returns {Promise<Object>} - Resolves to { SECRET_NAME: value, ... }
 */
async function loadKeyVaultSecrets(vaultUrl, secretNames) {
  if (!vaultUrl) throw new Error("Missing Key Vault URL");
  const credential = new DefaultAzureCredential();
  const client = new SecretClient(vaultUrl, credential);
  const result = {};
  for (const name of secretNames) {
    try {
      const latest = await client.getSecret(name);
      result[name] = latest.value;
    } catch (err) {
      throw new Error(`Failed to load secret '${name}': ${err.message}`);
    }
  }
  return result;
}

module.exports = { loadKeyVaultSecrets };
