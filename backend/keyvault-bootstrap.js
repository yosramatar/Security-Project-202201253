// backend/keyvault-bootstrap.js
// Loads secrets from Azure Key Vault and sets them for the backend

const { loadKeyVaultSecrets } = require("./azure-keyvault");
const { setSecretsFromKms } = require("./security");

/**
 * Loads secrets from Azure Key Vault and applies them to the backend config.
 * @returns {Promise<void>}
 */
async function bootstrapKeyVault() {
  const vaultUrl = process.env.HCA_KEYVAULT_URL;
  if (!vaultUrl) return; // No Key Vault configured
  const secretNames = ["HCA_ENC_KEY", "HCA_BCRYPT_ROUNDS"];
  // SSRF protection: Only allow Azure Key Vault URLs
  const { isSafeOutboundUrl } = require('./security');
  const allowedVaultDomains = ['vault.azure.net'];
  if (!isSafeOutboundUrl(vaultUrl, allowedVaultDomains)) {
    throw new Error('Key Vault URL is not allowed or is unsafe');
  }
  const secrets = await loadKeyVaultSecrets(vaultUrl, secretNames);
  setSecretsFromKms(secrets);
  console.log("Loaded secrets from Azure Key Vault:", Object.keys(secrets));
}

module.exports = { bootstrapKeyVault };
