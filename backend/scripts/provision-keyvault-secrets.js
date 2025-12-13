// backend/scripts/provision-keyvault-secrets.js
// Script to provision and rotate secrets in Azure Key Vault for HealthCureAlpha

const { DefaultAzureCredential } = require("@azure/identity");
const { SecretClient } = require("@azure/keyvault-secrets");
const crypto = require("crypto");

const vaultUrl = process.env.HCA_KEYVAULT_URL;
if (!vaultUrl) {
  console.error("Set HCA_KEYVAULT_URL to your Azure Key Vault URL (e.g. https://myvault.vault.azure.net/)");
  process.exit(1);
}

const secrets = [
  {
    name: "HCA_ENC_KEY",
    value: crypto.randomBytes(48).toString("base64"),
    description: "Main encryption key for PHI and session data (base64, 48 bytes)",
  },
  {
    name: "HCA_BCRYPT_ROUNDS",
    value: "12",
    description: "Bcrypt cost factor for password hashing (10-14 recommended)",
  },
];

async function provisionSecrets() {
  const credential = new DefaultAzureCredential();
  const client = new SecretClient(vaultUrl, credential);
  for (const secret of secrets) {
    try {
      await client.setSecret(secret.name, secret.value);
      console.log(`Set secret: ${secret.name}`);
    } catch (err) {
      console.error(`Failed to set secret ${secret.name}:`, err.message);
    }
  }
  console.log("Provisioning complete.");
}

async function rotateSecret(name) {
  const credential = new DefaultAzureCredential();
  const client = new SecretClient(vaultUrl, credential);
  let newValue;
  if (name === "HCA_ENC_KEY") {
    newValue = crypto.randomBytes(48).toString("base64");
  } else if (name === "HCA_BCRYPT_ROUNDS") {
    newValue = "12";
  } else {
    console.error("Unknown secret name for rotation.");
    process.exit(1);
  }
  await client.setSecret(name, newValue);
  console.log(`Rotated secret: ${name}`);
}

if (require.main === module) {
  const [,, cmd, arg] = process.argv;
  if (cmd === "rotate" && arg) {
    rotateSecret(arg).catch(err => {
      console.error("Rotation failed:", err);
      process.exit(1);
    });
  } else {
    provisionSecrets().catch(err => {
      console.error("Provisioning failed:", err);
      process.exit(1);
    });
  }
}
