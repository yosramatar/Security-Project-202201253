// backend/seed.js
require("dotenv").config();

const db = require("./db");
const {
  hashPassword,
  verifyPassword,
  needsPasswordRehash,
  encryptText,
  decryptText,
  generateTotpSecret,
  generateTotpUri,
} = require("./security");

const seedTotpSecrets = {
  "admin@healthcurealpha.com": process.env.HCA_ADMIN_TOTP_SECRET || "JBSWY3DPEHPK3PXP",
  "doc1@healthcurealpha.com": "KRSWYYTPNJ2W4ZLS",
  "doc2@healthcurealpha.com": "MFRGGZDFMZTWQ2LK",
  "nurse1@healthcurealpha.com": "NB2W45DFOJQXGZJT",
  "nurse2@healthcurealpha.com": "OJXW4ZDJNZTWOYLN",
  "patient1@healthcurealpha.com": "PJSXG5DSMRQWK3TL",
  "patient2@healthcurealpha.com": "QKZWC5DJNZTWOYLT",
};

function ensureSeedSecret(email) {
  const key = email.toLowerCase();
  if (!seedTotpSecrets[key]) {
    seedTotpSecrets[key] = generateTotpSecret();
  }
  return seedTotpSecrets[key];
}

db.exec("UPDATE users SET email = LOWER(email)");

const users = [
  {
    email: "admin@healthcurealpha.com",
    password: process.env.HCA_ADMIN_PASSWORD || "Admin#2025!",
    name: "System Admin",
    role: "admin",
  },
  {
    email: "doc1@healthcurealpha.com",
    password: "Doctor#2025!",
    name: "Dr. Ahmed",
    role: "doctor",
  },
  {
    email: "doc2@healthcurealpha.com",
    password: "Doctor#2025!",
    name: "Dr. Sara",
    role: "doctor",
  },
  {
    email: "nurse1@healthcurealpha.com",
    password: "Nurse#2025!",
    name: "Nurse Mona",
    role: "nurse",
  },
  {
    email: "nurse2@healthcurealpha.com",
    password: "Nurse#2025!",
    name: "Nurse Ali",
    role: "nurse",
  },
  {
    email: "patient1@healthcurealpha.com",
    password: "Patient#2025!",
    name: "Patient Karim",
    role: "patient",
  },
  {
    email: "patient2@healthcurealpha.com",
    password: "Patient#2025!",
    name: "Patient Layla",
    role: "patient",
  },
];

for (const u of users) {
  const lowerEmail = u.email.toLowerCase();
  const existing = db
    .prepare(
      "SELECT id, password_hash, status, mfa_secret, mfa_enabled, watch_status, failed_login_count FROM users WHERE LOWER(email) = ?"
    )
    .get(lowerEmail);

  const hashedPassword = hashPassword(u.password);
  const totpSecret = ensureSeedSecret(lowerEmail);
  const encryptedSecret = encryptText(totpSecret);

  if (existing) {
    const matches = verifyPassword(u.password, existing.password_hash);
    if (!matches || needsPasswordRehash(existing.password_hash)) {
      db.prepare(
        "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
      ).run(hashedPassword, existing.id);
      console.log("Updated password:", lowerEmail);
    }

    if (existing.status !== "active") {
      db.prepare(
        "UPDATE users SET status = 'active', updated_at = CURRENT_TIMESTAMP WHERE id = ?"
      ).run(existing.id);
      console.log("Reactivated:", lowerEmail);
    } else if (matches && !needsPasswordRehash(existing.password_hash)) {
      console.log("Skip (already exists):", lowerEmail);
    }

    const currentSecret = existing.mfa_secret ? decryptText(existing.mfa_secret) : null;
    if (!currentSecret || currentSecret !== totpSecret || !existing.mfa_enabled) {
      db.prepare(
        `UPDATE users
         SET mfa_secret = ?, mfa_enabled = 1, signup_token = NULL, watch_status = 'normal', failed_login_count = 0
         WHERE id = ?`
      ).run(encryptedSecret, existing.id);
      console.log("Updated MFA secret:", lowerEmail);
    }

    continue;
  }

  db.prepare(
    `INSERT INTO users (email, password_hash, name, role, status, mfa_secret, mfa_enabled, watch_status, failed_login_count)
     VALUES (?, ?, ?, ?, 'active', ?, 1, 'normal', 0)`
  ).run(lowerEmail, hashedPassword, u.name, u.role, encryptedSecret);

  console.log("Inserted:", lowerEmail);
}

console.log("✅ Seeding done.");
console.log("--- TOTP secrets (store securely) ---");
for (const [email, secret] of Object.entries(seedTotpSecrets)) {
  console.log(`${email}: ${secret} | ${generateTotpUri(email, secret)}`);
}
