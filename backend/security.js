const crypto = require('crypto');
// Key management: support multiple keys and rotation
const ENCRYPTION_KEYS = {
  v1: process.env.HCA_ENCRYPTION_KEY_V1 || 'default_demo_key_32byteslong!',
  v2: process.env.HCA_ENCRYPTION_KEY_V2 || '', // Add new keys here for rotation
};
const DEFAULT_ENCRYPTION_VERSION = process.env.HCA_ENCRYPTION_VERSION || 'v1';

// Encrypt with current key version
function encryptText(plainText, version = DEFAULT_ENCRYPTION_VERSION) {
  const key = ENCRYPTION_KEYS[version] || ENCRYPTION_KEYS[DEFAULT_ENCRYPTION_VERSION];
  if (!key) throw new Error(`No encryption key for version ${version}`);
  // Ensure a 32-byte key for AES-256 by deriving via SHA-256 if necessary
  const keyBuf = crypto.createHash('sha256').update(String(key)).digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', keyBuf, iv);
  let encrypted = cipher.update(plainText, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  // Store as version:iv:encrypted
  return `${version}:${iv.toString('base64')}:${encrypted}`;
}

// Decrypt using key version
function decryptText(encText) {
  if (!encText || typeof encText !== 'string') return '';
  // Legacy: plain or base64 (no colon)
  if (!encText.includes(':')) {
    // Try base64 decode, fallback to plain
    try {
      // If it's valid base64, decode, else return as is
      const buf = Buffer.from(encText, 'base64');
      // If decoding gives a printable string, return it
      if (buf.toString('utf8').match(/^[A-Za-z0-9]+$/)) {
        return buf.toString('utf8');
      }
    } catch (e) {}
    return encText;
  }
  // New: version:iv:encrypted
  const [version, ivB64, encrypted] = encText.split(':');
  if (!version || !ivB64 || !encrypted) return '';
  const key = ENCRYPTION_KEYS[version] || ENCRYPTION_KEYS[DEFAULT_ENCRYPTION_VERSION];
  if (!key) throw new Error(`No encryption key found for version: ${version}`);
  let iv;
  try {
    iv = Buffer.from(ivB64, 'base64');
  } catch (e) {
    return '';
  }
  try {
    // Derive 32-byte key via SHA-256 to ensure valid key length
    const keyBuf = crypto.createHash('sha256').update(String(key)).digest();
    const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuf, iv);
    let decrypted = decipher.update(encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    return '';
  }
}

module.exports = {
  // ...existing exports...
  encryptText,
  decryptText,
  ENCRYPTION_KEYS,
  DEFAULT_ENCRYPTION_VERSION,
};
// SSRF protection utility
const net = require('net');
const { URL } = require('url');

function isSafeOutboundUrl(url, allowlist = []) {
  try {
    const parsed = new URL(url);
    // Only allow http/https
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    // Allowlist check
    if (allowlist.length && !allowlist.some(domain => parsed.hostname.endsWith(domain))) return false;
    // Block internal IPs
    const ip = net.isIP(parsed.hostname) ? parsed.hostname : null;
    if (ip) {
      // Block private ranges
      if (
        ip.startsWith('10.') ||
        ip.startsWith('192.168.') ||
        ip.startsWith('172.') ||
        ip === '127.0.0.1' ||
        ip === '::1'
      ) return false;
    }
    // Block localhost
    if (['localhost', '127.0.0.1', '::1'].includes(parsed.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

module.exports.isSafeOutboundUrl = isSafeOutboundUrl;
// backend/security.js
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const { authenticator } = require("otplib");

// ====== CONFIG ======
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 120; // per IP per minute


// Key/secret config (supports Azure Key Vault)
let ENC_KEY_SOURCE = process.env.HCA_ENC_KEY;
let BCRYPT_ROUNDS_ENV = process.env.HCA_BCRYPT_ROUNDS;
// UNUSED: const DEFAULT_ENC_KEY = "healthcurealpha-dev-secret-key";
// const ENC_ALGO = "aes-256-gcm";

// Allow dynamic override for KMS integration
function setSecretsFromKms({ HCA_ENC_KEY, HCA_BCRYPT_ROUNDS }) {
  if (HCA_ENC_KEY) ENC_KEY_SOURCE = HCA_ENC_KEY;
  if (HCA_BCRYPT_ROUNDS) BCRYPT_ROUNDS_ENV = HCA_BCRYPT_ROUNDS;
}

// const ENC_KEY = crypto.createHash("sha256").update(ENC_KEY_SOURCE || DEFAULT_ENC_KEY).digest(); // 32 bytes

const PASSWORD_BLACKLIST = (() => {
  try {
    const listPath = path.join(__dirname, "password-blacklist.txt");
    const raw = fs.readFileSync(listPath, "utf8");
    return new Set(
      raw
        .split(/\r?\n/)
        .map(entry => entry.trim().toLowerCase())
        .filter(Boolean)
    );
  } catch (err) {
    console.warn("⚠️ Failed to load password blacklist", err);
    return new Set();
  }
})();


const BCRYPT_ROUNDS = (() => {
  const configured = Number(BCRYPT_ROUNDS_ENV || 12);
  if (!Number.isFinite(configured)) return 12;
  return Math.min(Math.max(Math.round(configured), 10), 14);
})();

authenticator.options = {
  window: 1,
};

if (!ENC_KEY_SOURCE) {
  console.warn("⚠️ HCA_ENC_KEY is not set. Using developer fallback encryption key. Configure a secure value in production.");
}
if (BCRYPT_ROUNDS_ENV && (BCRYPT_ROUNDS < 10 || BCRYPT_ROUNDS > 14)) {
  console.warn("⚠️ HCA_BCRYPT_ROUNDS adjusted to", BCRYPT_ROUNDS, "(supported range 10-14).");
}

// ====== STATE (in-memory) ======
const loginAttempts = new Map(); // key: email|ip -> { attempts, firstAttempt, lockedUntil }
const rateBuckets = new Map(); // key: ip -> { count, windowStart }

// ====== IP + RATE LIMITING ======
function getClientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (fwd && typeof fwd === "string") {
    return fwd.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "unknown";
}

function checkRateLimit(ip, max = RATE_LIMIT_MAX_REQUESTS, windowMs = RATE_LIMIT_WINDOW_MS) {
  const now = Date.now();
  let bucket = rateBuckets.get(ip);

  if (!bucket || now - bucket.windowStart > windowMs) {
    bucket = { windowStart: now, count: 0 };
  }

  bucket.count += 1;
  rateBuckets.set(ip, bucket);

  return bucket.count <= max;
}

// ====== LOGIN ATTEMPT CONTROL ======
function checkLoginAllowed(key) {
  const now = Date.now();
  const entry = loginAttempts.get(key);

  if (!entry) {
    return { allowed: true };
  }

  if (entry.lockedUntil && now < entry.lockedUntil) {
    const secs = Math.ceil((entry.lockedUntil - now) / 1000);
    return {
      allowed: false,
      message: `Too many failed attempts. Try again in ${secs} seconds.`,
    };
  }

  // Window expired -> reset
  if (now - entry.firstAttempt > LOGIN_WINDOW_MS) {
    loginAttempts.delete(key);
    return { allowed: true };
  }

  return { allowed: true };
}

function registerLoginFailure(key) {
  const now = Date.now();
  let entry = loginAttempts.get(key);

  if (!entry || now - entry.firstAttempt > LOGIN_WINDOW_MS) {
    entry = { attempts: 0, firstAttempt: now, lockedUntil: null };
  }

  entry.attempts += 1;

  if (entry.attempts >= MAX_LOGIN_ATTEMPTS) {
    entry.lockedUntil = now + LOCKOUT_MS;
  }

  loginAttempts.set(key, entry);
}

function registerLoginSuccess(key) {
  loginAttempts.delete(key);
}

// ====== INPUT VALIDATION ======
function validateEmail(email) {
  if (typeof email !== "string") return false;
  if (email.length < 5 || email.length > 254) return false;
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email.trim());
}

function isPasswordBreached(password) {
  if (typeof password !== "string") return false;
  return PASSWORD_BLACKLIST.has(password.trim().toLowerCase());
}

function validatePassword(password) {
  if (typeof password !== "string") return false;
  const value = password.trim();
  if (value.length < 12 || value.length > 128) return false;
  const upper = /[A-Z]/.test(value);
  const lower = /[a-z]/.test(value);
  const digit = /\d/.test(value);
  const special = /[^A-Za-z0-9]/.test(value);
  if (!(upper && lower && digit && special)) return false;
  if (isPasswordBreached(value)) return false;
  return true;
}

function validateName(name) {
  if (typeof name !== "string") return false;
  const trimmed = name.trim();
  if (!trimmed || trimmed.length < 2 || trimmed.length > 100) return false;
  // Allow letters, spaces, dots, hyphens, apostrophes
  const re = /^[A-Za-z\s.\-']+$/;
  return re.test(trimmed);
}

function validateDateTime(dt) {
  if (typeof dt !== "string") return false;
  const t = Date.parse(dt);
  if (Number.isNaN(t)) return false;
  // Basic: not in the far past (before 2000) and not > 5 years in future
  const time = new Date(dt).getTime();
  const now = Date.now();
  const fiveYears = 5 * 365 * 24 * 60 * 60 * 1000;
  return time > new Date("2000-01-01").getTime() && time < now + fiveYears;
}

// New: validate numeric IDs (doctorId, nurseId, appointmentId, etc.)
function validateId(id) {
  const n = Number(id);
  if (!Number.isInteger(n)) return false;
  return n > 0 && n < 1_000_000_000;
}

// New: validate diagnosis notes (PHI text)
function validateNotes(notes) {
  if (typeof notes !== "string") return false;
  const trimmed = notes.trim();
  if (!trimmed) return false;
  // simple limit: 1–2000 chars
  return trimmed.length >= 1 && trimmed.length <= 2000;
}

// New: validate medications array
function validateMedications(meds) {
  if (!Array.isArray(meds)) return false;
  if (meds.length > 50) return false; // arbitrary cap
  return meds.every(m => {
    if (typeof m !== "string") return false;
    const t = m.trim();
    return t.length > 0 && t.length <= 200;
  });
}

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function normalizeNotesInput(notes) {
  if (typeof notes !== "string") return null;
  const sanitized = sanitizeString(notes);
  return validateNotes(sanitized) ? sanitized : null;
}

function normalizeMedicationsInput(meds) {
  if (!Array.isArray(meds)) return null;
  const sanitized = meds.map(item => {
    if (typeof item !== "string") return null;
    return sanitizeString(item);
  });
  if (sanitized.some(item => item == null || item.length === 0)) {
    return null;
  }
  return validateMedications(sanitized) ? sanitized : null;
}

function validateDiagnosisPayload(body) {
  if (!isPlainObject(body)) {
    return { ok: false, error: "Invalid JSON payload" };
  }

  const appointmentId = body.appointmentId;
  const notes = normalizeNotesInput(body.notes);

  if (!validateId(appointmentId) || !notes) {
    return { ok: false, error: "Invalid input fields" };
  }

  return {
    ok: true,
    appointmentId: Number(appointmentId),
    notes,
  };
}

function validateMedicationPayload(body) {
  if (!isPlainObject(body)) {
    return { ok: false, error: "Invalid JSON payload" };
  }

  const appointmentId = body.appointmentId;
  const medications = normalizeMedicationsInput(body.medications);

  if (!validateId(appointmentId) || !medications) {
    return { ok: false, error: "Invalid input fields" };
  }

  return {
    ok: true,
    appointmentId: Number(appointmentId),
    medications,
  };
}

function validateOptionalReason(reason) {
  if (reason == null || reason === "") {
    return { ok: true, value: "" };
  }
  if (typeof reason !== "string") {
    return { ok: false, error: "Invalid reason" };
  }
  let sanitized = sanitizeString(reason);
  if (sanitized.length > 200) {
    sanitized = sanitized.slice(0, 200);
  }
  return { ok: true, value: sanitized };
}

// ====== SIMPLE SANITIZER ======
const CONTROL_CHARS_REGEX = /\p{Cc}/gu;

function sanitizeString(str) {
  if (typeof str !== "string") return "";
  return str.replace(CONTROL_CHARS_REGEX, "").trim();
}

// ====== PASSWORD HELPERS ======
function hashPassword(password) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("Password must be a non-empty string");
  }
  return bcrypt.hashSync(password, BCRYPT_ROUNDS);
}

function verifyPassword(password, storedHash) {
  if (typeof password !== "string" || !storedHash) return false;

  if (storedHash.startsWith("$2")) {
    try {
      return bcrypt.compareSync(password, storedHash);
    } catch {
      return false;
    }
  }

  // Legacy SHA-256 hex hashes support (64 hex chars)
  const legacy = crypto.createHash("sha256").update(password).digest("hex");
  if (storedHash.length !== legacy.length) return false;

  return crypto.timingSafeEqual(Buffer.from(storedHash, "utf8"), Buffer.from(legacy, "utf8"));
}

function needsPasswordRehash(storedHash) {
  if (!storedHash) return true;
  if (!storedHash.startsWith("$2")) return true;
  const match = /^\$2[aby]\$(\d{2})\$/.exec(storedHash);
  if (!match) return true;
  const rounds = Number(match[1]);
  return rounds !== BCRYPT_ROUNDS;
}

// ====== PHI ENCRYPTION HELPERS ======


function generateTotpUri(email, secret, issuer = "HealthCureAlpha") {
  const ident = typeof email === "string" ? email.trim().toLowerCase() : "user";
  return authenticator.keyuri(ident, issuer, secret);
}

function generateTotpSecret() {
  try {
    return authenticator.generateSecret();
  } catch (e) {
    console.error('Failed to generate TOTP secret', e);
    return null;
  }
}

function verifyTotpToken(secret, token) {
  if (!secret) return false;
  if (typeof token !== "string") return false;
  const cleaned = token.replace(/\s+/g, "");
  if (!/^\d{6}$/.test(cleaned)) return false;
  try {
    return authenticator.check(cleaned, secret);
  } catch (err) {
    return false;
  }
}

module.exports = {
  getClientIp,
  checkRateLimit,
  checkLoginAllowed,
  registerLoginFailure,
  registerLoginSuccess,
  validateEmail,
  validatePassword,
  validateName,
  validateDateTime,
  validateId,
  validateNotes,
  sanitizeString,
  validateDiagnosisPayload,
  validateMedicationPayload,
  validateOptionalReason,
  hashPassword,
  verifyPassword,
  needsPasswordRehash,
  encryptText,
  decryptText,
  generateTotpSecret,
  generateTotpUri,
  verifyTotpToken,
  isPasswordBreached,
  setSecretsFromKms,
  isSafeOutboundUrl,
};
