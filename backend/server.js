    
// Admin: rotate SSN encryption key for all users
function handleAdminRotateSsnKey(req, res, session) {
  if (!session || session.role !== "admin") return sendJson(res, 403, { error: "Forbidden" });
  readJsonBody(req, res).then(body => {
    const newVersion = body?.version;
    if (!newVersion || !ENCRYPTION_KEYS[newVersion]) {
      return sendJson(res, 400, { error: "Invalid or missing key version" });
    }
    const users = db.prepare("SELECT id, ssn_encrypted FROM users WHERE ssn_encrypted IS NOT NULL AND ssn_encrypted != ''").all();
    let updated = 0;
    for (const user of users) {
      try {
        const ssn = decryptText(user.ssn_encrypted);
        const reEncrypted = encryptText(ssn, newVersion);
        db.prepare("UPDATE users SET ssn_encrypted = ? WHERE id = ?").run(reEncrypted, user.id);
        updated++;
      } catch (err) {
        console.error(`Failed to re-encrypt SSN for user ${user.id}:`, err);
      }
    }
    logSecurityEvent("SSN_KEY_ROTATION", { adminId: session.userId, version: newVersion, updated });
    sendJson(res, 200, { message: `SSN key rotation complete. ${updated} records updated.` });
  });
}

// Break-glass emergency access API (real implementation)
function handleAdminBreakGlass(req, res, session) {
  if (!session || session.role !== "admin") {
    return sendJson(res, 403, { error: "Forbidden" });
  }
  const rows = db.prepare(`SELECT * FROM break_glass_requests ORDER BY requested_at DESC`).all();
  sendJson(res, 200, { requests: rows });
}
const path = require("path");
// Session timeout constants must be defined before use
const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes idle timeout
const SESSION_ABSOLUTE_TIMEOUT_MS = 12 * 60 * 60 * 1000; // 12 hours hard cap
const fs = require("fs");
const LOG_DIR = path.join(__dirname, "logs");
const AUTH_EVENT_LOG_PATH = path.join(LOG_DIR, "auth-events.log");
const { logSecurityEvent, logAlert } = require("./logger");
const sessions = new Map();
// In-memory login attempt tracker for brute force protection
const loginAttempts = new Map();
// --- CSRF Token Validation Helper ---
const crypto = require('crypto');
const CSRF_SECRET = process.env.HCA_CSRF_SECRET || 'default_csrf_secret';
function validateCsrfToken(sessionId, csrfToken) {
  if (!sessionId || !csrfToken) return false;
  // Ensure sessionId is a string for HMAC
  const sid = String(sessionId);
  // Simple HMAC-based CSRF token validation
  const expected = crypto.createHmac('sha256', CSRF_SECRET).update(sid).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(csrfToken));
  } catch (e) {
    return false;
  }
}

// Approve break-glass request
function handleApproveBreakGlass(req, res, session) {
  if (!session || session.role !== "admin") return sendJson(res, 403, { error: "Forbidden" });
  readJsonBody(req, res).then(body => {
    const id = Number(body?.id);
    if (!id) return sendJson(res, 400, { error: "Request ID required" });
    db.prepare(`UPDATE break_glass_requests SET status='approved', approved_by=?, approved_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'`).run(
      session.userId,
      id
    );
    logSecurityEvent("BREAK_GLASS_APPROVED", { adminId: session.userId, requestId: id });
    sendJson(res, 200, { message: "Break-glass request approved" });
  });
}

// Revoke break-glass request
function handleRevokeBreakGlass(req, res, session) {
  if (!session || session.role !== "admin") return sendJson(res, 403, { error: "Forbidden" });
  readJsonBody(req, res).then(body => {
    const id = Number(body?.id);
    if (!id) return sendJson(res, 400, { error: "Request ID required" });
    db.prepare(`UPDATE break_glass_requests SET status='revoked', revoked_by=?, revoked_at=CURRENT_TIMESTAMP WHERE id=? AND status='approved'`).run(
      session.userId,
      id
    );
    logSecurityEvent("BREAK_GLASS_REVOKED", { adminId: session.userId, requestId: id });
    sendJson(res, 200, { message: "Break-glass access revoked" });
  });
}
// --- CSRF Protection ---
// (Moved after crypto is required)

// Set SameSite=Strict for session cookies
function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', `session=${token}; HttpOnly; Path=/; SameSite=Strict`);
}
async function handleOidcLogin(req, res) {
  // Generate state/nonce for CSRF and replay protection
  const { generators } = require('openid-client');
  const state = generators.state();
  const nonce = generators.nonce();
  // Store in-memory for demo; in prod, use encrypted cookie or session store
  sessions.set(`oidc:${state}`, { nonce, createdAt: Date.now() });
  const url = getAuthUrl(state, nonce);
  res.writeHead(302, { Location: url });
  res.end();
}

async function handleOidcCallback(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state) {
    return sendJson(res, 400, { error: 'Missing code or state' });
  }
  const sessionData = sessions.get(`oidc:${state}`);
  if (!sessionData) {
    return sendJson(res, 400, { error: 'Invalid state' });
  }
  sessions.delete(`oidc:${state}`);
  try {
    const { userinfo } = await handleCallback(code, state, sessionData.nonce);
    // Map OIDC userinfo to local user/role
    // Example: userinfo.email, userinfo.name, userinfo.preferred_username
    // You may want to auto-provision or require pre-registration
    const email = (userinfo.email || '').toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return sendJson(res, 403, { error: 'No local account for federated user' });
    }
    // Set session cookie with SameSite=Strict
    setSessionCookie(res, user.sessionToken || '');
    // Issue local session token
    const token = generateToken();
    const now = Date.now();
    const sessionInfo = {
      userId: user.id,
      role: user.role,
      name: user.name,
      createdAt: now,
      lastSeen: now,
      expiresAt: now + SESSION_IDLE_TIMEOUT_MS,
      absoluteExpiresAt: now + SESSION_ABSOLUTE_TIMEOUT_MS,
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'] || '',
      oidc: true,
    };
    sessions.set(token, sessionInfo);
    persistSession(token, sessionInfo);
    logSecurityEvent('LOGIN_SUCCESS_OIDC', { userId: user.id, role: user.role });
    recordAuthEvent({ userId: user.id, email, eventType: 'LOGIN_SUCCESS_OIDC' });
    // Redirect to frontend with token (for demo; in prod, use secure cookie or PKCE)
    res.writeHead(302, { Location: `/login-oidc-success?token=${encodeURIComponent(token)}` });
    res.end();
  } catch (err) {
    console.error('OIDC callback failed', err);
    return sendJson(res, 500, { error: 'OIDC login failed' });
  }
}
// backend/server.js

require("dotenv").config();

// Optionally load secrets from Azure Key Vault before anything else
const { bootstrapKeyVault } = require("./keyvault-bootstrap");
const { initOidcClient, getAuthUrl, handleCallback } = require("./oidc");
let keyVaultReady = Promise.resolve();
if (process.env.HCA_KEYVAULT_URL) {
  keyVaultReady = bootstrapKeyVault();
}

const http = require("http");
const https = require("https");
const helmet = require("helmet");
const db = require("./db");
const { evaluateAccess } = require("./policy");
const {
  ENCRYPTION_KEYS,
  encryptText,
  decryptText,
  getClientIp,
  checkLoginAllowed,
  registerLoginFailure,
  validateEmail,
  isPasswordBreached,
  validatePassword,
  validateName,
  validateDateTime,
  validateId,
  validateDiagnosisPayload,
  validateMedicationPayload,
  validateOptionalReason,
  sanitizeString,
  hashPassword,
  verifyPassword,
  needsPasswordRehash,
  generateTotpUri,
  verifyTotpToken,
  generateTotpSecret,
  checkRateLimit,
  registerLoginSuccess,
  setPasswordResetToken,
  validatePasswordResetToken,
  clearPasswordResetToken,
  sendJson,
  readJsonBody,
  recordAuthEvent,
  persistSession,
  generateToken
} = require("./security");
const { handleCreateBreakGlass } = require("./controllers/patient");
const { handleAdminListSessions, handleAdminRevokeSession } = require("./controllers/admin");

const PORT = Number(process.env.PORT || 3000);
const TLS_KEY_PATH = process.env.HCA_TLS_KEY_PATH;
const TLS_CERT_PATH = process.env.HCA_TLS_CERT_PATH;
const TLS_CA_PATH = process.env.HCA_TLS_CA_PATH;
const TLS_ENABLED = Boolean(TLS_KEY_PATH && TLS_CERT_PATH);

// --- Enforce HTTPS ---
function enforceHttps(req, res) {
  if (!req.socket?.encrypted && TLS_ENABLED) {
    const host = req.headers.host || `localhost:${PORT}`;
    const url = `https://${host}${req.url}`;
    res.writeHead(301, { Location: url });
    res.end();
    return true;
  }
  return false;
}

const DEFAULT_PUBLIC_ORIGIN = TLS_ENABLED
  ? `https://localhost:${PORT}`
  : `http://localhost:${PORT}`;
const PUBLIC_ORIGIN = process.env.HCA_PUBLIC_ORIGIN || DEFAULT_PUBLIC_ORIGIN;

const derivedOrigins = [];
if (PUBLIC_ORIGIN.includes("localhost")) {
  derivedOrigins.push(PUBLIC_ORIGIN.replace("localhost", "127.0.0.1"));
}
if (PUBLIC_ORIGIN.startsWith("https:")) {
  derivedOrigins.push(PUBLIC_ORIGIN.replace("https:", "http:"));
}

const configuredOrigins = (process.env.HCA_ALLOWED_ORIGINS || "")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

const allowedOrigins = new Set([
  ...configuredOrigins,
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  `http://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`,
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  PUBLIC_ORIGIN,
  ...derivedOrigins,
]);

const cspConnectSources = Array.from(new Set(["'self'", PUBLIC_ORIGIN, ...derivedOrigins]));

const STATUS_ACTIVE = "active";
const STATUS_DISABLED = "disabled";
const STATUS_BANNED = "banned";
const STATUS_PENDING = "pending_mfa";

const WATCH_NORMAL = "normal";
const WATCH_YELLOW = "yellow";

const YELLOWLIST_THRESHOLD = 3;

function ensureSchema() {
  try {
    const columns = db.prepare("PRAGMA table_info(users)").all();
    const names = new Set(columns.map(col => col.name));

    if (!names.has("explicit_entitlements")) {
      db.prepare("ALTER TABLE users ADD COLUMN explicit_entitlements TEXT").run();
    }

    if (!names.has("status")) {
      db.prepare("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'").run();
      db.prepare("UPDATE users SET status = 'active' WHERE status IS NULL").run();
    }

    if (!names.has("mfa_secret")) {
      db.prepare("ALTER TABLE users ADD COLUMN mfa_secret TEXT").run();
    }

    if (!names.has("mfa_enabled")) {
      db.prepare("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0").run();
    }

    if (!names.has("watch_status")) {
      db.prepare("ALTER TABLE users ADD COLUMN watch_status TEXT NOT NULL DEFAULT 'normal'").run();
    }

    if (!names.has("failed_login_count")) {
      db.prepare("ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0").run();
    }

    if (!names.has("signup_token")) {
      db.prepare("ALTER TABLE users ADD COLUMN signup_token TEXT").run();
    }

    if (!names.has("yellowlisted_at")) {
      db.prepare("ALTER TABLE users ADD COLUMN yellowlisted_at DATETIME").run();
    }

    if (!names.has("ssn_encrypted")) {
      db.prepare("ALTER TABLE users ADD COLUMN ssn_encrypted TEXT").run();
    }
  } catch (err) {
    console.error("Failed to ensure users table schema", err);
  }

  try {
    db.prepare(
      `CREATE TABLE IF NOT EXISTS user_blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT NOT NULL UNIQUE,
        reason TEXT,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`
    ).run();
  } catch (err) {
    console.error("Failed to ensure user_blacklist table", err);
  }

  try {
    db.prepare(
      `CREATE TABLE IF NOT EXISTS auth_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        email TEXT,
        event_type TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        detail TEXT,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`
    ).run();
    db.prepare(
      "CREATE INDEX IF NOT EXISTS idx_auth_events_created_at ON auth_events (created_at DESC)"
    ).run();
  } catch (err) {
    console.error("Failed to ensure auth_events table", err);
  }

  try {
    db.prepare(
      `CREATE TABLE IF NOT EXISTS password_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      )`
    ).run();
    db.prepare(
      "CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history (user_id, created_at DESC)"
    ).run();
  } catch (err) {
    console.error("Failed to ensure password_history table", err);
  }

  try {
    db.prepare(
      `CREATE TABLE IF NOT EXISTS user_sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        ip TEXT,
        user_agent TEXT,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen_at DATETIME,
        expires_at DATETIME,
        absolute_expires_at DATETIME,
        refresh_token TEXT,
        refresh_expires_at DATETIME,
        refresh_rotated_at DATETIME,
        refresh_prev_token TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      )`
    ).run();
    db.prepare(
      "CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions (user_id, created_at DESC)"
    ).run();
    db.prepare(
      "CREATE INDEX IF NOT EXISTS idx_user_sessions_refresh_token ON user_sessions (refresh_token)"
    ).run();
  } catch (err) {
    console.error("Failed to ensure user_sessions table", err);
  }
}


// Wait for Key Vault secrets before continuing startup
keyVaultReady.then(async () => {
  ensureSchema();
  if (process.env.OIDC_ISSUER_URL) {
    try {
      await initOidcClient();
      console.log("OIDC SSO enabled");
    } catch (err) {
      console.error("OIDC SSO initialization failed", err);
      process.exit(1);
    }
  }
  // ...existing code...
// --- Password Reset Logic ---
// const PASSWORD_RESET_EXPIRY_MINUTES = 30;

// function generateResetToken() {
// UNUSED: return ALLOWED_FILE_TYPES.includes(mime);
// }

// UNUSED: return size <= MAX_FILE_SIZE;
//   const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
//   if (!user) return null;
//   const token = generateResetToken();
//   const expires = Date.now() + PASSWORD_RESET_EXPIRY_MINUTES * 60 * 1000;
// UNUSED: return crypto.randomBytes(32).toString('hex');
//   // Log event (simulate email send)
//   db.prepare('INSERT INTO audit_log (event, user_id, detail, created_at) VALUES (?, ?, ?, ?)').run('PASSWORD_RESET_REQUEST', user.id, `Token: ${token}`, Date.now());
// UNUSED: function setPasswordResetToken(email) {}

// function clearPasswordResetToken(token) {
// UNUSED: function validatePasswordResetToken(token) {}
// --- API Endpoints ---
// --- API Endpoints ---
// UNUSED: function clearPasswordResetToken(token) {}

  // Ensure schema for break-glass and missing columns after db is initialized

  // ensureBreakGlassSchema(); // Not defined, commented out to resolve error
  // UNUSED: function handleAdminRotateSsnKey(req, res, session) {}

  // (Move all code after ensureSchema() into this block)
  // UNUSED: function handleAdminBreakGlass(req, res, session) {}

let authEventStream = null;
try {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  authEventStream = fs.createWriteStream(AUTH_EVENT_LOG_PATH, { flags: "a" });
  authEventStream.on("error", (err) => {
    console.error("Failed to write auth event log", err);
    try {
      authEventStream?.end();
    } catch (closeErr) {
      console.error("Failed to close auth event log", closeErr);
    }
    authEventStream = null;
  });
} catch (err) {
  console.error("Failed to prepare auth event log stream", err);
}

const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: cspConnectSources,
      formAction: ["'self'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
  frameguard: { action: "deny" },
  referrerPolicy: { policy: "no-referrer" },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: "same-origin" },
  crossOriginResourcePolicy: { policy: "cross-origin" },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
});

function applyHelmet(req, res) {
  return new Promise((resolve, reject) => {
    helmetMiddleware(req, res, (err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

process.on("exit", () => {
  if (authEventStream) {
    try {
      authEventStream.end();
    } catch (err) {
      console.error("Failed to close auth event stream", err);
    }
  }
});

process.on("SIGINT", () => {
  if (authEventStream) {
    try {
      authEventStream.end();
    } catch (err) {
      console.error("Failed to close auth event stream", err);
    }
  }
  process.exit(0);
});

const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes idle timeout
const SESSION_ABSOLUTE_TIMEOUT_MS = 12 * 60 * 60 * 1000; // 12 hours hard cap
const SESSION_CLEANUP_INTERVAL_MS = 60 * 60 * 1000; // prune expired sessions hourly
const MAX_JSON_BODY_BYTES = 512 * 1024; // limit JSON payloads to 512 KB
const BLACKLIST_REASON_BAN = "admin_ban";
const PASSWORD_HISTORY_LIMIT = 5;

function normalizeEmail(email) {
  if (typeof email !== "string") return "";
  return email.trim().toLowerCase();
}

function truncateDetail(detail) {
  if (detail == null) return null;
  if (typeof detail === "string") {
    return detail.slice(0, 2048);
  }
  try {
    return JSON.stringify(detail).slice(0, 2048);
  } catch (err) {
    return String(detail).slice(0, 2048);
  }
}

function recordPasswordHistory(userId, passwordHash) {
  if (!userId || !passwordHash) return;
  try {
    db.prepare(
      `INSERT INTO password_history (user_id, password_hash)
       VALUES (?, ?)`
    ).run(userId, passwordHash);
    db.prepare(
      `DELETE FROM password_history
       WHERE id IN (
         SELECT id FROM password_history
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT -1 OFFSET ?
       )`
    ).run(userId, PASSWORD_HISTORY_LIMIT);
  } catch (err) {
    console.error("Failed to record password history", err);
  }
}

function passwordUsedRecently(userId, password) {
  if (!userId || !password) return false;
  try {
    const rows = db
      .prepare(
        `SELECT password_hash
         FROM password_history
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT ?`
      )
      .all(userId, PASSWORD_HISTORY_LIMIT);
    return rows.some(row => verifyPassword(password, row.password_hash));
  } catch (err) {
    console.error("Failed to check password history", err);
    return false;
  }
}

function recordAuthEvent({ userId = null, email = null, eventType, ip = null, userAgent = null, detail = null }) {
  if (!eventType) return;
  const normalizedEmail = email ? normalizeEmail(email) : null;
  const entry = {
    timestamp: new Date().toISOString(),
    userId,
    email: normalizedEmail,
    eventType,
    ip: ip || null,
    userAgent: truncateDetail(userAgent),
    detail: truncateDetail(detail),
  };
  try {
    db.prepare(
      `INSERT INTO auth_events (user_id, email, event_type, ip, user_agent, detail)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(userId, normalizedEmail, eventType, entry.ip, entry.userAgent, entry.detail);
  } catch (err) {
    console.error("Failed to record auth event", err);
  }

  if (authEventStream) {
    try {
      authEventStream.write(`${JSON.stringify(entry)}\n`);
    } catch (err) {
      console.error("Failed to append auth event log", err);
    }
  }
}


function deleteSessionRecord(token) {
  if (!token) return;
  try {
    db.prepare("DELETE FROM user_sessions WHERE token = ?").run(token);
  } catch (err) {
    console.error("Failed to delete session record", err);
  }
}

function deleteSessionsForUser(userId, { excludeToken = null } = {}) {
  if (!userId) return;
  try {
    if (excludeToken) {
      db.prepare(
        "DELETE FROM user_sessions WHERE user_id = ? AND token != ?"
      ).run(userId, excludeToken);
    } else {
      db.prepare("DELETE FROM user_sessions WHERE user_id = ?").run(userId);
    }
  } catch (err) {
    console.error("Failed to delete user sessions", err);
  }
}

function revokeSessionToken(token) {
  if (!token) return false;
  const existing = sessions.get(token);
  if (existing) {
    sessions.delete(token);
  }
  deleteSessionRecord(token);
  return true;
}

function loadPersistedSession(token) {
  if (!token) return null;
  try {
    const row = db
      .prepare(
        `SELECT token, user_id, ip, user_agent, created_at, last_seen_at, expires_at, absolute_expires_at
         FROM user_sessions
         WHERE token = ?`
      )
      .get(token);
    if (!row) return null;

    const user = db
      .prepare("SELECT id, role, name, status FROM users WHERE id = ?")
      .get(row.user_id);
    if (!user || user.status !== STATUS_ACTIVE) {
      deleteSessionRecord(token);
      return null;
    }

    const now = Date.now();
    const expiresAt = row.expires_at ? Date.parse(row.expires_at) : null;
    const absoluteExpiresAt = row.absolute_expires_at ? Date.parse(row.absolute_expires_at) : null;
    if ((expiresAt && now >= expiresAt) || (absoluteExpiresAt && now >= absoluteExpiresAt)) {
      deleteSessionRecord(token);
      return null;
    }

    const createdAt = row.created_at ? Date.parse(row.created_at) : now;
    const lastSeen = row.last_seen_at ? Date.parse(row.last_seen_at) : now;
    const session = {
      userId: user.id,
      role: user.role,
      name: user.name,
      createdAt,
      lastSeen,
      expiresAt,
      absoluteExpiresAt,
      ip: row.ip || null,
      userAgent: row.user_agent || null,
      token,
    };
    sessions.set(token, session);
    return session;
  } catch (err) {
    console.error("Failed to load persisted session", err);
    return null;
  }
}

function updatePersistedSession(token, session) {
  if (!token || !session) return;
  try {
    db.prepare(
      `UPDATE user_sessions
       SET last_seen_at = ?, expires_at = ?, absolute_expires_at = ?
       WHERE token = ?`
    ).run(
      new Date(session.lastSeen || Date.now()).toISOString(),
      session.expiresAt ? new Date(session.expiresAt).toISOString() : null,
      session.absoluteExpiresAt ? new Date(session.absoluteExpiresAt).toISOString() : null,
      token
    );
  } catch (err) {
    console.error("Failed to update session record", err);
  }
}

function listUserSessions(userId) {
  if (!userId) return [];
  try {
    return db
      .prepare(
        `SELECT token, ip, user_agent, created_at, last_seen_at, expires_at, absolute_expires_at
         FROM user_sessions
         WHERE user_id = ?
         ORDER BY created_at DESC`
      )
      .all(userId);
  } catch (err) {
    console.error("Failed to list user sessions", err);
    return [];
  }
}

function getUserAgent(req) {
  const ua = req.headers?.["user-agent"];
  if (!ua) return null;
  return ua.slice(0, 512);
}

function generateSignupToken() {
  return crypto.randomBytes(24).toString("hex");
}

function isEmailBlacklisted(email) {
  const identifier = normalizeEmail(email);
  if (!identifier) return false;
  try {
    const row = db.prepare("SELECT 1 FROM user_blacklist WHERE identifier = ?").get(identifier);
    return !!row;
  } catch (err) {
    console.error("Failed to read blacklist", err);
    return false;
  }
}

function addEmailToBlacklist(email, reason = null) {
  const identifier = normalizeEmail(email);
  if (!identifier) return;
  try {
    db.prepare(
      `INSERT INTO user_blacklist (identifier, reason)
       VALUES (?, ?)
       ON CONFLICT(identifier) DO UPDATE SET reason = excluded.reason, created_at = CURRENT_TIMESTAMP`
    ).run(identifier, truncateDetail(reason));
  } catch (err) {
    console.error("Failed to update blacklist", err);
  }
}

function removeEmailFromBlacklist(email) {
  const identifier = normalizeEmail(email);
  if (!identifier) return;
  try {
    db.prepare("DELETE FROM user_blacklist WHERE identifier = ?").run(identifier);
  } catch (err) {
    console.error("Failed to remove from blacklist", err);
  }
}

function incrementFailedLogin(userId) {
  if (!userId) return false;
  try {
    const row = db.prepare("SELECT failed_login_count, watch_status FROM users WHERE id = ?").get(userId);
    if (!row) return false;
    const current = Number(row.failed_login_count || 0);
    const next = current + 1;
    const promoteToYellow = next >= YELLOWLIST_THRESHOLD && row.watch_status !== WATCH_YELLOW;

    if (promoteToYellow) {
      db.prepare(
        `UPDATE users
         SET failed_login_count = ?, watch_status = ?, yellowlisted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`
      ).run(next, WATCH_YELLOW, userId);
      return true;
    }

    db.prepare(
      "UPDATE users SET failed_login_count = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    ).run(next, userId);
  } catch (err) {
    console.error("Failed to increment failed login count", err);
  }
  return false;
}

function resetFailedLogin(userId) {
  if (!userId) return;
  try {
    db.prepare(
      "UPDATE users SET failed_login_count = 0 WHERE id = ?"
    ).run(userId);
  } catch (err) {
    console.error("Failed to reset failed login count", err);
  }
}

function clearYellowStatus(userId) {
  if (!userId) return;
  try {
    db.prepare(
      `UPDATE users
       SET watch_status = ?, failed_login_count = 0, yellowlisted_at = NULL, updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`
    ).run(WATCH_NORMAL, userId);
  } catch (err) {
    console.error("Failed to clear yellow status", err);
  }
}

function invalidateSessionsForUser(userId, { excludeToken = null } = {}) {
  if (!userId) return;
  console.log(`[DEBUG] invalidateSessionsForUser: userId=${userId}, excludeToken=${excludeToken}`);
  for (const [token, session] of sessions.entries()) {
    if (session.userId === userId) {
      if (excludeToken && token === excludeToken) continue;
      console.log(`[DEBUG] Deleting session token=${token} for userId=${userId}`);
      sessions.delete(token);
      deleteSessionRecord(token);
    }
  }
  deleteSessionsForUser(userId, { excludeToken });
}

// ---------- Helpers ----------
function sendJson(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    let total = 0;
    let aborted = false;

    req.on("data", chunk => {
      if (aborted) return;
      total += chunk.length;
      if (total > MAX_JSON_BODY_BYTES) {
        aborted = true;
        const err = new Error("Payload too large");
        err.code = "PAYLOAD_TOO_LARGE";
        reject(err);
        req.destroy();
        return;
      }
      body += chunk;
    });

    req.on("end", () => {
      if (aborted) return;
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        e.code = "INVALID_JSON";
        reject(e);
      }
    });

    req.on("error", err => {
      if (aborted) return;
      reject(err);
    });
  });
}

async function readJsonBody(req, res) {
  try {
    return await parseBody(req);
  } catch (err) {
    if (err?.code === "PAYLOAD_TOO_LARGE") {
      logSecurityEvent("PAYLOAD_TOO_LARGE", { detail: req.url });
      sendJson(res, 413, { error: "Payload too large" });
      return null;
    }

    logSecurityEvent("INVALID_JSON", { detail: req.url });
    sendJson(res, 400, { error: "Invalid JSON payload" });
    return null;
  }
}

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

function getSession(req) {
  const auth = req.headers["authorization"];
  if (!auth) return null;
  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return null;
  const token = parts[1];
  let session = sessions.get(token);
  if (!session) {
    session = loadPersistedSession(token);
    if (!session) return null;
  }

  const now = Date.now();
  if (
    (session.expiresAt && now >= session.expiresAt) ||
    (session.absoluteExpiresAt && now >= session.absoluteExpiresAt)
  ) {
    sessions.delete(token);
    deleteSessionRecord(token);
    return null;
  }

  try {
    const row = db.prepare("SELECT status FROM users WHERE id = ?").get(session.userId);
    if (!row || row.status !== STATUS_ACTIVE) {
      sessions.delete(token);
      return null;
    }
  } catch (err) {
    console.error("Failed to validate session status", err);
    return null;
  }

  const currentIp = getClientIp(req) || session.ip || null;
  const currentUa = getUserAgent(req) || session.userAgent || null;
  session.ip = currentIp;
  session.userAgent = currentUa;
  session.lastSeen = now;
  session.expiresAt = now + SESSION_IDLE_TIMEOUT_MS;
  session.token = token;
  updatePersistedSession(token, session);
  return session;
}

function requireSession(res, session) {
  if (!session) {
    logSecurityEvent("UNAUTHORIZED_ACCESS", {
      detail: "Missing or invalid session token",
    });
    sendJson(res, 401, { error: "Unauthorized" });
    return false;
  }
  if (session.expiresAt) {
    res.setHeader("X-Session-Expires", new Date(session.expiresAt).toISOString());
  }
  return true;
}

function requireRole(res, session, roles) {
  if (!requireSession(res, session)) return false;
  if (!roles.includes(session.role)) {
    logSecurityEvent("FORBIDDEN_ACCESS", {
      userId: session.userId,
      role: session.role,
      requiredRoles: roles,
    });
    sendJson(res, 403, { error: "Forbidden" });
    return false;
  }
  return true;
}

// ---------- Auth Handlers ----------

// Public patient signup (two-step with mandatory TOTP verification)
async function handleSignup(req, res) {
  const body = await readJsonBody(req, res);
  if (!body) return;
  const phaseRaw = typeof body.phase === "string" ? body.phase.trim().toLowerCase() : "init";
  const ip = getClientIp(req);
  const userAgent = getUserAgent(req);

  if (phaseRaw === "verify") {
    return handleSignupVerify(body, res, ip, userAgent);
  }

  return handleSignupInit(body, res, ip, userAgent);
}

function handleSignupInit(body, res, ip, userAgent) {
  let { email, name, password } = body;
  email = normalizeEmail(email);
  name = sanitizeString(name);
  password = typeof password === "string" ? password : "";

  if (!validateEmail(email) || !validatePassword(password) || !validateName(name)) {
    return sendJson(res, 400, { error: "Invalid signup fields" });
  }

  if (isPasswordBreached(password)) {
    return sendJson(res, 400, { error: "Password is too common" });
  }

  if (isEmailBlacklisted(email)) {
    logSecurityEvent("SIGNUP_BLOCKED_BLACKLIST", { ip, detail: email });
    recordAuthEvent({ email, eventType: "SIGNUP_BLOCKED", ip, userAgent, detail: "Email blacklisted" });
    return sendJson(res, 403, { error: "Signups for this address are not allowed." });
  }

  try {
    const secret = generateTotpSecret();
    const encryptedSecret = encryptText(secret);
    const signupToken = generateSignupToken();
    const otpauthUrl = generateTotpUri(email, secret);
    const passwordHash = hashPassword(password);

    const existing = db
      .prepare("SELECT id, status FROM users WHERE LOWER(email) = ?")
      .get(email);

    let userId;
    let statusCode = 201;

    if (existing) {
      if (existing.status === STATUS_BANNED) {
        logSecurityEvent("SIGNUP_BLOCKED_BANNED", { ip, detail: email });
        recordAuthEvent({ userId: existing.id, email, eventType: "SIGNUP_BLOCKED", ip, userAgent, detail: "Banned account" });
        return sendJson(res, 403, { error: "Account is banned. Contact support." });
      }

      if (existing.status !== STATUS_PENDING) {
        return sendJson(res, 409, { error: "Email already registered." });
      }

      if (passwordUsedRecently(existing.id, password)) {
        return sendJson(res, 400, { error: "Choose a password you have not used recently" });
      }

      statusCode = 200;
      db.prepare(
        `UPDATE users
         SET password_hash = ?, name = ?, mfa_secret = ?, mfa_enabled = 0, signup_token = ?, status = ?, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`
      ).run(passwordHash, name, encryptedSecret, signupToken, STATUS_PENDING, existing.id);
      userId = existing.id;
    } else {
      const result = db.prepare(
        `INSERT INTO users (email, password_hash, name, role, status, mfa_secret, mfa_enabled, watch_status, failed_login_count, signup_token)
         VALUES (?, ?, ?, 'patient', ?, ?, 0, ?, 0, ?)`
      ).run(email, passwordHash, name, STATUS_PENDING, encryptedSecret, WATCH_NORMAL, signupToken);
      userId = result.lastInsertRowid;
    }

    recordPasswordHistory(userId, passwordHash);

    logSecurityEvent("SIGNUP_INIT", { ip, userId, detail: email });
    recordAuthEvent({ userId, email, eventType: "SIGNUP_INIT", ip, userAgent, detail: "Patient signup initiated" });

    return sendJson(res, statusCode, {
      message: "Scan the secret with your authenticator app and submit the six-digit code to activate your account.",
      secret,
      otpauthUrl,
      signupToken,
    });
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: "Server error" });
  }
}

function handleSignupVerify(body, res, ip, userAgent) {
  const signupToken = typeof body.signupToken === "string" ? body.signupToken.trim() : "";
  const totpCodeRaw = typeof body.totpCode === "string" ? body.totpCode : String(body.totpCode || "");
  const totpCode = totpCodeRaw.trim();

  if (!signupToken || !totpCode) {
    return sendJson(res, 400, { error: "Missing verification fields" });
  }

  try {
    const user = db
      .prepare("SELECT id, email, mfa_secret, status FROM users WHERE signup_token = ?")
      .get(signupToken);

    if (!user) {
      return sendJson(res, 404, { error: "Signup token not found" });
    }

    if (user.status === STATUS_BANNED) {
      logSecurityEvent("SIGNUP_BLOCKED_BANNED", { ip, userId: user.id, detail: user.email });
      recordAuthEvent({ userId: user.id, email: user.email, eventType: "SIGNUP_BLOCKED", ip, userAgent, detail: "Banned during verification" });
      return sendJson(res, 403, { error: "Account is banned. Contact support." });
    }

    if (user.status !== STATUS_PENDING) {
      return sendJson(res, 400, { error: "Account already verified" });
    }

    const secret = decryptText(user.mfa_secret);
    if (!secret) {
      console.error("Missing or invalid MFA secret for user", user.id);
      return sendJson(res, 500, { error: "MFA secret unavailable" });
    }

    const valid = verifyTotpToken(secret, totpCode);
    if (!valid) {
      logSecurityEvent("SIGNUP_TOTP_FAILED", { userId: user.id, detail: user.email, ip });
      recordAuthEvent({ userId: user.id, email: user.email, eventType: "SIGNUP_TOTP_FAILED", ip, userAgent });
      return sendJson(res, 401, { error: "Invalid MFA code" });
    }

    db.prepare(
      `UPDATE users
       SET status = ?, mfa_enabled = 1, signup_token = NULL, updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`
    ).run(STATUS_ACTIVE, user.id);

    logSecurityEvent("SIGNUP_COMPLETED", { userId: user.id, detail: user.email, ip });
    recordAuthEvent({ userId: user.id, email: user.email, eventType: "SIGNUP_COMPLETED", ip, userAgent });

    return sendJson(res, 200, { message: "Account activated. You can now log in." });
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// Login
async function handleLogin(req, res, ip) {
  const body = await readJsonBody(req, res);
  if (!body) return;
  const userAgent = getUserAgent(req);

  let { email } = body;
  const { password } = body;
  const totpCodeRaw = body.totpCode ?? body.totp ?? body.code ?? "";
  const totpCode = typeof totpCodeRaw === "string" ? totpCodeRaw.trim() : String(totpCodeRaw || "").trim();

  email = normalizeEmail(email);

  if (!validateEmail(email) || typeof password !== "string") {
    return sendJson(res, 400, { error: "Invalid input fields" });
  }

  const loginKey = `${email}|${ip}`;
  const allowedInfo = checkLoginAllowed(loginKey);
  if (!allowedInfo.allowed) {
    logSecurityEvent("LOGIN_LOCKED", { ip, detail: email });
    recordAuthEvent({ email, eventType: "LOGIN_LOCKED", ip, userAgent });
    return sendJson(res, 429, { error: allowedInfo.message });
  }

  try {
    const stmt = db.prepare(
      `SELECT id, role, password_hash, name, status, mfa_secret, mfa_enabled, watch_status
       FROM users WHERE LOWER(email) = ?`
    );
    const user = stmt.get(email);
    if (!user) {
      registerLoginFailure(loginKey);
      logSecurityEvent("LOGIN_FAILURE", { ip, detail: email });
      recordAuthEvent({ email, eventType: "LOGIN_FAILURE", ip, userAgent, detail: "Unknown account" });
      return sendJson(res, 401, { error: "Invalid credentials" });
    }

    if (user.status === STATUS_BANNED) {
      logSecurityEvent("LOGIN_BLOCKED_BANNED", { ip, userId: user.id, role: user.role });
      recordAuthEvent({ userId: user.id, email, eventType: "LOGIN_BLOCKED", ip, userAgent, detail: "Banned account" });
      return sendJson(res, 403, { error: "Account is banned. Contact administrator." });
    }

    if (user.status === STATUS_PENDING) {
      logSecurityEvent("LOGIN_BLOCKED_PENDING", { ip, userId: user.id, role: user.role });
      recordAuthEvent({ userId: user.id, email, eventType: "LOGIN_BLOCKED", ip, userAgent, detail: "Pending MFA verification" });
      return sendJson(res, 403, { error: "Account pending MFA verification." });
    }

    if (user.status !== STATUS_ACTIVE) {
      logSecurityEvent("LOGIN_BLOCKED", { ip, userId: user.id, role: user.role, detail: user.status });
      recordAuthEvent({ userId: user.id, email, eventType: "LOGIN_BLOCKED", ip, userAgent, detail: `Status ${user.status}` });
      return sendJson(res, 403, { error: "Account disabled. Contact administrator." });
    }

    const passwordOk = verifyPassword(password, user.password_hash);
    if (!passwordOk) {
      registerLoginFailure(loginKey);
      const yellowed = incrementFailedLogin(user.id);
      logSecurityEvent("LOGIN_FAILURE", { ip, userId: user.id, role: user.role });
      recordAuthEvent({ userId: user.id, email, eventType: "LOGIN_FAILURE", ip, userAgent, detail: "Password mismatch" });
      if (yellowed) {
        logSecurityEvent("USER_YELLOWLISTED", { userId: user.id, detail: email, ip });
        recordAuthEvent({ userId: user.id, email, eventType: "USER_YELLOWLISTED", ip, userAgent });
      }
      return sendJson(res, 401, { error: "Invalid credentials" });
    }

    // Only require MFA if enabled for this user
    if (user.mfa_enabled) {
      if (!totpCode) {
        return sendJson(res, 400, { error: "MFA code required" });
      }
      if (!/^\d{6}$/.test(totpCode)) {
        return sendJson(res, 400, { error: "MFA code must be six digits" });
      }
      if (typeof user.mfa_secret !== 'string' || !user.mfa_secret.trim()) {
        logSecurityEvent("LOGIN_BLOCKED_NO_MFA", { userId: user.id, role: user.role, ip });
        recordAuthEvent({ userId: user.id, email, eventType: "LOGIN_BLOCKED", ip, userAgent, detail: "MFA not configured or secret missing" });
        return sendJson(res, 403, { error: "MFA not configured or secret missing. Contact administrator." });
      }
      const secret = decryptText(user.mfa_secret);
      if (!secret) {
        console.error("Missing or invalid MFA secret for user", user.id);
        return sendJson(res, 500, { error: "MFA secret unavailable or invalid" });
      }
      if (!verifyTotpToken(secret, totpCode)) {
        registerLoginFailure(loginKey);
        const yellowed = incrementFailedLogin(user.id);
        logSecurityEvent("LOGIN_FAILURE_MFA", { ip, userId: user.id, role: user.role });
        recordAuthEvent({ userId: user.id, email, eventType: "LOGIN_FAILURE_MFA", ip, userAgent });
        if (yellowed) {
          logSecurityEvent("USER_YELLOWLISTED", { userId: user.id, detail: email, ip });
          recordAuthEvent({ userId: user.id, email, eventType: "USER_YELLOWLISTED", ip, userAgent });
        }
        return sendJson(res, 401, { error: "Invalid MFA code" });
      }
    }

    if (!user.mfa_enabled || typeof user.mfa_secret !== 'string' || !user.mfa_secret.trim()) {
      logSecurityEvent("LOGIN_BLOCKED_NO_MFA", { userId: user.id, role: user.role, ip });
      recordAuthEvent({ userId: user.id, email, eventType: "LOGIN_BLOCKED", ip, userAgent, detail: "MFA not configured or secret missing" });
      return sendJson(res, 403, { error: "MFA not configured or secret missing. Contact administrator." });
    }

    const secret = decryptText(user.mfa_secret);
    if (!secret) {
      console.error("Missing or invalid MFA secret for user", user.id);
      return sendJson(res, 500, { error: "MFA secret unavailable or invalid" });
    }

    if (!verifyTotpToken(secret, totpCode)) {
      registerLoginFailure(loginKey);
      const yellowed = incrementFailedLogin(user.id);
      logSecurityEvent("LOGIN_FAILURE_MFA", { ip, userId: user.id, role: user.role });
      recordAuthEvent({ userId: user.id, email, eventType: "LOGIN_FAILURE_MFA", ip, userAgent });
      if (yellowed) {
        logSecurityEvent("USER_YELLOWLISTED", { userId: user.id, detail: email, ip });
        recordAuthEvent({ userId: user.id, email, eventType: "USER_YELLOWLISTED", ip, userAgent });
      }
      return sendJson(res, 401, { error: "Invalid MFA code" });
    }

    if (needsPasswordRehash(user.password_hash)) {
      try {
        const newHash = hashPassword(password);
        db.prepare(
          "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        ).run(newHash, user.id);
        recordPasswordHistory(user.id, newHash);
      } catch (rehashErr) {
        console.error("Failed to rehash password", rehashErr);
      }
    }


    registerLoginSuccess(loginKey);
    resetFailedLogin(user.id);
    // Update last_login timestamp
    try {
      db.prepare("UPDATE users SET last_login = ? WHERE id = ?").run(new Date().toISOString(), user.id);
    } catch (err) {
      console.error("Failed to update last_login", err);
    }

    // Generate access and refresh tokens
    const token = generateToken();
    const refreshToken = generateToken();
    const now = Date.now();
    const refreshExpiresAt = now + 7 * 24 * 60 * 60 * 1000; // 7 days
    const sessionInfo = {
      userId: user.id,
      role: user.role,
      name: user.name,
      createdAt: now,
      lastSeen: now,
      expiresAt: now + SESSION_IDLE_TIMEOUT_MS,
      absoluteExpiresAt: now + SESSION_ABSOLUTE_TIMEOUT_MS,
      ip,
      userAgent,
      refreshToken,
      refreshExpiresAt,
      refreshRotatedAt: null,
      refreshPrevToken: null,
    };
    sessions.set(token, sessionInfo);
    // Persist session with refresh token
    try {
      db.prepare(
        `INSERT OR REPLACE INTO user_sessions (
           token, user_id, ip, user_agent, created_at, last_seen_at, expires_at, absolute_expires_at,
           refresh_token, refresh_expires_at, refresh_rotated_at, refresh_prev_token
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        token,
        sessionInfo.userId,
        sessionInfo.ip || null,
        truncateDetail(sessionInfo.userAgent) || null,
        new Date(sessionInfo.createdAt || Date.now()).toISOString(),
        new Date(sessionInfo.lastSeen || Date.now()).toISOString(),
        sessionInfo.expiresAt ? new Date(sessionInfo.expiresAt).toISOString() : null,
        sessionInfo.absoluteExpiresAt ? new Date(sessionInfo.absoluteExpiresAt).toISOString() : null,
        refreshToken,
        new Date(refreshExpiresAt).toISOString(),
        null,
        null
      );
    } catch (err) {
      console.error("Failed to persist session with refresh token", err);
    }

    logSecurityEvent("LOGIN_SUCCESS", {
      ip,
      userId: user.id,
      role: user.role,
    });
    recordAuthEvent({ userId: user.id, email, eventType: "LOGIN_SUCCESS", ip, userAgent });

    // Issue a CSRF token tied to the user id for frontend to include in state-changing requests
    const csrfToken = crypto.createHmac('sha256', CSRF_SECRET).update(String(user.id)).digest('hex');
    return sendJson(res, 200, {
      message: "Login successful",
      token,
      refreshToken,
      refreshExpiresAt: new Date(refreshExpiresAt).toISOString(),
      role: user.role,
      name: user.name,
      userId: user.id,
      sessionExpiresAt: new Date(now + SESSION_IDLE_TIMEOUT_MS).toISOString(),
      watchStatus: user.watch_status,
      csrfToken,
    });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// Change password (any role)
async function handleChangePassword(req, res, session) {
  const body = await readJsonBody(req, res);
  if (!body) return;
  const { oldPassword, newPassword } = body;

  if (!oldPassword || !validatePassword(newPassword)) {
    return sendJson(res, 400, { error: "Invalid input fields" });
  }

  if (isPasswordBreached(newPassword)) {
    return sendJson(res, 400, { error: "Password is too common" });
  }

  try {
    const getStmt = db.prepare("SELECT password_hash FROM users WHERE id = ?");
    const user = getStmt.get(session.userId);
    if (!user) return sendJson(res, 404, { error: "User not found" });

    if (!verifyPassword(oldPassword, user.password_hash)) {
      return sendJson(res, 401, { error: "Old password incorrect" });
    }

    if (passwordUsedRecently(session.userId, newPassword)) {
      return sendJson(res, 400, { error: "Choose a password you have not used recently" });
    }

    const newHash = hashPassword(newPassword);
    const upd = db.prepare(
      "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    );
    upd.run(newHash, session.userId);
    recordPasswordHistory(session.userId, newHash);
    if (session.token) {
      invalidateSessionsForUser(session.userId, { excludeToken: session.token });
    } else {
      invalidateSessionsForUser(session.userId);
    }

    logSecurityEvent("PASSWORD_CHANGE", {
      userId: session.userId,
      role: session.role,
    });

    return sendJson(res, 200, { message: "Password changed" });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

async function handleLogout(req, res, session) {
  if (session.token) {
    sessions.delete(session.token);
    deleteSessionRecord(session.token);
  }

  logSecurityEvent("LOGOUT", {
    userId: session.userId,
    role: session.role,
  });

  return sendJson(res, 200, { message: "Logged out" });
}

async function handleListOwnSessions(req, res, session) {
  if (!requireSession(res, session)) return;
  const rows = listUserSessions(session.userId);
  const formatted = rows.map(row => ({
    token: row.token,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    expiresAt: row.expires_at,
    absoluteExpiresAt: row.absolute_expires_at,
    ip: row.ip,
    userAgent: row.user_agent,
    current: session.token === row.token,
  }));
  // Include a CSRF token derived from the user id so the frontend can include it
  const csrfToken = crypto.createHmac('sha256', CSRF_SECRET).update(String(session.userId)).digest('hex');
  return sendJson(res, 200, { sessions: formatted, csrfToken });
}

async function handleRevokeOwnSessions(req, res, session) {
  if (!requireSession(res, session)) return;
  const body = await readJsonBody(req, res);
  if (!body) return;
  const { token, revokeAll = false, keepCurrent = true } = body;

  if (revokeAll) {
    if (keepCurrent && session.token) {
      invalidateSessionsForUser(session.userId, { excludeToken: session.token });
    } else {
      invalidateSessionsForUser(session.userId);
      if (session.token) {
        revokeSessionToken(session.token);
      }
    }

    logSecurityEvent("SESSION_REVOKE_SELF_ALL", {
      userId: session.userId,
      keepCurrent,
    });
    recordAuthEvent({ userId: session.userId, email: null, eventType: "SESSION_REVOKE_SELF_ALL", detail: keepCurrent ? "All except current" : "Revoked all" });

    return sendJson(res, 200, {
      message: keepCurrent ? "All other sessions revoked" : "All sessions revoked",
      currentRevoked: !keepCurrent,
    });
  }

  if (!token || typeof token !== "string") {
    return sendJson(res, 400, { error: "token is required" });
  }

  const entries = listUserSessions(session.userId);
  const target = entries.find(entry => entry.token === token);
  if (!target) {
    return sendJson(res, 404, { error: "Session not found" });
  }

  const revoked = revokeSessionToken(token);
  if (!revoked) {
    return sendJson(res, 500, { error: "Failed to revoke session" });
  }

  const isCurrent = session.token === token;
  logSecurityEvent("SESSION_REVOKE_SELF", {
    userId: session.userId,
    current: isCurrent,
  });
  recordAuthEvent({ userId: session.userId, email: null, eventType: "SESSION_REVOKE_SELF", detail: isCurrent ? "Revoked own session" : "Revoked alternate session" });

  return sendJson(res, 200, {
    message: isCurrent ? "Session revoked. Please log in again." : "Session revoked.",
    currentRevoked: isCurrent,
  });
}

// ---------- Admin Handlers ----------

// Admin creates doctor or nurse
async function handleAdminCreateUser(req, res, session) {
  if (!requireRole(res, session, ["admin"])) return;
  const body = await readJsonBody(req, res);
  if (!body) return;
  let { email, name } = body;
  const { password, role } = body;
  // Normalize role to avoid client-side casing/whitespace issues
  const roleNormalized = typeof role === 'string' ? role.trim().toLowerCase() : '';
  console.log(`[DEBUG] handleAdminCreateUser: received body=${JSON.stringify(body)}`);
  console.log(`[DEBUG] handleAdminCreateUser: role='${role}' -> normalized='${roleNormalized}'`);

  email = normalizeEmail(email);
  name = sanitizeString(name);

  if (!validateEmail(email) || !validatePassword(password) || !validateName(name)) {
    return sendJson(res, 400, { error: "Invalid input fields" });
  }

  if (!["doctor", "nurse"].includes(roleNormalized)) {
    return sendJson(res, 400, { error: "Role must be doctor or nurse" });
  }

  if (isEmailBlacklisted(email)) {
    return sendJson(res, 409, { error: "Email is blacklisted." });
  }

  try {
    const existsStmt = db.prepare("SELECT id FROM users WHERE LOWER(email) = ?");
    const existing = existsStmt.get(email);
    if (existing) {
      return sendJson(res, 409, { error: "Email already exists" });
    }
    const mfaEnabled = body.hasOwnProperty('mfaEnabled') ? Boolean(body.mfaEnabled) : true;
    let secret = null;
    let encryptedSecret = '';
    if (mfaEnabled) {
      secret = generateTotpSecret();
      encryptedSecret = encryptText(secret);
    }
    const hash = hashPassword(password);
    const ssnEncrypted = body.ssn ? encryptText(body.ssn) : '';
    const insert = db.prepare(
      `INSERT INTO users (email, password_hash, name, role, status, mfa_secret, mfa_enabled, watch_status, failed_login_count, ssn_encrypted)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
    );
    const info = insert.run(email, hash, name, roleNormalized, STATUS_ACTIVE, encryptedSecret, mfaEnabled ? 1 : 0, WATCH_NORMAL, ssnEncrypted);
    recordPasswordHistory(info.lastInsertRowid, hash);

    logSecurityEvent("ADMIN_CREATE_USER", {
      userId: session.userId,
      role: session.role,
      detail: `Created ${roleNormalized} with id=${info.lastInsertRowid}`,
    });
    recordAuthEvent({ userId: info.lastInsertRowid, email, eventType: "ADMIN_CREATE_USER", detail: `Role ${role}`, ip: getClientIp(req), userAgent: getUserAgent(req) });
    const resp = {
      message: `${roleNormalized} created.`,
      userId: info.lastInsertRowid,
    };
    if (mfaEnabled) {
      resp.mfaSecret = secret;
      resp.otpauthUrl = generateTotpUri(email, secret);
      resp.message = `${roleNormalized} created. Provide the MFA secret to the user for enrollment.`;
    }
    return sendJson(res, 201, resp);
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// Admin disable user (doctor/nurse/patient)
async function handleAdminDisableUser(req, res, session) {
  if (!requireRole(res, session, ["admin"])) return;
  const body = await readJsonBody(req, res);
  if (!body) return;
  console.log(`[DEBUG] handleAdminDisableUser: admin session.userId=${session.userId}, target userId=${body?.userId}`);
  const { userId } = body;

  if (!validateId(userId)) return sendJson(res, 400, { error: "Invalid userId" });

  // Prevent admin from disabling themselves
  if (userId === session.userId) {
    return sendJson(res, 400, { error: "You cannot disable your own account while logged in." });
  }

  try {
    const getStmt = db.prepare("SELECT role, status, email FROM users WHERE id = ?");
    const user = getStmt.get(userId);
    if (!user) return sendJson(res, 404, { error: "User not found" });
    if (user.role === "admin") {
      return sendJson(res, 400, { error: "Cannot delete admin" });
    }

    if (user.status === STATUS_BANNED) {
      return sendJson(res, 400, { error: "User is banned" });
    }

    if (user.status === STATUS_DISABLED) {
      return sendJson(res, 200, { message: "User already disabled" });
    }

    const upd = db.prepare(
      "UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    );
    upd.run(STATUS_DISABLED, userId);

    invalidateSessionsForUser(userId);

    logSecurityEvent("ADMIN_DISABLE_USER", {
      userId: session.userId,
      role: session.role,
      detail: `Disabled user id=${userId}, role=${user.role}`,
    });
    recordAuthEvent({ userId, email: user.email, eventType: "ADMIN_DISABLE_USER", detail: `Disabled by ${session.userId}`, ip: getClientIp(req), userAgent: getUserAgent(req) });

    return sendJson(res, 200, { message: "User disabled" });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

async function handleAdminRestoreUser(req, res, session) {
  if (!requireRole(res, session, ["admin"])) return;
  const body = await readJsonBody(req, res);
  if (!body) return;
  const { userId } = body;

  if (!validateId(userId)) return sendJson(res, 400, { error: "Invalid userId" });

  try {
    const getStmt = db.prepare("SELECT role, status, email FROM users WHERE id = ?");
    const user = getStmt.get(userId);
    if (!user) return sendJson(res, 404, { error: "User not found" });
    if (user.role === "admin") {
      return sendJson(res, 400, { error: "Admin accounts are always active" });
    }

    if (user.status === STATUS_BANNED) {
      return sendJson(res, 400, { error: "Use unban endpoint for banned users" });
    }

    if (user.status === STATUS_ACTIVE) {
      return sendJson(res, 200, { message: "User already active" });
    }

    const upd = db.prepare(
      "UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    );
    upd.run(STATUS_ACTIVE, userId);

    logSecurityEvent("ADMIN_RESTORE_USER", {
      userId: session.userId,
      role: session.role,
      detail: `Restored user id=${userId}, role=${user.role}`,
    });
    recordAuthEvent({ userId, email: user.email, eventType: "ADMIN_RESTORE_USER", detail: `Restored by ${session.userId}`, ip: getClientIp(req), userAgent: getUserAgent(req) });

    return sendJson(res, 200, { message: "User reactivated" });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// Admin: locked accounts stub (returns empty list for now)
async function handleAdminLockedAccounts(req, res, session) {
  if (!requireRole(res, session, ["admin"])) return;
  // TODO: implement real locked accounts logic
  return sendJson(res, 200, { locked: [] });
}

async function handleAdminBanUser(req, res, session) {
  if (!requireRole(res, session, ["admin"])) return;
  const body = await readJsonBody(req, res);
  if (!body) return;

  console.log(`[DEBUG] handleAdminBanUser: admin session.userId=${session.userId}, target userId=${body?.userId}`);

  const { userId, reason } = body;
  if (!validateId(userId)) return sendJson(res, 400, { error: "Invalid userId" });
  // Prevent admin from banning themselves
  if (userId === session.userId) {
    return sendJson(res, 400, { error: "You cannot ban your own account while logged in." });
  }
  const reasonResult = validateOptionalReason(reason);
  if (!reasonResult.ok) {
    return sendJson(res, 400, { error: reasonResult.error });
  }
  const normalizedReason = reasonResult.value;

  try {
    const user = db
      .prepare("SELECT id, email, role, status FROM users WHERE id = ?")
      .get(userId);
    if (!user) return sendJson(res, 404, { error: "User not found" });
    if (user.role === "admin") {
      return sendJson(res, 400, { error: "Cannot ban admin" });
    }
    if (user.status === STATUS_BANNED) {
      return sendJson(res, 200, { message: "User already banned" });
    }

    db.prepare(
      `UPDATE users
       SET status = ?, watch_status = ?, failed_login_count = 0, signup_token = NULL, updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`
    ).run(STATUS_BANNED, WATCH_NORMAL, userId);

    invalidateSessionsForUser(userId);
    const blacklistReason = normalizedReason || BLACKLIST_REASON_BAN;
    addEmailToBlacklist(user.email, blacklistReason);

    logSecurityEvent("ADMIN_BAN_USER", {
      userId: session.userId,
      role: session.role,
      detail: `Banned user id=${userId}`,
    });
    recordAuthEvent({ userId, email: user.email, eventType: "ADMIN_BAN_USER", detail: normalizedReason || "Banned", ip: getClientIp(req), userAgent: getUserAgent(req) });

    return sendJson(res, 200, { message: "User banned and blacklisted" });
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// Admin: enable/disable MFA for a user
async function handleAdminSetMfa(req, res, session) {
  if (!requireRole(res, session, ["admin"])) return;
  const body = await readJsonBody(req, res);
  if (!body) return;
  const { userId, mfaEnabled } = body;
  if (!validateId(userId) || typeof mfaEnabled !== 'boolean') return sendJson(res, 400, { error: 'Invalid input' });

  try {
    const user = db.prepare("SELECT id, email, role, status FROM users WHERE id = ?").get(userId);
    if (!user) return sendJson(res, 404, { error: 'User not found' });
    if (user.role === 'admin') return sendJson(res, 400, { error: 'Cannot change MFA for admin' });

    if (mfaEnabled) {
      const secret = generateTotpSecret();
      const encrypted = encryptText(secret);
      db.prepare("UPDATE users SET mfa_secret = ?, mfa_enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(encrypted, userId);
      logSecurityEvent('ADMIN_SET_MFA', { userId: session.userId, detail: `Enabled MFA for ${userId}` });
      recordAuthEvent({ userId, email: user.email, eventType: 'ADMIN_SET_MFA', detail: 'Enabled MFA', ip: getClientIp(req), userAgent: getUserAgent(req) });
      return sendJson(res, 200, { message: 'MFA enabled', mfaSecret: secret, otpauthUrl: generateTotpUri(user.email, secret) });
    } else {
      db.prepare("UPDATE users SET mfa_secret = NULL, mfa_enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(userId);
      invalidateSessionsForUser(userId);
      logSecurityEvent('ADMIN_SET_MFA', { userId: session.userId, detail: `Disabled MFA for ${userId}` });
      recordAuthEvent({ userId, email: user.email, eventType: 'ADMIN_SET_MFA', detail: 'Disabled MFA', ip: getClientIp(req), userAgent: getUserAgent(req) });
      return sendJson(res, 200, { message: 'MFA disabled' });
    }
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: 'Server error' });
  }
}

async function handleAdminUnbanUser(req, res, session) {
  if (!requireRole(res, session, ["admin"])) return;
  const body = await readJsonBody(req, res);
  if (!body) return;

  const { userId } = body;
  if (!validateId(userId)) return sendJson(res, 400, { error: "Invalid userId" });

  try {
    const user = db
      .prepare("SELECT id, email, role, status FROM users WHERE id = ?")
      .get(userId);
    if (!user) return sendJson(res, 404, { error: "User not found" });
    if (user.role === "admin") {
      return sendJson(res, 400, { error: "Cannot unban admin" });
    }

    if (user.status !== STATUS_BANNED) {
      return sendJson(res, 200, { message: "User not banned" });
    }

    db.prepare(
      `UPDATE users
       SET status = ?, watch_status = ?, failed_login_count = 0, updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`
    ).run(STATUS_DISABLED, WATCH_NORMAL, userId);

    removeEmailFromBlacklist(user.email);
    invalidateSessionsForUser(userId);

    logSecurityEvent("ADMIN_UNBAN_USER", {
      userId: session.userId,
      role: session.role,
      detail: `Unbanned user id=${userId}`,
    });
    recordAuthEvent({ userId, email: user.email, eventType: "ADMIN_UNBAN_USER", detail: "Status set to disabled", ip: getClientIp(req), userAgent: getUserAgent(req) });

    return sendJson(res, 200, { message: "User unbanned and set to disabled" });
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: "Server error" });
  }
}

async function handleAdminClearYellow(req, res, session) {
  if (!requireRole(res, session, ["admin"])) return;
  const body = await readJsonBody(req, res);
  if (!body) return;
  const { userId } = body;

  if (!validateId(userId)) return sendJson(res, 400, { error: "Invalid userId" });

  try {
    const user = db.prepare("SELECT id, email FROM users WHERE id = ?").get(userId);
    if (!user) return sendJson(res, 404, { error: "User not found" });

    clearYellowStatus(userId);
    logSecurityEvent("ADMIN_CLEAR_YELLOW", {
      userId: session.userId,
      role: session.role,
      detail: `Cleared yellow flag for user id=${userId}`,
    });
    recordAuthEvent({ userId, email: user.email, eventType: "ADMIN_CLEAR_YELLOW", ip: getClientIp(req), userAgent: getUserAgent(req) });

    return sendJson(res, 200, { message: "Yellow flag cleared" });
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: "Server error" });
  }
}

async function handleAdminListAuthEvents(req, res, session, query) {
  if (!requireRole(res, session, ["admin"])) return;

  let limit = Number.parseInt(query.limit, 10);
  let offset = Number.parseInt(query.offset, 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > 200) limit = 100;
  if (!Number.isFinite(offset) || offset < 0) offset = 0;

  const where = [];
  const params = [];

  if (query.userId && validateId(query.userId)) {
    where.push("user_id = ?");
    params.push(Number(query.userId));
  }

  if (query.email && validateEmail(query.email)) {
    where.push("LOWER(email) = ?");
    params.push(normalizeEmail(query.email));
  }

  if (query.eventType && typeof query.eventType === "string") {
    where.push("event_type = ?");
    params.push(query.eventType.trim());
  }

  let sql = "SELECT id, user_id, email, event_type, ip, user_agent, detail, created_at FROM auth_events";
  if (where.length) {
    sql += " WHERE " + where.join(" AND ");
  }
  sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
  params.push(limit, offset);

  try {
    const rows = db.prepare(sql).all(...params);
    return sendJson(res, 200, { events: rows, limit, offset });
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: "Server error" });
  }
}

async function handleAdminListBlacklist(req, res, session, query) {
  if (!requireRole(res, session, ["admin"])) return;
  let limit = Number.parseInt(query.limit, 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > 200) limit = 100;

  try {
    const rows = db
      .prepare(
        "SELECT identifier, reason, created_at FROM user_blacklist ORDER BY created_at DESC LIMIT ?"
      )
      .all(limit);
    return sendJson(res, 200, { blacklist: rows, limit });
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// Automated entitlement review/orphaned-role detection
async function handleAdminEntitlementReview(req, res, session) {
  if (!requireRole(res, session, ["admin"])) return;
  try {
    const users = db.prepare('SELECT id, email, name, role, status, last_login, explicit_entitlements, ssn_encrypted FROM users').all();
    const appointments = db.prepare('SELECT id, patient_id, doctor_id, nurse_id FROM appointments').all();
    const assignments = {};
    users.forEach(u => {
      assignments[u.id] = {
        id: u.id,
        name: u.name,
        email: u.email,
        role: u.role,
        status: u.status,
        last_login: u.last_login,
        explicit_entitlements: u.explicit_entitlements || '',
        ssn: u.ssn_encrypted ? decryptText(u.ssn_encrypted) : '',
        assignments: [],
        orphaned: false,
      };
    });
    appointments.forEach(a => {
      if (assignments[a.doctor_id]) {
        assignments[a.doctor_id].assignments.push(`Doctor for appointment ${a.id}`);
      }
      if (assignments[a.nurse_id]) {
        assignments[a.nurse_id].assignments.push(`Nurse for appointment ${a.id}`);
      }
      if (assignments[a.patient_id]) {
        assignments[a.patient_id].assignments.push(`Patient for appointment ${a.id}`);
      }
    });
    Object.values(assignments).forEach(a => {
      const isOrphaned = a.assignments.length === 0 && a.status === 'active' && a.role !== 'admin' && !a.explicit_entitlements;
      if (isOrphaned) {
        a.orphaned = true;
      }
    });
    return sendJson(res, 200, { review: Object.values(assignments) });
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: "Server error" });
  }
}
// Admin list users by role
async function handleAdminListUsers(req, res, session, query) {
  if (!requireRole(res, session, ["admin"])) return;
  const role = query.role;
  try {
    let rows;
    if (role) {
      const stmt = db.prepare(
        `SELECT id, email, name, role, status, watch_status, failed_login_count, mfa_enabled, yellowlisted_at, mfa_secret
         FROM users WHERE role = ? ORDER BY id ASC`
      );
      rows = stmt.all(role);
    } else {
      const stmt = db.prepare(
        `SELECT id, email, name, role, status, watch_status, failed_login_count, mfa_enabled, yellowlisted_at, mfa_secret
         FROM users ORDER BY id ASC`
      );
      rows = stmt.all();
    }

    // Decrypt MFA secrets for admin display. Only admins hit this endpoint (requireRole above).
    const users = rows.map(r => {
      let plainSecret = null;
      try {
        if (r.mfa_secret) {
          plainSecret = decryptText(r.mfa_secret) || null;
        }
      } catch (e) {
        console.error('Failed to decrypt MFA secret for user', r.id, e);
        plainSecret = null;
      }
      return {
        id: r.id,
        email: r.email,
        name: r.name,
        role: r.role,
        status: r.status,
        watch_status: r.watch_status,
        failed_login_count: r.failed_login_count,
        mfa_enabled: r.mfa_enabled,
        yellowlisted_at: r.yellowlisted_at,
        mfaSecret: plainSecret,
        // provide an otpauth URL so admins can open in an authenticator if desired
        otpauthUrl: plainSecret ? generateTotpUri(r.email, plainSecret) : null,
      };
    });

    return sendJson(res, 200, { users });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}


// ---------- Patient Handlers ----------

// Patient applies for appointment
async function handlePatientApplyAppointment(req, res, session) {
  if (!requireRole(res, session, ["patient"])) return;
  const body = await readJsonBody(req, res);
  if (!body) return;
  const { doctorId, datetime } = body;

  if (!validateId(doctorId) || !validateDateTime(datetime)) {
    return sendJson(res, 400, { error: "Invalid input fields" });
  }

  try {
    const docStmt = db.prepare(
      "SELECT id, assigned_nurse_id FROM users WHERE id = ? AND role = 'doctor' AND status = 'active'"
    );
    const doctor = docStmt.get(doctorId);
    if (!doctor) return sendJson(res, 404, { error: "Doctor not found" });

    const ins = db.prepare(
      "INSERT INTO appointments (patient_id, doctor_id, nurse_id, datetime, status) VALUES (?, ?, ?, ?, 'pending')"
    );
    const info = ins.run(
      session.userId,
      doctor.id,
      doctor.assigned_nurse_id || null,
      datetime
    );

    logSecurityEvent("PATIENT_APPLY_APPOINTMENT", {
      userId: session.userId,
      role: session.role,
      detail: `Appointment id=${info.lastInsertRowid} with doctor id=${doctorId}`,
    });

    return sendJson(res, 201, {
      message: "Appointment request submitted",
      appointmentId: info.lastInsertRowid
    });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// Patient view own appointments + diagnosis (with PHI decryption)
async function handlePatientDiagnosis(req, res, session) {
  if (!requireRole(res, session, ["patient"])) return;
  try {
    const apptStmt = db.prepare(
      "SELECT * FROM appointments WHERE patient_id = ? ORDER BY datetime DESC"
    );
    const appointments = apptStmt.all(session.userId);

    let diagnosis = [];
    if (appointments.length > 0) {
      const ids = appointments.map(a => a.id);
      const placeholders = ids.map(() => "?").join(", ");
      const diagStmt = db.prepare(
        `SELECT * FROM diagnosis WHERE appointment_id IN (${placeholders})`
      );
      diagnosis = diagStmt.all(...ids);
    }

    // Decrypt PHI fields
    diagnosis = diagnosis.map(d => {
      const notesDec = d.notes ? decryptText(d.notes) : "";
      const medsDec = d.medications ? decryptText(d.medications) : null;
      return {
        ...d,
        notes: notesDec || "",
        medications: medsDec ? JSON.parse(medsDec) : [],
      };
    });

    return sendJson(res, 200, { appointments, diagnosis });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

async function handlePatientListDoctors(req, res, session) {
  if (!requireRole(res, session, ["patient"])) return;
  try {
    const stmt = db.prepare(
      "SELECT id, name FROM users WHERE role = 'doctor' AND status = 'active' ORDER BY name ASC"
    );
    const doctors = stmt.all();

    return sendJson(res, 200, { doctors });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

async function handleDoctorListNurses(req, res, session) {
  if (!requireRole(res, session, ["doctor"])) return;
  try {
    const stmt = db.prepare(
      "SELECT id, name FROM users WHERE role = 'nurse' AND status = 'active' ORDER BY name ASC"
    );
    const nurses = stmt.all();

    return sendJson(res, 200, { nurses });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// ---------- Doctor Handlers ----------

// Doctor assigns nurse to themselves
async function handleDoctorAssignNurse(req, res, session) {
  if (!requireRole(res, session, ["doctor"])) return;
  const body = await readJsonBody(req, res);
  if (!body) return;
  const { nurseId } = body;

  if (!validateId(nurseId)) return sendJson(res, 400, { error: "Invalid nurseId" });

  try {
    const nurseStmt = db.prepare(
      "SELECT id FROM users WHERE id = ? AND role = 'nurse' AND status = 'active'"
    );
    const nurse = nurseStmt.get(nurseId);
    if (!nurse) return sendJson(res, 404, { error: "Nurse not found" });

    const upd = db.prepare(
      "UPDATE users SET assigned_nurse_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND role = 'doctor' AND status = 'active'"
    );
    const result = upd.run(nurseId, session.userId);
    if (result.changes === 0) {
      return sendJson(res, 409, { error: "Doctor account is not active" });
    }

    logSecurityEvent("DOCTOR_ASSIGN_NURSE", {
      userId: session.userId,
      role: session.role,
      detail: `Assigned nurse id=${nurseId}`,
    });

    return sendJson(res, 200, { message: "Nurse assigned" });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// Doctor sees their appointments
async function handleDoctorAppointments(req, res, session) {
  if (!requireRole(res, session, ["doctor"])) return;
  try {
    const stmt = db.prepare(
      `SELECT a.*, 
              p.name AS patient_name,
              p.email AS patient_email
       FROM appointments a
       JOIN users p ON a.patient_id = p.id
       WHERE a.doctor_id = ?
       ORDER BY a.datetime DESC`
    );
    const rows = stmt.all(session.userId);
    return sendJson(res, 200, { appointments: rows });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// Doctor writes diagnosis (notes encrypted)
// Accept an optional `providedBody` to avoid re-reading the request stream when routing already consumed it.
async function handleDoctorWriteDiagnosis(req, res, session, providedBody) {
  if (!requireRole(res, session, ["doctor"])) return;
  const body = providedBody || await readJsonBody(req, res);
  if (!body) return;
  const diagnosisPayload = validateDiagnosisPayload(body);
  if (!diagnosisPayload.ok) {
    return sendJson(res, 400, { error: diagnosisPayload.error });
  }
  const { appointmentId, notes } = diagnosisPayload;

  try {
    // verify appointment belongs to this doctor
    const apptStmt = db.prepare(
      "SELECT * FROM appointments WHERE id = ? AND doctor_id = ?"
    );
    const appt = apptStmt.get(appointmentId, session.userId);
    if (!appt) return sendJson(res, 404, { error: "Appointment not found" });

    const encNotes = encryptText(notes);

    const upsert = db.prepare(
      `INSERT INTO diagnosis (appointment_id, doctor_id, notes, medications)
       VALUES (?, ?, ?, COALESCE((SELECT medications FROM diagnosis WHERE appointment_id = ?),'')) 
       ON CONFLICT(appointment_id) DO UPDATE SET
         notes = excluded.notes,
         updated_at = CURRENT_TIMESTAMP`
    );
    upsert.run(appointmentId, session.userId, encNotes, appointmentId);

    const updAppt = db.prepare(
      "UPDATE appointments SET status = 'completed', updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    );
    updAppt.run(appointmentId);

    logSecurityEvent("DOCTOR_WRITE_DIAGNOSIS", {
      userId: session.userId,
      role: session.role,
      detail: `Appointment id=${appointmentId}`,
    });

    return sendJson(res, 200, { message: "Diagnosis saved" });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// ---------- Nurse Handlers ----------

// Nurse sees appointments where they are assigned
async function handleNurseAppointments(req, res, session) {
  if (!requireRole(res, session, ["nurse"])) return;
  try {
    const stmt = db.prepare(
      `SELECT a.*, 
              p.name AS patient_name,
              d.name AS doctor_name
       FROM appointments a
       JOIN users p ON a.patient_id = p.id
       JOIN users d ON a.doctor_id = d.id
       WHERE a.nurse_id = ?
       ORDER BY a.datetime DESC`
    );
    const rows = stmt.all(session.userId);
    return sendJson(res, 200, { appointments: rows });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// Nurse writes medications (encrypted)
// Accept an optional `providedBody` to avoid re-reading the request stream when routing already consumed it.
async function handleNurseMedications(req, res, session, providedBody) {
  if (!requireRole(res, session, ["nurse"])) return;
  const body = providedBody || await readJsonBody(req, res);
  if (!body) return;
  const medicationPayload = validateMedicationPayload(body);
  if (!medicationPayload.ok) {
    return sendJson(res, 400, { error: medicationPayload.error });
  }
  const { appointmentId, medications } = medicationPayload;

  try {
    const apptStmt = db.prepare(
      "SELECT * FROM appointments WHERE id = ? AND nurse_id = ?"
    );
    const appt = apptStmt.get(appointmentId, session.userId);
    if (!appt) {
      return sendJson(res, 404, { error: "Appointment not found for this nurse" });
    }

    const medsJson = JSON.stringify(medications);
    const encMeds = encryptText(medsJson);

    const upsert = db.prepare(
      `INSERT INTO diagnosis (appointment_id, doctor_id, notes, medications)
       VALUES (?, ?, '', ?)
       ON CONFLICT(appointment_id) DO UPDATE SET
          medications = excluded.medications,
          updated_at = CURRENT_TIMESTAMP`
    );
    upsert.run(appointmentId, appt.doctor_id, encMeds);

    logSecurityEvent("NURSE_WRITE_MEDICATIONS", {
      userId: session.userId,
      role: session.role,
      detail: `Appointment id=${appointmentId}, medsCount=${medications.length}`,
    });

    return sendJson(res, 200, { message: "Medications saved" });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: "Server error" });
  }
}

// ---------- HTTP Server ----------
// Lockout and backoff config
async function requestHandler(req, res) {
  // Only declare these once at the top of the handler
  const hostHeader = req.headers.host || `localhost:${PORT}`;
  const protocol = req.socket?.encrypted ? "https" : TLS_ENABLED ? "https" : "http";
  const requestUrl = new URL(req.url, `${protocol}://${hostHeader}`);
  const { pathname, searchParams } = requestUrl;
  const query = Object.fromEntries(searchParams.entries());

  // --- Always set CORS headers at the very top of the request handler ---
  const origin = req.headers.origin;
  const isDev = process.env.NODE_ENV !== 'production';
  function isLocalOrigin(o) {
    if (!o) return false;
    try {
      const u = new URL(o);
      const h = u.hostname;
      return h === 'localhost' || h === '127.0.0.1' || h.startsWith('192.168.') || h.startsWith('10.') || h.startsWith('172.');
    } catch (e) {
      return false;
    }
  }

  // Echo allowed development origins (or known local network ranges), otherwise fall back
  if (origin && (isDev || isLocalOrigin(origin))) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else if (origin && allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else if (!origin && isDev) {
    // No Origin header (file:// or some local clients) — allow for local dev
    res.setHeader("Access-Control-Allow-Origin", "*");
  } else {
    // Explicitly block unknown cross-origins in non-dev by returning null
    res.setHeader("Access-Control-Allow-Origin", "null");
  }
  console.debug(`[CORS] origin=${origin} isDev=${isDev} allowedOrigins=${Array.from(allowedOrigins).join(',')}`);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token");
  res.setHeader("Vary", "Origin"); // better with CORS caching
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // Preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  // ABAC middleware: helper to check contextual access
  async function requireAbac(action, context) {
    if (!requireSession(res, session)) return false;
    if (!evaluateAccess(session, context, action)) {
      logSecurityEvent("FORBIDDEN_ABAC", { userId: session?.userId, role: session?.role, action, context });
      sendJson(res, 403, { error: "Forbidden by policy" });
      return false;
    }
    return true;
  }

  // Refresh token endpoint
  if (pathname === "/api/refresh" && req.method === "POST") {
    const body = await readJsonBody(req, res);
    if (!body || typeof body.refreshToken !== "string") {
      return sendJson(res, 400, { error: "refreshToken is required" });
    }
    const now = Date.now();
    // Find session by refresh token
    const row = db.prepare(
      `SELECT * FROM user_sessions WHERE refresh_token = ?`
    ).get(body.refreshToken);
    if (!row) {
      logSecurityEvent("REFRESH_TOKEN_INVALID", { detail: "Not found" });
      return sendJson(res, 401, { error: "Invalid refresh token" });
    }
    // Check expiry
        if (row.refresh_expires_at && now >= Date.parse(row.refresh_expires_at)) {
          logSecurityEvent("REFRESH_TOKEN_EXPIRED", { userId: row.user_id });
          // Revoke session
          db.prepare("DELETE FROM user_sessions WHERE token = ?").run(row.token);
          return sendJson(res, 401, { error: "Refresh token expired" });
        }
        // Enforce rotation: only allow previous token for a short window (e.g., 30s)
        if (row.refresh_prev_token && body.refreshToken === row.refresh_prev_token) {
          const rotatedAt = row.refresh_rotated_at ? Date.parse(row.refresh_rotated_at) : 0;
          if (now - rotatedAt > 30000) { // 30s window
            logSecurityEvent("REFRESH_TOKEN_REUSE_DETECTED", { userId: row.user_id });
            db.prepare("DELETE FROM user_sessions WHERE token = ?").run(row.token);
            return sendJson(res, 401, { error: "Refresh token reuse detected" });
          }
        }
        // Rotate refresh token
        const newRefreshToken = generateToken();
        const newAccessToken = generateToken();
        const newRefreshExpiresAt = now + 7 * 24 * 60 * 60 * 1000;
        // Update session
        db.prepare(
          `UPDATE user_sessions SET
            token = ?,
            refresh_prev_token = refresh_token,
            refresh_token = ?,
            refresh_expires_at = ?,
            refresh_rotated_at = ?
           WHERE token = ?`
        ).run(
          newAccessToken,
          newRefreshToken,
          new Date(newRefreshExpiresAt).toISOString(),
          new Date(now).toISOString(),
          row.token
        );
        // Update in-memory session
        const oldSession = sessions.get(row.token);
        if (oldSession) {
          sessions.delete(row.token);
          oldSession.token = newAccessToken;
          oldSession.refreshToken = newRefreshToken;
          oldSession.refreshExpiresAt = newRefreshExpiresAt;
          oldSession.refreshRotatedAt = now;
          oldSession.refreshPrevToken = row.refresh_token;
          sessions.set(newAccessToken, oldSession);
        }
        logSecurityEvent("REFRESH_TOKEN_ROTATED", { userId: row.user_id });
        // Include CSRF token derived from user id so frontend can continue to supply it
        const csrfToken = crypto.createHmac('sha256', CSRF_SECRET).update(String(row.user_id)).digest('hex');
        return sendJson(res, 200, {
          token: newAccessToken,
          refreshToken: newRefreshToken,
          refreshExpiresAt: new Date(newRefreshExpiresAt).toISOString(),
          csrfToken,
        });
        }
      // (Removed duplicate declaration of hostHeader, protocol, requestUrl, pathname, searchParams, query)

  const ip = getClientIp(req);

  // Enforce HTTPS for all requests
  if (enforceHttps(req, res)) return;
  try {
    await applyHelmet(req, res);
  } catch (err) {
    console.error("Failed to apply security headers", err);
    return sendJson(res, 500, { error: "Server error" });
  }

  // Rate limiting per IP (all API endpoints)
  if (!checkRateLimit(ip)) {
    logSecurityEvent("RATE_LIMIT_HIT", { ip, detail: pathname });
    return sendJson(res, 429, { error: "Too many requests from this IP" });
  }

  const session = getSession(req);
  console.log(`[REQ] ${req.method} ${pathname} origin=${origin} ip=${ip} hasSession=${Boolean(session)}`);

  // --- CSRF Token Validation for state-changing requests ---
  // Exclude login and password reset endpoints from CSRF validation
  // Exclude login, signup and password-reset endpoints from CSRF validation
  const csrfRequired = ["POST", "PUT", "DELETE"].includes(req.method)
    && pathname !== "/api/login"
    && pathname !== "/api/signup"
    && !pathname.startsWith("/api/password-reset");
  if (csrfRequired) {
    const csrfToken = req.headers["x-csrf-token"] || (req.body && req.body.csrfToken);
    const sessionId = session?.userId || session?.token || "";
    if (!validateCsrfToken(sessionId, csrfToken)) {
      return sendJson(res, 403, { error: "Invalid or missing CSRF token" });
    }
  }

  // Rate limiting per IP (all API endpoints)
  if (!checkRateLimit(ip)) {
    logSecurityEvent("RATE_LIMIT_HIT", { ip, detail: pathname });
    return sendJson(res, 429, { error: "Too many requests from this IP" });
  }

  // session already initialized above

  try {
    // Auth
        // --- Password Reset Endpoints ---
        if (pathname === '/api/password-reset/request' && req.method === 'POST') {
          const { email } = await readJsonBody(req, res);
          const token = setPasswordResetToken(email);
          if (!token) return sendJson(res, 404, { error: 'User not found' });
          return sendJson(res, 200, { message: 'Reset requested', token }); // In real app, do not send token to client
        }
        if (pathname === '/api/password-reset/submit' && req.method === 'POST') {
          const { token, newPassword } = await readJsonBody(req, res);
          const userId = validatePasswordResetToken(token);
          if (!userId) return sendJson(res, 400, { error: 'Invalid or expired token' });
          // Password policy
          if (!newPassword || newPassword.length < 12) return sendJson(res, 400, { error: 'Password too short' });
          const hash = hashPassword(newPassword);
          db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, userId);
          clearPasswordResetToken(token);
          db.prepare('INSERT INTO audit_log (event, user_id, detail, created_at) VALUES (?, ?, ?, ?)').run('PASSWORD_RESET_COMPLETE', userId, 'Password changed', Date.now());
          return sendJson(res, 200, { message: 'Password reset successful' });
        }
    if (pathname === "/api/signup" && req.method === "POST") {
      return handleSignup(req, res);
    }
    if (pathname === "/api/login" && req.method === "POST") {
      // Monitor for brute force: log alert if >3 failed attempts in 5 min
      const key = req.body?.email + "|" + ip;
      const entry = loginAttempts.get(key);
      if (entry && entry.attempts > 3 && Date.now() - entry.firstAttempt < 5 * 60 * 1000) {
        logAlert("BRUTE_FORCE_ATTEMPT", { email: req.body?.email, ip, attempts: entry.attempts });
      }
      return handleLogin(req, res, ip);
    }
    if (pathname === "/api/oidc/login" && req.method === "GET") {
      return handleOidcLogin(req, res);
    }
    if (pathname === "/api/oidc/callback" && req.method === "GET") {
      return handleOidcCallback(req, res);
    }
    if (pathname === "/api/change-password" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleChangePassword(req, res, session);
    }
    if (pathname === "/api/logout" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleLogout(req, res, session);
    }
    if (pathname === "/api/session/active" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handleListOwnSessions(req, res, session);
    }
    if (pathname === "/api/session/revoke" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleRevokeOwnSessions(req, res, session);
    }

    // Admin
    if (pathname === "/api/admin/create-user" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleAdminCreateUser(req, res, session);
    }
    if (pathname === "/api/admin/set-mfa" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleAdminSetMfa(req, res, session);
    }
    if (pathname === "/api/admin/delete-user" && req.method === "DELETE") {
      if (!requireSession(res, session)) return;
      return handleAdminDisableUser(req, res, session);
    }
    if (pathname === "/api/admin/restore-user" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleAdminRestoreUser(req, res, session);
    }
    if (pathname === "/api/admin/ban-user" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleAdminBanUser(req, res, session);
    }
    if (pathname === "/api/admin/unban-user" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleAdminUnbanUser(req, res, session);
    }
    if (pathname === "/api/admin/clear-yellow" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleAdminClearYellow(req, res, session);
    }
    if (pathname === "/api/admin/users" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handleAdminListUsers(req, res, session, query);
    }
    if (pathname === "/api/admin/auth-events" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handleAdminListAuthEvents(req, res, session, query);
    }
    if (pathname === "/api/admin/locked-accounts" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handleAdminLockedAccounts(req, res, session);
    }
    if (pathname === "/api/admin/break-glass" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handleAdminBreakGlass(req, res, session);
    }
    if (pathname === "/api/break-glass" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      logAlert("BREAK_GLASS_REQUESTED", { userId: session.userId, email: session.email });
      return handleCreateBreakGlass(req, res, session);
    }
    if (pathname === "/api/admin/break-glass/approve" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleApproveBreakGlass(req, res, session);
    }
    if (pathname === "/api/admin/break-glass/revoke" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleRevokeBreakGlass(req, res, session);
    }
    if (pathname === "/api/admin/entitlement-review" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handleAdminEntitlementReview(req, res, session);
    }
    // Admin: rotate SSN encryption key for all users
    if (pathname === "/api/admin/rotate-ssn-key" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleAdminRotateSsnKey(req, res, session);
    }
    if (pathname === "/api/admin/break-glass" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handleAdminBreakGlass(req, res, session);
    }


    if (pathname === "/api/admin/blacklist" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handleAdminListBlacklist(req, res, session, query);
    }
    if (pathname === "/api/admin/sessions" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handleAdminListSessions(req, res, session);
    }
    if (pathname === "/api/admin/sessions/revoke" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleAdminRevokeSession(req, res, session);
    }

    // Patient
    if (pathname === "/api/patient/apply-appointment" && req.method === "POST") {
      // ABAC: patient can apply for own, doctor/nurse can assign
      const patientId = session.userId;
      const context = { patientId };
      if (!await requireAbac("apply_appointment", context)) return;
      return handlePatientApplyAppointment(req, res, session);
    }
    if (pathname === "/api/patient/diagnosis" && req.method === "GET") {
      // ABAC: patient can view own, doctor/nurse can view assigned
      const patientId = session.userId;
      const context = { patientId };
      if (!await requireAbac("view_diagnosis", context)) return;
      return handlePatientDiagnosis(req, res, session);
    }
    if (pathname === "/api/patient/doctors" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handlePatientListDoctors(req, res, session);
    }

    // Doctor
    if (pathname === "/api/doctor/assign-nurse" && req.method === "POST") {
      if (!requireSession(res, session)) return;
      return handleDoctorAssignNurse(req, res, session);
    }
    if (pathname === "/api/doctor/appointments" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handleDoctorAppointments(req, res, session);
    }
    if (pathname === "/api/doctor/nurses" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handleDoctorListNurses(req, res, session);
    }
    if (pathname === "/api/doctor/diagnosis" && req.method === "POST") {
      // ABAC: doctor can write for assigned, nurse can assist
      const body = await readJsonBody(req, res);
      const context = { patientId: body?.appointmentId ? db.prepare('SELECT patient_id FROM appointments WHERE id = ?').get(body.appointmentId)?.patient_id : null };
      if (!await requireAbac("write_diagnosis", context)) return;
      return handleDoctorWriteDiagnosis(req, res, session, body);
    }

    // Nurse
    if (pathname === "/api/nurse/appointments" && req.method === "GET") {
      if (!requireSession(res, session)) return;
      return handleNurseAppointments(req, res, session);
    }
    if (pathname === "/api/nurse/medications" && req.method === "POST") {
      // ABAC: nurse can write for assigned
      const body = await readJsonBody(req, res);
      const context = { patientId: body?.appointmentId ? db.prepare('SELECT patient_id FROM appointments WHERE id = ?').get(body.appointmentId)?.patient_id : null };
      if (!await requireAbac("write_medications", context)) return;
      return handleNurseMedications(req, res, session, body);
    }

    // 404
    sendJson(res, 404, { error: "Not found" });
  } catch (e) {
    console.error(e);
    logSecurityEvent("SERVER_ERROR", { detail: e.message || String(e) });
    sendJson(res, 500, { error: "Server error" });
  }
}

let server;
if (TLS_ENABLED) {
  try {
    const tlsOptions = {
      key: fs.readFileSync(path.resolve(TLS_KEY_PATH)),
      cert: fs.readFileSync(path.resolve(TLS_CERT_PATH)),
    };
    if (TLS_CA_PATH) {
      tlsOptions.ca = fs.readFileSync(path.resolve(TLS_CA_PATH));
    }
    server = https.createServer(tlsOptions, requestHandler);
    console.log("TLS enabled; certificate loaded from", path.resolve(TLS_CERT_PATH));
  } catch (err) {
    console.error("Failed to load TLS materials", err);
    process.exit(1);
  }
} else {
  server = http.createServer(requestHandler);
}

server.listen(PORT, () => {
  const scheme = TLS_ENABLED ? "https" : "http";
  console.log(`🚀 Server running on ${scheme}://localhost:${PORT}`);
});

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    if (
      (session.expiresAt && now >= session.expiresAt) ||
      (session.absoluteExpiresAt && now >= session.absoluteExpiresAt)
    ) {
      sessions.delete(token);
      deleteSessionRecord(token);
    }
  }
  try {
    db.prepare(
      `DELETE FROM user_sessions
       WHERE (expires_at IS NOT NULL AND expires_at <= ?)
          OR (absolute_expires_at IS NOT NULL AND absolute_expires_at <= ?)`
    ).run(new Date(now).toISOString(), new Date(now).toISOString());
  } catch (err) {
    console.error("Failed to purge expired sessions", err);
  }

}, SESSION_CLEANUP_INTERVAL_MS).unref();
});