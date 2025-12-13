// backend/logger.js
const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");

const { URL } = require("url");

const LOG_FILE = path.join(__dirname, "security.log");
const SIEM_ENDPOINT = process.env.HCA_LOG_WEBHOOK || process.env.HCA_SIEM_WEBHOOK || "";
let siemUrl;
let siemInitWarned = false;

if (SIEM_ENDPOINT) {
  try {
    siemUrl = new URL(SIEM_ENDPOINT);
  } catch (err) {
    console.error("❌ Invalid HCA_LOG_WEBHOOK URL: ", err.message || err);
    siemUrl = null;
  }
} else {
  console.info("ℹ️ Security logs will remain local; set HCA_LOG_WEBHOOK to forward to SIEM.");
}

function forwardToSiem(entry) {
  if (!siemUrl) return;

  const data = JSON.stringify(entry);
  const isHttps = siemUrl.protocol === "https:";
  const transport = isHttps ? https : http;

  const options = {
    hostname: siemUrl.hostname,
    port: siemUrl.port || (isHttps ? 443 : 80),
    path: siemUrl.pathname + (siemUrl.search || ""),
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(data),
    },
  };

  const req = transport.request(options, res => {
    // Drain response to free socket
    res.on("data", () => {});
  });

  req.on("error", err => {
    if (!siemInitWarned) {
      console.error("⚠️ Failed to forward security log to SIEM:", err.message || err);
      siemInitWarned = true;
    }
  });

  req.write(data);
  req.end();
}

/**
 * Lightweight security/audit logger.
 * Writes JSON lines to backend/security.log
 *
 * eventType: string (e.g., LOGIN_SUCCESS, LOGIN_FAILURE, ADMIN_CREATE_USER, etc.)
 * options: { userId, role, ip, detail }
 */
function logSecurityEvent(eventType, { userId = null, role = null, ip = null, detail = "" } = {}) {
  const ts = new Date().toISOString();
  const entry = {
    ts,
    eventType,
    userId,
    role,
    ip,
    detail,
  };

  const line = JSON.stringify(entry) + "\n";

  fs.appendFile(LOG_FILE, line, err => {
    if (err) {
      console.error("❌ Failed to write security log:", err.message || err);
    }
  });

  if (siemUrl) {
    setImmediate(() => forwardToSiem(entry));
  }
}

function logAlert(eventType, detail) {
  const ts = new Date().toISOString();
  const entry = { ts, eventType, alert: true, detail };
  fs.appendFile(LOG_FILE, JSON.stringify(entry) + "\n", err => {
    if (err) {
      console.error("❌ Failed to write alert log:", err.message || err);
    }
  });
  if (siemUrl) {
    setImmediate(() => forwardToSiem(entry));
  }
}

module.exports = {
  logSecurityEvent,
  logAlert,
};
