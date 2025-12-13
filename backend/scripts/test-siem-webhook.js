#!/usr/bin/env node

require("dotenv").config();

const http = require("http");
const https = require("https");
const { URL } = require("url");

const endpoint = process.env.HCA_LOG_WEBHOOK || process.env.HCA_SIEM_WEBHOOK || "";

if (!endpoint) {
  console.error("❌ No SIEM webhook configured. Set HCA_LOG_WEBHOOK (or legacy HCA_SIEM_WEBHOOK).\n");
  process.exitCode = 1;
  return;
}

let url;
try {
  url = new URL(endpoint);
} catch (err) {
  console.error("❌ Invalid webhook URL:", err.message || err);
  process.exitCode = 1;
  return;
}

const payload = {
  ts: new Date().toISOString(),
  eventType: "SIEM_TEST_EVENT",
  detail: "Manual connectivity check via npm run siem:test",
  source: "healthcurealpha-backend",
};

const data = JSON.stringify(payload);
const isHttps = url.protocol === "https:";
const transport = isHttps ? https : http;

const options = {
  hostname: url.hostname,
  port: url.port || (isHttps ? 443 : 80),
  path: `${url.pathname}${url.search || ""}`,
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(data),
  },
  timeout: 5000,
};

const req = transport.request(options, res => {
  const chunks = [];
  res.on("data", chunk => chunks.push(chunk));
  res.on("end", () => {
    const body = Buffer.concat(chunks).toString("utf8");
    console.log(`✅ Webhook responded with ${res.statusCode}`);
    if (body) {
      console.log(body);
    }
  });
});

req.on("timeout", () => {
  console.error("⚠️ Webhook request timed out after 5 seconds.");
  req.destroy();
  process.exitCode = 1;
});

req.on("error", err => {
  console.error("⚠️ Failed to reach SIEM webhook:", err.message || err);
  process.exitCode = 1;
});

req.write(data);
req.end();
