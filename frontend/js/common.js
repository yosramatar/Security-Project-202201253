// frontend/js/common.js

// --- XSS Mitigation: Input Sanitization ---
export function sanitizeInput(str) {
  if (typeof str !== "string") return "";
  return str.replace(/[&<>'"`]/g, function (c) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '`': '&#96;'
    }[c] || c;
  });
}

const API_BASE = "http://localhost:3000";

// ---- Theme handling ----
function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("hcTheme", theme);
}

function initThemeToggle() {
  const btn = document.getElementById("themeToggle");
  const saved = localStorage.getItem("hcTheme") || "light";
  setTheme(saved);

  if (!btn) return;

  function updateLabel() {
    const current = document.documentElement.dataset.theme || "light";
    btn.textContent = current === "light" ? "Dark mode" : "Light mode";
  }

  updateLabel();

  btn.addEventListener("click", () => {
    const current = document.documentElement.dataset.theme || "light";
    const next = current === "light" ? "dark" : "light";
    setTheme(next);
    updateLabel();
  });
}

// ---- Session helpers ----
function saveSession(payload) {
  localStorage.setItem("hcSession", JSON.stringify(payload));
}

function getSession() {
  const raw = localStorage.getItem("hcSession");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function clearSession() {
  localStorage.removeItem("hcSession");
}

// Authenticated fetch helper
async function authFetch(path, options = {}) {
  const session = getSession();
  const headers = Object.assign({}, options.headers || {});
  headers["Content-Type"] = "application/json";

  if (session && session.token) {
    headers["Authorization"] = "Bearer " + session.token;
  }

  const res = await fetch(API_BASE + path, {
    ...options,
    headers
  });

  return res;
}

// Require a role on dashboard pages
function requireRolePage(allowedRoles) {
  const session = getSession();
  if (!session || (allowedRoles && !allowedRoles.includes(session.role))) {
    window.location.href = "index.html";
    return null;
  }

  const nameEl = document.getElementById("userNameLabel");
  const roleEl = document.getElementById("userRoleLabel");
  if (nameEl) nameEl.textContent = session.name;
  if (roleEl) roleEl.textContent = session.role;

  const logoutBtn = document.getElementById("logoutBtn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
      clearSession();
      window.location.href = "index.html";
    });
  }

  return session;
}

// Init for every page
document.addEventListener("DOMContentLoaded", () => {
  initThemeToggle();
});

// CSP is enforced by backend via helmet (see backend/server.js)
