// --- Password Reset UI Logic ---
document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("login-form");
  const resetRequestForm = document.getElementById("reset-request-form");
  const resetConfirmForm = document.getElementById("reset-confirm-form");
  const forgotPasswordLink = document.getElementById("forgot-password-link");
  const backToLoginLink = document.getElementById("back-to-login-link");
  const backToLoginLink2 = document.getElementById("back-to-login-link2");
  const resetRequestMsg = document.getElementById("reset-request-message");
  const resetConfirmMsg = document.getElementById("reset-confirm-message");

  function showForm(form) {
    [loginForm, resetRequestForm, resetConfirmForm].forEach(f => f.classList.add("hidden"));
    form.classList.remove("hidden");
  }

  if (forgotPasswordLink) {
    forgotPasswordLink.addEventListener("click", e => {
      e.preventDefault();
      showForm(resetRequestForm);
    });
  }
  if (backToLoginLink) {
    backToLoginLink.addEventListener("click", e => {
      e.preventDefault();
      showForm(loginForm);
    });
  }
  if (backToLoginLink2) {
    backToLoginLink2.addEventListener("click", e => {
      e.preventDefault();
      showForm(loginForm);
    });
  }

  if (resetRequestForm) {
    resetRequestForm.addEventListener("submit", async e => {
      e.preventDefault();
      resetRequestMsg.textContent = "";
      const email = document.getElementById("reset-email").value.trim();
      if (!email) {
        resetRequestMsg.textContent = "Email required.";
        resetRequestMsg.className = "form-message error";
        return;
      }
      try {
        const res = await fetch("/api/password-reset/request", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email })
        });
        const data = await res.json();
        if (res.ok) {
          resetRequestMsg.textContent = "Reset requested. Check your email for the token.";
          resetRequestMsg.className = "form-message success";
          showForm(resetConfirmForm);
        } else {
          resetRequestMsg.textContent = data.error || "Request failed.";
          resetRequestMsg.className = "form-message error";
        }
      } catch (err) {
        resetRequestMsg.textContent = "Network error.";
        resetRequestMsg.className = "form-message error";
      }
    });
  }

  if (resetConfirmForm) {
    resetConfirmForm.addEventListener("submit", async e => {
      e.preventDefault();
      resetConfirmMsg.textContent = "";
      const token = document.getElementById("reset-token").value.trim();
      const newPassword = document.getElementById("reset-new-password").value;
      if (!token || !newPassword) {
        resetConfirmMsg.textContent = "Token and new password required.";
        resetConfirmMsg.className = "form-message error";
        return;
      }
      try {
        const res = await fetch("/api/password-reset/submit", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token, newPassword })
        });
        const data = await res.json();
        if (res.ok) {
          resetConfirmMsg.textContent = "Password reset successful. You can now log in.";
          resetConfirmMsg.className = "form-message success";
          showForm(loginForm);
        } else {
          resetConfirmMsg.textContent = data.error || "Reset failed.";
          resetConfirmMsg.className = "form-message error";
        }
      } catch (err) {
        resetConfirmMsg.textContent = "Network error.";
        resetConfirmMsg.className = "form-message error";
      }
    });
  }
});
// OIDC SSO login handler
document.addEventListener("DOMContentLoaded", () => {
  const oidcBtn = document.getElementById("oidc-login-btn");
  if (oidcBtn) {
    oidcBtn.addEventListener("click", () => {
      window.location.href = `${API_BASE}/oidc/login`;
    });
  }
  // Handle OIDC login success redirect
  if (window.location.pathname.endsWith("/login-oidc-success")) {
    const url = new URL(window.location.href);
    const token = url.searchParams.get("token");
    if (token) {
      // Fetch user info using token
      fetch(`${API_BASE}/session/active`, {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then(r => r.json())
        .then(data => {
          if (data.sessions && data.sessions.length) {
            // Use first session for now
            const session = data.sessions.find(s => s.current) || data.sessions[0];
            // Store token and session metadata
            localStorage.setItem("hc_token", token);
            // If backend provided a CSRF token (useful after OIDC flows), store it
            if (data.csrfToken) localStorage.setItem("hc_csrf", data.csrfToken);
            localStorage.setItem("hc_role", session.role || "");
            localStorage.setItem("hc_name", session.name || "");
            localStorage.setItem("hc_userId", session.userId || "");
            localStorage.setItem("hc_session_expires", session.expiresAt || "");
            window.location.href = "dashboard.html";
          } else {
            alert("SSO login failed: no session info");
            window.location.href = "index.html";
          }
        })
        .catch(() => {
          alert("SSO login failed");
          window.location.href = "index.html";
        });
    } else {
      alert("SSO login failed: missing token");
      window.location.href = "index.html";
    }
  }
});
// frontend/js/auth.js

// Determine API origin:
// - If frontend is served on port 8080 (local static server) assume backend runs on https://localhost:3000
// - Otherwise use the page origin so HTTPS pages call HTTPS backend on same origin
const API_ORIGIN = (typeof window !== 'undefined' && window.location && window.location.origin)
  ? (window.location.hostname === 'localhost' && window.location.port === '8080' ? 'https://localhost:3000' : window.location.origin)
  : 'http://localhost:3000';
const API_BASE = `${API_ORIGIN}/api`;
const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000; // must align with backend

const STORAGE_KEYS = {
  token: "hc_token",
  refreshToken: "hc_refresh_token",
  refreshExpires: "hc_refresh_expires",
  csrf: "hc_csrf",
  role: "hc_role",
  name: "hc_name",
  userId: "hc_userId",
  sessionExpires: "hc_session_expires",
};

function storeValue(key, value) {
  if (value === null || value === undefined) {
    localStorage.removeItem(key);
  } else {
    localStorage.setItem(key, value);
  }
}

function clearStoredSession() {
  Object.values(STORAGE_KEYS).forEach(key => localStorage.removeItem(key));
}

function getSessionInfo() {
  const token = localStorage.getItem(STORAGE_KEYS.token) || "";
  const refreshToken = localStorage.getItem(STORAGE_KEYS.refreshToken) || "";
  const csrf = localStorage.getItem(STORAGE_KEYS.csrf) || "";
  const refreshExpiresRaw = localStorage.getItem(STORAGE_KEYS.refreshExpires);
  const refreshExpiresAt = refreshExpiresRaw ? Date.parse(refreshExpiresRaw) : null;
  const role = localStorage.getItem(STORAGE_KEYS.role) || "";
  const name = localStorage.getItem(STORAGE_KEYS.name) || "";
  const userIdRaw = localStorage.getItem(STORAGE_KEYS.userId);
  const userId = userIdRaw ? Number(userIdRaw) : null;
  const expiresRaw = localStorage.getItem(STORAGE_KEYS.sessionExpires);
  const expiresAt = expiresRaw ? Date.parse(expiresRaw) : null;

  return { token, refreshToken, refreshExpiresAt, role, name, userId, expiresAt, csrf };
}

function buildApiUrl(path) {
  if (/^https?:/i.test(path)) return path;
  if (path.startsWith("/")) return `${API_ORIGIN}${path}`;
  return `${API_ORIGIN}/${path}`;
}

function handleSessionExpired() {
  clearStoredSession();
  const isOnLogin = /index\.html$/i.test(window.location.pathname);
  if (!isOnLogin) {
    window.location.href = "index.html";
  }
}

function applySessionToDom(session) {
  const label = session.name && session.role ? `${session.name} (${session.role})` : "";
  const badge = document.getElementById("current-user-badge");
  if (badge && label) {
    badge.textContent = label;
  }
  document.querySelectorAll("[data-current-user]").forEach(el => {
    el.textContent = label;
  });
}

async function logoutUser(event) {
  if (event && typeof event.preventDefault === "function") {
    event.preventDefault();
  }

  const session = getSessionInfo();

  try {
    if (session.token) {
      await window.apiFetch("/api/logout", { method: "POST" });
    }
  } catch (err) {
    console.warn("Logout request failed", err);
  } finally {
    clearStoredSession();
    window.location.href = "index.html";
  }
}

function attachLogoutHandler() {
  const buttons = [
    document.getElementById("logout-btn"),
    document.getElementById("logoutBtn"),
  ].filter(Boolean);

  buttons.forEach(btn => {
    if (!btn.dataset.boundLogout) {
      btn.addEventListener("click", logoutUser);
      btn.dataset.boundLogout = "true";
    }
  });
}

function bumpIdleExpiry() {
  const nextExpiry = new Date(Date.now() + SESSION_IDLE_TIMEOUT_MS).toISOString();
  storeValue(STORAGE_KEYS.sessionExpires, nextExpiry);
}

async function apiFetch(path, options = {}) {
  let session = getSessionInfo();
  let url = buildApiUrl(path);
  let headers = new Headers(options.headers || {});

  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (session.token) {
    headers.set("Authorization", `Bearer ${session.token}`);
  // Attach CSRF token for state-changing requests
  const method = (options.method || "GET").toUpperCase();
  if (["POST", "PUT", "DELETE"].includes(method) && session.csrf) {
    headers.set("X-CSRF-Token", session.csrf);
  }
  }

  let response;
  try {
    response = await fetch(url, { ...options, headers });
  } catch (err) {
    // Browser/network error (could be SSL when backend isn't serving TLS).
    // In local dev, if the API origin is localhost over HTTPS, retry over HTTP.
    try {
      const isLocalHttps = /^https:\/\/localhost(:|$)/i.test(url) || /^https:\/\/localhost(:|$)/i.test(API_ORIGIN);
      if (isLocalHttps) {
        const fallbackUrl = url.replace(/^https:/i, "http:");
        console.warn("apiFetch: HTTPS request failed, retrying over HTTP:", fallbackUrl, err);
        response = await fetch(fallbackUrl, { ...options, headers });
      } else {
        throw err;
      }
    } catch (err2) {
      // Rethrow the original error for clarity
      throw err;
    }
  }
  // If session expired, try refresh
  if ((response.status === 401 || response.status === 403) && session.refreshToken) {
    // Try refresh
    try {
      const refreshRes = await fetch(`${API_BASE}/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: session.refreshToken }),
      });
      const refreshData = await refreshRes.json().catch(() => ({}));
      if (refreshRes.ok && refreshData.token && refreshData.refreshToken) {
        // Store new tokens
        storeValue(STORAGE_KEYS.token, refreshData.token);
        storeValue(STORAGE_KEYS.refreshToken, refreshData.refreshToken);
        if (refreshData.csrfToken) storeValue(STORAGE_KEYS.csrf, refreshData.csrfToken);
        storeValue(STORAGE_KEYS.refreshExpires, refreshData.refreshExpiresAt || "");
        bumpIdleExpiry();
        // Retry original request with new token
        session = getSessionInfo();
        headers.set("Authorization", `Bearer ${session.token}`);
        response = await fetch(url, { ...options, headers });
      } else {
        clearStoredSession();
        handleSessionExpired();
        throw new Error(refreshData.error || "Session expired");
      }
    } catch (err) {
      clearStoredSession();
      handleSessionExpired();
      throw err;
    }
  }

  const text = await response.text();
  let data;
  if (!text) {
    data = {};
  } else {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  const expiryHeader = response.headers.get("x-session-expires");
  if (expiryHeader) {
    storeValue(STORAGE_KEYS.sessionExpires, expiryHeader);
  } else if (session.token && response.ok) {
    bumpIdleExpiry();
  }

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      clearStoredSession();
      handleSessionExpired();
    }
    const error = new Error(typeof data === "object" && data?.error ? data.error : "Request failed");
    error.data = data;
    error.status = response.status;
    throw error;
  }

  return data;
}

function requireRole(allowedRoles = []) {
  const session = getSessionInfo();

  if (!session.token || !session.role) {
    handleSessionExpired();
    return null;
  }

  if (session.expiresAt && session.expiresAt <= Date.now()) {
    handleSessionExpired();
    return null;
  }

  if (Array.isArray(allowedRoles) && allowedRoles.length > 0) {
    if (!allowedRoles.includes(session.role)) {
      handleSessionExpired();
      return null;
    }
  }

  applySessionToDom(session);
  attachLogoutHandler();
  return session;
}

function storeSessionFromLogin(payload) {
  storeValue(STORAGE_KEYS.token, payload.token || "");
  storeValue(STORAGE_KEYS.refreshToken, payload.refreshToken || "");
  storeValue(STORAGE_KEYS.refreshExpires, payload.refreshExpiresAt || "");
  if (payload.csrfToken) storeValue(STORAGE_KEYS.csrf, payload.csrfToken);
  storeValue(STORAGE_KEYS.role, payload.role || "");
  storeValue(STORAGE_KEYS.name, payload.name || "");
  if (payload.userId !== undefined && payload.userId !== null) {
    storeValue(STORAGE_KEYS.userId, String(payload.userId));
  }

  const expires = payload.sessionExpiresAt && !Number.isNaN(Date.parse(payload.sessionExpiresAt))
    ? payload.sessionExpiresAt
    : new Date(Date.now() + SESSION_IDLE_TIMEOUT_MS).toISOString();
  storeValue(STORAGE_KEYS.sessionExpires, expires);
}

window.apiFetch = apiFetch;
window.requireRole = requireRole;
window.logoutUser = logoutUser;
window.clearStoredSession = clearStoredSession;

document.addEventListener("DOMContentLoaded", () => {
  const body = document.body;

  /* =========================
     Theme toggle (supports two ID conventions)
     ========================= */

  const themeToggle = document.getElementById("theme-toggle") || document.getElementById("themeToggle");

  function updateThemeLabel(btn) {
    if (!btn) return;
    const dark = body.classList.contains("theme-dark");
    btn.textContent = dark ? "Light mode" : "Dark mode";
  }

  if (themeToggle) {
    updateThemeLabel(themeToggle);
    themeToggle.addEventListener("click", () => {
      if (body.classList.contains("theme-dark")) {
        body.classList.remove("theme-dark");
        body.classList.add("theme-light");
      } else {
        body.classList.remove("theme-light");
        body.classList.add("theme-dark");
      }
      updateThemeLabel(themeToggle);
    });
  }

  /* =========================
     Tabs (Login / Signup)
     ========================= */

  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".panel");

  function activateTab(targetId) {
    tabs.forEach(t => t.classList.remove("active"));
    panels.forEach(p => p.classList.remove("active"));

    const tab = document.querySelector(`.tab[data-target="${targetId}"]`);
    const panel = document.getElementById(targetId);

    if (tab) tab.classList.add("active");
    if (panel) panel.classList.add("active");
  }

  function showElement(el) {
    if (!el) return;
    el.classList.remove("hidden");
  }

  function hideElement(el) {
    if (!el) return;
    el.classList.add("hidden");
  }

  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const targetId = tab.dataset.target;
      if (targetId) activateTab(targetId);
    });
  });

  if (document.getElementById("login-panel")) {
    activateTab("login-panel");
  }

  /* =========================
     Disable copy/paste on password fields (frontend UX hardening)
     ========================= */

  document.querySelectorAll("input.no-copy").forEach(input => {
    ["copy", "cut", "paste"].forEach(evt => {
      input.addEventListener(evt, e => e.preventDefault());
    });
  });

  /* =========================
     Password show / hide
     ========================= */

  document.querySelectorAll(".toggle-password").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.target;
      const input = document.getElementById(targetId);
      if (!input) return;

      if (input.type === "password") {
        input.type = "text";
        btn.textContent = "Hide";
      } else {
        input.type = "password";
        btn.textContent = "Show";
      }
    });
  });

  /* =========================
     Password strength meter (signup)
     ========================= */

  const signupPassword = document.getElementById("signup-password");
  const pwStrength = document.getElementById("pw-strength");

  function evaluatePassword(pw) {
    return {
      length: pw.length >= 12,
      upper: /[A-Z]/.test(pw),
      lower: /[a-z]/.test(pw),
      digit: /[0-9]/.test(pw),
      special: /[^A-Za-z0-9]/.test(pw),
    };
  }

  function renderPwStrength(pw) {
    if (!pwStrength) return;

    const r = evaluatePassword(pw);

    pwStrength.innerHTML = `
      <div class="pw-rule ${r.length ? "pw-valid" : "pw-invalid"}">
        • Minimum 12 characters
      </div>
      <div class="pw-rule ${r.upper ? "pw-valid" : "pw-invalid"}">
        • One uppercase letter
      </div>
      <div class="pw-rule ${r.lower ? "pw-valid" : "pw-invalid"}">
        • One lowercase letter
      </div>
      <div class="pw-rule ${r.digit ? "pw-valid" : "pw-invalid"}">
        • One number
      </div>
      <div class="pw-rule ${r.special ? "pw-valid" : "pw-invalid"}">
        • One special symbol
      </div>
    `;
  }

  if (signupPassword) {
    renderPwStrength("");
    signupPassword.addEventListener("input", e => {
      renderPwStrength(e.target.value || "");
    });
  }

  function passwordStrongEnough(pw) {
    const r = evaluatePassword(pw);
    return r.length && r.upper && r.lower && r.digit && r.special;
  }

  /* =========================
     Login
     ========================= */

  const loginForm = document.getElementById("login-form");
  const loginMsg = document.getElementById("login-message");
  const loginTotpInput = document.getElementById("login-totp");
  const loginTotpLabel = loginTotpInput?.closest("label");

  // Hide MFA field by default
  if (loginTotpLabel) loginTotpLabel.style.display = "none";

  function setLoginMessage(text, isError = false) {
    if (!loginMsg) return;
    loginMsg.textContent = text;
    loginMsg.classList.toggle("error", isError);
    loginMsg.classList.toggle("success", !isError && !!text);
  }

  async function handleLogin(e) {
    e.preventDefault();
    if (!loginForm) return;

    const email = document.getElementById("login-email")?.value.trim();
    const password = document.getElementById("login-password")?.value;
    const totpCode = loginTotpInput?.value.trim() || "";

    setLoginMessage("");

    if (!email || !password) {
      setLoginMessage("Email and password are required.", true);
      return;
    }

    // If MFA field is hidden, do initial login attempt without totpCode
    if (loginTotpLabel && loginTotpLabel.style.display === "none") {
      try {
        const res = await fetch(`${API_BASE}/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok && data && data.error && /mfa|totp|code/i.test(data.error)) {
          // Show MFA field and ask for code
          if (loginTotpLabel) loginTotpLabel.style.display = "";
          setLoginMessage("MFA code required for this account. Please enter your code.", true);
          loginTotpInput.focus();
          return;
        }
        if (!res.ok) {
          setLoginMessage(data.error || "Login failed.", true);
          return;
        }
        storeSessionFromLogin(data);
        applySessionToDom(getSessionInfo());
        if (loginTotpInput) loginTotpInput.value = "";
        setLoginMessage("Login successful. Redirecting…", false);
        switch (data.role) {
          case "admin":
            window.location.href = "admin.html";
            break;
          case "doctor":
            window.location.href = "doctor.html";
            break;
          case "nurse":
            window.location.href = "nurse.html";
            break;
          default:
            window.location.href = "patient.html";
        }
        return;
      } catch (err) {
        console.error(err);
        setLoginMessage("Network error while logging in.", true);
        return;
      }
    }

    // If MFA field is visible, require 6-digit code
    if (!/^\d{6}$/.test(totpCode)) {
      setLoginMessage("MFA code must be six digits.", true);
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, totpCode }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setLoginMessage(data.error || "Login failed.", true);
        return;
      }
      storeSessionFromLogin(data);
      applySessionToDom(getSessionInfo());
      if (loginTotpInput) loginTotpInput.value = "";
      setLoginMessage("Login successful. Redirecting…", false);
      switch (data.role) {
        case "admin":
          window.location.href = "admin.html";
          break;
        case "doctor":
          window.location.href = "doctor.html";
          break;
        case "nurse":
          window.location.href = "nurse.html";
          break;
        default:
          window.location.href = "patient.html";
      }
    } catch (err) {
      console.error(err);
      setLoginMessage("Network error while logging in.", true);
    }
  }

  if (loginForm) {
    loginForm.addEventListener("submit", handleLogin);
  }

  /* =========================
     Signup (patient only)
     ========================= */

  const signupForm = document.getElementById("signup-form");
  const signupMsg = document.getElementById("signup-message");
  const signupMfaContainer = document.getElementById("signup-mfa-container");
  const signupMfaSecretEl = document.getElementById("signup-mfa-secret");
  const signupMfaUriEl = document.getElementById("signup-mfa-uri");
  const signupMfaCodeInput = document.getElementById("signup-mfa-code");
  const signupMfaMessage = document.getElementById("signup-mfa-message");
  const signupMfaVerifyBtn = document.getElementById("signup-mfa-verify");
  const signupNameInput = document.getElementById("signup-name");
  const signupEmailInput = document.getElementById("signup-email");
  const signupPasswordInput = document.getElementById("signup-password");
  const signupPasswordConfirmInput = document.getElementById("signup-password-confirm");
  let signupContext = null;

  function setSignupMessage(text, isError = false) {
    if (!signupMsg) return;
    signupMsg.textContent = text;
    signupMsg.classList.toggle("error", isError);
    signupMsg.classList.toggle("success", !isError && !!text);
  }

  function setSignupMfaMessage(text, isError = false) {
    if (!signupMfaMessage) return;
    signupMfaMessage.textContent = text;
    signupMfaMessage.className = "form-message";
    if (text) {
      signupMfaMessage.classList.add(isError ? "error" : "success");
    }
  }

  function disableSignupInputs(disabled) {
    [signupNameInput, signupEmailInput, signupPasswordInput, signupPasswordConfirmInput].forEach(input => {
      if (input) input.disabled = disabled;
    });
  }

  function resetSignupFlow() {
    signupContext = null;
    disableSignupInputs(false);
    if (signupMfaCodeInput) signupMfaCodeInput.value = "";
    setSignupMfaMessage("");
    hideElement(signupMfaContainer);
    if (signupMfaUriEl) signupMfaUriEl.href = "#";
    if (signupMfaSecretEl) signupMfaSecretEl.textContent = "";
  }

  async function handleSignup(e) {
    e.preventDefault();
    if (!signupForm) return;

    if (signupContext) {
      setSignupMessage("Complete MFA verification below to finish signup.", true);
      if (signupMfaCodeInput) signupMfaCodeInput.focus();
      return;
    }

    const name = signupNameInput?.value.trim();
    const email = signupEmailInput?.value.trim();
    const password = signupPasswordInput?.value || "";
    const passwordConfirm = signupPasswordConfirmInput?.value || "";

    setSignupMessage("");
    setSignupMfaMessage("");

    if (!name || !email || !password || !passwordConfirm) {
      setSignupMessage("All fields are required.", true);
      return;
    }

    if (password !== passwordConfirm) {
      setSignupMessage("Passwords do not match.", true);
      return;
    }

    if (!passwordStrongEnough(password)) {
      setSignupMessage("Password is not strong enough. Please satisfy all the rules.", true);
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phase: "init", name, email, password }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        disableSignupInputs(false);
        hideElement(signupMfaContainer);
        setSignupMessage(data.error || "Failed to create account.", true);
        return;
      }

      signupContext = {
        signupToken: data.signupToken,
        email,
        secret: data.secret,
        otpauthUrl: data.otpauthUrl,
      };

      disableSignupInputs(true);

      if (signupMfaSecretEl) signupMfaSecretEl.textContent = data.secret || "";
      if (signupMfaUriEl) {
        if (data.otpauthUrl) {
          signupMfaUriEl.href = data.otpauthUrl;
          signupMfaUriEl.target = "_blank";
          signupMfaUriEl.classList.remove("disabled");
          signupMfaUriEl.title = data.otpauthUrl;
        } else {
          signupMfaUriEl.href = "#";
          signupMfaUriEl.removeAttribute("target");
          signupMfaUriEl.classList.add("disabled");
          signupMfaUriEl.title = "";
        }
      }

      showElement(signupMfaContainer);
      setSignupMessage("MFA secret generated. Enter the code below to activate your account.", false);
      setSignupMfaMessage("Waiting for MFA verification...");
      if (signupMfaCodeInput) {
        signupMfaCodeInput.value = "";
        signupMfaCodeInput.focus();
      }
    } catch (err) {
      console.error(err);
      disableSignupInputs(false);
      hideElement(signupMfaContainer);
      setSignupMessage("Network error while creating account.", true);
    }
  }

  if (signupForm) {
    signupForm.addEventListener("submit", handleSignup);
  }

  if (signupMfaVerifyBtn) {
    signupMfaVerifyBtn.addEventListener("click", async () => {
      if (!signupContext) {
        setSignupMfaMessage("Submit the signup form first to generate an MFA secret.", true);
        return;
      }

      const totpCode = signupMfaCodeInput?.value.trim() || "";
      if (!/^\d{6}$/.test(totpCode)) {
        setSignupMfaMessage("Enter a valid six-digit MFA code.", true);
        signupMfaCodeInput?.focus();
        return;
      }

      signupMfaVerifyBtn.disabled = true;
      signupMfaVerifyBtn.classList.add("loading");
      setSignupMfaMessage("Verifying code…");

      try {
        const res = await fetch(`${API_BASE}/signup`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            phase: "verify",
            signupToken: signupContext.signupToken,
            totpCode,
          }),
        });

        const data = await res.json().catch(() => ({}));

        if (!res.ok) {
          setSignupMfaMessage(data.error || "Verification failed.", true);
          return;
        }

        setSignupMfaMessage(data.message || "MFA verified.");
        setSignupMessage("Account activated. You can log in now.", false);

        resetSignupFlow();
        if (signupForm) signupForm.reset();
        if (pwStrength) renderPwStrength("");
        activateTab("login-panel");
      } catch (err) {
        console.error(err);
        setSignupMfaMessage("Network error while verifying code.", true);
      } finally {
        signupMfaVerifyBtn.disabled = false;
        signupMfaVerifyBtn.classList.remove("loading");
      }
    });
  }

  /* =========================
     Change password (all authenticated roles)
     ========================= */

  const changePwBtn = document.getElementById("changePasswordBtn");

  if (changePwBtn) {
    function ensureChangePasswordModal() {
      let modal = document.getElementById("changePasswordModal");
      if (modal) return modal;

      modal = document.createElement("div");
      modal.id = "changePasswordModal";
      modal.className = "modal-overlay";
      modal.innerHTML = `
        <div class="modal-card glass-card">
          <h2>Change password</h2>
          <form class="form-vertical" autocomplete="off">
            <label>
              Current password
              <input type="password" name="currentPassword" autocomplete="current-password" required />
            </label>
            <label>
              New password
              <input type="password" name="newPassword" autocomplete="new-password" required />
            </label>
            <label>
              Confirm new password
              <input type="password" name="confirmPassword" autocomplete="new-password" required />
            </label>
            <button type="submit" class="btn-primary">Update password</button>
          </form>
          <div class="form-message" data-change-message></div>
          <section class="session-manager">
            <h3>Active sessions</h3>
            <p class="muted">Review devices signed in to your account. Revoke anything you do not recognise.</p>
            <div class="session-list" data-session-list>
              <p class="muted">Loading sessions…</p>
            </div>
            <div class="session-actions">
              <button type="button" class="btn-outline" data-refresh-sessions>Refresh</button>
              <button type="button" class="btn-danger" data-revoke-all>Sign out other sessions</button>
            </div>
            <div class="form-message" data-session-message></div>
          </section>
          <div class="modal-actions">
            <button type="button" class="btn-outline" data-dismiss>Cancel</button>
          </div>
        </div>
      `;

      document.body.appendChild(modal);
      return modal;
    }

    const overlay = ensureChangePasswordModal();
    const form = overlay.querySelector("form");
    const messageEl = overlay.querySelector("[data-change-message]");
    const closeButtons = overlay.querySelectorAll("[data-dismiss]");
    const submitBtn = form.querySelector("button[type='submit']");
    const sessionListEl = overlay.querySelector("[data-session-list]");
    const sessionMessageEl = overlay.querySelector("[data-session-message]");
    const refreshSessionsBtn = overlay.querySelector("[data-refresh-sessions]");
    const revokeAllBtn = overlay.querySelector("[data-revoke-all]");
    let sessionsLoading = false;

    function setMessage(text, type = "") {
      if (!messageEl) return;
      messageEl.textContent = text;
      messageEl.className = "form-message";
      if (type) {
        messageEl.classList.add(type);
      }
    }

    function setSessionMessage(text, type = "") {
      if (!sessionMessageEl) return;
      sessionMessageEl.textContent = text;
      sessionMessageEl.className = "form-message";
      if (type) {
        sessionMessageEl.classList.add(type);
      }
    }

    function renderSessions(sessionsData) {
      if (!sessionListEl) return;
      sessionListEl.innerHTML = "";
      if (!Array.isArray(sessionsData) || sessionsData.length === 0) {
        sessionListEl.innerHTML = '<p class="muted">No other active sessions found.</p>';
        return;
      }

      sessionsData.forEach(item => {
        const container = document.createElement("div");
        container.className = "session-row";

        const meta = document.createElement("div");
        meta.className = "session-meta";
        const created = item.createdAt ? new Date(item.createdAt).toLocaleString() : "Unknown";
        const lastSeen = item.lastSeenAt ? new Date(item.lastSeenAt).toLocaleString() : "Unknown";
        meta.innerHTML = `
          <div><strong>${item.current ? "Current session" : "Session"}</strong></div>
          <div class="muted">Last seen: ${lastSeen}</div>
          <div class="muted">IP: ${item.ip || "Unknown"}</div>
          <div class="muted">Created: ${created}</div>
          ${item.userAgent ? `<div class="muted">Agent: ${item.userAgent}</div>` : ""}
        `;

        container.appendChild(meta);

        if (!item.current) {
          const action = document.createElement("div");
          action.className = "session-actions-inline";
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "btn-outline";
          btn.dataset.revokeToken = item.token;
          btn.textContent = "Revoke";
          action.appendChild(btn);
          container.appendChild(action);
        }

        sessionListEl.appendChild(container);
      });
    }

    async function loadSessions() {
      if (sessionsLoading) return;
      sessionsLoading = true;
      setSessionMessage("");
      if (sessionListEl) {
        sessionListEl.innerHTML = '<p class="muted">Loading sessions…</p>';
      }
      try {
        const data = await window.apiFetch("/api/session/active");
        renderSessions(data?.sessions || []);
      } catch (err) {
        console.error(err);
        setSessionMessage(err?.data?.error || err.message || "Failed to load sessions.", "error");
      } finally {
        sessionsLoading = false;
      }
    }

    async function revokeSession(token) {
      if (!token) return;
      try {
        const result = await window.apiFetch("/api/session/revoke", {
          method: "POST",
          body: JSON.stringify({ token }),
        });
        setSessionMessage(result?.message || "Session revoked.", "success");
        await loadSessions();
        if (result?.currentRevoked) {
          handleSessionExpired();
        }
      } catch (err) {
        console.error(err);
        setSessionMessage(err?.data?.error || err.message || "Failed to revoke session.", "error");
      }
    }

    async function revokeAllSessions() {
      try {
        const result = await window.apiFetch("/api/session/revoke", {
          method: "POST",
          body: JSON.stringify({ revokeAll: true, keepCurrent: true }),
        });
        setSessionMessage(result?.message || "Other sessions revoked.", "success");
        await loadSessions();
      } catch (err) {
        console.error(err);
        setSessionMessage(err?.data?.error || err.message || "Failed to revoke sessions.", "error");
      }
    }

    function openModal() {
      overlay.classList.add("active");
      document.body.classList.add("modal-open");
      form.reset();
      setMessage("");
      setSessionMessage("");
      loadSessions();
      const first = form.querySelector("input[name='currentPassword']");
      if (first) first.focus();
    }

    function closeModal() {
      overlay.classList.remove("active");
      document.body.classList.remove("modal-open");
      setMessage("");
      setSessionMessage("");
    }

    changePwBtn.addEventListener("click", e => {
      e.preventDefault();
      openModal();
    });

    closeButtons.forEach(btn => {
      btn.addEventListener("click", closeModal);
    });

    overlay.addEventListener("click", e => {
      if (e.target === overlay) {
        closeModal();
      }
    });

    if (refreshSessionsBtn) {
      refreshSessionsBtn.addEventListener("click", () => {
        loadSessions();
      });
    }

    if (revokeAllBtn) {
      revokeAllBtn.addEventListener("click", () => {
        revokeAllSessions();
      });
    }

    if (sessionListEl) {
      sessionListEl.addEventListener("click", e => {
        const btn = e.target.closest("[data-revoke-token]");
        if (btn?.dataset?.revokeToken) {
          revokeSession(btn.dataset.revokeToken);
        }
      });
    }

    document.addEventListener("keydown", e => {
      if (e.key === "Escape" && overlay.classList.contains("active")) {
        closeModal();
      }
    });

    form.addEventListener("submit", async e => {
      e.preventDefault();
      const currentPassword = form.querySelector("input[name='currentPassword']")?.value || "";
      const newPassword = form.querySelector("input[name='newPassword']")?.value || "";
      const confirmPassword = form.querySelector("input[name='confirmPassword']")?.value || "";

      setMessage("");

      if (!currentPassword || !newPassword || !confirmPassword) {
        setMessage("All fields are required.", "error");
        return;
      }

      if (newPassword !== confirmPassword) {
        setMessage("New passwords do not match.", "error");
        return;
      }

      if (!passwordStrongEnough(newPassword)) {
        setMessage("Password does not meet complexity requirements.", "error");
        return;
      }

      submitBtn.disabled = true;
      submitBtn.classList.add("loading");

      try {
        await window.apiFetch("/api/change-password", {
          method: "POST",
          body: JSON.stringify({ oldPassword: currentPassword, newPassword }),
        });

        setMessage("Password updated successfully.", "success");
        await loadSessions();
        form.reset();
        setTimeout(closeModal, 1200);
      } catch (err) {
        const text = err?.data?.error || err.message || "Failed to change password.";
        setMessage(text, "error");
      } finally {
        submitBtn.disabled = false;
        submitBtn.classList.remove("loading");
      }
    });

  }
});
