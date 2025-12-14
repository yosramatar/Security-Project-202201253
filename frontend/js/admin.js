
// Helper: get colspan for a table body
function tableColspan(body) {
  const headerCells = body?.closest("table")?.querySelectorAll("thead th");
  return headerCells && headerCells.length ? headerCells.length : 5;
}

        const ssnBody = document.querySelector('#ssnTable tbody');
        const refreshSsnBtn = document.getElementById('refreshSsnTable');

        async function loadSsnTable() {
          if (!ssnBody) return;
          ssnBody.innerHTML = '<tr><td colspan="5">Loading…</td></tr>';
          try {
            // Use the entitlement review API to get all users with decrypted SSN
            const data = await window.apiFetch('/api/admin/entitlement-review');
            const entries = Array.isArray(data.review) ? data.review : [];
            ssnBody.innerHTML = '';
            if (!entries.length) {
              ssnBody.innerHTML = '<tr><td colspan="5" class="muted">No data.</td></tr>';
              return;
            }
            entries.forEach(item => {
              const tr = document.createElement('tr');
              tr.innerHTML = `
                <td>${item.id}</td>
                <td>${item.name || ''}</td>
                <td>${item.email || ''}</td>
                <td>${item.role || ''}</td>
                <td>${item.ssn || ''}</td>
              `;
              ssnBody.appendChild(tr);
            });
          } catch (err) {
            console.error('Failed to load SSN table:', err);
            if (ssnBody) ssnBody.innerHTML = '<tr><td colspan="5" class="error">Failed to load SSNs.</td></tr>';
          }
        }

        if (refreshSsnBtn) {
          refreshSsnBtn.addEventListener('click', () => {
            loadSsnTable();
          });
        }

        if (ssnBody) {
          loadSsnTable();
        }
        // ---- Locked Accounts Management --------------------------------------
        const lockedBody = document.querySelector("#lockedAccountsTable tbody");
        const refreshLockedBtn = document.getElementById("refreshLockedAccounts");

        async function loadLockedAccounts() {
          if (!lockedBody) return;
          const colspan = tableColspan(lockedBody);
          lockedBody.innerHTML = `<tr><td colspan="${colspan}">Loading…</td></tr>`;
          try {
            const data = await window.apiFetch("/api/admin/locked-accounts");
            const entries = Array.isArray(data.locked) ? data.locked : [];
            lockedBody.innerHTML = "";
            if (!entries.length) {
              lockedBody.innerHTML = `<tr><td colspan="${colspan}" class="muted">No locked accounts.</td></tr>`;
              return;
            }
            entries.forEach(item => {
              const tr = document.createElement("tr");
              tr.innerHTML = `
                <td>${item.name || ""}</td>
                <td>${item.email || ""}</td>
                <td>${item.lockout_until ? new Date(item.lockout_until).toLocaleString() : ""}</td>
                <td>${item.failed_attempts ?? 0}</td>
                <td><button class="btn-small btn-danger" data-unlock-account="${item.id}">Unlock</button></td>
              `;
              lockedBody.appendChild(tr);
            });
          } catch (err) {
            console.error("Failed to load locked accounts:", err);
            if (lockedBody) lockedBody.innerHTML = `<tr><td colspan="${colspan}" class="error">Failed to load locked accounts.</td></tr>`;
          }
        }

        if (refreshLockedBtn) {
          refreshLockedBtn.addEventListener("click", () => {
            loadLockedAccounts();
          });
        }

        if (lockedBody) {
          lockedBody.addEventListener("click", async (e) => {
            const btn = e.target.closest("[data-unlock-account]");
            if (!btn) return;
            const userId = btn.getAttribute("data-unlock-account");
            if (!userId) return;
            btn.disabled = true;
            btn.textContent = "Unlocking...";
            try {
              await window.apiFetch("/api/admin/unlock-account", {
                method: "POST",
                body: { id: userId }
              });
              btn.textContent = "Unlocked";
              setTimeout(loadLockedAccounts, 1000);
            } catch (err) {
              btn.textContent = "Error";
              btn.disabled = false;
            }
          });
        }

        // Initial load
        loadLockedAccounts();
    // ---- Session Management --------------------------------------
    const sessionsBody = document.querySelector("#sessionsTable tbody");
    const refreshSessionsBtn = document.getElementById("refreshSessions");

    async function loadSessions() {
      if (!sessionsBody) return;
      const colspan = tableColspan(sessionsBody);
      sessionsBody.innerHTML = `<tr><td colspan="${colspan}">Loading…</td></tr>`;
      try {
        const data = await window.apiFetch("/api/admin/sessions");
        const entries = Array.isArray(data.sessions) ? data.sessions : [];
        sessionsBody.innerHTML = "";
        if (!entries.length) {
          sessionsBody.innerHTML = `<tr><td colspan="${colspan}" class="muted">No active sessions.</td></tr>`;
          return;
        }
        entries.forEach(item => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td>${item.token}</td>
            <td>${item.user_name || item.user_email || ""}</td>
            <td>${item.ip || ""}</td>
            <td>${item.user_agent || ""}</td>
            <td>${item.created_at ? new Date(item.created_at).toLocaleString() : ""}</td>
            <td>${item.last_seen_at ? new Date(item.last_seen_at).toLocaleString() : ""}</td>
            <td>${item.expires_at ? new Date(item.expires_at).toLocaleString() : ""}</td>
            <td><button class="btn-small btn-danger" data-revoke-session="${item.token}">Revoke</button></td>
          `;
          sessionsBody.appendChild(tr);
        });
      } catch (err) {
        console.error("Failed to load sessions:", err);
        sessionsBody.innerHTML = `<tr><td colspan="${colspan}" class="error">Failed to load sessions.</td></tr>`;
      }
    }

    if (refreshSessionsBtn) {
      refreshSessionsBtn.addEventListener("click", () => {
        loadSessions();
      });
    }
  // ---- Break-Glass Emergency Access --------------------------------------
  const breakGlassBody = document.querySelector("#breakGlassTable tbody");
  const refreshBreakGlassBtn = document.getElementById("refreshBreakGlass");

  async function loadBreakGlassRequests() {
    if (!breakGlassBody) return;
    const colspan = tableColspan(breakGlassBody);
    breakGlassBody.innerHTML = `<tr><td colspan="${colspan}">Loading…</td></tr>`;
    try {
      const data = await window.apiFetch("/api/admin/break-glass");
      const entries = Array.isArray(data.requests) ? data.requests : [];
      breakGlassBody.innerHTML = "";
      if (!entries.length) {
        breakGlassBody.innerHTML = `<tr><td colspan="${colspan}" class="muted">No requests.</td></tr>`;
        return;
      }
      entries.forEach(item => {
              const approvals = item.approvals ? item.approvals.map(a => a.name || a.id).join(", ") : "None";
              const tr = document.createElement("tr");
              tr.innerHTML = `
                <td>${item.id}</td>
                <td>${item.user_name || ""}</td>
                <td>${item.reason || ""}</td>
                <td>${item.requested_at ? new Date(item.requested_at).toLocaleString() : ""}</td>
                <td>${item.status || ""}</td>
                <td>${approvals}</td>
                <td>
                  <button class="btn-small btn-success" data-approve-break-glass="${item.id}">Approve</button>
                  <button class="btn-small btn-danger" data-revoke-break-glass="${item.id}">Revoke</button>
                </td>
              `;
              breakGlassBody.appendChild(tr);
      });
    } catch (err) {
      console.error("Failed to load break-glass requests:", err);
      breakGlassBody.innerHTML = `<tr><td colspan="${colspan}" class="error">Failed to load requests.</td></tr>`;
    }
  }

  if (refreshBreakGlassBtn) {
    refreshBreakGlassBtn.addEventListener("click", () => {
      loadBreakGlassRequests();
    });
  }
// frontend/js/admin.js

document.addEventListener("DOMContentLoaded", () => {
  const entitlementReviewBody = document.querySelector("#entitlementReviewTable tbody");
  const refreshEntitlementReviewBtn = document.getElementById("refreshEntitlementReview");
  // Optional role check: only runs if auth.js exposes requireRole
  if (typeof window.requireRole === "function") {
    const info = window.requireRole(["admin"]);
    if (!info) {
      // requireRole already handled redirect / message
      return;
    }
  }

  if (typeof window.apiFetch !== "function") {
    console.error("apiFetch is not defined. Check that auth.js is loaded first.");
    return;
  }

  const createForm   = document.getElementById("createUserForm");
  const createMsg    = document.getElementById("createUserMessage");
  const createMfaBox = document.getElementById("createUserMfa");
  const createMfaSecretEl = document.querySelector("[data-create-mfa-secret]");
  const createMfaUriEl = document.querySelector("[data-create-mfa-uri]");
  const createMfaCopyBtn = document.querySelector("[data-create-mfa-copy]");
  const mfaCheckbox = document.getElementById("mfaEnabled");
  const doctorsBody  = document.querySelector("#doctorsTable tbody");
  const nursesBody   = document.querySelector("#nursesTable tbody");
  const patientsBody = document.querySelector("#patientsTable tbody");
  const authEventsBody = document.querySelector("#authEventsTable tbody");
  const blacklistBody  = document.querySelector("#blacklistTable tbody");
  const refreshAuthEventsBtn = document.getElementById("refreshAuthEvents");
  const refreshBlacklistBtn  = document.getElementById("refreshBlacklist");

  // ---- Helpers -----------------------------------------------------

  function tableColspan(body) {
    const headerCells = body?.closest("table")?.querySelectorAll("thead th");
    return headerCells && headerCells.length ? headerCells.length : 5;
  }

  function renderStatusBadge(status) {
    switch (status) {
      case "active":
        return "<span class=\"status-badge status-active\">Active</span>";
      case "disabled":
        return "<span class=\"status-badge status-disabled\">Disabled</span>";
      case "banned":
        return "<span class=\"status-badge status-banned\">Banned</span>";
      case "pending_mfa":
        return "<span class=\"status-badge status-pending\">Pending MFA</span>";
      default:
        return `<span class="status-badge">${status || "unknown"}</span>`;
    }
  }

  function renderWatchBadge(user) {
    const status = user.watch_status === "yellow" ? "watch-yellow" : "watch-normal";
    const count = Number(user.failed_login_count || 0);
    const label = user.watch_status === "yellow" ? `Yellow (${count})` : "Normal";
    return `<span class="watch-badge ${status}">${label}</span>`;
  }

  function renderMfaBadge(user) {
    const checked = user.mfa_enabled ? 'checked' : '';
    const secretHtml = user.mfaSecret ? `<div class="mfa-secret" style="margin-top:6px; font-size:12px"><code>${user.mfaSecret}</code></div>` : '';
    const linkHtml = user.otpauthUrl ? `<div style="margin-top:6px"><a class="btn-small" href="${user.otpauthUrl}" target="_blank" rel="noopener">Open in authenticator</a></div>` : '';
    return `
      <div>
        <label class="checkbox-label">
          <input type="checkbox" data-mfa-toggle="${user.id}" ${checked} />
          <span style="font-size:12px; margin-left:6px">MFA</span>
        </label>
        ${secretHtml}
        ${linkHtml}
      </div>
    `;
  }

  function renderActionButtons(user) {
    if (user.role === "admin") {
      return "<span class='muted'>Protected</span>";
    }

    const buttons = [];

    if (user.status === "banned") {
      buttons.push(`<button type="button" class="btn-small" data-unban-id="${user.id}">Unban</button>`);
    } else {
      if (user.status === "active") {
        buttons.push(`<button type="button" class="btn-small btn-danger" data-delete-id="${user.id}">Disable</button>`);
      } else if (user.status === "disabled" || user.status === "pending_mfa") {
        buttons.push(`<button type="button" class="btn-small" data-restore-id="${user.id}">Restore</button>`);
      }

      buttons.push(`<button type="button" class="btn-small btn-danger" data-ban-id="${user.id}">Ban</button>`);
    }

    if (user.watch_status === "yellow") {
      buttons.push(`<button type="button" class="btn-small" data-clear-yellow-id="${user.id}">Clear Watch</button>`);
    }

    // If MFA secret available, show it alongside actions for quick provisioning
    const secretHtml = user.mfaSecret ? `<div class="mfa-secret-inline" style="margin-top:6px; font-size:12px"><code>${user.mfaSecret}</code></div>` : '';
    return buttons.join(" ") + secretHtml;
  }

  function showCreateMfa(secret, uri) {
    if (!createMfaBox) return;
    if (secret) {
      if (createMfaSecretEl) createMfaSecretEl.textContent = secret;
      if (createMfaCopyBtn) {
        createMfaCopyBtn.disabled = false;
        createMfaCopyBtn.textContent = "Copy";
        createMfaCopyBtn.classList.remove("copied");
      }
      if (createMfaUriEl) {
        if (uri) {
          createMfaUriEl.href = uri;
          createMfaUriEl.classList.remove("disabled");
          createMfaUriEl.title = uri;
        } else {
          createMfaUriEl.href = "#";
          createMfaUriEl.classList.add("disabled");
          createMfaUriEl.title = "";
        }
      }
      createMfaBox.classList.remove("hidden");
    } else {
      if (createMfaSecretEl) createMfaSecretEl.textContent = "";
      if (createMfaCopyBtn) {
        createMfaCopyBtn.disabled = true;
        createMfaCopyBtn.textContent = "Copy";
        createMfaCopyBtn.classList.remove("copied");
      }
      if (createMfaUriEl) {
        createMfaUriEl.href = "#";
        createMfaUriEl.classList.add("disabled");
        createMfaUriEl.title = "";
      }
      createMfaBox.classList.add("hidden");
    }
  }

  // Copy-to-clipboard for created MFA secret
  if (createMfaCopyBtn) {
    createMfaCopyBtn.addEventListener("click", (ev) => {
      ev.preventDefault();
      const secret = createMfaSecretEl ? createMfaSecretEl.textContent : "";
      if (!secret) return;
      navigator.clipboard?.writeText(secret).then(() => {
        createMfaCopyBtn.classList.add("copied");
        createMfaCopyBtn.textContent = "Copied";
        setTimeout(() => {
          createMfaCopyBtn.classList.remove("copied");
          createMfaCopyBtn.textContent = "Copy";
        }, 2000);
      }).catch((err) => {
        console.error("Copy failed", err);
        alert("Copy failed — please select and copy the secret manually.");
      });
    });
  }

    async function loadUsers(role, targetBody) {
      if (!targetBody) return;
      const colspan = tableColspan(targetBody);
      targetBody.innerHTML = `<tr><td colspan="${colspan}">Loading…</td></tr>`;

      try {
        // Always send role as lowercase
        const query = role ? `?role=${encodeURIComponent(role.toLowerCase())}` : "";
        const data  = await window.apiFetch(`/api/admin/users${query}`);

        targetBody.innerHTML = "";

        if (!data.users || data.users.length === 0) {
          targetBody.innerHTML =
            `<tr><td colspan="${colspan}" class="muted">No users yet.</td></tr>`;
          return;
        }

        data.users.forEach((u) => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td>${u.id}</td>
            <td>${u.name || ""}</td>
            <td>${u.email || ""}</td>
            <td>${renderStatusBadge(u.status)}</td>
            <td>${renderWatchBadge(u)}</td>
            <td>${renderMfaBadge(u)}</td>
            <td>${renderActionButtons(u)}</td>
          `;
          targetBody.appendChild(tr);
        });
      } catch (err) {
        console.error("Failed to load users:", err);
        if (targetBody) targetBody.innerHTML =
          `<tr><td colspan="${colspan}" class="error">Failed to load users.</td></tr>`;
      }
    }

  async function loadAuthEvents() {
    if (!authEventsBody) return;
    const colspan = tableColspan(authEventsBody);
    authEventsBody.innerHTML = `<tr><td colspan="${colspan}">Loading…</td></tr>`;

    try {
      const data = await window.apiFetch("/api/admin/auth-events?limit=100");
      const events = Array.isArray(data.events) ? data.events : [];

      authEventsBody.innerHTML = "";

      if (!events.length) {
        authEventsBody.innerHTML = `<tr><td colspan="${colspan}" class="muted">No events recorded.</td></tr>`;
        return;
      }

      events.forEach(ev => {
        const tr = document.createElement("tr");
        const ts = ev.created_at ? new Date(ev.created_at).toLocaleString() : "";
        const userLabel = ev.email
          ? `${ev.email}${ev.user_id ? ` (#${ev.user_id})` : ""}`
          : ev.user_id
            ? `User #${ev.user_id}`
            : "—";
        tr.innerHTML = `
          <td>${ts}</td>
          <td>${userLabel}</td>
          <td>${ev.event_type || ""}</td>
          <td>${ev.detail || ""}</td>
          <td>${ev.ip || ""}</td>
        `;
        authEventsBody.appendChild(tr);
      });
    } catch (err) {
      console.error("Failed to load auth events:", err);
      authEventsBody.innerHTML = `<tr><td colspan="${colspan}" class="error">Failed to load events.</td></tr>`;
    }
  }

  async function loadBlacklist() {
    if (!blacklistBody) return;
    const colspan = tableColspan(blacklistBody);
    blacklistBody.innerHTML = `<tr><td colspan="${colspan}">Loading…</td></tr>`;

    try {
      const data = await window.apiFetch("/api/admin/blacklist?limit=100");
      const entries = Array.isArray(data.blacklist) ? data.blacklist : [];

      blacklistBody.innerHTML = "";

      if (!entries.length) {
        blacklistBody.innerHTML = `<tr><td colspan="${colspan}" class="muted">Blacklist is empty.</td></tr>`;
        return;
      }

      entries.forEach(item => {
        const tr = document.createElement("tr");
        const ts = item.created_at ? new Date(item.created_at).toLocaleString() : "";
        tr.innerHTML = `
          <td>${item.identifier}</td>
          <td>${item.reason || "—"}</td>
          <td>${ts}</td>
        `;
        blacklistBody.appendChild(tr);
      });
    } catch (err) {
      console.error("Failed to load blacklist:", err);
      blacklistBody.innerHTML = `<tr><td colspan="${colspan}" class="error">Failed to load blacklist.</td></tr>`;
    }
  }

  async function loadEntitlementReview() {
    if (!entitlementReviewBody) return;
    const colspan = tableColspan(entitlementReviewBody);
    entitlementReviewBody.innerHTML = `<tr><td colspan="${colspan}">Loading…</td></tr>`;

    try {
      // Fetch entitlement review data from backend API (to be implemented)
      const data = await window.apiFetch("/api/admin/entitlement-review");
      const entries = Array.isArray(data.review) ? data.review : [];

      entitlementReviewBody.innerHTML = "";
      if (!entries.length) {
        entitlementReviewBody.innerHTML = `<tr><td colspan="${colspan}" class="muted">No data.</td></tr>`;
        return;
      }
      entries.forEach(item => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${item.id}</td>
          <td>${item.name || ""}</td>
          <td>${item.email || ""}</td>
          <td>${item.role || ""}</td>
          <td>${renderStatusBadge(item.status)}</td>
          <td>${item.last_login || ""}</td>
          <td>${item.explicit_entitlements || ""}</td>
          <td>${item.assignments ? item.assignments.join(", ") : ""}</td>
          <td>${item.orphaned ? '<span class="status-badge status-banned">Orphaned</span>' : ''}</td>
        `;
        entitlementReviewBody.appendChild(tr);
      });
    } catch (err) {
      console.error("Failed to load entitlement review:", err);
      entitlementReviewBody.innerHTML = `<tr><td colspan="${colspan}" class="error">Failed to load review.</td></tr>`;
    }
  }

  async function refreshAll() {
    await Promise.all([
      loadUsers("doctor", doctorsBody),
      loadUsers("nurse", nursesBody),
      loadUsers("patient", patientsBody),
      loadAuthEvents(),
      loadBlacklist(),
      loadEntitlementReview(),
    ]);
  }

  // ---- Create doctor / nurse --------------------------------------

  if (createForm) {
    createForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (createMsg) {
        if (createMsg) createMsg.textContent = "";
        createMsg.className = "form-message";
      }

      const nameInput = document.getElementById("fullName");
      const emailInput = document.getElementById("email");
      const passwordInput = document.getElementById("password");
      const roleInput = document.getElementById("role");
      const name = nameInput ? nameInput.value.trim() : "";
      const email = emailInput ? emailInput.value.trim() : "";
      const password = passwordInput ? passwordInput.value : "";
      const role = roleInput ? roleInput.value : "";
      const mfaEnabled = mfaCheckbox ? mfaCheckbox.checked : true;

      if (!name || !email || !password) {
        if (createMsg) {
          createMsg.textContent = "All fields are required.";
          createMsg.classList.add("error");
        }
        return;
      }

      const passwordIssues = [];
      if (password.length < 12) passwordIssues.push("be at least 12 characters");
      if (!/[a-z]/.test(password)) passwordIssues.push("include a lowercase letter");
      if (!/[A-Z]/.test(password)) passwordIssues.push("include an uppercase letter");
      if (!/[0-9]/.test(password)) passwordIssues.push("include a digit");
      if (!/[^A-Za-z0-9]/.test(password)) passwordIssues.push("include a symbol");

      if (passwordIssues.length) {
        if (createMsg) {
          if (createMsg) {
            createMsg.textContent = `Password must ${passwordIssues.join(", ")}.`;
            createMsg.classList.add("error");
          }
        }
        return;
      }

      try {
        const data = await window.apiFetch("/api/admin/create-user", {
          method: "POST",
          body: JSON.stringify({ name, email, password, role: (role || '').toLowerCase(), mfaEnabled }),
        });

        if (createMsg) {
          if (createMsg) {
            createMsg.textContent = data.message || "User created.";
            createMsg.classList.add("success");
          }
        }
        createForm.reset();
        showCreateMfa(data.mfaSecret, data.otpauthUrl);
        await refreshAll();
      } catch (err) {
        console.error("Create user failed:", err);
        const msg = err?.data?.error || "Create failed.";
        if (createMsg) {
          if (createMsg) {
            createMsg.textContent = msg;
            createMsg.classList.add("error");
          }
        }
        showCreateMfa(null);
      }
    });
  }

  // ---- Delete user (doctor / nurse / patient) ---------------------

  document.addEventListener("click", async (e) => {
    const deleteBtn = e.target.closest("[data-delete-id]");
    if (deleteBtn) {
      const id = deleteBtn.getAttribute("data-delete-id");
      if (!id) return;

      if (!confirm(`Disable user ID ${id}?`)) return;

      try {
        await window.apiFetch("/api/admin/delete-user", {
          method: "DELETE",
          body: JSON.stringify({ userId: Number(id) }),
        });
        await refreshAll();
      } catch (err) {
        console.error("Disable user failed:", err);
        alert("Failed to disable user.");
      }
      return;
    }

    const restoreBtn = e.target.closest("[data-restore-id]");
    if (restoreBtn) {
      const id = restoreBtn.getAttribute("data-restore-id");
      if (!id) return;

      try {
        await window.apiFetch("/api/admin/restore-user", {
          method: "POST",
          body: JSON.stringify({ userId: Number(id) }),
        });
        await refreshAll();
      } catch (err) {
        console.error("Restore user failed:", err);
        alert("Failed to restore user.");
      }
      return;
    }

    const banBtn = e.target.closest("[data-ban-id]");
    if (banBtn) {
      const id = banBtn.getAttribute("data-ban-id");
      if (!id) return;

      if (!confirm(`Ban user ID ${id}? They will be blacklisted.`)) return;
      const reason = prompt("Ban reason (optional):", "");

      try {
        await window.apiFetch("/api/admin/ban-user", {
          method: "POST",
          body: JSON.stringify({ userId: Number(id), reason: reason || undefined }),
        });
        await refreshAll();
      } catch (err) {
        console.error("Ban user failed:", err);
        alert("Failed to ban user.");
      }
      return;
    }

    const unbanBtn = e.target.closest("[data-unban-id]");
    if (unbanBtn) {
      const id = unbanBtn.getAttribute("data-unban-id");
      if (!id) return;

      try {
        await window.apiFetch("/api/admin/unban-user", {
          method: "POST",
          body: JSON.stringify({ userId: Number(id) }),
        });
        await refreshAll();
      } catch (err) {
        console.error("Unban user failed:", err);
        alert("Failed to unban user.");
      }
      return;
    }

    // MFA toggle (event delegation targets the checkbox input)
    const mfaToggle = e.target.closest("input[data-mfa-toggle]");
    if (mfaToggle) {
      const id = mfaToggle.getAttribute("data-mfa-toggle");
      if (!id) return;
      const newState = mfaToggle.checked;
      try {
        const resp = await window.apiFetch("/api/admin/set-mfa", {
          method: "POST",
          body: JSON.stringify({ userId: Number(id), mfaEnabled: Boolean(newState) }),
        });
        if (resp.mfaSecret) {
          // Show the secret in the create MFA box to allow admin to provision for user
          showCreateMfa(resp.mfaSecret, resp.otpauthUrl);
        } else {
          // Refresh to show updated state
          await refreshAll();
        }
      } catch (err) {
        console.error("Set MFA failed:", err);
        alert("Failed to change MFA state.");
        // revert checkbox UI if request failed
        mfaToggle.checked = !newState;
      }
      return;
    }

    const clearBtn = e.target.closest("[data-clear-yellow-id]");
    if (clearBtn) {
      const id = clearBtn.getAttribute("data-clear-yellow-id");
      if (!id) return;

      try {
        await window.apiFetch("/api/admin/clear-yellow", {
          method: "POST",
          body: JSON.stringify({ userId: Number(id) }),
        });
        await refreshAll();
      } catch (err) {
        console.error("Clear yellow failed:", err);
        alert("Failed to clear watch status.");
      }
      return;
    }
  });

  // ---- Initial load -----------------------------------------------

  if (refreshAuthEventsBtn) {
    refreshAuthEventsBtn.addEventListener("click", () => {
      loadAuthEvents();
    });
  }

  if (refreshBlacklistBtn) {
    refreshBlacklistBtn.addEventListener("click", () => {
      loadBlacklist();
    });
  }

  if (refreshEntitlementReviewBtn) {
    refreshEntitlementReviewBtn.addEventListener("click", () => {
      loadEntitlementReview();
    });
  }

  refreshAll().catch((err) => {
    console.error("Initial admin dashboard load failed:", err);
  });
});

