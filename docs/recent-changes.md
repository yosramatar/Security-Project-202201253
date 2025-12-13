## Recent Changes (admin + MFA + CORS + debugging)

Summary of recent development work performed on the HealthCureAlpha codebase.

Completed items
- **Backend**
  - Relaxed CORS handling for local development: server now echoes local origins (including `localhost`, `127.0.0.1`, `192.168.*`) when `NODE_ENV !== 'production'` and sets appropriate CORS headers for preflight requests.
  - Added a terse request log at request entry to surface incoming requests and context: `[REQ] <METHOD> <PATH> origin=<origin> ip=<ip> hasSession=<true|false>`.
  - Added debug logging in key admin handlers to help trace admin actions and session invalidation.
  - Prevented admins from accidentally disabling or banning their own active session (self-target protections in `handleAdminDisableUser` and `handleAdminBanUser`).
  - Extended `handleAdminCreateUser` to accept an optional `mfaEnabled` boolean. When `mfaEnabled` is `true` a TOTP secret is generated, stored encrypted, and returned (with `otpauth` URL). When `false` no secret is generated and the account is created with `mfa_enabled = 0`.
  - Implemented a new admin API: `POST /api/admin/set-mfa` which enables or disables MFA for an existing user. Enabling returns a TOTP secret + `otpauth` URL; disabling clears the secret and invalidates sessions for that user.
  - Added small improvements to session handling and safety around persisted sessions and session invalidation (debug logs added to `invalidateSessionsForUser`).

- **Frontend**
  - Admin create-user UI: added an `mfaEnabled` checkbox to the create form so admins can choose whether to require MFA for a newly created user.
  - The create flow now sends `mfaEnabled` in the POST body to `/api/admin/create-user` and displays the returned `mfaSecret` and provisioning `otpauthUrl` in a provisioning box.
  - Added a copy-to-clipboard button for the MFA secret and small visual feedback when copied.
  - Added a per-user MFA toggle in the users table (checkbox). Toggling calls `POST /api/admin/set-mfa` to enable/disable MFA for that user; enabling shows the returned secret in the provisioning box so the admin can provision the authenticator.
  - Minor UI elements added: `createUserMessage` (status area for the create form) and styles for the MFA box and copy button.

- **Files changed (high level)**
  - backend/server.js — CORS logic, request logging, admin handlers (`handleAdminCreateUser`, `handleAdminSetMfa`), some debug logs
  - backend/db.js — unchanged except DB path already in place
  - frontend/pages/admin.html — create-user form updates, MFA provisioning box, copy button
  - frontend/js/admin.js — sends `mfaEnabled`, shows MFA secret, copy button wiring, per-user MFA toggle handler, rendering changes
  - frontend/css/styles.css — styles for MFA box, copy button, small layout tweaks

How to test (quick)
1. Start backend (from `backend/`):

```bash
cd backend
node server.js
```

2. Serve the frontend (from `frontend/`), if not already running:

```bash
cd frontend
npx http-server .
```

3. Open the admin page (e.g., `http://localhost:8080/pages/admin.html` or the host/port shown by your static server).
4. Create a user via the form with `Require MFA` checked: observe the provisioning box with the `mfaSecret` and `Open in authenticator` link. Use the copy button to copy the secret.
5. If create requests do not reach the backend, check the backend terminal for the `[REQ]` log lines to confirm requests and note any CORS debug lines (`[CORS] origin=...`). If you see `Access-Control` errors in the browser console, paste them here and I'll help fix them.

Notes & Next steps
- If you want the backend to persist audit logs of these admin actions in a separate changelog file or database table, I can add that.
- I can add an automatic QR (inline image) for the `otpauthUrl` in the UI for one-click provisioning.
- If you want the server to be more restrictive about which local IP ranges are allowed, we can convert the permissive dev-mode CORS to a config-driven list in `HCA_ALLOWED_ORIGINS`.

If you'd like, I can also create a short `docs/operation-checklist.md` with exact verification steps and expected server log lines for each operation.

---
Generated on: December 13, 2025
