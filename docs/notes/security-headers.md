# Security Headers Quick Reference

- Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' http://localhost:3000; form-action 'self'; base-uri 'self'; frame-ancestors 'none'. Locks the app to first-party resources during local development.
- X-Frame-Options / frame-ancestors: deny embedding to block clickjacking against the admin and clinical consoles.
- X-Content-Type-Options: nosniff to prevent MIME confusion when APIs return JSON payloads.
- Referrer-Policy: no-referrer to avoid leaking PHI-related URLs to third parties.
- Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Resource-Policy: cross-origin to isolate the browsing context while allowing local dev assets.
- Strict-Transport-Security: max-age=31536000; includeSubDomains (expects TLS termination in production environments).
- Cache-Control / Pragma: no-store, no-cache to prevent caching of bearer tokens or decrypted PHI in intermediaries.
