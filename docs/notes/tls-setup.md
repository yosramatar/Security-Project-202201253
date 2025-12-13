# Local TLS Setup Notes

This project can now serve HTTPS directly for local testing so teams can validate HSTS/CSP behaviour and API consumers can exercise certificate pinning ahead of production rollout.

## Enable TLS in the backend

1. Generate or obtain a key/certificate pair. For quick local smoke tests you can use OpenSSL:
   ```bash
   openssl req -x509 -nodes -newkey rsa:2048 -keyout certs/dev.key -out certs/dev.crt -days 5 -subj "/CN=localhost"
   ```
2. Export the file locations to the backend via environment variables before starting the server:
   - `HCA_TLS_KEY_PATH` – absolute or relative path to the private key (`dev.key`).
   - `HCA_TLS_CERT_PATH` – certificate chain in PEM format (`dev.crt`).
   - `HCA_TLS_CA_PATH` *(optional)* – bundle of trusted issuers if clients require mutual TLS.
3. (Optional) Set `PORT` and `HCA_PUBLIC_ORIGIN` if you need to bind to a different port or advertised origin.
4. Start the backend (`npm start`). The console prints a TLS-enabled banner when TLS is active and the server listens on `https://localhost:<PORT>`.

## CORS and CSP behaviour

- The server automatically updates CORS rules and the CSP `connect-src` directive to include the HTTPS origin derived from the environment.
- Additional front-end origins can be whitelisted via `HCA_ALLOWED_ORIGINS`, using a comma-separated list (e.g., `https://app.example.com,https://admin.example.com`).

## Certificate rotation checklist

- Replace the files referenced by `HCA_TLS_KEY_PATH`/`HCA_TLS_CERT_PATH` and restart the service.
- If the certificate issuer changes, update any client trust stores and refresh `HCA_TLS_CA_PATH` when mutual TLS is enabled.
- Document renewals in the security change log and capture the new certificate thumbprint for inventory tracking.
