Local HTTPS for Development

This document shows how to run the frontend (and optionally the backend) over HTTPS locally so your browser will stop showing "Not secure" warnings and you can safely test features that require secure contexts (e.g., Service Worker, secure cookies, MFA provisioning flows).

Prerequisite: install mkcert (creates a locally-trusted CA) and `http-server` via `npx` (or use any static server that supports `--ssl`).

Windows (recommended):

1. Install mkcert and its CA (Chocolatey example):

    choco install mkcert -y
    mkcert -install

2. Create certs for your dev host(s). Replace `192.168.56.1` with the IP/hostname you use to open the site in the browser. Include `localhost` and `127.0.0.1` if you use those as well.

    mkcert 192.168.56.1 localhost 127.0.0.1
    # mkcert will write files like: 192.168.56.1+2.pem and 192.168.56.1+2-key.pem

3. Serve the `frontend/` folder with `http-server` over HTTPS using the generated cert and key:

    cd frontend
    npx http-server . -p 8080 --ssl --cert 192.168.56.1+2.pem --key 192.168.56.1+2-key.pem

4. Open the secure URL in your browser:

    https://192.168.56.1:8080/pages/admin.html

Backend HTTPS (optional)

The backend already supports TLS if you provide `HCA_TLS_CERT_PATH` and `HCA_TLS_KEY_PATH` environment variables. Example (PowerShell):

    $env:HCA_TLS_CERT_PATH = "C:\path\to\192.168.56.1+2.pem"
    $env:HCA_TLS_KEY_PATH = "C:\path\to\192.168.56.1+2-key.pem"
    cd backend
    npm start

Security notes

- Do not use self-signed or untrusted certificates for testing PHI in browsers (mkcert creates a locally-trusted CA, which is acceptable for local dev).
- Do not disable browser security warnings or ignore certificate errors when handling PHI.
- Remove or rotate any demo keys before deploying to production; use a real KMS/Key Vault in production environments.

Troubleshooting

- If the browser still shows a warning, ensure the mkcert root CA is installed and trusted in the OS/browser.
- Some corporate OSs or browsers may require additional trust steps (e.g., Firefox uses its own cert store).

If you'd like, I can add a small `serve-https.ps1` script to `frontend/` to wrap the `npx http-server` command — say yes and I'll create it and a short `frontend/README.md` linking to this doc.
