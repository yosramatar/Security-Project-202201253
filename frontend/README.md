Local HTTPS (dev)

Quick start to run the frontend over HTTPS using mkcert-generated certs.

1. Generate certs (example):

    mkcert 192.168.56.1 localhost 127.0.0.1

2. Run the helper. You can run the PowerShell helper, or use the cross-platform Node server from any shell:

PowerShell (Windows):

    ./serve-https.ps1 -Cert "192.168.56.1+2.pem" -Key "192.168.56.1+2-key.pem" -Port 8080

Cross-platform (Node, works in bash):

    node serve-https.js --cert 192.168.56.1+2.pem --key 192.168.56.1+2-key.pem --port 8080

This Node script serves the current directory over HTTPS. See `../docs/dev-https.md` for full instructions.
