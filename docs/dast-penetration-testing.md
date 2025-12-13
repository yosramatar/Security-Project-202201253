# DAST & Penetration Testing

## Recommended Tools
- OWASP ZAP (Zed Attack Proxy)
- Burp Suite Community Edition
- Nikto (for basic web server checks)
- Nuclei (for automated vulnerability scanning)

## How to Run (Example: OWASP ZAP)
1. Download and install OWASP ZAP: https://www.zaproxy.org/download/
2. Start ZAP and set target to `http://localhost:3000`.
3. Use the "Automated Scan" feature to crawl and attack the app.
4. Review alerts and export the report.

## Example Script (for CI/CD)
```bash
# Run ZAP baseline scan (requires Docker)
docker run -v $(pwd):/zap/wrk -t owasp/zap2docker-stable zap-baseline.py -t http://host.docker.internal:3000 -r zap-report.html
```

## Documentation
- Save scan reports in `build/dast-reports/`.
- Document findings and remediation steps in `docs/dast-findings.md`.

## Next Steps
- Integrate DAST scans into CI/CD pipeline.
- Schedule regular scans and review findings.
- Document penetration testing methodology and results.
