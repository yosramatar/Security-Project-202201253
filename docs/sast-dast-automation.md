# SAST/DAST Automation

## Static Application Security Testing (SAST)
- Recommended tools: ESLint (with security plugins), SonarQube, Semgrep
- Example: Run Semgrep on backend code

```bash
npx semgrep --config=auto backend/
```

## Dynamic Application Security Testing (DAST)
- See DAST documentation (`docs/dast-penetration-testing.md`)
- Automate OWASP ZAP baseline scan in CI/CD:

```bash
docker run -v $(pwd):/zap/wrk -t owasp/zap2docker-stable zap-baseline.py -t http://host.docker.internal:3000 -r zap-report.html
```

## CI/CD Integration
- Add SAST/DAST steps to your CI pipeline (GitHub Actions, GitLab CI, etc.)
- Fail builds on critical findings, notify security team

## Next Steps
- Document findings and remediation steps
- Schedule regular automated scans
