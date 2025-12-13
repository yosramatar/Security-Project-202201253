# Dependency Scanning (SBOM)

## Automated Scans

- `npm audit` is run to generate a Software Bill of Materials and scan for vulnerabilities. Results are saved to `build/sbom-audit.json`.
- Snyk scan attempted via `npx snyk test`, results (if snyk is installed/configured) are saved to `build/sbom-snyk.json`.

## How to Run

1. Run `npm audit --json > build/sbom-audit.json` in the `backend` directory.
2. (Optional) Run `npx snyk test --json > build/sbom-snyk.json` if Snyk is installed and configured.

## Next Steps
- Review the generated SBOM files for vulnerabilities and outdated packages.
- Integrate these scans into CI/CD for continuous monitoring.
- Document remediation steps for any critical findings.

---

For more advanced SBOM and dependency scanning, consider integrating Snyk, OWASP Dependency-Check, or GitHub Dependabot into your CI pipeline.
