# Task 04 — Dependency Audit

> **Status: placeholder.** No audit has been done yet. The project or
> dependency set to audit will be copied in from the assessment brief.

## Topic

An audit of third-party dependencies for known vulnerabilities and
supply-chain risk.

## Expected focus areas

- Known vulnerabilities (CVE/GHSA/OSV), and whether the vulnerable code is
  actually reachable
- Supply-chain risk: unpinned or floating versions, unmaintained packages,
  typosquatting, suspicious install scripts, licence issues
- Prioritised remediation: upgrade paths, replacements, compensating controls
- Reproducibility: committed lockfiles and documented tool versions

## Planned contents

- Audit report with findings and remediation
- The exact commands and tool versions used, so results can be reproduced

## Validation (planned)

Candidate tools, none run yet: `osv-scanner`, `govulncheck`, `npm audit` /
`pip-audit` (depending on ecosystem), and `trivy fs`. Results are reported
only from real runs; nothing is estimated or invented.
