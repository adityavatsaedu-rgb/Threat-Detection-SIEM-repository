# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| >= 1.0  | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

**Do NOT open a public GitHub issue for security bugs.**

Please email the maintainer directly. We will respond within 48 hours
and aim to release a patch within 14 days of confirmed severity.

## Scope

- Detection engine bypass (rule evasion techniques)
- Remote code execution in the detection pipeline
- Secrets leaking via logs, errors, or debug output
- Dependency vulnerabilities (critical/high CVEs)

## Out of scope

- Social engineering
- Physical access attacks
- Vulnerabilities in third-party SIEM platforms (Elastic, Splunk)
