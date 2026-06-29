# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |

## Reporting a vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Contact the maintainer directly via GitHub private messaging or
by opening a GitHub Security Advisory on this repository.

Expected response time: 48 hours.
Expected patch timeline: 14 days from confirmed severity.

## Scope

In scope:
- Detection engine bypass or rule evasion
- Remote code execution within the pipeline
- Credential or secret exposure via logs or errors
- Critical or high severity dependency vulnerabilities

Out of scope:
- Social engineering
- Physical access attacks
- Vulnerabilities in third-party platforms such as
  Elasticsearch, Splunk, or Grafana

## Disclosure policy

We follow coordinated disclosure. Please allow reasonable time
for a fix before any public disclosure.
