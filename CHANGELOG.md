# Changelog

All notable changes are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

## [1.0.0] — 2026-06-29

### Added
- Sigma rule evaluation engine with wildcard and modifier support
- Windows EVTX parser normalized to Elastic Common Schema
- Linux syslog parser covering SSH brute force and sudo abuse
- AWS CloudTrail parser with high-risk API surface detection
- Threat intelligence enrichment via AlienVault OTX and VirusTotal
- GeoIP enrichment using MaxMind GeoLite2
- Multi-channel alerting: Slack, PagerDuty, JIRA, Email
- Alert deduplication and rate limiting
- Docker Compose stack: Elasticsearch 8.15, Kibana, Logstash, Grafana 11
- Kubernetes deployment manifest with hardened security context
- GitHub Actions CI: lint, test, Sigma validation, Trivy scan, SBOM
- Detection rules: RDP brute force, PowerShell obfuscation,
  PsExec lateral movement, scheduled task persistence,
  event log tampering, Linux reverse shell, AWS IAM escalation
- MITRE ATT&CK coverage report generator
- Full test suite with unit and integration coverage
