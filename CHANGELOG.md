

## [Unreleased]

### Added
- Full Sigma rule evaluation engine with wildcard and modifier support
- Windows EVTX parser normalizing to Elastic Common Schema (ECS)
- Linux syslog parser covering SSH and sudo events
- AWS CloudTrail parser with high-risk API detection
- Threat intelligence enrichment via AlienVault OTX and VirusTotal
- GeoIP enrichment using MaxMind GeoLite2
- Multi-channel alerting: Slack, PagerDuty, JIRA, Email
- Alert deduplication and rate limiting
- Docker Compose stack: Elasticsearch 8.15, Kibana, Logstash, Grafana 11
- Kubernetes deployment manifest with security context
- GitHub Actions CI: lint, test, Sigma validation, Trivy scan, SBOM
- 3 production Sigma rules: RDP brute force, PowerShell obfuscation, PsExec/WMI
- Coverage report generator script
- Complete test suite with 20+ unit tests

## [0.1.0] — 2025-01-01

### Added
- Initial project structure
