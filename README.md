# Threat Detection & SIEM Framework

[![CI](https://github.com/adityavatsaedu-rgb/Threat-Detection-SIEM-repository/actions/workflows/ci.yml/badge.svg)](https://github.com/adityavatsaedu-rgb/Threat-Detection-SIEM-repository/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-0D1117)](LICENSE)
[![Sigma](https://img.shields.io/badge/Sigma-Rules-FF6B35)](https://sigmahq.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-E63946)](https://attack.mitre.org)
[![ECS](https://img.shields.io/badge/ECS-Compatible-005571?logo=elastic)](https://elastic.co/ecs)

A production-grade, open-source threat detection and SIEM framework engineered for security operations teams. Ingests, normalizes, correlates, and alerts on adversary activity across enterprise log sources with full MITRE ATT&CK traceability.

---

## Architecture

```text
+-------------------------------------------------------------+
|                        LOG SOURCES                          |
|    Windows Events | Linux Syslog | AWS CloudTrail | IDS     |
+---------------------------+---------------------------------+
                            |
                   +--------v--------+
                   |  Log Ingestion  |  Filebeat / Fluentd / API
                   |  and Parsing    |  ECS Normalization
                   +--------+--------+
                            |
                   +--------v--------+
                   |   Enrichment    |  GeoIP / Threat Intel
                   +--------+--------+
                            |
             +--------------v--------------+
             |       Detection Engine       |
             |   Sigma Rules | YARA Rules   |
             |   Snort Rules | Anomaly      |
             +--------------+--------------+
                            |
                   +--------v--------+
                   |  Alert Pipeline |  Slack / PagerDuty / JIRA
                   +--------+--------+
                            |
                   +--------v--------+
                   |   Dashboards    |  Kibana / Grafana / Splunk
                   +-----------------+
```

---

## Detection Coverage

| Tactic               | Rules   | Techniques                 |
|----------------------|---------|----------------------------|
| Credential Access    | 18      | T1003, T1110, T1555, T1212 |
| Execution            | 22      | T1059, T1106, T1204, T1569 |
| Persistence          | 16      | T1053, T1098, T1136, T1543 |
| Lateral Movement     | 14      | T1021, T1076, T1091, T1534 |
| Defense Evasion      | 20      | T1070, T1112, T1218, T1562 |
| Privilege Escalation | 10      | T1055, T1068, T1098, T1134 |
| Exfiltration         | 12      | T1041, T1048, T1052, T1567 |
| Command and Control  | 15      | T1071, T1095, T1105, T1571 |
| Total                | 127     | 50+ techniques             |

---

## Repository Structure

```text
.
+-- detectors/
|   +-- sigma_engine.py         Sigma rule evaluator
|   +-- yara_scanner.py         YARA file and memory scanner
|   +-- anomaly_detector.py     Statistical baseline detection
|   +-- correlation_engine.py   Multi-event correlation
+-- parsers/
|   +-- evtx_parser.py          Windows Event Log (EVTX)
|   +-- syslog_parser.py        Linux auth/syslog/auditd
|   +-- cloudtrail_parser.py    AWS CloudTrail
|   +-- firewall_parser.py      Palo Alto, Cisco ASA, Fortinet
+-- enrichment/
|   +-- threat_intel.py         OTX, VirusTotal, MISP
|   +-- geoip_enricher.py       MaxMind GeoIP2
|   +-- asset_context.py        Asset criticality mapping
+-- alerting/
|   +-- alert_manager.py        Slack, PagerDuty, JIRA, Email
+-- correlations/               Multi-event correlation rules
+-- rules/
|   +-- sigma/
|   |   +-- windows/            credential_access, execution,
|   |   |                       lateral_movement, persistence,
|   |   |                       defense_evasion, discovery
|   |   +-- linux/              execution, persistence
|   |   +-- cloud/aws/          IAM, CloudTrail detections
|   |   +-- network/            c2, exfiltration
|   +-- yara/                   YARA rules
|   +-- snort/                  Snort/Suricata rules
+-- tests/
|   +-- unit/                   Unit tests per module
|   +-- integration/            End-to-end pipeline tests
|   +-- fixtures/               Raw log samples (anonymized)
|   +-- rule_samples/           Per-rule trigger events
+-- dashboards/
|   +-- kibana/                 Kibana saved objects
|   +-- grafana/                Grafana provisioning JSON
|   +-- splunk/                 Splunk saved searches
+-- scripts/
|   +-- ingest_logs.py          CLI log ingestion entry point
|   +-- generate_report.py      MITRE coverage report generator
+-- config/
|   +-- config.example.yaml     Configuration template
+-- docs/                       Architecture and playbooks
+-- k8s/                        Kubernetes manifests
+-- docker-compose.yml          Local ELK and Grafana stack
+-- Dockerfile                  Detection engine container
+-- Makefile                    Developer workflow commands
+-- pyproject.toml              Tool configuration
+-- requirements.txt            Runtime dependencies
+-- requirements-dev.txt        Development dependencies
```

---

## Quick Start

Prerequisites: Python 3.11+, Docker, Docker Compose

```bash
git clone https://github.com/adityavatsaedu-rgb/Threat-Detection-SIEM-repository.git
cd Threat-Detection-SIEM-repository
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml
python scripts/ingest_logs.py --source windows --input logs/security.jsonl
docker-compose up -d
```

Kibana: http://localhost:5601
Grafana: http://localhost:3000
Elasticsearch: http://localhost:9200

---

## Alerting Pipeline

| Severity | SLA        | Destinations             |
|----------|------------|--------------------------|
| Critical | Immediate  | PagerDuty + Slack + JIRA |
| High     | < 15 min   | Slack + JIRA             |
| Medium   | < 1 hour   | Slack                    |
| Low      | Daily      | Email digest             |

---

## Development

```bash
make install          # Install all dependencies
make test             # Run test suite with coverage
make lint             # ruff + mypy + bandit
make validate-rules   # Validate all Sigma and YARA rules
make docker           # Build container image
make report           # Generate MITRE ATT&CK coverage report
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All rule contributions require a MITRE ATT&CK technique mapping, a raw log sample, and documented false positives.

---

## License

MIT License — Copyright 2025 Aditya Vatsa
