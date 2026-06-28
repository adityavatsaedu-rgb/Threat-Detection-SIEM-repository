# Threat Detection & SIEM Framework

[![CI](https://github.com/adityavatsaedu-rgb/Threat-Detection-SIEM-repository/actions/workflows/ci.yml/badge.svg)](https://github.com/adityavatsaedu-rgb/Threat-Detection-SIEM-repository/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11+-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Sigma](https://img.shields.io/badge/sigma-rules-orange)](https://sigmahq.io)
[![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)](https://attack.mitre.org)
[![ECS](https://img.shields.io/badge/ECS-compatible-blue?logo=elastic)](https://elastic.co/ecs)

Production-grade threat detection and SIEM framework for security operations teams. Built around the Sigma rule specification with full MITRE ATT&CK traceability, multi-source log normalization to Elastic Common Schema, and a pluggable real-time alerting pipeline.

---

## Architecture
LOG SOURCES

Windows Event Logs

Linux syslog / auditd

AWS CloudTrail

Network IDS/IPS

|

v

INGESTION AND PARSING

Filebeat / Fluentd / Direct API

Normalization to Elastic Common Schema (ECS)

|

v

ENRICHMENT

MaxMind GeoIP2

AlienVault OTX

VirusTotal

Asset context

|

v

DETECTION ENGINE

Sigma rule evaluator

YARA file scanner

Snort/Suricata rules

Statistical anomaly baseline

|

v

ALERT PIPELINE

Severity-based routing

Deduplication and rate limiting

Slack / PagerDuty / JIRA / Email

|

v

DASHBOARDS

Kibana / Grafana / Splunk

---

## Detection Coverage

| Tactic               | Rules | Key Techniques             |
|----------------------|-------|----------------------------|
| Credential Access    | 18    | T1003, T1110, T1555        |
| Execution            | 22    | T1059, T1106, T1204        |
| Persistence          | 16    | T1053, T1098, T1136        |
| Lateral Movement     | 14    | T1021, T1076, T1091        |
| Defense Evasion      | 20    | T1070, T1112, T1218        |
| Privilege Escalation | 10    | T1055, T1068, T1134        |
| Exfiltration         | 12    | T1041, T1048, T1567        |
| Command and Control  | 15    | T1071, T1095, T1105        |
| **Total**            | **127** | **50+ techniques**       |

---

## Structure
detectors/

sigma_engine.py         Sigma rule evaluator

yara_scanner.py         YARA file and memory scanner

anomaly_detector.py     Statistical baseline detection

correlation_engine.py   Multi-event time-window correlation
parsers/

evtx_parser.py          Windows Event Log normalization

syslog_parser.py        Linux auth / syslog / auditd

cloudtrail_parser.py    AWS CloudTrail

firewall_parser.py      Palo Alto, Cisco ASA, Fortinet
enrichment/

threat_intel.py         OTX, VirusTotal, MISP integration

geoip_enricher.py       MaxMind GeoIP2

asset_context.py        Asset criticality mapping
alerting/

alert_manager.py        Routing, deduplication, rate limiting
rules/

sigma/windows/          credential_access, execution,

lateral_movement, persistence,

defense_evasion, discovery

sigma/linux/            execution, persistence

sigma/cloud/aws/        IAM, CloudTrail detections

sigma/network/          C2, exfiltration

yara/                   Malware and webshell signatures

snort/                  Network detection rules
tests/

unit/                   Per-module unit tests

integration/            End-to-end pipeline tests

fixtures/               Anonymized raw log samples

rule_samples/           Per-rule trigger events
dashboards/

kibana/                 Saved objects and index patterns

grafana/                Provisioning JSON

splunk/                 Saved searches
scripts/

ingest_logs.py          CLI ingestion entry point

generate_report.py      MITRE ATT&CK coverage report
config/

config.example.yaml     Configuration template
k8s/                        Kubernetes deployment manifests

docs/                       Architecture notes and playbooks

---

## Quick Start

```bash
git clone https://github.com/adityavatsaedu-rgb/Threat-Detection-SIEM-repository.git
cd Threat-Detection-SIEM-repository
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml
```

Run against a Windows event log export:
```bash
python scripts/ingest_logs.py --source windows --input logs/security.jsonl
```

Run against AWS CloudTrail:
```bash
python scripts/ingest_logs.py --source cloudtrail --input logs/trail.jsonl
```

Start the full local stack:
```bash
docker-compose up -d
```

| Service       | URL                        |
|---------------|----------------------------|
| Kibana        | http://localhost:5601       |
| Grafana       | http://localhost:3000       |
| Elasticsearch | http://localhost:9200       |

---

## Alerting

| Severity | SLA       | Channels                 |
|----------|-----------|--------------------------|
| Critical | Immediate | PagerDuty, Slack, JIRA   |
| High     | 15 min    | Slack, JIRA              |
| Medium   | 1 hour    | Slack                    |
| Low      | Daily     | Email                    |

---

## Development

```bash
make install          # dependencies
make test             # pytest with coverage
make lint             # ruff, mypy, bandit
make validate-rules   # Sigma rule validation
make docker           # build container
make report           # MITRE coverage report
```

---

## Deployment

```bash
# Docker Compose
docker-compose up -d

# Kubernetes
kubectl apply -f k8s/
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every rule contribution requires a MITRE ATT&CK technique mapping, a raw log sample in `tests/rule_samples/`, and documented false positives.

---

## License

MIT License — Copyright 2026 Aditya Vatsa
