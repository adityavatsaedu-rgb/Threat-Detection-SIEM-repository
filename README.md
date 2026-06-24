# 🛡️ Threat Detection & SIEM Framework

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0D1117,50:00FF41,100:0D1117&height=220&section=header&text=Threat%20Detection%20Framework&fontSize=40&fontColor=FFFFFF&animation=fadeIn&fontAlignY=38&desc=SIEM%20|%20Log%20Analysis%20|%20Alerting%20|%20Threat%20Intelligence&descAlignY=58&descSize=16&descColor=A0A0A0" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Sigma_Rules-Enabled-FF6B35?style=for-the-badge&logo=elastic&logoColor=white"/>
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-E63946?style=for-the-badge&logo=target&logoColor=white"/>
  <img src="https://img.shields.io/badge/YARA-Rules-7400B8?style=for-the-badge&logo=virustotal&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Elastic-Compatible-005571?style=for-the-badge&logo=elastic&logoColor=white"/>
  <img src="https://img.shields.io/badge/Splunk-Compatible-65A637?style=for-the-badge&logo=splunk&logoColor=white"/>
  <img src="https://img.shields.io/badge/OpenSearch-Compatible-003B57?style=for-the-badge&logo=opensearch&logoColor=white"/>
</p>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Detection Coverage](#detection-coverage)
- [Components](#components)
- [Quick Start](#quick-start)
- [Detection Rules](#detection-rules)
- [Log Parsers](#log-parsers)
- [Alerting Pipeline](#alerting-pipeline)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Deployment](#deployment)
- [Contributing](#contributing)

---

## 🔍 Overview

A production-grade, open-source **Threat Detection & SIEM Framework** designed for SOC teams. It provides:

- **Multi-source log ingestion** with normalized schema (ECS-compatible)
- **Sigma rule engine** with real-time and batch evaluation
- **YARA-based file/memory scanning** integrated into the pipeline
- **MITRE ATT&CK-mapped detections** across 15+ tactic categories
- **Pluggable alerting** (Slack, PagerDuty, JIRA, Email, Webhook)
- **Threat intelligence enrichment** via MISP, OTX, VirusTotal
- **Dashboards** for Kibana, Grafana, and Splunk

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        LOG SOURCES                               │
│  Windows Events │ Linux Syslog │ AWS CloudTrail │ Firewall/IDS  │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Log Ingestion  │  (Filebeat / Fluentd / API)
                    │   & Parsing     │
                    └────────┬────────┘
                             │ Normalized ECS Events
                    ┌────────▼────────┐
                    │   Enrichment    │  (GeoIP, TI Feeds, WHOIS)
                    │    Engine       │
                    └────────┬────────┘
                             │
              ┌──────────────▼──────────────┐
              │      Detection Engine        │
              │  ┌──────────┐ ┌──────────┐  │
              │  │  Sigma   │ │   YARA   │  │
              │  │  Rules   │ │  Rules   │  │
              │  └──────────┘ └──────────┘  │
              │  ┌──────────┐ ┌──────────┐  │
              │  │ Snort/   │ │ Anomaly  │  │
              │  │  Suric.  │ │ Baseline │  │
              │  └──────────┘ └──────────┘  │
              └──────────────┬──────────────┘
                             │ Alerts
                    ┌────────▼────────┐
                    │    Alerting     │  (Slack / PagerDuty / JIRA)
                    │    Pipeline     │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   Dashboards    │  (Kibana / Grafana / Splunk)
                    └─────────────────┘
```

---

## 🎯 Detection Coverage

| Category | Rules | MITRE Techniques |
|---|---|---|
| Credential Access | 18 | T1003, T1110, T1555, T1212 |
| Lateral Movement | 14 | T1021, T1076, T1091, T1534 |
| Execution | 22 | T1059, T1106, T1204, T1569 |
| Persistence | 16 | T1053, T1098, T1136, T1543 |
| Defense Evasion | 20 | T1070, T1112, T1218, T1562 |
| Exfiltration | 12 | T1041, T1048, T1052, T1567 |
| Command & Control | 15 | T1071, T1095, T1105, T1571 |
| Discovery | 10 | T1016, T1018, T1057, T1082 |
| **Total** | **127** | **50+ techniques** |

---

## 🧩 Components

```
threat-detection-siem/
├── detectors/                  # Core detection engine
│   ├── sigma_engine.py         # Sigma rule evaluator
│   ├── yara_scanner.py         # YARA rule scanner
│   ├── anomaly_detector.py     # Statistical anomaly detection
│   └── correlation_engine.py   # Multi-event correlation
├── rules/
│   ├── sigma/                  # Sigma detection rules (.yml)
│   │   ├── windows/
│   │   ├── linux/
│   │   ├── cloud/
│   │   └── network/
│   ├── yara/                   # YARA rules (.yar)
│   └── snort/                  # Snort/Suricata rules (.rules)
├── parsers/
│   ├── windows_event_parser.py
│   ├── syslog_parser.py
│   ├── cloudtrail_parser.py
│   └── firewall_parser.py
├── enrichment/
│   ├── geoip_enricher.py
│   ├── threat_intel.py         # MISP, OTX, VT integration
│   └── asset_context.py
├── alerting/
│   ├── alert_manager.py
│   ├── slack_notifier.py
│   ├── pagerduty_notifier.py
│   └── jira_notifier.py
├── dashboards/
│   ├── kibana/
│   ├── grafana/
│   └── splunk/
├── scripts/
│   ├── ingest_logs.py
│   ├── tune_rules.py
│   └── generate_report.py
├── tests/
├── docs/
└── .github/workflows/
```

---

## 🚀 Quick Start

### Prerequisites

```bash
python >= 3.11
docker & docker-compose
```

### 1. Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/threat-detection-siem.git
cd threat-detection-siem
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your SIEM endpoint, TI API keys, alert destinations
```

### 3. Run Detection Engine

```bash
# Real-time mode (tail logs)
python -m detectors.sigma_engine --mode realtime --source /var/log/

# Batch mode (analyze log archive)
python -m detectors.sigma_engine --mode batch --input logs/archive.jsonl

# With enrichment
python -m detectors.sigma_engine --mode realtime --enrich geoip,threatintel
```

### 4. Docker Stack

```bash
docker-compose up -d
# Kibana: http://localhost:5601
# Grafana: http://localhost:3000
```

---

## 📜 Detection Rules

Rules follow the **Sigma** specification and are organized by platform and MITRE tactic.

Example — Brute Force Detection:
```yaml
# rules/sigma/windows/credential_access/brute_force_rdp.yml
title: RDP Brute Force Attack
id: a3f1b2c4-...
status: stable
description: Detects multiple failed RDP authentication attempts from a single source
references:
  - https://attack.mitre.org/techniques/T1110/
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 10
  timeframe: 5m
  condition: selection | count(TargetUserName) by IpAddress > 10
falsepositives:
  - Legitimate admin automation
level: high
```

See [`rules/sigma/`](rules/sigma/) for all 127 rules.

---

## 🔎 Log Parsers

All parsers normalize to **Elastic Common Schema (ECS)** for cross-platform compatibility.

Supported sources:
- Windows Security/System/Application Event Logs (EVTX)
- Linux syslog, auditd, auth.log
- AWS CloudTrail, GuardDuty, VPC Flow Logs
- Azure AD Sign-in Logs, Activity Logs
- Palo Alto, Cisco ASA, Fortinet firewall logs
- Zeek/Bro network logs

---

## 🔔 Alerting Pipeline

Alerts are routed based on severity and rule tags:

| Severity | SLA | Destinations |
|---|---|---|
| Critical | Immediate | PagerDuty + Slack + JIRA |
| High | < 15 min | Slack + JIRA |
| Medium | < 1 hour | Slack |
| Low | Daily digest | Email |

---

## 🗺️ MITRE ATT&CK Coverage

![MITRE ATT&CK Navigator](docs/images/attack_navigator.png)

Navigator layer file: [`docs/attack_navigator_layer.json`](docs/attack_navigator_layer.json)

---

## 🚢 Deployment

### Production (Docker Compose)

```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Kubernetes

```bash
kubectl apply -f k8s/
```

### Standalone

```bash
python scripts/ingest_logs.py --config config/config.yaml
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Rule contributions must include:
- MITRE ATT&CK technique mapping
- Log sample triggering the rule
- False positive documentation
- Sigma validation: `sigma check rules/sigma/your_rule.yml`

---

## 📄 License

MIT License © 2025 Aditya Vatsa — Built for the defender community.

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0D1117,50:00FF41,100:0D1117&height=160&section=footer&text=Made%20with%20❤️%20for%20the%20Defender%20Community&fontColor=FFFFFF&fontSize=18&animation=fadeIn" />
</p>

<p align="center">
  © 2025 Aditya Vatsa • Built for modern defenders
</p>
