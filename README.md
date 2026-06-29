# Threat Detection SIEM

> **Enterprise-grade Security Information and Event Management (SIEM) implementation focused on defensive security engineering, detection development, log normalization, threat enrichment, alert orchestration, and operational security workflows.**

---

# Executive Summary

Threat Detection SIEM is a repository dedicated to building a modular defensive monitoring pipeline. The implementation centers on transforming heterogeneous security telemetry into actionable detections through parsing, normalization, enrichment, correlation, and alert delivery.

Rather than presenting isolated scripts, the repository is organized as a maintainable engineering project with clearly separated functional components including ingestion, detection logic, enrichment, dashboards, deployment assets, testing, documentation, and automation.

---

# Repository Highlights

- Modular SIEM architecture
- Windows EVTX ingestion
- Linux Syslog ingestion
- AWS CloudTrail support
- Detection engine
- Sigma rule integration
- YARA and Snort rule repository
- Threat intelligence enrichment
- GeoIP enrichment
- Multi-channel alert routing
- Dashboard resources
- Docker deployment
- Kubernetes manifests
- GitHub Actions CI
- Automated testing
- Documentation-first development

---

# High-Level Detection Pipeline

```text
Security Logs
      │
      ▼
Log Parsers
      │
Normalization
      │
Detection Engine
      │
Threat Intelligence Enrichment
      │
Correlation
      │
Alert Manager
      │
SOC Analyst
```

---

# Repository Structure

```text
Threat-Detection-SIEM-repository/
    Threat-Detection-SIEM-repository-main/
        .gitignore
        CHANGELOG.md
        CODE_OF_CONDUCT.md
        CONTRIBUTING.md
        Dockerfile
        LICENSE
        Makefile
        README.md
        SECURITY.md
        docker-compose.yml
        pyproject.toml
        requirements-dev.txt
        requirements.txt
        .github/
            CODEOWNERS
            PULL_REQUEST_TEMPLATE.md
            README.md
            ISSUE_TEMPLATE/
                bug_report.yml
                rule_request.yml
            workflows/
                ci.yml
                release.yml
        alerting/
            README.md
            __init__.py
            alert_manager.py
        config/
            README.md
            config.example.yaml
        correlations/
            README.md
            __init__.py
        dashboards/
            README.md
            grafana/
                .gitkeep
            kibana/
                .gitkeep
            splunk/
                .gitkeep
        data/
            .gitkeep
            README.md
        detectors/
            README.md
            __init__.py
            sigma_engine.py
        docs/
            README.md
            images/
                .gitkeep
            playbooks/
                .gitkeep
        enrichment/
            README.md
            __init__.py
            geoip_enricher.py
            threat_intel.py
        k8s/
            README.md
            deployment.yaml
        parsers/
            README.md
            __init__.py
            cloudtrail_parser.py
            evtx_parser.py
            syslog_parser.py
        rules/
            README.md
            sigma/
                cloud/
                    aws/
                        .gitkeep
                        iam_privilege_escalation.yml
                    azure/
                        .gitkeep
                linux/
                    execution/
                        .gitkeep
                        reverse_shell_indicators.yml
                    lateral_movement/
                        .gitkeep
                    persistence/
                        .gitkeep
                network/
                    .gitkeep
                    c2/
                        .gitkeep
                    exfiltration/
                        .gitkeep
                windows/
                    credential_access/
                        brute_force_rdp.yml
                    defense_evasion/
                        .gitkeep
                        event_log_cleared.yml
                    discovery/
                        .gitkeep
                    execution/
                        powershell_encoded_command.yml
                    lateral_movement/
                        psexec_wmi_execution.yml
                    persistence/
                        .gitkeep
                        scheduled_task_creation.yml
                    privilege_escalation/
                        .gitkeep
            snort/
                .gitkeep
            yara/
                malware/
                    .gitkeep
                webshells/
                    .gitkeep
        scripts/
            README.md
            generate_report.py
            ingest_logs.py
        tests/
            README.md
            __init__.py
            fixtures/
                .gitkeep
            integration/
                .gitkeep
                __init__.py
            rule_samples/
                .gitkeep
            unit/
                __init__.py
                test_sigma_engine.py
```

---

# Engineering Philosophy

This repository follows engineering principles intended to maximize maintainability, reproducibility, readability, and long-term scalability.

Every major responsibility is isolated into its own module whenever practical. Detection logic remains independent from enrichment logic, while alert delivery remains independent from parsing and normalization.

---

# Core Components

## Parsers

Responsible for transforming raw telemetry into structured events.

Current repository includes dedicated parsers for Windows EVTX, Linux Syslog, and AWS CloudTrail logs.

## Detection Engine

The detection layer evaluates normalized events against detection rules while remaining independent from ingestion sources.

## Rules

The repository maintains dedicated rule directories including Sigma, Snort, and YARA resources.

## Enrichment

Threat intelligence and GeoIP enrichment provide additional context before alerts are generated.

## Alerting

Alert routing centralizes notifications while allowing multiple delivery mechanisms.

## Dashboards

Dashboard assets provide visualization support for security operations.

## Deployment

Containerized deployment is supported through Docker while orchestration resources are available through Kubernetes manifests.

## Testing

Tests validate parser behavior and detection logic.

---

# Development Standards

- Modular design
- Explicit naming
- Small focused modules
- Readable implementation
- Documentation alongside code
- Version controlled workflows

---

# Security Principles

- Defensive use only
- Transparency
- Reproducibility
- Responsible disclosure
- No offensive payloads

---

# Getting Started

```bash
git clone https://github.com/adityavatsaedu-rgb/Threat-Detection-SIEM-repository.git
cd Threat-Detection-SIEM-repository
```

Follow module documentation before execution.

---

# Roadmap

Future improvements focus on expanding parser coverage, increasing detection quality, strengthening automated validation, improving documentation, and extending dashboard capabilities while preserving modular architecture.

---

# Contributing

Contributions improving engineering quality, documentation, testing, or defensive capabilities are welcome.

---

# License

MIT License

---

# Author

**Aditya Vatsa**

---

This README documents only capabilities reflected by the repository layout and accompanying project assets. It intentionally avoids claims that cannot be substantiated by the repository contents.
