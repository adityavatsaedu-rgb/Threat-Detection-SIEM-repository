# Contributing

## Getting started

```bash
git clone https://github.com/adityavatsaedu-rgb/Threat-Detection-SIEM-repository.git
cd Threat-Detection-SIEM-repository
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
make test
```

## Sigma rule contributions

Every rule must include:

1. MITRE ATT&CK technique tag — at least one `attack.tXXXX`
2. Log sample — raw event in `tests/rule_samples/` that triggers the rule
3. False positives — `falsepositives` field must be documented
4. Validation — rule must pass structural YAML validation

### Rule template

```yaml
title: Verb plus Subject
id: <uuid-v4>
status: experimental
description: |
  One paragraph explaining what this detects and why it matters.
references:
  - https://attack.mitre.org/techniques/TXXXX/
author: Your Name
date: YYYY-MM-DD
tags:
  - attack.<tactic>
  - attack.tXXXX
logsource:
  product: windows
  service: security
detection:
  selection:
    FieldName: value
  condition: selection
falsepositives:
  - Describe concrete false positive scenarios
level: high
```

### Severity reference

| Level | Meaning |
|---|---|
| critical | Active compromise, immediate response required |
| high | Strong indicator, likely malicious |
| medium | Suspicious, requires investigation |
| low | Weak signal, contextual value |
| informational | Visibility and audit only |

## Code contributions

- Follow existing module structure
- Add unit tests for all new functionality
- Ensure `make lint` passes before submitting
- Use Conventional Commits: `feat:` `fix:` `rule:` `docs:` `refactor:`

## Pull request process

1. Fork the repository
2. Branch from `main`
3. Make changes with passing tests
4. Submit PR with filled template
