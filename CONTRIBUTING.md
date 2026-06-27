# Contributing to Threat Detection SIEM

Thank you for helping make this project better.

## Sigma rule contributions

Every new detection rule must include:

1. **MITRE ATT&CK mapping** — at least one `attack.tXXXX` tag
2. **Log sample** — a raw event in `tests/rule_samples/` that triggers the rule
3. **False positive documentation** — the `falsepositives` field must be non-empty
4. **Sigma validation** — `sigma check rules/sigma/your_rule.yml` must pass

### Rule template

```yaml
title: Verb + Subject
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
  product: windows|linux|cloud|network
  service: security|syslog|cloudtrail|...
detection:
  selection:
    FieldName: value
  filter:
    FieldName: benign_value
  condition: selection and not filter
falsepositives:
  - Describe concrete false positive scenarios
level: informational|low|medium|high|critical
```

### Severity guide

| Level | Meaning |
|---|---|
| critical | Active attack, immediate response required |
| high | Strong indicator, likely malicious |
| medium | Suspicious, needs investigation |
| low | Weak signal, contextual value |
| informational | Audit / visibility only |

## Code contributions

```bash
git clone https://github.com/adityavatsaedu-rgb/Threat-Detection-SIEM-repository
cd Threat-Detection-SIEM-repository
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
make test
```

Use Conventional Commits: `feat:`, `fix:`, `rule:`, `docs:`, `refactor:`, `test:`
