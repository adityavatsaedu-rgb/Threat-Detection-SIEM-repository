"""
Detection Coverage Report Generator
Scans all Sigma rules and produces a MITRE ATT&CK coverage report.

Usage:
  python scripts/generate_report.py --rules rules/sigma --output report.md
"""

import argparse
import re
from collections import defaultdict
from pathlib import Path

import yaml

TACTIC_NAMES = {
    "TA0001": "Initial Access",       "TA0002": "Execution",
    "TA0003": "Persistence",          "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",      "TA0006": "Credential Access",
    "TA0007": "Discovery",            "TA0008": "Lateral Movement",
    "TA0009": "Collection",           "TA0010": "Exfiltration",
    "TA0011": "Command and Control",  "TA0040": "Impact",
}


def load_rules(rules_dir: str) -> list[dict]:
    rules = []
    for path in Path(rules_dir).rglob("*.yml"):
        try:
            with open(path) as fh:
                data = yaml.safe_load(fh)
            if data and "detection" in data:
                data["_path"] = str(path)
                rules.append(data)
        except Exception:
            pass
    return rules


def generate_report(rules: list[dict]) -> str:
    by_level: dict[str, int] = defaultdict(int)
    by_tactic: dict[str, list[str]] = defaultdict(list)
    techniques: set[str] = set()

    for rule in rules:
        level = rule.get("level", "unknown")
        by_level[level] += 1
        for tag in rule.get("tags", []):
            if re.match(r"attack\.t\d{4}", tag, re.I):
                tech = tag.replace("attack.", "").upper()
                techniques.add(tech)
            tactic_map = {
                "credential_access": "TA0006", "execution": "TA0002",
                "persistence": "TA0003", "lateral_movement": "TA0008",
                "defense_evasion": "TA0005", "discovery": "TA0007",
                "exfiltration": "TA0010", "command_and_control": "TA0011",
                "privilege_escalation": "TA0004", "impact": "TA0040",
            }
            for tactic_tag, tactic_id in tactic_map.items():
                if f"attack.{tactic_tag}" == tag:
                    by_tactic[TACTIC_NAMES[tactic_id]].append(rule.get("title", ""))

    lines = [
        "# Detection Coverage Report",
        "",
        f"**Total rules:** {len(rules)}  ",
        f"**Unique techniques:** {len(techniques)}  ",
        "",
        "## Rules by severity",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for level in ["critical", "high", "medium", "low", "informational"]:
        lines.append(f"| {level.capitalize()} | {by_level.get(level, 0)} |")

    lines += ["", "## Coverage by tactic", "", "| Tactic | Rules |", "|---|---|"]
    for tactic, rule_titles in sorted(by_tactic.items()):
        lines.append(f"| {tactic} | {len(rule_titles)} |")

    lines += ["", "## MITRE ATT&CK techniques covered", ""]
    for tech in sorted(techniques):
        lines.append(f"- {tech}")

    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser(description="Generate detection coverage report")
    p.add_argument("--rules",  default="rules/sigma")
    p.add_argument("--output", default="docs/coverage_report.md")
    args = p.parse_args()

    rules = load_rules(args.rules)
    print(f"Loaded {len(rules)} rules")
    report = generate_report(rules)

    with open(args.output, "w") as fh:
        fh.write(report)
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
