"""
Sigma Rule Evaluation Engine
Evaluates normalized log events against Sigma rules with MITRE ATT&CK mapping.
"""

import os
import re
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any, Generator
from collections import defaultdict

import yaml
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────

@dataclass
class SigmaRule:
    id: str
    title: str
    status: str
    description: str
    level: str                          # informational / low / medium / high / critical
    tags: list[str] = field(default_factory=list)
    logsource: dict = field(default_factory=dict)
    detection: dict = field(default_factory=dict)
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    author: str = ""
    date: str = ""
    modified: str = ""

    @property
    def mitre_techniques(self) -> list[str]:
        return [t.replace("attack.", "").upper() for t in self.tags if re.match(r"attack\.t\d{4}", t, re.I)]

    @property
    def mitre_tactics(self) -> list[str]:
        tactic_map = {
            "initial_access": "TA0001", "execution": "TA0002",
            "persistence": "TA0003", "privilege_escalation": "TA0004",
            "defense_evasion": "TA0005", "credential_access": "TA0006",
            "discovery": "TA0007", "lateral_movement": "TA0008",
            "collection": "TA0009", "exfiltration": "TA0010",
            "command_and_control": "TA0011", "impact": "TA0040",
        }
        return [tactic_map[t.replace("attack.", "")] for t in self.tags
                if t.replace("attack.", "") in tactic_map]


@dataclass
class DetectionAlert:
    rule_id: str
    rule_title: str
    level: str
    event: dict
    matched_fields: dict
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "alert_id": f"{self.rule_id}-{int(self.timestamp.timestamp())}",
            "rule": {"id": self.rule_id, "title": self.rule_title, "level": self.level},
            "mitre": {"techniques": self.mitre_techniques, "tactics": self.mitre_tactics},
            "event": self.event,
            "matched": self.matched_fields,
            "@timestamp": self.timestamp.isoformat() + "Z",
        }


# ─────────────────────────────────────────────
# Rule Loader
# ─────────────────────────────────────────────

class SigmaRuleLoader:
    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self._rules: list[SigmaRule] = []

    def load_all(self) -> list[SigmaRule]:
        self._rules = []
        for path in self.rules_dir.rglob("*.yml"):
            try:
                rule = self._parse_file(path)
                if rule and rule.status not in ("deprecated", "unsupported"):
                    self._rules.append(rule)
            except Exception as exc:
                logger.warning("Failed to load rule %s: %s", path, exc)
        logger.info("Loaded %d Sigma rules from %s", len(self._rules), self.rules_dir)
        return self._rules

    def _parse_file(self, path: Path) -> SigmaRule | None:
        with open(path) as fh:
            data = yaml.safe_load(fh)
        if not data or "detection" not in data:
            return None
        return SigmaRule(
            id=data.get("id", str(path.stem)),
            title=data.get("title", ""),
            status=data.get("status", "experimental"),
            description=data.get("description", ""),
            level=data.get("level", "medium"),
            tags=data.get("tags", []),
            logsource=data.get("logsource", {}),
            detection=data.get("detection", {}),
            falsepositives=data.get("falsepositives", []),
            references=data.get("references", []),
            author=data.get("author", ""),
            date=str(data.get("date", "")),
            modified=str(data.get("modified", "")),
        )

    @property
    def rules(self) -> list[SigmaRule]:
        return self._rules


# ─────────────────────────────────────────────
# Condition Evaluator
# ─────────────────────────────────────────────

class ConditionEvaluator:
    """Evaluates Sigma detection conditions against a normalized event."""

    def evaluate(self, rule: SigmaRule, event: dict) -> tuple[bool, dict]:
        detection = rule.detection
        named_selections: dict[str, bool] = {}
        matched_fields: dict[str, Any] = {}

        # Evaluate all named selections (everything except 'condition' and 'timeframe')
        for key, val in detection.items():
            if key in ("condition", "timeframe"):
                continue
            hit, fields = self._eval_selection(val, event)
            named_selections[key] = hit
            if hit:
                matched_fields.update(fields)

        condition_str = detection.get("condition", "selection")
        result = self._eval_condition(condition_str, named_selections)
        return result, matched_fields if result else {}

    def _eval_selection(self, selection: Any, event: dict) -> tuple[bool, dict]:
        if isinstance(selection, dict):
            return self._eval_dict_selection(selection, event)
        if isinstance(selection, list):
            # OR of items
            for item in selection:
                hit, fields = self._eval_selection(item, event)
                if hit:
                    return True, fields
            return False, {}
        return False, {}

    def _eval_dict_selection(self, sel: dict, event: dict) -> tuple[bool, dict]:
        matched: dict = {}
        for key, expected in sel.items():
            field_name, modifier = self._parse_field_modifier(key)
            actual = self._get_nested(event, field_name)
            if actual is None:
                return False, {}
            if not self._match_value(actual, expected, modifier):
                return False, {}
            matched[field_name] = actual
        return True, matched

    def _parse_field_modifier(self, key: str) -> tuple[str, str]:
        parts = key.split("|")
        return parts[0], parts[1] if len(parts) > 1 else "equals"

    def _match_value(self, actual: Any, expected: Any, modifier: str) -> bool:
        actual_str = str(actual).lower()
        if isinstance(expected, list):
            return any(self._match_single(actual_str, str(e).lower(), modifier) for e in expected)
        return self._match_single(actual_str, str(expected).lower(), modifier)

    def _match_single(self, actual: str, expected: str, modifier: str) -> bool:
        if modifier in ("equals", ""):
            # Support wildcards
            pattern = re.escape(expected).replace(r"\*", ".*").replace(r"\?", ".")
            return bool(re.fullmatch(pattern, actual, re.IGNORECASE))
        if modifier == "contains":
            return expected in actual
        if modifier == "startswith":
            return actual.startswith(expected)
        if modifier == "endswith":
            return actual.endswith(expected)
        if modifier == "re":
            return bool(re.search(expected, actual, re.IGNORECASE))
        return False

    def _eval_condition(self, condition: str, selections: dict[str, bool]) -> bool:
        # Replace named selections with True/False, then eval basic AND/OR/NOT/1of/all of
        cond = condition.strip()

        # Handle "1 of selection*" / "all of selection*"
        one_of_match = re.match(r"1 of (\w+)\*", cond)
        all_of_match = re.match(r"all of (\w+)\*", cond)
        if one_of_match:
            prefix = one_of_match.group(1)
            return any(v for k, v in selections.items() if k.startswith(prefix))
        if all_of_match:
            prefix = all_of_match.group(1)
            keys = [k for k in selections if k.startswith(prefix)]
            return bool(keys) and all(selections[k] for k in keys)

        # Replace names with bool literals
        for name, val in sorted(selections.items(), key=lambda x: -len(x[0])):
            cond = re.sub(rf"\b{re.escape(name)}\b", str(val), cond)

        cond = cond.replace("not ", " not ").replace(" and ", " and ").replace(" or ", " or ")
        try:
            # Safe eval: only booleans and logical ops
            return bool(eval(cond, {"__builtins__": {}}, {"True": True, "False": False}))  # noqa: S307
        except Exception:
            logger.debug("Could not evaluate condition: %s", cond)
            return False

    @staticmethod
    def _get_nested(obj: dict, key: str) -> Any:
        """Supports dotted key paths: 'process.name'"""
        for part in key.split("."):
            if not isinstance(obj, dict):
                return None
            obj = obj.get(part)
        return obj


# ─────────────────────────────────────────────
# Time-window aggregation (for count conditions)
# ─────────────────────────────────────────────

class TimeWindowAggregator:
    def __init__(self):
        self._buckets: dict[str, list[dict]] = defaultdict(list)

    def add(self, rule_id: str, event: dict, window_seconds: int) -> list[dict]:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)
        bucket = self._buckets[rule_id]
        bucket.append({"ts": now, "event": event})
        self._buckets[rule_id] = [e for e in bucket if e["ts"] >= cutoff]
        return [e["event"] for e in self._buckets[rule_id]]


# ─────────────────────────────────────────────
# Main Engine
# ─────────────────────────────────────────────

class SigmaEngine:
    def __init__(self, rules_dir: str, alert_callback=None):
        self.loader = SigmaRuleLoader(rules_dir)
        self.evaluator = ConditionEvaluator()
        self.aggregator = TimeWindowAggregator()
        self.alert_callback = alert_callback or self._default_alert_handler
        self._rules: list[SigmaRule] = []
        self._stats = {"processed": 0, "alerts": 0, "rules_hit": defaultdict(int)}

    def load_rules(self) -> int:
        self._rules = self.loader.load_all()
        return len(self._rules)

    def process_event(self, event: dict) -> list[DetectionAlert]:
        self._stats["processed"] += 1
        alerts = []
        for rule in self._rules:
            if not self._logsource_matches(rule, event):
                continue
            hit, matched = self.evaluator.evaluate(rule, event)
            if hit:
                alert = DetectionAlert(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    level=rule.level,
                    event=event,
                    matched_fields=matched,
                    mitre_techniques=rule.mitre_techniques,
                    mitre_tactics=rule.mitre_tactics,
                )
                alerts.append(alert)
                self._stats["alerts"] += 1
                self._stats["rules_hit"][rule.id] += 1
                self.alert_callback(alert)
        return alerts

    def process_stream(self, events: Generator[dict, None, None]) -> None:
        for event in events:
            self.process_event(event)

    def process_file(self, path: str) -> list[DetectionAlert]:
        all_alerts = []
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    all_alerts.extend(self.process_event(event))
                except json.JSONDecodeError:
                    logger.warning("Skipping non-JSON line")
        return all_alerts

    def _logsource_matches(self, rule: SigmaRule, event: dict) -> bool:
        ls = rule.logsource
        if not ls:
            return True
        for key in ("product", "service", "category"):
            if key in ls:
                event_val = str(event.get("log", {}).get(key, event.get(key, ""))).lower()
                if ls[key].lower() not in event_val:
                    return False
        return True

    @staticmethod
    def _default_alert_handler(alert: DetectionAlert) -> None:
        print(json.dumps(alert.to_dict(), indent=2, default=str))

    @property
    def stats(self) -> dict:
        return dict(self._stats)


# ─────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Sigma Detection Engine")
    p.add_argument("--rules", default="rules/sigma", help="Path to Sigma rules directory")
    p.add_argument("--mode", choices=["batch", "realtime"], default="batch")
    p.add_argument("--input", help="Input JSONL log file (batch mode)")
    p.add_argument("--source", help="Log directory to tail (realtime mode)")
    p.add_argument("--output", help="Output JSONL alert file")
    p.add_argument("--log-level", default="INFO")
    return p


def main():
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s %(message)s")

    alerts_out = open(args.output, "w") if args.output else None

    def handler(alert: DetectionAlert):
        data = json.dumps(alert.to_dict(), default=str)
        print(data)
        if alerts_out:
            alerts_out.write(data + "\n")

    engine = SigmaEngine(rules_dir=args.rules, alert_callback=handler)
    n = engine.load_rules()
    logger.info("Rules loaded: %d", n)

    if args.mode == "batch":
        if not args.input:
            raise SystemExit("--input required in batch mode")
        engine.process_file(args.input)
    else:
        # Realtime stub — integrate with Filebeat/Fluentd in production
        logger.info("Realtime mode: watching %s", args.source)
        import time
        while True:
            time.sleep(1)

    stats = engine.stats
    logger.info("Done. Processed: %d events, Alerts: %d", stats["processed"], stats["alerts"])
    if alerts_out:
        alerts_out.close()


if __name__ == "__main__":
    main()
