"""
Unit tests for the Sigma detection engine and Windows event parser.
"""

import json
import textwrap
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from detectors.sigma_engine import (
    ConditionEvaluator,
    DetectionAlert,
    SigmaEngine,
    SigmaRule,
    SigmaRuleLoader,
)
from parsers.windows_event_parser import WindowsEventParser


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def sample_rule() -> SigmaRule:
    return SigmaRule(
        id="test-001",
        title="Test Rule",
        status="stable",
        description="Test",
        level="high",
        tags=["attack.credential_access", "attack.t1110.001"],
        logsource={"product": "windows", "service": "security"},
        detection={
            "selection": {"EventID": 4625, "LogonType": 10},
            "condition": "selection",
        },
    )


@pytest.fixture
def matching_event() -> dict:
    return {
        "EventID": "4625",
        "LogonType": "10",
        "IpAddress": "192.168.1.50",
        "TargetUserName": "Administrator",
        "log": {"product": "windows", "service": "security"},
    }


@pytest.fixture
def non_matching_event() -> dict:
    return {
        "EventID": "4624",  # Successful logon, not 4625
        "LogonType": "2",
        "log": {"product": "windows", "service": "security"},
    }


# ─────────────────────────────────────────────
# SigmaRule Tests
# ─────────────────────────────────────────────

class TestSigmaRule:
    def test_mitre_techniques_extracted(self, sample_rule):
        assert "T1110.001" in sample_rule.mitre_techniques

    def test_mitre_tactics_extracted(self, sample_rule):
        assert "TA0006" in sample_rule.mitre_tactics

    def test_no_tags(self):
        rule = SigmaRule(id="x", title="x", status="stable", description="",
                         level="low", tags=[], logsource={}, detection={})
        assert rule.mitre_techniques == []
        assert rule.mitre_tactics == []


# ─────────────────────────────────────────────
# ConditionEvaluator Tests
# ─────────────────────────────────────────────

class TestConditionEvaluator:
    def setup_method(self):
        self.evaluator = ConditionEvaluator()

    def test_simple_match(self, sample_rule, matching_event):
        hit, fields = self.evaluator.evaluate(sample_rule, matching_event)
        assert hit is True
        assert "EventID" in fields

    def test_no_match_wrong_event_id(self, sample_rule, non_matching_event):
        hit, fields = self.evaluator.evaluate(sample_rule, non_matching_event)
        assert hit is False
        assert fields == {}

    def test_wildcard_match(self):
        rule = SigmaRule(
            id="wc-001", title="Wildcard", status="stable", description="",
            level="medium", logsource={},
            detection={
                "selection": {"process.name|endswith": ".exe"},
                "condition": "selection",
            },
        )
        event = {"process": {"name": "malware.exe"}}
        hit, _ = self.evaluator.evaluate(rule, event)
        assert hit is True

    def test_contains_modifier(self):
        rule = SigmaRule(
            id="ct-001", title="Contains", status="stable", description="",
            level="medium", logsource={},
            detection={
                "selection": {"process.command_line|contains": "mimikatz"},
                "condition": "selection",
            },
        )
        event = {"process": {"command_line": "C:\\tools\\mimikatz.exe lsadump::sam"}}
        hit, fields = self.evaluator.evaluate(rule, event)
        assert hit is True

    def test_list_of_values_or_logic(self):
        rule = SigmaRule(
            id="list-001", title="List", status="stable", description="",
            level="high", logsource={},
            detection={
                "selection": {"EventID": [4624, 4625, 4648]},
                "condition": "selection",
            },
        )
        for eid in (4624, 4625, 4648):
            hit, _ = self.evaluator.evaluate(rule, {"EventID": str(eid)})
            assert hit is True
        hit, _ = self.evaluator.evaluate(rule, {"EventID": "9999"})
        assert hit is False

    def test_not_condition(self):
        rule = SigmaRule(
            id="not-001", title="NOT", status="stable", description="",
            level="low", logsource={},
            detection={
                "selection": {"EventID": 4625},
                "filter": {"IpAddress": "-"},
                "condition": "selection and not filter",
            },
        )
        event_with_dash = {"EventID": "4625", "IpAddress": "-"}
        event_without_dash = {"EventID": "4625", "IpAddress": "10.0.0.1"}
        hit1, _ = self.evaluator.evaluate(rule, event_with_dash)
        hit2, _ = self.evaluator.evaluate(rule, event_without_dash)
        assert hit1 is False
        assert hit2 is True

    def test_one_of_condition(self):
        rule = SigmaRule(
            id="oneOf-001", title="1of", status="stable", description="",
            level="high", logsource={},
            detection={
                "selection1": {"EventID": 4624},
                "selection2": {"EventID": 4625},
                "condition": "1 of selection*",
            },
        )
        hit, _ = self.evaluator.evaluate(rule, {"EventID": "4624"})
        assert hit is True
        hit, _ = self.evaluator.evaluate(rule, {"EventID": "9999"})
        assert hit is False

    def test_nested_field_path(self):
        rule = SigmaRule(
            id="nest-001", title="Nested", status="stable", description="",
            level="low", logsource={},
            detection={
                "selection": {"process.name": "cmd.exe"},
                "condition": "selection",
            },
        )
        event = {"process": {"name": "cmd.exe"}}
        hit, fields = self.evaluator.evaluate(rule, event)
        assert hit is True
        assert fields.get("process.name") == "cmd.exe"


# ─────────────────────────────────────────────
# SigmaRuleLoader Tests
# ─────────────────────────────────────────────

class TestSigmaRuleLoader:
    def test_load_rule_file(self, tmp_path):
        rule_data = {
            "id": "load-001",
            "title": "Loaded Rule",
            "status": "stable",
            "description": "Test",
            "level": "high",
            "logsource": {"product": "windows"},
            "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
        }
        rule_dir = tmp_path / "sigma"
        rule_dir.mkdir()
        (rule_dir / "test.yml").write_text(yaml.dump(rule_data))

        loader = SigmaRuleLoader(str(rule_dir))
        rules = loader.load_all()
        assert len(rules) == 1
        assert rules[0].id == "load-001"

    def test_skip_deprecated(self, tmp_path):
        rule_data = {
            "id": "dep-001", "title": "Deprecated", "status": "deprecated",
            "level": "low", "logsource": {},
            "detection": {"selection": {}, "condition": "selection"},
        }
        rule_dir = tmp_path / "sigma"
        rule_dir.mkdir()
        (rule_dir / "dep.yml").write_text(yaml.dump(rule_data))
        loader = SigmaRuleLoader(str(rule_dir))
        rules = loader.load_all()
        assert len(rules) == 0

    def test_ignore_malformed_file(self, tmp_path):
        rule_dir = tmp_path / "sigma"
        rule_dir.mkdir()
        (rule_dir / "bad.yml").write_text("{ invalid yaml: [\n")
        loader = SigmaRuleLoader(str(rule_dir))
        rules = loader.load_all()  # Should not raise
        assert len(rules) == 0


# ─────────────────────────────────────────────
# SigmaEngine Tests
# ─────────────────────────────────────────────

class TestSigmaEngine:
    def test_alerts_on_match(self, tmp_path, sample_rule, matching_event):
        # Write rule to temp dir
        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        rule_data = {
            "id": sample_rule.id, "title": sample_rule.title,
            "status": sample_rule.status, "description": sample_rule.description,
            "level": sample_rule.level, "tags": sample_rule.tags,
            "logsource": sample_rule.logsource, "detection": sample_rule.detection,
        }
        (rule_dir / "test.yml").write_text(yaml.dump(rule_data))

        received = []
        engine = SigmaEngine(str(rule_dir), alert_callback=received.append)
        engine.load_rules()
        alerts = engine.process_event(matching_event)

        assert len(alerts) == 1
        assert alerts[0].rule_id == "test-001"
        assert len(received) == 1

    def test_no_alert_on_no_match(self, tmp_path, sample_rule, non_matching_event):
        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        rule_data = {
            "id": sample_rule.id, "title": sample_rule.title,
            "status": sample_rule.status, "description": sample_rule.description,
            "level": sample_rule.level, "tags": sample_rule.tags,
            "logsource": sample_rule.logsource, "detection": sample_rule.detection,
        }
        (rule_dir / "test.yml").write_text(yaml.dump(rule_data))

        engine = SigmaEngine(str(rule_dir))
        engine.load_rules()
        alerts = engine.process_event(non_matching_event)
        assert alerts == []

    def test_stats_incremented(self, tmp_path, sample_rule, matching_event):
        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        rule_data = {
            "id": sample_rule.id, "title": sample_rule.title,
            "status": sample_rule.status, "description": sample_rule.description,
            "level": sample_rule.level, "tags": sample_rule.tags,
            "logsource": sample_rule.logsource, "detection": sample_rule.detection,
        }
        (rule_dir / "test.yml").write_text(yaml.dump(rule_data))
        engine = SigmaEngine(str(rule_dir))
        engine.load_rules()
        engine.process_event(matching_event)
        assert engine.stats["processed"] == 1
        assert engine.stats["alerts"] == 1

    def test_batch_file_processing(self, tmp_path, sample_rule, matching_event, non_matching_event):
        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        rule_data = {
            "id": sample_rule.id, "title": sample_rule.title,
            "status": sample_rule.status, "description": sample_rule.description,
            "level": sample_rule.level, "tags": sample_rule.tags,
            "logsource": sample_rule.logsource, "detection": sample_rule.detection,
        }
        (rule_dir / "test.yml").write_text(yaml.dump(rule_data))

        log_file = tmp_path / "events.jsonl"
        log_file.write_text(
            json.dumps(matching_event) + "\n" + json.dumps(non_matching_event) + "\n"
        )

        engine = SigmaEngine(str(rule_dir))
        engine.load_rules()
        alerts = engine.process_file(str(log_file))
        assert len(alerts) == 1


# ─────────────────────────────────────────────
# Windows Event Parser Tests
# ─────────────────────────────────────────────

class TestWindowsEventParser:
    def setup_method(self):
        self.parser = WindowsEventParser()

    def test_parse_4625_xml(self):
        xml = textwrap.dedent("""\
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>4625</EventID>
            <Channel>Security</Channel>
            <Computer>WORKSTATION-01</Computer>
            <TimeCreated SystemTime="2024-06-01T10:00:00.000Z"/>
          </System>
          <EventData>
            <Data Name="TargetUserName">Administrator</Data>
            <Data Name="IpAddress">192.168.1.100</Data>
            <Data Name="LogonType">10</Data>
            <Data Name="FailureReason">%%2313</Data>
          </EventData>
        </Event>
        """)
        result = self.parser.parse_xml(xml)
        assert result is not None
        assert result.event_id == 4625
        assert result.computer == "WORKSTATION-01"
        ecs = result.to_ecs()
        assert ecs["source"]["ip"] == "192.168.1.100"
        assert ecs["user"]["name"] == "Administrator"
        assert ecs["event"]["outcome"] == "failure"

    def test_parse_4688_xml(self):
        xml = textwrap.dedent("""\
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>4688</EventID>
            <Channel>Security</Channel>
            <Computer>WORKSTATION-01</Computer>
            <TimeCreated SystemTime="2024-06-01T10:01:00.000Z"/>
          </System>
          <EventData>
            <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
            <Data Name="CommandLine">cmd.exe /c whoami</Data>
            <Data Name="SubjectUserName">user01</Data>
            <Data Name="NewProcessId">0x1234</Data>
          </EventData>
        </Event>
        """)
        result = self.parser.parse_xml(xml)
        assert result is not None
        assert result.event_id == 4688
        ecs = result.to_ecs()
        assert "cmd.exe" in ecs["process"]["name"]
        assert "whoami" in ecs["process"]["command_line"]

    def test_ps_suspicious_score_detects_obfuscation(self):
        xml = textwrap.dedent("""\
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>4688</EventID>
            <Channel>Security</Channel>
            <Computer>SERVER-01</Computer>
            <TimeCreated SystemTime="2024-06-01T10:02:00.000Z"/>
          </System>
          <EventData>
            <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
            <Data Name="CommandLine">powershell.exe -enc aQBlAHgA -noprofile -bypass</Data>
          </EventData>
        </Event>
        """)
        result = self.parser.parse_xml(xml)
        assert result is not None
        ecs = result.to_ecs()
        assert ecs.get("threat", {}).get("ps_suspicious", 0) >= 2

    def test_parse_malformed_xml_returns_none(self):
        result = self.parser.parse_xml("<not valid xml>")
        assert result is None

    def test_parse_dict_winlogbeat_format(self):
        event = {
            "@timestamp": "2024-06-01T12:00:00.000Z",
            "winlog": {
                "event_id": 4625,
                "channel": "Security",
                "computer_name": "HOST-01",
                "event_data": {
                    "TargetUserName": "admin",
                    "IpAddress": "10.0.0.5",
                    "LogonType": "3",
                },
            },
            "host": {"name": "HOST-01"},
        }
        result = self.parser.parse_dict(event)
        assert result is not None
        assert result.event_id == 4625
        ecs = result.to_ecs()
        assert ecs["source"]["ip"] == "10.0.0.5"
