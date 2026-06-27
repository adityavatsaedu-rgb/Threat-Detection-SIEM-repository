"""
Windows Event Log Parser
Parses Windows EVTX events and normalizes to Elastic Common Schema (ECS).
Covers: Security, System, Application, PowerShell/Operational, Sysmon logs.
"""

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# ECS Field Mappings per Event ID
# ─────────────────────────────────────────────

# Format: EventID → {ecs_field: xpath_or_data_field}
EVENT_FIELD_MAP: dict[int, dict[str, str]] = {
    # Logon events
    4624: {
        "event.action": "An account was successfully logged on",
        "event.outcome": "success",
        "user.name": "TargetUserName",
        "user.domain": "TargetDomainName",
        "source.ip": "IpAddress",
        "source.port": "IpPort",
        "winlog.logon.type": "LogonType",
        "winlog.logon.id": "TargetLogonId",
    },
    4625: {
        "event.action": "An account failed to log on",
        "event.outcome": "failure",
        "user.name": "TargetUserName",
        "user.domain": "TargetDomainName",
        "source.ip": "IpAddress",
        "source.port": "IpPort",
        "winlog.logon.type": "LogonType",
        "winlog.failure.reason": "FailureReason",
    },
    4648: {
        "event.action": "A logon was attempted using explicit credentials",
        "user.name": "SubjectUserName",
        "user.domain": "SubjectDomainName",
        "winlog.target_user.name": "TargetUserName",
        "destination.address": "TargetServerName",
    },
    # Account management
    4720: {"event.action": "A user account was created", "user.name": "TargetUserName"},
    4728: {"event.action": "A member was added to a security-enabled global group", "user.name": "MemberName"},
    4732: {"event.action": "A member was added to a security-enabled local group", "user.name": "MemberName"},
    4756: {"event.action": "A member was added to a security-enabled universal group", "user.name": "MemberName"},
    4767: {"event.action": "A user account was unlocked", "user.name": "TargetUserName"},
    # Process events
    4688: {
        "event.action": "A new process has been created",
        "process.name": "NewProcessName",
        "process.pid": "NewProcessId",
        "process.command_line": "CommandLine",
        "process.parent.name": "ParentProcessName",
        "user.name": "SubjectUserName",
    },
    4689: {
        "event.action": "A process has exited",
        "process.name": "ProcessName",
        "process.pid": "ProcessId",
        "process.exit_code": "ExitStatus",
    },
    # Object access
    4663: {
        "event.action": "An attempt was made to access an object",
        "file.path": "ObjectName",
        "user.name": "SubjectUserName",
        "winlog.access_mask": "AccessMask",
    },
    # Audit policy
    4719: {"event.action": "System audit policy was changed"},
    # PowerShell
    4103: {
        "event.action": "PowerShell Module Logging",
        "powershell.command.value": "Payload",
    },
    4104: {
        "event.action": "PowerShell Script Block Logging",
        "powershell.script_block_text": "ScriptBlockText",
        "powershell.file.path": "Path",
    },
    # Service events
    7045: {
        "event.action": "A new service was installed",
        "service.name": "ServiceName",
        "service.type": "ServiceType",
        "process.name": "ImagePath",
    },
    # Sysmon
    1: {    # Process Create
        "event.action": "Process Create",
        "process.name": "Image",
        "process.pid": "ProcessId",
        "process.command_line": "CommandLine",
        "process.hash.md5": "Hashes",
        "process.parent.name": "ParentImage",
        "user.name": "User",
    },
    3: {    # Network Connect
        "event.action": "Network connection detected",
        "source.ip": "SourceIp",
        "source.port": "SourcePort",
        "destination.ip": "DestinationIp",
        "destination.port": "DestinationPort",
        "destination.domain": "DestinationHostname",
        "process.name": "Image",
    },
    11: {   # File Create
        "event.action": "File created",
        "file.path": "TargetFilename",
        "process.name": "Image",
    },
    13: {   # Registry Value Set
        "event.action": "Registry value set",
        "registry.path": "TargetObject",
        "registry.value": "Details",
        "process.name": "Image",
    },
}

# EventID → MITRE technique hints
MITRE_HINTS: dict[int, list[str]] = {
    4625: ["T1110"],
    4648: ["T1550.002"],
    4688: ["T1059"],
    4104: ["T1059.001"],
    4720: ["T1136.001"],
    4728: ["T1098"],
    4732: ["T1098"],
    7045: ["T1543.003"],
    1:    ["T1059"],
    3:    ["T1071"],
    13:   ["T1112"],
}


@dataclass
class ParsedEvent:
    raw: dict
    ecs: dict
    event_id: int
    channel: str
    computer: str
    timestamp: datetime
    mitre_hints: list[str] = field(default_factory=list)

    def to_ecs(self) -> dict:
        return self.ecs


# ─────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────

class WindowsEventParser:
    NS = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}

    def parse_xml(self, xml_str: str) -> ParsedEvent | None:
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            logger.warning("XML parse error: %s", e)
            return None

        system = root.find("ev:System", self.NS)
        if system is None:
            return None

        event_id = self._int(self._text(system, "ev:EventID"))
        computer = self._text(system, "ev:Computer") or "unknown"
        channel = self._text(system, "ev:Channel") or "unknown"
        time_created = system.find("ev:TimeCreated", self.NS)
        ts_str = time_created.get("SystemTime", "") if time_created is not None else ""
        try:
            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            timestamp = datetime.utcnow()

        # Extract raw EventData key-value pairs
        raw_data: dict[str, str] = {}
        event_data = root.find("ev:EventData", self.NS)
        if event_data is not None:
            for item in event_data.findall("ev:Data", self.NS):
                name = item.get("Name", "")
                value = (item.text or "").strip()
                if name:
                    raw_data[name] = value

        # Build ECS document
        ecs = self._build_ecs(event_id, raw_data, computer, channel, timestamp)

        return ParsedEvent(
            raw={"event_id": event_id, "channel": channel, "computer": computer, "data": raw_data},
            ecs=ecs,
            event_id=event_id,
            channel=channel,
            computer=computer,
            timestamp=timestamp,
            mitre_hints=MITRE_HINTS.get(event_id, []),
        )

    def parse_dict(self, event: dict) -> ParsedEvent | None:
        """Parse from pre-parsed dict (e.g. from Winlogbeat JSON)."""
        event_id = event.get("winlog", {}).get("event_id") or event.get("EventID")
        if not event_id:
            return None
        event_id = int(event_id)
        computer = (event.get("host", {}).get("name")
                    or event.get("winlog", {}).get("computer_name", "unknown"))
        channel = event.get("winlog", {}).get("channel", "unknown")
        ts = event.get("@timestamp") or event.get("TimeCreated", "")
        try:
            timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            timestamp = datetime.utcnow()

        raw_data = event.get("winlog", {}).get("event_data", {}) or {}
        ecs = self._build_ecs(event_id, raw_data, computer, channel, timestamp)
        # Merge existing ECS fields from Winlogbeat
        for k, v in event.items():
            if k not in ecs:
                ecs[k] = v

        return ParsedEvent(
            raw=event,
            ecs=ecs,
            event_id=event_id,
            channel=channel,
            computer=computer,
            timestamp=timestamp,
            mitre_hints=MITRE_HINTS.get(event_id, []),
        )

    def _build_ecs(self, event_id: int, data: dict, computer: str,
                   channel: str, timestamp: datetime) -> dict:
        mapping = EVENT_FIELD_MAP.get(event_id, {})
        ecs: dict[str, Any] = {
            "@timestamp": timestamp.isoformat() + "Z",
            "event": {
                "code": str(event_id),
                "kind": "event",
                "category": self._event_category(event_id),
                "type": self._event_type(event_id),
            },
            "host": {"name": computer},
            "log": {"product": "windows", "service": channel.lower()},
            "winlog": {"event_id": event_id, "channel": channel, "computer_name": computer},
        }

        for ecs_path, source in mapping.items():
            if ecs_path.startswith("event.action"):
                self._set_nested(ecs, "event.action", source)
                continue
            if ecs_path.startswith("event.outcome"):
                self._set_nested(ecs, "event.outcome", source)
                continue
            value = data.get(source, "")
            if value and value != "-":
                self._set_nested(ecs, ecs_path, self._coerce(ecs_path, value))

        # Special handling: extract MD5 from Sysmon hash string "MD5=abc,SHA256=def"
        hashes = data.get("Hashes", "")
        if hashes:
            for part in hashes.split(","):
                if "=" in part:
                    algo, val = part.split("=", 1)
                    algo = algo.strip().lower()
                    if algo in ("md5", "sha1", "sha256"):
                        self._set_nested(ecs, f"process.hash.{algo}", val.strip().lower())

        # Detect suspicious PowerShell patterns
        cmdline = (data.get("CommandLine", "") + data.get("ScriptBlockText", "")).lower()
        if cmdline:
            ecs.setdefault("threat", {})["ps_suspicious"] = self._ps_suspicious_score(cmdline)

        return ecs

    @staticmethod
    def _ps_suspicious_score(text: str) -> int:
        indicators = [
            "downloadstring", "iex", "invoke-expression", "bypass", "-enc",
            "encodedcommand", "frombase64string", "hidden", "noprofile",
            "webclient", "shellcode", "mimikatz", "lsass",
        ]
        return sum(1 for i in indicators if i in text)

    @staticmethod
    def _event_category(event_id: int) -> list[str]:
        mapping = {
            range(4624, 4650): ["authentication"],
            range(4688, 4690): ["process"],
            range(4700, 4720): ["configuration"],
            range(4720, 4800): ["iam"],
        }
        for r, cats in mapping.items():
            if event_id in r:
                return cats
        if event_id in (1, 11):
            return ["process"]
        if event_id == 3:
            return ["network"]
        return ["host"]

    @staticmethod
    def _event_type(event_id: int) -> list[str]:
        success_ids = {4624, 4688}
        failure_ids = {4625}
        creation_ids = {4720, 4688, 7045, 1}
        if event_id in success_ids:
            return ["start", "allowed"]
        if event_id in failure_ids:
            return ["start", "denied"]
        if event_id in creation_ids:
            return ["creation"]
        return ["info"]

    @staticmethod
    def _coerce(field_path: str, value: str) -> Any:
        int_fields = {"process.pid", "source.port", "destination.port"}
        if field_path in int_fields:
            try:
                return int(value, 16) if value.startswith("0x") else int(value)
            except ValueError:
                return value
        return value

    @staticmethod
    def _set_nested(obj: dict, path: str, value: Any) -> None:
        parts = path.split(".")
        for part in parts[:-1]:
            obj = obj.setdefault(part, {})
        obj[parts[-1]] = value

    @staticmethod
    def _text(element: ET.Element, tag: str) -> str | None:
        child = element.find(tag, {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"})
        return child.text if child is not None else None

    @staticmethod
    def _int(val: str | None) -> int:
        try:
            return int(val or 0)
        except (ValueError, TypeError):
            return 0
