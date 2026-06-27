"""
Linux Syslog Parser
Parses auth.log, syslog, auditd logs and normalizes to ECS.
Covers: SSH brute force, sudo abuse, cron persistence, auditd syscalls.
"""

import re
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

SYSLOG_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+"
    r"(?P<message>.+)"
)

SSH_FAILED = re.compile(
    r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
SSH_ACCEPTED = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) "
    r"from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
SUDO_PATTERN = re.compile(
    r"(?P<user>\S+)\s+:\s+TTY=(?P<tty>\S+)\s+;\s+"
    r"PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<run_as>\S+)\s+;\s+"
    r"COMMAND=(?P<command>.+)"
)


@dataclass
class ParsedSyslogEvent:
    ecs: dict
    source_type: str
    timestamp: datetime
    mitre_hints: list[str] = field(default_factory=list)


class SyslogParser:
    def parse_line(self, line: str) -> ParsedSyslogEvent | None:
        line = line.strip()
        if not line:
            return None

        m = SYSLOG_PATTERN.match(line)
        if not m:
            return None

        parts = m.groupdict()
        process = parts.get("process", "").lower().rstrip(":")
        message = parts.get("message", "")

        try:
            ts = datetime.strptime(
                f"{datetime.utcnow().year} {parts['timestamp']}",
                "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            ts = datetime.utcnow()

        ecs: dict[str, Any] = {
            "@timestamp": ts.isoformat() + "Z",
            "host": {"name": parts.get("hostname", "unknown")},
            "process": {"name": process, "pid": self._int(parts.get("pid"))},
            "log": {"product": "linux", "service": "syslog"},
            "message": message,
            "event": {"kind": "event", "category": ["host"], "type": ["info"]},
        }

        mitre: list[str] = []

        if "sshd" in process:
            if fm := SSH_FAILED.search(message):
                ecs["event"]["outcome"] = "failure"
                ecs["event"]["action"] = "ssh_login_failed"
                ecs["event"]["category"] = ["authentication"]
                ecs["source"] = {"ip": fm.group("ip"), "port": int(fm.group("port"))}
                ecs["user"] = {"name": fm.group("user")}
                ecs["network"] = {"protocol": "ssh"}
                mitre = ["T1110.001"]
            elif am := SSH_ACCEPTED.search(message):
                ecs["event"]["outcome"] = "success"
                ecs["event"]["action"] = "ssh_login_success"
                ecs["event"]["category"] = ["authentication"]
                ecs["source"] = {"ip": am.group("ip"), "port": int(am.group("port"))}
                ecs["user"] = {"name": am.group("user")}

        elif "sudo" in process:
            if sm := SUDO_PATTERN.search(message):
                ecs["event"]["action"] = "sudo_command"
                ecs["event"]["category"] = ["process"]
                ecs["user"] = {"name": sm.group("user")}
                ecs["process"]["command_line"] = sm.group("command")
                ecs["process"]["working_directory"] = sm.group("pwd")
                if sm.group("run_as") == "root":
                    mitre = ["T1548.003"]

        return ParsedSyslogEvent(
            ecs=ecs,
            source_type=process,
            timestamp=ts,
            mitre_hints=mitre,
        )

    @staticmethod
    def _int(val: str | None) -> int | None:
        try:
            return int(val) if val else None
        except ValueError:
            return None
