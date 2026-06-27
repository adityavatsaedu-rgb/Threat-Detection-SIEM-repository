"""
Alert Manager — Multi-channel alert routing with deduplication and rate limiting.
Supports: Slack, PagerDuty, JIRA, Email, Generic Webhook.
"""

import hashlib
import json
import logging
import smtplib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import requests

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ─────────────────────────────────────────────
# Alert Model
# ─────────────────────────────────────────────

@dataclass
class Alert:
    alert_id: str
    title: str
    severity: str           # informational / low / medium / high / critical
    description: str
    source_event: dict
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    enrichment: dict = field(default_factory=dict)

    @property
    def dedup_key(self) -> str:
        key = f"{self.title}:{self.source_event.get('host', {}).get('name', '')}:{self.severity}"
        return hashlib.md5(key.encode()).hexdigest()[:12]  # noqa: S324

    @property
    def severity_int(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 0)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "mitre": {"techniques": self.mitre_techniques, "tactics": self.mitre_tactics},
            "tags": self.tags,
            "@timestamp": self.timestamp.isoformat() + "Z",
            "enrichment": self.enrichment,
        }


# ─────────────────────────────────────────────
# Notifier Base
# ─────────────────────────────────────────────

class Notifier(ABC):
    name: str = "base"

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        ...

    def _severity_color(self, severity: str) -> str:
        return {
            "critical": "#FF0000", "high": "#FF6B35",
            "medium": "#FFB347", "low": "#4FC3F7", "informational": "#90A4AE",
        }.get(severity.lower(), "#9E9E9E")

    def _severity_emoji(self, severity: str) -> str:
        return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "informational": "⚪"}.get(
            severity.lower(), "⚫"
        )


# ─────────────────────────────────────────────
# Slack
# ─────────────────────────────────────────────

class SlackNotifier(Notifier):
    name = "slack"

    def __init__(self, webhook_url: str, channel: str = "#alerts", timeout: int = 10):
        self._webhook = webhook_url
        self._channel = channel
        self._timeout = timeout

    def send(self, alert: Alert) -> bool:
        emoji = self._severity_emoji(alert.severity)
        color = self._severity_color(alert.severity)
        mitre_str = ", ".join(alert.mitre_techniques) if alert.mitre_techniques else "N/A"
        payload = {
            "channel": self._channel,
            "username": "ThreatBot",
            "icon_emoji": ":shield:",
            "attachments": [{
                "color": color,
                "title": f"{emoji} [{alert.severity.upper()}] {alert.title}",
                "text": alert.description,
                "fields": [
                    {"title": "MITRE Techniques", "value": mitre_str, "short": True},
                    {"title": "Alert ID", "value": alert.alert_id, "short": True},
                    {"title": "Timestamp", "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"), "short": True},
                ],
                "footer": "Threat Detection SIEM",
                "ts": int(alert.timestamp.timestamp()),
            }],
        }
        try:
            resp = requests.post(self._webhook, json=payload, timeout=self._timeout)
            resp.raise_for_status()
            return True
        except requests.RequestException as e:
            logger.error("Slack notification failed: %s", e)
            return False


# ─────────────────────────────────────────────
# PagerDuty
# ─────────────────────────────────────────────

class PagerDutyNotifier(Notifier):
    name = "pagerduty"
    EVENTS_API = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key: str, timeout: int = 10):
        self._routing_key = routing_key
        self._timeout = timeout

    def send(self, alert: Alert) -> bool:
        severity_map = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}
        payload = {
            "routing_key": self._routing_key,
            "event_action": "trigger",
            "dedup_key": alert.dedup_key,
            "payload": {
                "summary": f"[{alert.severity.upper()}] {alert.title}",
                "severity": severity_map.get(alert.severity.lower(), "info"),
                "source": alert.source_event.get("host", {}).get("name", "unknown"),
                "timestamp": alert.timestamp.isoformat() + "Z",
                "custom_details": {
                    "mitre_techniques": alert.mitre_techniques,
                    "description": alert.description,
                    "alert_id": alert.alert_id,
                },
            },
        }
        try:
            resp = requests.post(self.EVENTS_API, json=payload, timeout=self._timeout)
            resp.raise_for_status()
            return True
        except requests.RequestException as e:
            logger.error("PagerDuty notification failed: %s", e)
            return False


# ─────────────────────────────────────────────
# JIRA
# ─────────────────────────────────────────────

class JiraNotifier(Notifier):
    name = "jira"

    def __init__(self, base_url: str, email: str, api_token: str,
                 project_key: str, issue_type: str = "Bug", timeout: int = 15):
        self._url = base_url.rstrip("/")
        self._auth = (email, api_token)
        self._project = project_key
        self._issue_type = issue_type
        self._timeout = timeout

    def send(self, alert: Alert) -> bool:
        mitre_str = "\n".join(f"* {t}" for t in alert.mitre_techniques) or "N/A"
        description = (
            f"*Severity:* {alert.severity.upper()}\n"
            f"*Alert ID:* {alert.alert_id}\n"
            f"*Timestamp:* {alert.timestamp.isoformat()}Z\n\n"
            f"*Description:*\n{alert.description}\n\n"
            f"*MITRE ATT&CK Techniques:*\n{mitre_str}"
        )
        payload = {
            "fields": {
                "project": {"key": self._project},
                "summary": f"[{alert.severity.upper()}] {alert.title}",
                "description": description,
                "issuetype": {"name": self._issue_type},
                "priority": {"name": self._jira_priority(alert.severity)},
                "labels": [f"siem", f"severity-{alert.severity}"] + alert.mitre_techniques,
            }
        }
        try:
            resp = requests.post(
                f"{self._url}/rest/api/2/issue",
                json=payload,
                auth=self._auth,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            issue_key = resp.json().get("key", "N/A")
            logger.info("JIRA issue created: %s", issue_key)
            return True
        except requests.RequestException as e:
            logger.error("JIRA notification failed: %s", e)
            return False

    @staticmethod
    def _jira_priority(severity: str) -> str:
        return {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}.get(
            severity.lower(), "Medium"
        )


# ─────────────────────────────────────────────
# Email
# ─────────────────────────────────────────────

class EmailNotifier(Notifier):
    name = "email"

    def __init__(self, smtp_host: str, smtp_port: int, username: str,
                 password: str, recipients: list[str], use_tls: bool = True):
        self._host = smtp_host
        self._port = smtp_port
        self._username = username
        self._password = password
        self._recipients = recipients
        self._use_tls = use_tls

    def send(self, alert: Alert) -> bool:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SIEM Alert][{alert.severity.upper()}] {alert.title}"
        msg["From"] = self._username
        msg["To"] = ", ".join(self._recipients)

        html = self._render_html(alert)
        msg.attach(MIMEText(html, "html"))

        try:
            with smtplib.SMTP(self._host, self._port) as server:
                if self._use_tls:
                    server.starttls()
                server.login(self._username, self._password)
                server.sendmail(self._username, self._recipients, msg.as_string())
            return True
        except smtplib.SMTPException as e:
            logger.error("Email notification failed: %s", e)
            return False

    def _render_html(self, alert: Alert) -> str:
        color = self._severity_color(alert.severity)
        mitre_items = "".join(f"<li>{t}</li>" for t in alert.mitre_techniques)
        return f"""
        <html><body style="font-family: sans-serif;">
          <div style="border-left: 5px solid {color}; padding: 10px 20px;">
            <h2 style="color:{color}">[{alert.severity.upper()}] {alert.title}</h2>
            <p><strong>Alert ID:</strong> {alert.alert_id}</p>
            <p><strong>Time:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p><strong>Description:</strong><br>{alert.description}</p>
            <p><strong>MITRE ATT&CK:</strong><ul>{mitre_items}</ul></p>
          </div>
        </body></html>
        """


# ─────────────────────────────────────────────
# Deduplication + Rate Limiter
# ─────────────────────────────────────────────

class DeduplicationStore:
    def __init__(self, window_seconds: int = 3600):
        self._seen: dict[str, float] = {}
        self._window = window_seconds

    def is_duplicate(self, key: str) -> bool:
        now = time.monotonic()
        if key in self._seen and now - self._seen[key] < self._window:
            return True
        self._seen[key] = now
        # Periodic cleanup
        if len(self._seen) > 10_000:
            cutoff = now - self._window
            self._seen = {k: v for k, v in self._seen.items() if v > cutoff}
        return False


class RateLimiter:
    def __init__(self, max_per_minute: int = 60):
        self._max = max_per_minute
        self._window: list[float] = []

    def allow(self) -> bool:
        now = time.monotonic()
        self._window = [t for t in self._window if now - t < 60]
        if len(self._window) >= self._max:
            return False
        self._window.append(now)
        return True


# ─────────────────────────────────────────────
# Alert Manager
# ─────────────────────────────────────────────

@dataclass
class RoutingRule:
    min_severity: str
    notifiers: list[str]       # notifier names
    tag_filter: list[str] = field(default_factory=list)   # empty = match all

    def matches(self, alert: Alert) -> bool:
        if alert.severity_int < SEVERITY_ORDER.get(self.min_severity.lower(), 0):
            return False
        if self.tag_filter and not any(t in alert.tags for t in self.tag_filter):
            return False
        return True


class AlertManager:
    def __init__(self, notifiers: list[Notifier], routing: list[RoutingRule],
                 dedup_window: int = 3600, rate_limit: int = 120):
        self._notifiers: dict[str, Notifier] = {n.name: n for n in notifiers}
        self._routing = routing
        self._dedup = DeduplicationStore(dedup_window)
        self._rate = RateLimiter(rate_limit)
        self._stats = {"received": 0, "deduplicated": 0, "rate_limited": 0, "sent": 0, "failed": 0}

    def dispatch(self, alert: Alert) -> dict[str, bool]:
        self._stats["received"] += 1

        if self._dedup.is_duplicate(alert.dedup_key):
            logger.debug("Deduplicated alert: %s", alert.alert_id)
            self._stats["deduplicated"] += 1
            return {}

        if not self._rate.allow():
            logger.warning("Rate limit hit — dropping alert: %s", alert.alert_id)
            self._stats["rate_limited"] += 1
            return {}

        notifier_names = set()
        for rule in self._routing:
            if rule.matches(alert):
                notifier_names.update(rule.notifiers)

        results: dict[str, bool] = {}
        for name in notifier_names:
            notifier = self._notifiers.get(name)
            if not notifier:
                logger.warning("Unknown notifier: %s", name)
                continue
            try:
                ok = notifier.send(alert)
                results[name] = ok
                self._stats["sent" if ok else "failed"] += 1
            except Exception as e:
                logger.error("Notifier %s raised: %s", name, e)
                results[name] = False
                self._stats["failed"] += 1

        return results

    @property
    def stats(self) -> dict:
        return dict(self._stats)
