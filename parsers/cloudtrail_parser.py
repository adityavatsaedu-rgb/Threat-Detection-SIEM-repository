"""
AWS CloudTrail Parser
Normalizes CloudTrail events to ECS.
Covers: IAM changes, S3 data events, EC2 actions, console logins,
        root account usage, credential abuse.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

HIGH_RISK_APIS = {
    "CreateUser", "DeleteUser", "AttachUserPolicy", "AttachRolePolicy",
    "CreateAccessKey", "DeleteAccessKey", "PutUserPolicy", "PutRolePolicy",
    "CreateLoginProfile", "UpdateLoginProfile", "ConsoleLogin",
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    "AuthorizeSecurityGroupIngress", "CreateVpc", "ModifyInstanceAttribute",
    "RunInstances", "TerminateInstances",
    "GetSecretValue", "DeleteSecret",
    "GetObject", "PutBucketPolicy", "DeleteBucketPolicy",
}

MITRE_API_MAP: dict[str, list[str]] = {
    "ConsoleLogin":           ["T1078.004"],
    "CreateUser":             ["T1136.003"],
    "CreateAccessKey":        ["T1098"],
    "AttachUserPolicy":       ["T1098.001"],
    "AttachRolePolicy":       ["T1098.001"],
    "StopLogging":            ["T1562.008"],
    "DeleteTrail":            ["T1562.008"],
    "GetSecretValue":         ["T1552.001"],
    "RunInstances":           ["T1578.002"],
    "AuthorizeSecurityGroupIngress": ["T1562.007"],
    "GetObject":              ["T1530"],
}


@dataclass
class ParsedCloudTrailEvent:
    ecs: dict
    event_name: str
    aws_region: str
    is_high_risk: bool
    timestamp: datetime
    mitre_hints: list[str] = field(default_factory=list)


class CloudTrailParser:
    def parse(self, record: dict) -> ParsedCloudTrailEvent | None:
        if not record.get("eventName"):
            return None

        event_name   = record.get("eventName", "")
        event_source = record.get("eventSource", "")
        aws_region   = record.get("awsRegion", "unknown")
        error_code   = record.get("errorCode", "")
        error_msg    = record.get("errorMessage", "")

        try:
            ts = datetime.fromisoformat(
                record.get("eventTime", "").replace("Z", "+00:00")
            )
        except ValueError:
            ts = datetime.utcnow()

        user_identity = record.get("userIdentity", {})
        source_ip     = record.get("sourceIPAddress", "")
        user_agent    = record.get("userAgent", "")

        ecs: dict[str, Any] = {
            "@timestamp": ts.isoformat() + "Z",
            "event": {
                "kind":     "event",
                "action":   event_name,
                "provider": event_source,
                "outcome":  "failure" if error_code else "success",
                "category": self._event_category(event_name, event_source),
            },
            "cloud": {
                "provider": "aws",
                "region":   aws_region,
                "service":  {"name": event_source.replace(".amazonaws.com", "")},
            },
            "user": {
                "name":   user_identity.get("userName") or user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName", "unknown"),
                "id":     user_identity.get("principalId", ""),
                "type":   user_identity.get("type", ""),
            },
            "source": {"ip": source_ip},
            "user_agent": {"original": user_agent},
            "log": {"product": "aws", "service": "cloudtrail"},
            "aws": {
                "cloudtrail": {
                    "event_version": record.get("eventVersion", ""),
                    "request_parameters": record.get("requestParameters"),
                    "response_elements": record.get("responseElements"),
                    "error_code": error_code,
                    "error_message": error_msg,
                    "read_only": record.get("readOnly", False),
                    "resources": record.get("resources", []),
                }
            },
        }

        if user_identity.get("type") == "Root":
            ecs["threat"] = {"root_account_usage": True}

        return ParsedCloudTrailEvent(
            ecs=ecs,
            event_name=event_name,
            aws_region=aws_region,
            is_high_risk=event_name in HIGH_RISK_APIS,
            timestamp=ts,
            mitre_hints=MITRE_API_MAP.get(event_name, []),
        )

    @staticmethod
    def _event_category(name: str, source: str) -> list[str]:
        if "iam" in source or name in ("CreateUser", "DeleteUser", "CreateAccessKey"):
            return ["iam"]
        if "signin" in source or name == "ConsoleLogin":
            return ["authentication"]
        if "ec2" in source or "lambda" in source:
            return ["process"]
        if "s3" in source:
            return ["file"]
        return ["configuration"]
