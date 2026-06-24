"""
Threat Intelligence Enrichment Engine
Enriches log events with IOC data from MISP, AlienVault OTX, and VirusTotal.
Implements in-memory caching with TTL to minimize API calls.
"""

import hashlib
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"


@dataclass
class ThreatIntelResult:
    ioc: str
    ioc_type: IOCType
    is_malicious: bool
    confidence: float           # 0.0 – 1.0
    sources: list[str]
    tags: list[str]
    first_seen: str = ""
    last_seen: str = ""
    malware_families: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ioc": self.ioc,
            "ioc_type": self.ioc_type.value,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "sources": self.sources,
            "tags": self.tags,
            "malware_families": self.malware_families,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


# ─────────────────────────────────────────────
# TTL Cache
# ─────────────────────────────────────────────

class TTLCache:
    def __init__(self, ttl_seconds: int = 3600, max_size: int = 50_000):
        self._store: dict[str, tuple[Any, float]] = {}
        self._ttl = ttl_seconds
        self._max = max_size

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires = entry
        if time.monotonic() > expires:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        if len(self._store) >= self._max:
            # Evict oldest 10%
            cutoff = time.monotonic()
            self._store = {k: v for k, v in self._store.items() if v[1] > cutoff}
        self._store[key] = (value, time.monotonic() + self._ttl)

    def __len__(self) -> int:
        return len(self._store)


# ─────────────────────────────────────────────
# Provider Base
# ─────────────────────────────────────────────

class TIProvider:
    name: str = "base"

    def lookup(self, ioc: str, ioc_type: IOCType) -> ThreatIntelResult | None:
        raise NotImplementedError


# ─────────────────────────────────────────────
# AlienVault OTX
# ─────────────────────────────────────────────

class OTXProvider(TIProvider):
    name = "otx"
    BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str, timeout: int = 10):
        self._key = api_key
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"X-OTX-API-KEY": api_key})

    def lookup(self, ioc: str, ioc_type: IOCType) -> ThreatIntelResult | None:
        endpoint_map = {
            IOCType.IP: f"indicators/IPv4/{ioc}/general",
            IOCType.DOMAIN: f"indicators/domain/{ioc}/general",
            IOCType.URL: f"indicators/url/{ioc}/general",
            IOCType.HASH_MD5: f"indicators/file/{ioc}/general",
            IOCType.HASH_SHA1: f"indicators/file/{ioc}/general",
            IOCType.HASH_SHA256: f"indicators/file/{ioc}/general",
        }
        endpoint = endpoint_map.get(ioc_type)
        if not endpoint:
            return None

        try:
            resp = self._session.get(f"{self.BASE}/{endpoint}", timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            logger.warning("OTX lookup failed for %s: %s", ioc, e)
            return None

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        tags = []
        families = []
        for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
            tags.extend(pulse.get("tags", []))
            families.extend(pulse.get("malware_families", []))

        return ThreatIntelResult(
            ioc=ioc,
            ioc_type=ioc_type,
            is_malicious=pulse_count > 0,
            confidence=min(1.0, pulse_count / 10),
            sources=["otx"],
            tags=list(set(tags)),
            malware_families=list(set(families)),
            raw=data,
        )


# ─────────────────────────────────────────────
# VirusTotal
# ─────────────────────────────────────────────

class VirusTotalProvider(TIProvider):
    name = "virustotal"
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, timeout: int = 10):
        self._key = api_key
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"x-apikey": api_key})

    def lookup(self, ioc: str, ioc_type: IOCType) -> ThreatIntelResult | None:
        if ioc_type == IOCType.IP:
            url = f"{self.BASE}/ip_addresses/{ioc}"
        elif ioc_type == IOCType.DOMAIN:
            url = f"{self.BASE}/domains/{ioc}"
        elif ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
            url = f"{self.BASE}/files/{ioc}"
        else:
            return None

        try:
            resp = self._session.get(url, timeout=self._timeout)
            if resp.status_code == 404:
                return ThreatIntelResult(ioc=ioc, ioc_type=ioc_type,
                                         is_malicious=False, confidence=0.0,
                                         sources=["virustotal"], tags=[])
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            logger.warning("VT lookup failed for %s: %s", ioc, e)
            return None

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        confidence = malicious / total

        return ThreatIntelResult(
            ioc=ioc,
            ioc_type=ioc_type,
            is_malicious=malicious > 3,
            confidence=round(confidence, 3),
            sources=["virustotal"],
            tags=[],
            raw=data,
        )


# ─────────────────────────────────────────────
# IOC Extractor
# ─────────────────────────────────────────────

class IOCExtractor:
    """Extracts IOCs from a normalized ECS event."""

    HASH_FIELDS = [
        "process.hash.md5", "process.hash.sha1", "process.hash.sha256",
        "file.hash.md5", "file.hash.sha1", "file.hash.sha256",
    ]
    IP_FIELDS = [
        "source.ip", "destination.ip", "client.ip", "server.ip",
        "network.forwarded_ip",
    ]
    DOMAIN_FIELDS = [
        "dns.question.name", "url.domain", "destination.domain",
    ]
    URL_FIELDS = ["url.full", "http.request.referrer"]

    def extract(self, event: dict) -> list[tuple[str, IOCType]]:
        iocs = []
        for field_path, ioc_type in (
            [(f, IOCType.IP) for f in self.IP_FIELDS]
            + [(f, IOCType.DOMAIN) for f in self.DOMAIN_FIELDS]
            + [(f, IOCType.URL) for f in self.URL_FIELDS]
        ):
            val = self._get(event, field_path)
            if val and self._validate(val, ioc_type):
                iocs.append((val, ioc_type))

        for field_path in self.HASH_FIELDS:
            val = self._get(event, field_path)
            if val:
                ioc_type = self._hash_type(val)
                if ioc_type:
                    iocs.append((val, ioc_type))

        return iocs

    def _validate(self, val: str, ioc_type: IOCType) -> bool:
        if ioc_type == IOCType.IP:
            try:
                ip = ipaddress.ip_address(val)
                return not (ip.is_private or ip.is_loopback or ip.is_link_local)
            except ValueError:
                return False
        if ioc_type == IOCType.DOMAIN:
            return "." in val and len(val) > 3
        return bool(val)

    @staticmethod
    def _hash_type(val: str) -> IOCType | None:
        length_map = {32: IOCType.HASH_MD5, 40: IOCType.HASH_SHA1, 64: IOCType.HASH_SHA256}
        if re.match(r"^[0-9a-f]+$", val, re.I):
            return length_map.get(len(val))
        return None

    @staticmethod
    def _get(obj: dict, path: str) -> str | None:
        for part in path.split("."):
            if not isinstance(obj, dict):
                return None
            obj = obj.get(part)
        return str(obj) if obj else None


import re  # noqa: E402 — needed by IOCExtractor above


# ─────────────────────────────────────────────
# Main Enrichment Engine
# ─────────────────────────────────────────────

class ThreatIntelEnricher:
    def __init__(self, providers: list[TIProvider], cache_ttl: int = 3600):
        self._providers = providers
        self._cache = TTLCache(ttl_seconds=cache_ttl)
        self._extractor = IOCExtractor()
        self._stats = {"lookups": 0, "cache_hits": 0, "positives": 0}

    def enrich(self, event: dict) -> dict:
        """Enrich an ECS event with TI data. Returns event with threat.* fields."""
        iocs = self._extractor.extract(event)
        results = []
        for ioc, ioc_type in iocs:
            result = self._lookup(ioc, ioc_type)
            if result:
                results.append(result)

        if results:
            malicious = [r for r in results if r.is_malicious]
            event.setdefault("threat", {})["indicators"] = [r.to_dict() for r in results]
            if malicious:
                event["threat"]["enriched"] = True
                event["threat"]["max_confidence"] = max(r.confidence for r in malicious)
                self._stats["positives"] += 1

        return event

    def _lookup(self, ioc: str, ioc_type: IOCType) -> ThreatIntelResult | None:
        cache_key = f"{ioc_type.value}:{ioc}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return cached

        self._stats["lookups"] += 1
        results = []
        for provider in self._providers:
            try:
                result = provider.lookup(ioc, ioc_type)
                if result:
                    results.append(result)
            except Exception as e:
                logger.error("Provider %s error: %s", provider.name, e)

        if not results:
            return None

        # Merge results: is_malicious is True if any provider says so
        merged = ThreatIntelResult(
            ioc=ioc,
            ioc_type=ioc_type,
            is_malicious=any(r.is_malicious for r in results),
            confidence=max(r.confidence for r in results),
            sources=[r.sources[0] for r in results],
            tags=list({tag for r in results for tag in r.tags}),
            malware_families=list({f for r in results for f in r.malware_families}),
        )
        self._cache.set(cache_key, merged)
        return merged

    @property
    def stats(self) -> dict:
        return {"cache_size": len(self._cache), **self._stats}
