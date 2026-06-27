"""
GeoIP Enrichment
Enriches source/destination IPs with geographic and ASN data.
Uses MaxMind GeoLite2 (free) or GeoIP2 (paid) databases.
"""

import logging
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import maxminddb
    MAXMIND_AVAILABLE = True
except ImportError:
    MAXMIND_AVAILABLE = False
    logger.warning("maxminddb not installed — GeoIP enrichment disabled. pip install maxminddb")


@dataclass
class GeoIPResult:
    ip: str
    country_iso: str = ""
    country_name: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    asn: int = 0
    org: str = ""
    is_tor: bool = False
    is_vpn: bool = False


class GeoIPEnricher:
    # IPs that should never be enriched
    SKIP_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fe80::/10"),
    ]

    def __init__(self, city_db_path: str, asn_db_path: str | None = None):
        self._city_db = None
        self._asn_db = None
        if MAXMIND_AVAILABLE:
            try:
                self._city_db = maxminddb.open_database(city_db_path)
                logger.info("GeoIP city database loaded: %s", city_db_path)
            except Exception as e:
                logger.warning("Could not load GeoIP database: %s", e)
            if asn_db_path and Path(asn_db_path).exists():
                try:
                    self._asn_db = maxminddb.open_database(asn_db_path)
                except Exception as e:
                    logger.warning("Could not load ASN database: %s", e)

    def enrich(self, event: dict) -> dict:
        for field_path in ("source.ip", "destination.ip", "client.ip"):
            ip = self._get(event, field_path)
            if ip and self._should_enrich(ip):
                result = self.lookup(ip)
                if result:
                    prefix = field_path.split(".")[0]
                    event.setdefault(prefix, {})["geo"] = {
                        "country_iso_code": result.country_iso,
                        "country_name":     result.country_name,
                        "city_name":        result.city,
                        "location": {
                            "lat": result.latitude,
                            "lon": result.longitude,
                        },
                    }
                    event[prefix]["as"] = {
                        "number":       result.asn,
                        "organization": {"name": result.org},
                    }
        return event

    def lookup(self, ip: str) -> GeoIPResult | None:
        if not self._city_db:
            return None
        try:
            record = self._city_db.get(ip)
            if not record:
                return None
            country = record.get("country", {})
            city    = record.get("city", {})
            loc     = record.get("location", {})
            result  = GeoIPResult(
                ip=ip,
                country_iso=country.get("iso_code", ""),
                country_name=(country.get("names") or {}).get("en", ""),
                city=(city.get("names") or {}).get("en", ""),
                latitude=loc.get("latitude", 0.0),
                longitude=loc.get("longitude", 0.0),
            )
            if self._asn_db:
                asn_record = self._asn_db.get(ip) or {}
                result.asn = asn_record.get("autonomous_system_number", 0)
                result.org = asn_record.get("autonomous_system_organization", "")
            return result
        except Exception as e:
            logger.debug("GeoIP lookup failed for %s: %s", ip, e)
            return None

    def _should_enrich(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return not any(addr in net for net in self.SKIP_RANGES)
        except ValueError:
            return False

    @staticmethod
    def _get(obj: dict, path: str) -> str | None:
        for part in path.split("."):
            if not isinstance(obj, dict):
                return None
            obj = obj.get(part)
        return str(obj) if obj else None
