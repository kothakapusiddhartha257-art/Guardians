"""Evidence-first IP intelligence with safe optional enrichment.

No result is assumed benign when a DNS/database/API lookup is unavailable.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError
import ipaddress
import os
from pathlib import Path
import socket

import dns.resolver


def _within(seconds: float, operation, default):
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(operation)
        try:
            return future.result(timeout=seconds)
        except (TimeoutError, OSError, socket.gaierror):
            return default


def _ptr(ip: str) -> str | None:
    return _within(1.5, lambda: socket.gethostbyaddr(ip)[0].rstrip("."), None)


def _forward_confirms(hostname: str, ip: str) -> bool | None:
    def resolve() -> bool:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, None)}
        return ip in addresses
    return _within(1.5, resolve, None)


def _asn(ip: str) -> dict:
    address = ipaddress.ip_address(ip)
    if address.version != 4:
        return {"status": "not_checked", "reason": "Team Cymru DNS query is configured for IPv4 only"}
    query = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 1.5
        record = str(resolver.resolve(query, "TXT")[0]).strip('"')
        fields = [value.strip() for value in record.split("|")]
        return {"status": "available", "asn": fields[0] if fields else None,
                "prefix": fields[1] if len(fields) > 1 else None,
                "country": fields[2] if len(fields) > 2 else None,
                "source": "Team Cymru DNS"}
    except Exception:
        return {"status": "unavailable", "reason": "ASN DNS lookup failed or timed out"}


def _geoip(ip: str) -> dict:
    database_path = os.getenv("GEOIP_DB_PATH", "")
    if not database_path or not Path(database_path).is_file():
        return {"status": "not_configured", "reason": "Set GEOIP_DB_PATH to a GeoLite2/GeoIP2 City database"}
    try:
        import geoip2.database  # Optional dependency; no network request is made.
        with geoip2.database.Reader(database_path) as reader:
            result = reader.city(ip)
            return {"status": "available", "country": result.country.name,
                    "city": result.city.name, "latitude": result.location.latitude,
                    "longitude": result.location.longitude, "source": "MaxMind local database"}
    except ImportError:
        return {"status": "not_configured", "reason": "Install geoip2 to use GEOIP_DB_PATH"}
    except Exception:
        return {"status": "unavailable", "reason": "GeoIP lookup failed"}


def _tor(ip: str) -> dict:
    path = os.getenv("TOR_EXIT_NODE_FILE", "")
    if not path or not Path(path).is_file():
        return {"status": "not_configured", "reason": "Set TOR_EXIT_NODE_FILE to a current Tor exit-node IP list"}
    try:
        entries = {line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")}
        return {"status": "available", "is_tor_exit_node": ip in entries, "source": "local Tor exit-node list"}
    except OSError:
        return {"status": "unavailable", "reason": "Tor exit-node list could not be read"}


def inspect_ip(value: str | None) -> dict:
    """Validate and enrich one IP, returning explicit source/status metadata."""
    if not value:
        return {"status": "not_available", "reason": "No public sender IP was found in Received headers"}
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return {"status": "invalid", "ip": value, "reason": "Invalid IP address format"}
    result = {"status": "available", "ip": str(address), "version": address.version,
              "is_global": address.is_global, "is_private": address.is_private,
              "is_reserved": address.is_reserved, "is_loopback": address.is_loopback,
              "is_multicast": address.is_multicast}
    if not address.is_global:
        result["classification"] = "non_public"
        result["reason"] = "Private, reserved, loopback, multicast, or otherwise non-global address"
        return result

    ptr = _ptr(str(address))
    result["reverse_dns"] = {"status": "available", "hostname": ptr, "source": "PTR lookup"} if ptr else {"status": "unavailable", "hostname": None, "source": "PTR lookup"}
    result["forward_confirmed_reverse_dns"] = {"status": "available", "matches": _forward_confirms(ptr, str(address)), "source": "forward DNS"} if ptr else {"status": "not_checked", "reason": "No PTR hostname available"}
    result["asn"] = _asn(str(address))
    result["geoip"] = _geoip(str(address))
    result["tor"] = _tor(str(address))
    result["vpn_proxy"] = {"status": "not_configured", "reason": "Configure an approved VPN/proxy intelligence provider"}
    result["reputation"] = {"status": "not_configured", "reason": "Configure AbuseIPDB or VirusTotal API credentials"}
    return result
