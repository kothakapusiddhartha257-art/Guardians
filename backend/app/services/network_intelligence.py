"""Separate sender-network module: geolocation, ASN, anonymity and reputation.

All classifications carry a source/status. The module never guesses a location
or calls external intelligence unless the operator configured that provider.
"""
from __future__ import annotations

import os
from pathlib import Path

import httpx

from app.services.ip_intelligence import inspect_ip

# These are infrastructure-risk indicators, not a claim about the individual
# sender. A normal cloud ASN is not automatically malicious.
HIGH_RISK_ASNS = {200019: "Alexhost", 39351: "31173 Services", 44050: "M247"}


def _anonymous_geoip(ip: str) -> dict:
    path = os.getenv("GEOIP_ANONYMOUS_DB_PATH", "")
    if not path or not Path(path).is_file():
        return {"status": "not_configured", "reason": "Set GEOIP_ANONYMOUS_DB_PATH to MaxMind GeoIP2 Anonymous-IP database"}
    try:
        import geoip2.database
        with geoip2.database.Reader(path) as reader:
            item = reader.anonymous_ip(ip)
            return {"status": "available", "is_anonymous": item.is_anonymous,
                    "is_vpn": item.is_anonymous_vpn, "is_public_proxy": item.is_public_proxy,
                    "is_tor_exit_node": item.is_tor_exit_node, "is_hosting_provider": item.is_hosting_provider,
                    "source": "MaxMind GeoIP2 Anonymous-IP local database"}
    except Exception:
        return {"status": "unavailable", "reason": "Anonymous-IP lookup failed"}


def _ipqualityscore(ip: str) -> dict:
    key = os.getenv("IPQUALITYSCORE_API_KEY", "")
    if not key:
        return {"status": "not_configured", "reason": "Set IPQUALITYSCORE_API_KEY to enable provider VPN/proxy checks"}
    try:
        response = httpx.get(f"https://ipqualityscore.com/api/json/ip/{key}/{ip}", timeout=3.0)
        response.raise_for_status()
        item = response.json()
        return {"status": "available", "is_vpn": bool(item.get("vpn")), "is_proxy": bool(item.get("proxy")),
                "is_tor": bool(item.get("tor")), "is_bot": bool(item.get("bot_status")),
                "fraud_score": item.get("fraud_score"), "provider": "IPQualityScore"}
    except (httpx.HTTPError, ValueError):
        return {"status": "unavailable", "reason": "IPQualityScore lookup failed or timed out"}


def inspect_sender_network(ip: str | None) -> dict:
    """Return the complete evidence-based network profile for a sender IP."""
    base = inspect_ip(ip)
    if base.get("status") != "available" or not base.get("is_global"):
        return base | {"anonymity": {"status": "not_checked", "reason": "A global sender IP is required"}}
    address = base["ip"]
    local_anonymity = _anonymous_geoip(address)
    provider_anonymity = _ipqualityscore(address)
    tor = base.get("tor", {})
    is_tor = bool(tor.get("is_tor_exit_node")) or bool(local_anonymity.get("is_tor_exit_node")) or bool(provider_anonymity.get("is_tor"))
    is_vpn = bool(local_anonymity.get("is_vpn")) or bool(provider_anonymity.get("is_vpn"))
    is_proxy = bool(local_anonymity.get("is_public_proxy")) or bool(provider_anonymity.get("is_proxy"))
    try:
        asn_number = int(str(base.get("asn", {}).get("asn", "")).removeprefix("AS"))
    except ValueError:
        asn_number = None
    infrastructure_risk = {"status": "available", "is_known_high_risk": asn_number in HIGH_RISK_ASNS,
                           "asn": asn_number, "label": HIGH_RISK_ASNS.get(asn_number),
                           "reason": "Known high-risk hosting/anonymity ASN" if asn_number in HIGH_RISK_ASNS else "No local high-risk ASN match"}
    base["anonymity"] = {"is_tor": is_tor, "is_vpn": is_vpn, "is_proxy": is_proxy,
                         "local_database": local_anonymity, "provider": provider_anonymity,
                         "verdict": "anonymized" if (is_tor or is_vpn or is_proxy) else "not_detected"}
    base["infrastructure_risk"] = infrastructure_risk
    return base
