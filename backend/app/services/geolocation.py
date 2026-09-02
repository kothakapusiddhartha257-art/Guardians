import ipaddress
from typing import Optional, Dict, Any, List
from backend.app.schemas.canonical import GeoLocationRecord

# Known Cloud and Hosting ASNs
CLOUD_HOSTING_ASNS = {
    16509: "Amazon AWS", 14618: "Amazon AWS", 15169: "Google Cloud", 8075: "Microsoft Azure",
    13335: "Cloudflare", 14061: "DigitalOcean", 24940: "Hetzner Online", 16276: "OVH SAS",
    37963: "Alibaba Cloud", 20473: "Choopa / Vultr", 63949: "Linode / Akamai",
    46652: "Hostwinds", 51167: "Contabo GmbH", 200019: "Alexhost (Bulletproof)",
    44050: "M247 Ltd", 9009: "M247 Ltd", 39351: "31173 Services (TOR Exit)"
}

# Known VPN and TOR ASNs / Subnets
VPN_TOR_ASNS = {9009, 44050, 39351, 62240, 200019}

# Built-in GeoIP lookup database for standard demo / test IP ranges
DEMO_IP_DATABASE: Dict[str, Dict[str, Any]] = {
    # Bulletproof / Phishing infra
    "185.23.11.4": {
        "country": "Russia", "region": "Moscow", "city": "Moscow",
        "latitude": 55.7558, "longitude": 37.6173, "accuracy_radius_km": 20,
        "asn": 200019, "asn_org": "Alexhost SRL (Bulletproof)", "is_vpn": False, "is_tor": False, "is_hosting": True,
        "reputation": "MALICIOUS", "reputation_score": 0.92
    },
    "194.26.29.112": {
        "country": "Netherlands", "region": "North Holland", "city": "Amsterdam",
        "latitude": 52.3676, "longitude": 4.9041, "accuracy_radius_km": 10,
        "asn": 44050, "asn_org": "M247 Ltd (VPN/Proxy Node)", "is_vpn": True, "is_tor": False, "is_hosting": True,
        "reputation": "SUSPICIOUS", "reputation_score": 0.74
    },
    "185.220.101.5": {
        "country": "Germany", "region": "Hesse", "city": "Frankfurt",
        "latitude": 50.1109, "longitude": 8.6821, "accuracy_radius_km": 15,
        "asn": 39351, "asn_org": "TOR Exit Node Relay", "is_vpn": False, "is_tor": True, "is_hosting": True,
        "reputation": "MALICIOUS", "reputation_score": 0.88
    },
    # Legitimate ESPs & Corporate Gateways
    "209.85.220.41": {
        "country": "United States", "region": "California", "city": "Mountain View",
        "latitude": 37.4220, "longitude": -122.0841, "accuracy_radius_km": 50,
        "asn": 15169, "asn_org": "Google LLC", "is_vpn": False, "is_tor": False, "is_hosting": True,
        "reputation": "SAFE", "reputation_score": 0.02
    },
    "40.107.92.54": {
        "country": "United States", "region": "Washington", "city": "Redmond",
        "latitude": 47.6740, "longitude": -122.1215, "accuracy_radius_km": 50,
        "asn": 8075, "asn_org": "Microsoft Corporation", "is_vpn": False, "is_tor": False, "is_hosting": True,
        "reputation": "SAFE", "reputation_score": 0.01
    },
    "167.89.86.12": {
        "country": "United States", "region": "Colorado", "city": "Denver",
        "latitude": 39.7392, "longitude": -104.9903, "accuracy_radius_km": 30,
        "asn": 16509, "asn_org": "SendGrid / Twilio Inc", "is_vpn": False, "is_tor": False, "is_hosting": True,
        "reputation": "SAFE", "reputation_score": 0.05
    },
    "103.21.244.0": {
        "country": "India", "region": "Telangana", "city": "Hyderabad",
        "latitude": 17.3850, "longitude": 78.4867, "accuracy_radius_km": 25,
        "asn": 13335, "asn_org": "Cloudflare Datacenter", "is_vpn": False, "is_tor": False, "is_hosting": True,
        "reputation": "SUSPICIOUS", "reputation_score": 0.55
    }
}


def lookup_ip_intel(ip_str: Optional[str]) -> GeoLocationRecord:
    if not ip_str:
        return GeoLocationRecord(ip="0.0.0.0", country="Unknown", city="Unknown")

    # Check if private IP
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback:
            return GeoLocationRecord(
                ip=ip_str,
                country="Internal / Private Network",
                region="RFC 1918",
                city="Local Network",
                latitude=0.0,
                longitude=0.0,
                accuracy_radius_km=0,
                asn=0,
                asn_org="Private LAN / Intranet",
                is_vpn=False,
                is_tor=False,
                is_hosting=False,
                reputation="SAFE",
                reputation_score=0.0,
                infrastructure_confidence=1.0,
                actor_location_confidence=0.0
            )
    except ValueError:
        return GeoLocationRecord(ip=ip_str, country="Invalid IP", city="Invalid IP")

    # Check demo database
    if ip_str in DEMO_IP_DATABASE:
        data = DEMO_IP_DATABASE[ip_str]
        is_h = data.get("is_hosting", True)
        is_v = data.get("is_vpn", False)
        is_t = data.get("is_tor", False)

        # Calibrated Confidence Honesty
        # If hosting/VPN/TOR, actor location confidence is drastically reduced (hosting != human)
        infra_conf = 0.85
        actor_conf = 0.18 if (is_h or is_v or is_t) else 0.72

        return GeoLocationRecord(
            ip=ip_str,
            country=data.get("country", "Unknown"),
            region=data.get("region"),
            city=data.get("city", "Unknown"),
            latitude=data.get("latitude"),
            longitude=data.get("longitude"),
            accuracy_radius_km=data.get("accuracy_radius_km", 50),
            asn=data.get("asn"),
            asn_org=data.get("asn_org", "Unknown ASN"),
            is_vpn=is_v,
            is_tor=is_t,
            is_hosting=is_h,
            reputation=data.get("reputation", "UNKNOWN"),
            reputation_score=data.get("reputation_score", 0.0),
            infrastructure_confidence=infra_conf,
            actor_location_confidence=actor_conf
        )

    # Heuristic GeoIP fallback for arbitrary IPs
    octets = [int(p) for p in ip_str.split(".") if p.isdigit()]
    first_oct = octets[0] if octets else 100

    # Deterministic synthetic coordinates based on IP hash for visual demo consistency
    h = hash(ip_str)
    lat = ((h % 12000) / 100.0) - 30.0  # -30 to +90
    lon = (((h >> 4) % 36000) / 100.0) - 180.0  # -180 to +180
    
    country = "United States" if first_oct < 100 else ("Germany" if first_oct < 150 else ("India" if first_oct < 200 else "Singapore"))
    city = "Washington D.C." if country == "United States" else ("Frankfurt" if country == "Germany" else ("Mumbai" if country == "India" else "Singapore"))
    asn_num = 15169 if country == "United States" else (24940 if country == "Germany" else 55836)
    asn_name = CLOUD_HOSTING_ASNS.get(asn_num, f"Autonomous System AS{asn_num}")
    
    is_hosting = True
    is_vpn = first_oct % 7 == 0
    is_tor = first_oct % 13 == 0
    
    actor_conf = 0.20 if (is_hosting or is_vpn or is_tor) else 0.65

    return GeoLocationRecord(
        ip=ip_str,
        country=country,
        region="Default Region",
        city=city,
        latitude=round(lat, 4),
        longitude=round(lon, 4),
        accuracy_radius_km=50,
        asn=asn_num,
        asn_org=asn_name,
        is_vpn=is_vpn,
        is_tor=is_tor,
        is_hosting=is_hosting,
        reputation="UNKNOWN",
        reputation_score=0.20,
        infrastructure_confidence=0.75,
        actor_location_confidence=actor_conf
    )
