"""Passive URL safety checks for emails.

URLs are never opened in a browser or executed. Optional reputation lookups
send only the URL to the explicitly configured provider and fail closed as
"unavailable" - never as "safe".
"""
from __future__ import annotations

import base64
import os
import re
from ipaddress import ip_address
from urllib.parse import urlparse

import httpx

SUSPICIOUS_TLDS = {"xyz", "top", "click", "link", "zip", "mov", "icu", "cfd", "gq", "tk", "ml", "ga", "cf"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "s.id"}
BRANDS = {"microsoft": {"microsoft.com", "office.com", "office365.com"}, "google": {"google.com", "gmail.com"},
          "paypal": {"paypal.com"}, "amazon": {"amazon.com"}, "apple": {"apple.com"}, "hdfc": {"hdfcbank.com", "hdfc.com"}}


def _configured_reputation(url: str) -> list[dict]:
    """Use configured URL reputation services without following the link."""
    findings: list[dict] = []
    timeout = 4.0
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if vt_key:
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            response = httpx.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": vt_key}, timeout=timeout)
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
                if malicious:
                    findings.append({"provider": "VirusTotal", "verdict": "malicious", "detail": f"{malicious} security-engine detections"})
            elif response.status_code not in {404, 429}:
                findings.append({"provider": "VirusTotal", "verdict": "unavailable", "detail": f"lookup returned HTTP {response.status_code}"})
        except Exception:
            findings.append({"provider": "VirusTotal", "verdict": "unavailable", "detail": "lookup failed"})

    safe_browsing_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if safe_browsing_key:
        try:
            body = {"client": {"clientId": "traceguard", "clientVersion": "1.0"}, "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
            response = httpx.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={safe_browsing_key}", json=body, timeout=timeout)
            if response.status_code == 200 and response.json().get("matches"):
                findings.append({"provider": "Google Safe Browsing", "verdict": "malicious", "detail": "URL matched a Google Safe Browsing threat list"})
            elif response.status_code not in {200, 429}:
                findings.append({"provider": "Google Safe Browsing", "verdict": "unavailable", "detail": f"lookup returned HTTP {response.status_code}"})
        except Exception:
            findings.append({"provider": "Google Safe Browsing", "verdict": "unavailable", "detail": "lookup failed"})
    return findings


def inspect_url(url: str) -> dict:
    """Return explainable safety evidence for one unvisited URL."""
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower().rstrip(".")
    reasons: list[str] = []
    score = 0
    if parsed.scheme != "https":
        reasons.append("Link does not use HTTPS")
        score += 8
    if parsed.username or "@" in parsed.netloc:
        reasons.append("URL contains a user-info '@' obfuscation pattern")
        score += 30
    try:
        ip_address(host)
        reasons.append("Link uses a raw IP address instead of a domain")
        score += 25
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        reasons.append("Punycode domain may be used for look-alike characters")
        score += 25
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Frequently abused top-level domain: .{tld}")
        score += 15
    if host in SHORTENERS or any(host.endswith(f".{name}") for name in SHORTENERS):
        reasons.append("URL shortener hides the final destination")
        score += 12
    if len(host.split(".")) >= 5:
        reasons.append("Excessive subdomains can hide the true destination")
        score += 12
    normalized = host.replace("0", "o").replace("1", "l").replace("3", "e")
    for brand, legitimate in BRANDS.items():
        okay = any(host == item or host.endswith(f".{item}") for item in legitimate)
        if brand in normalized and not okay:
            reasons.append(f"Domain appears to imitate {brand.title()}")
            score += 30
            break
    path = (parsed.path + "?" + parsed.query).lower()
    if re.search(r"(login|signin|verify|password|otp|account|bank).{0,80}(update|confirm|secure|verify)|(?:verify|secure).{0,80}(login|account)", path):
        reasons.append("Sensitive account-verification path detected")
        score += 12
    reputation = _configured_reputation(url)
    for item in reputation:
        if item["verdict"] == "malicious":
            reasons.append(f"{item['provider']}: {item['detail']}")
            score = max(score, 85)
    return {"url": url, "host": host or "unknown", "risk_score": min(score, 100), "risk_reasons": reasons,
            "reputation": reputation, "checked_without_visiting": True}
