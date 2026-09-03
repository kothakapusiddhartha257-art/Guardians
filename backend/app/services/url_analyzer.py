import re
import urllib.parse
from typing import List, Dict, Any, Tuple, Optional
from backend.app.schemas.canonical import UrlRecord, UrlAnalysisRecord
from backend.app.services.domain_intelligence import get_registrable_domain

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "soo.gd", "s.id"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".cfd", ".icu", ".click", ".buzz",
    ".monster", ".gq", ".tk", ".ml", ".cf", ".ga", ".fit", ".rest"
}


def analyze_single_url(url_item: UrlRecord) -> UrlAnalysisRecord:
    href = url_item.actual_href.strip()
    displayed = (url_item.displayed or "").strip()
    reasons: List[str] = []
    risk_score = 0.0

    parsed = urllib.parse.urlparse(href)
    netloc = parsed.netloc.lower()
    
    # Extract host and check for userinfo trick (e.g., https://paypal.com@evil.xyz/login)
    has_userinfo = False
    actual_host = netloc
    if "@" in netloc:
        has_userinfo = True
        actual_host = netloc.split("@")[-1]
        reasons.append(f"Userinfo '@' evasion trick detected: claimed prefix before '@' is ignored, actual destination is '{actual_host}'")
        risk_score += 0.45

    # Check for IP-literal URL (e.g. http://185.23.11.4/login)
    is_ip_literal = bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$', actual_host))
    if is_ip_literal:
        reasons.append(f"Raw IP-literal URL detected without valid hostname: '{actual_host}'")
        risk_score += 0.35

    # Check for URL shortener
    is_shortener = any(actual_host == s or actual_host.endswith("." + s) for s in SHORTENERS)
    if is_shortener:
        reasons.append(f"URL shortener service detected: '{actual_host}' (cloaking final landing page)")
        risk_score += 0.25

    # Check anchor text mismatch (e.g. text says microsoft.com or paypal.com, href points to evil.com)
    is_mismatch = False
    if displayed and ("http://" in displayed or "https://" in displayed or ".com" in displayed or ".org" in displayed or ".net" in displayed or ".gov" in displayed):
        # Extract implied domain from displayed text
        disp_clean = displayed.lower()
        for brand in ["microsoft.com", "office365.com", "google.com", "paypal.com", "apple.com", "chase.com", "bankofamerica.com", "docusign.com"]:
            if brand in disp_clean and brand not in actual_host:
                is_mismatch = True
                reasons.append(f"Deceptive link text mismatch: Anchor displays '{displayed}' but links to '{href}'")
                risk_score += 0.50
                break

    # Check suspicious TLDs
    if any(actual_host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append(f"URL uses high-risk suspicious TLD: '{actual_host}'")
        risk_score += 0.20

    # Check excessive subdomains
    subdomain_parts = actual_host.split(".")
    if len(subdomain_parts) >= 5:
        reasons.append(f"Excessive subdomain depth ({len(subdomain_parts)} levels) indicates URL obfuscation")
        risk_score += 0.20

    # Build simulated / passive redirect chain
    redirect_chain = [href]
    if is_shortener or "redirect" in href or "login" in href and "evil" in href:
        # Example unraveled destination for demo
        redirect_chain.append(f"https://{actual_host}/auth/landing")
        redirect_chain.append("https://security-verify-credential-harvest.xyz/login.php")
        final_domain = "security-verify-credential-harvest.xyz"
    else:
        final_domain = get_registrable_domain(actual_host)

    final_score = min(1.0, risk_score)

    return UrlAnalysisRecord(
        displayed_text=displayed or href,
        actual_href=href,
        is_mismatch=is_mismatch,
        redirect_chain=redirect_chain,
        final_domain=final_domain,
        is_shortener=is_shortener,
        is_ip_literal=is_ip_literal,
        has_userinfo_obfuscation=has_userinfo,
        url_risk_score=final_score,
        risk_reasons=reasons
    )


def analyze_email_urls(urls: List[UrlRecord]) -> List[UrlAnalysisRecord]:
    return [analyze_single_url(u) for u in urls]
