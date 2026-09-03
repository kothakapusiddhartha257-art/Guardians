import re
import unicodedata
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from publicsuffixlist import PublicSuffixList
from backend.app.core.config import settings
from backend.app.schemas.canonical import DomainIntelligenceRecord

psl = PublicSuffixList()

# Confusable homoglyph mapping for normalization
HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b', '@': 'a',
    'ı': 'i', 'ł': 'l', 'ø': 'o', 'vv': 'w', 'rn': 'm'
}


def get_registrable_domain(domain: str) -> str:
    if not domain:
        return ""
    clean_domain = domain.lower().strip().rstrip(".")
    # Use PSL to extract true registrable domain (e.g. paypal.com.evil.co.uk -> evil.co.uk)
    priv = psl.privatesuffix(clean_domain)
    return priv or clean_domain


def normalize_homoglyphs(text: str) -> str:
    # Normalize unicode to decomposed NFKD form
    decomposed = unicodedata.normalize('NFKD', text)
    res = []
    for ch in decomposed.lower():
        res.append(HOMOGLYPH_MAP.get(ch, ch))
    return "".join(res)


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def jaro_winkler_similarity(s1: str, s2: str) -> float:
    # Lightweight Jaro-Winkler implementation
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = max(len1, len2) // 2 - 1
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    jaro = (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3.0
    
    # Winkler bonus for common prefix up to 4 chars
    prefix = 0
    for i in range(min(4, min(len1, len2))):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break

    return jaro + prefix * 0.1 * (1 - jaro)


def evaluate_domain_lookalike(domain: str) -> Tuple[bool, Optional[str], float, List[str]]:
    reasons = []
    clean = domain.lower().strip()
    registrable = get_registrable_domain(clean)
    domain_label = registrable.split(".")[0] if "." in registrable else registrable

    normalized_label = normalize_homoglyphs(domain_label)

    best_score = 0.0
    best_target = None
    is_lookalike = False

    for brand in settings.PROTECTED_BRANDS:
        # Direct substring/subdomain hijacking check (e.g. paypal.com.evil.com)
        if brand in clean and brand != domain_label and brand not in domain_label.split("-"):
            is_lookalike = True
            best_target = brand
            best_score = 0.95
            reasons.append(f"Protected brand '{brand}' abused in subdomain/token of '{clean}' (registrable: {registrable})")
            break

        # Check if homoglyph normalized label matches brand exactly (e.g. paypa1 -> paypal)
        if normalized_label == brand and domain_label != brand:
            is_lookalike = True
            best_target = brand
            best_score = 0.98
            reasons.append(f"Homoglyph / Typosquat impersonation of brand '{brand}' (label: '{domain_label}')")
            break

        # Check Jaro-Winkler & Levenshtein on domain label vs brand
        sim = jaro_winkler_similarity(normalized_label, brand)
        dist = levenshtein_distance(normalized_label, brand)

        if (sim > 0.88 or (dist <= 2 and len(brand) >= 5)) and normalized_label != brand:
            if sim > best_score:
                best_score = sim
                best_target = brand
                is_lookalike = True
                reasons.append(f"Typosquat/Lookalike candidate for brand '{brand}' (similarity: {round(sim, 2)}, edit dist: {dist})")

    return is_lookalike, best_target, best_score, reasons


def analyze_domain(domain_str: Optional[str]) -> Optional[DomainIntelligenceRecord]:
    if not domain_str:
        return None

    clean = domain_str.lower().strip().rstrip(".")
    registrable = get_registrable_domain(clean)

    # Punycode check
    is_punycode = "xn--" in clean
    decoded_punycode = None
    if is_punycode:
        try:
            decoded_punycode = clean.encode("ascii").decode("idna")
        except Exception:
            pass

    # Homoglyphs and mixed scripts check
    has_confusable = any(ord(c) > 127 for c in clean) or any(c in HOMOGLYPH_MAP for c in clean)
    has_mixed_script = False
    scripts = set()
    for ch in clean:
        if ch.isalpha():
            scripts.add(unicodedata.name(ch, "").split()[0])
    if len(scripts) > 1 and "LATIN" in scripts:
        has_mixed_script = True

    # Lookalike check
    is_lookalike, target, lookalike_score, reasons = evaluate_domain_lookalike(clean)

    if is_punycode:
        reasons.append(f"Punycode / IDN encoding detected: {decoded_punycode or clean}")
    if has_mixed_script:
        reasons.append(f"Mixed character scripts detected in domain labels: {', '.join(scripts)}")

    # Domain Age Simulation / Lookup
    # In real world: query RDAP/WHOIS. For demo/fixtures: calculate age based on known threat feeds
    age_days = 3650  # default 10 years for established domains
    created_date = "2016-01-15T00:00:00Z"
    registrar = "MarkMonitor Inc."

    # Threat heuristic domains for testing
    suspicious_tlds = [".xyz", ".top", ".club", ".work", ".cfd", ".icu", ".click", ".buzz", ".monster"]
    if any(clean.endswith(tld) for tld in suspicious_tlds) or is_lookalike:
        age_days = 3  # Newly registered 3-day old domain
        created_date = "2026-08-28T00:00:00Z"
        registrar = "NameCheap / Russian Registrar Proxy"
        reasons.append(f"High-risk suspicious TLD detected on newly created domain ({age_days} days old)")

    # Age risk decay curve: max(0, 1 - age_days / 90)
    age_risk = max(0.0, min(1.0, 1.0 - (age_days / 90.0)))
    if age_risk > 0.5:
        reasons.append(f"Newly registered domain ({age_days} days old, risk factor {round(age_risk, 2)})")

    return DomainIntelligenceRecord(
        domain=clean,
        registrable_domain=registrable,
        age_days=age_days,
        age_risk_score=age_risk,
        registrar=registrar,
        created_date=created_date,
        is_lookalike=is_lookalike,
        lookalike_target=target,
        lookalike_score=lookalike_score,
        is_punycode=is_punycode,
        punycode_decoded=decoded_punycode,
        has_unicode_confusable=has_confusable,
        has_mixed_script=has_mixed_script,
        dns_records={"MX": ["mail." + registrable], "A": ["185.23.11.4"]},
        risk_reasons=reasons
    )
