import pytest
from backend.app.services.domain_intelligence import (
    analyze_domain, get_registrable_domain, normalize_homoglyphs, evaluate_domain_lookalike
)


def test_public_suffix_extraction():
    assert get_registrable_domain("paypal.com.evil-update.co.uk") == "evil-update.co.uk"
    assert get_registrable_domain("login.microsoft.com") == "microsoft.com"


def test_homoglyph_detection():
    # Cyrillic 'а' in paypal
    spoofed = "pаypal.com"
    normalized = normalize_homoglyphs(spoofed)
    assert normalized == "paypal.com"


def test_lookalike_detection():
    is_lookalike, target, score, reasons = evaluate_domain_lookalike("paypa1.com")
    assert is_lookalike is True
    assert target == "paypal"
    assert score > 0.85


def test_domain_age_risk_decay():
    d_intel = analyze_domain("evil-threat-actor.xyz")
    assert d_intel.age_days < 10
    assert d_intel.age_risk_score > 0.80
