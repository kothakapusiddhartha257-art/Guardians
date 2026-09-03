import numpy as np
from typing import Dict, Any, List, Optional
from backend.app.schemas.canonical import RelayHop, GeoLocationRecord, DomainIntelligenceRecord

# Pre-seeded normal email baseline statistics
BASELINE_HOP_COUNT = 3.0
BASELINE_DOMAIN_AGE = 2500.0


def calculate_behavioral_anomaly_score(
    relay_hops: List[RelayHop],
    geo: Optional[GeoLocationRecord],
    domains: List[DomainIntelligenceRecord]
) -> float:
    anomaly_signals = 0.0

    # 1. Hop count deviation (e.g. unusually long relay path > 6 hops)
    hop_count = len(relay_hops)
    if hop_count > 5:
        anomaly_signals += 0.25
    elif hop_count == 0:
        anomaly_signals += 0.20

    # 2. Hosting / Bulletproof ASN anomaly
    if geo:
        if geo.is_vpn or geo.is_tor:
            anomaly_signals += 0.35
        elif geo.is_hosting and geo.asn in (200019, 44050, 39351):
            anomaly_signals += 0.40

    # 3. Domain freshness anomaly
    if domains:
        min_age = min([d.age_days for d in domains if d.age_days is not None], default=3650)
        if min_age < 7:
            anomaly_signals += 0.30
        elif min_age < 30:
            anomaly_signals += 0.15

    return round(min(1.0, max(0.05, anomaly_signals)), 3)
