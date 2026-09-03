import pytest
from backend.app.services.email_parser import parse_email_bytes
from backend.app.services.relay_tracer import reconstruct_relay_hops, get_earliest_reliable_hop
from backend.app.seeds.demo_emails import DEMO_BEC_EMAIL


def test_relay_path_trust_frontier():
    parsed = parse_email_bytes(DEMO_BEC_EMAIL.encode("utf-8"))
    hops = reconstruct_relay_hops(parsed)
    assert len(hops) == 3

    # Hop 3 is recipient MTA -> TRUSTED
    assert hops[-1].trust_level == "TRUSTED"
    
    # Earliest reliable hop
    earliest = get_earliest_reliable_hop(hops)
    assert earliest is not None
    assert earliest.ip_extracted == "185.23.11.4"
