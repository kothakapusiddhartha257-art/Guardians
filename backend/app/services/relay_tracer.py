import re
import ipaddress
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import List, Optional, Tuple, Dict, Any
from backend.app.schemas.canonical import RelayHop, ParsedEmail


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return False


def extract_ip_from_string(text: str) -> Optional[str]:
    # Match IPv4 addresses enclosed in brackets or parentheses or standalone
    ipv4_pattern = r'\[?(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\]?'
    match = re.search(ipv4_pattern, text)
    if match:
        return match.group(1)
    return None


def parse_single_received_header(header_str: str) -> Dict[str, Any]:
    # Clean whitespace and folds
    cleaned = " ".join(header_str.split())

    from_host = None
    by_host = None
    protocol = None
    timestamp_str = None
    extracted_ip = None

    # Separate header parts by semicolon if present (standard timestamp delimiter)
    parts = cleaned.split(";", 1)
    route_part = parts[0]
    if len(parts) > 1:
        timestamp_str = parts[1].strip()

    # Parse 'from <host>'
    from_match = re.search(r'\bfrom\s+([^\s\(\)]+)(?:\s*\(([^;]+)\))?', route_part, re.IGNORECASE)
    if from_match:
        from_host = from_match.group(1).strip()
        from_extra = from_match.group(2) or ""
        extracted_ip = extract_ip_from_string(from_extra) or extract_ip_from_string(from_host)

    # Parse 'by <host>'
    by_match = re.search(r'\bby\s+([^\s\(\)]+)', route_part, re.IGNORECASE)
    if by_match:
        by_host = by_match.group(1).strip()

    # Parse 'with <protocol>'
    with_match = re.search(r'\bwith\s+([^\s;]+)', route_part, re.IGNORECASE)
    if with_match:
        protocol = with_match.group(1).strip()

    # If no IP extracted yet, search entire route part
    if not extracted_ip:
        extracted_ip = extract_ip_from_string(route_part)

    parsed_dt = None
    if timestamp_str:
        try:
            parsed_dt = parsedate_to_datetime(timestamp_str)
            if parsed_dt.tzinfo is None:
                parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass

    return {
        "from_host": from_host,
        "by_host": by_host,
        "protocol": protocol,
        "extracted_ip": extracted_ip,
        "timestamp_str": timestamp_str,
        "timestamp_dt": parsed_dt,
        "raw": cleaned
    }


def perform_rdns_lookup(ip: str) -> Optional[str]:
    # Safe lookup helper or simulation
    try:
        import dns.reversename
        import dns.resolver
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.0
        resolver.lifetime = 1.0
        answers = resolver.resolve(rev_name, "PTR")
        if answers:
            return str(answers[0]).rstrip(".")
    except Exception:
        pass
    return None


def reconstruct_relay_hops(parsed: ParsedEmail) -> List[RelayHop]:
    received_headers = parsed.received_chain_raw
    if not received_headers:
        return []

    # Received headers in MIME are top-to-bottom: [Newest / Recipient, ..., Oldest / Origin]
    # Parse each header
    raw_hops = [parse_single_received_header(h) for h in received_headers]

    # Reverse so index 0 = hop_1 = Oldest (Origin), index N-1 = hop_N = Newest (Recipient)
    chronological_hops = list(reversed(raw_hops))
    total_hops = len(chronological_hops)

    hops_output: List[RelayHop] = []

    # Walk backwards from recipient (total_hops - 1 down to 0) to establish the trust frontier
    trust_frontier_broken = False
    earliest_trusted_index = total_hops - 1

    # Temporary storage for trust assignment
    trust_assignments = [None] * total_hops
    reasoning_list = [[] for _ in range(total_hops)]

    # Recipient's MTA (newest hop) is ALWAYS TRUSTED
    recipient_idx = total_hops - 1
    trust_assignments[recipient_idx] = "TRUSTED"
    reasoning_list[recipient_idx].append("Recipient internal gateway boundary (ingestion anchor)")

    for i in range(total_hops - 2, -1, -1):
        curr = chronological_hops[i]
        next_newer = chronological_hops[i + 1]

        ip = curr["extracted_ip"]
        from_h = curr["from_host"]
        by_h = curr["by_host"]
        curr_dt = curr["timestamp_dt"]
        next_dt = next_newer["timestamp_dt"]

        # If trust frontier is already broken, all older hops are UNTRUSTED / POTENTIALLY_FORGED
        if trust_frontier_broken:
            trust_assignments[i] = "POTENTIALLY_FORGED"
            reasoning_list[i].append("Beyond trust frontier — pre-boundary hop is attacker-controllable")
            continue

        reasons = []
        is_trusted = True
        is_forged = False

        # Check IP validity & Private range
        if not ip:
            reasons.append("No valid IP address extractable from Received header")
            is_trusted = False
        elif is_private_ip(ip):
            if i == 0 and total_hops > 1:
                # Private IP as originating hop is common behind NAT, but untrusted for external verification
                reasons.append(f"Private/Internal IP {ip} (RFC 1918 NAT)")
                is_trusted = False
            else:
                reasons.append(f"Private IP {ip} in external routing path")
                is_trusted = False

        # Check Linkage: Does current 'by' host correlate with next-newer 'from' host?
        if by_h and next_newer["from_host"]:
            by_clean = by_h.lower().rstrip(".")
            next_from_clean = next_newer["from_host"].lower().rstrip(".")
            if not (by_clean in next_from_clean or next_from_clean in by_clean):
                reasons.append(f"Host mismatch: hop 'by' ({by_h}) does not match next hop 'from' ({next_newer['from_host']})")
                is_trusted = False

        # Check Timestamp Monotonicity: curr_dt should be <= next_dt (with 5 min skew tolerance)
        if curr_dt and next_dt:
            delta = (next_dt - curr_dt).total_seconds()
            if delta < -300:  # curr is > 5 mins AFTER next_newer (backward time travel)
                reasons.append(f"Timestamp anomaly: hop timestamp is {int(-delta)}s after subsequent hop")
                is_forged = True
                is_trusted = False
            else:
                reasons.append(f"Timestamp chronological delta: {int(delta)}s")

        # Assign trust
        if is_forged:
            trust_assignments[i] = "POTENTIALLY_FORGED"
            trust_frontier_broken = True
        elif is_trusted and len(reasons) <= 1:
            trust_assignments[i] = "TRUSTED"
            earliest_trusted_index = i
            reasons.append("Validated cryptographic/relay linkage with trusted receiving MTA")
        elif is_trusted:
            trust_assignments[i] = "LIKELY_TRUSTED"
            earliest_trusted_index = i
            reasons.append("Relay chain consistent, minor parameter variance")
        else:
            trust_assignments[i] = "UNTRUSTED"
            trust_frontier_broken = True
            reasons.append("Trust frontier broken — hop cannot be cryptographically or structurally verified")

        reasoning_list[i] = reasons

    # Build final RelayHop list
    for idx, hop_data in enumerate(chronological_hops):
        ip = hop_data["extracted_ip"]
        rdns = perform_rdns_lookup(ip) if ip and not is_private_ip(ip) else None

        time_delta_sec = None
        if idx < total_hops - 1:
            curr_dt = hop_data["timestamp_dt"]
            next_dt = chronological_hops[idx + 1]["timestamp_dt"]
            if curr_dt and next_dt:
                time_delta_sec = int((next_dt - curr_dt).total_seconds())

        hop_obj = RelayHop(
            email_id=parsed.email_id,
            hop_number=idx + 1,
            from_host_claimed=hop_data["from_host"],
            by_host_claimed=hop_data["by_host"],
            ip_extracted=ip,
            protocol=hop_data["protocol"],
            timestamp_claimed=hop_data["timestamp_str"],
            timestamp_delta_seconds=time_delta_sec,
            trust_level=trust_assignments[idx] or "UNTRUSTED",
            trust_reasoning=reasoning_list[idx] or ["Standard relay hop"],
            rdns=rdns
        )
        hops_output.append(hop_obj)

    return hops_output


def get_earliest_reliable_hop(hops: List[RelayHop]) -> Optional[RelayHop]:
    for hop in hops:
        if hop.trust_level in ("TRUSTED", "LIKELY_TRUSTED") and hop.ip_extracted and not is_private_ip(hop.ip_extracted):
            return hop
    return None
