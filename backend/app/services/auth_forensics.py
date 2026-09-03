import re
import ipaddress
from typing import Optional, List, Dict, Any
import dns.resolver
from backend.app.schemas.canonical import (
    AuthResult, SpfResult, DkimResult, DmarcResult, ArcResult, ParsedEmail
)


DNS_CACHE: Dict[str, List[str]] = {}

def get_dns_txt_records(domain: str) -> List[str]:
    if domain in DNS_CACHE:
        return DNS_CACHE[domain]
    records = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 0.8
        resolver.lifetime = 0.8
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            # rdata.strings is a list of bytes chunks
            txt = "".join([chunk.decode("utf-8", errors="replace") for chunk in rdata.strings])
            records.append(txt)
    except Exception:
        pass
    DNS_CACHE[domain] = records
    return records


def evaluate_spf(
    domain: Optional[str],
    sending_ip: Optional[str],
    lookup_count: int = 0
) -> SpfResult:
    if not domain or not sending_ip:
        return SpfResult(
            result="none",
            domain_checked=domain,
            ip_checked=sending_ip,
            explanation="Missing domain or sending IP"
        )

    if lookup_count > 10:
        return SpfResult(
            result="permerror",
            domain_checked=domain,
            ip_checked=sending_ip,
            explanation="SPF lookup limit of 10 DNS queries exceeded (RFC 7208 4.6.4 violation)"
        )

    txt_records = get_dns_txt_records(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf_records:
        return SpfResult(
            result="none",
            domain_checked=domain,
            ip_checked=sending_ip,
            explanation=f"No SPF record found for domain {domain}"
        )

    if len(spf_records) > 1:
        return SpfResult(
            result="permerror",
            domain_checked=domain,
            ip_checked=sending_ip,
            record_text="; ".join(spf_records),
            explanation="Multiple SPF records found for domain (RFC 7208 violation)"
        )

    spf_text = spf_records[0]
    tokens = spf_text.split()[1:]  # skip v=spf1

    try:
        client_ip = ipaddress.ip_address(sending_ip)
    except ValueError:
        return SpfResult(
            result="permerror",
            domain_checked=domain,
            ip_checked=sending_ip,
            explanation=f"Invalid IP address format: {sending_ip}"
        )

    default_mechanism = "neutral"

    for token in tokens:
        qualifier = "+"
        mech = token
        if token[0] in "+-~?":
            qualifier = token[0]
            mech = token[1:]

        qual_map = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
        result_on_match = qual_map.get(qualifier, "pass")

        if mech == "all":
            return SpfResult(
                result=result_on_match,
                domain_checked=domain,
                ip_checked=sending_ip,
                record_text=spf_text,
                explanation=f"Matched directive: {token}"
            )

        elif mech.startswith("ip4:"):
            network_str = mech[4:]
            try:
                net = ipaddress.ip_network(network_str, strict=False)
                if client_ip in net:
                    return SpfResult(
                        result=result_on_match,
                        domain_checked=domain,
                        ip_checked=sending_ip,
                        record_text=spf_text,
                        explanation=f"IP {sending_ip} matches mechanism {token}"
                    )
            except Exception:
                pass

        elif mech.startswith("ip6:"):
            network_str = mech[4:]
            try:
                net = ipaddress.ip_network(network_str, strict=False)
                if client_ip in net:
                    return SpfResult(
                        result=result_on_match,
                        domain_checked=domain,
                        ip_checked=sending_ip,
                        record_text=spf_text,
                        explanation=f"IP {sending_ip} matches mechanism {token}"
                    )
            except Exception:
                pass

        elif mech.startswith("include:"):
            inc_domain = mech[8:]
            inc_res = evaluate_spf(inc_domain, sending_ip, lookup_count=lookup_count + 1)
            if inc_res.result == "pass":
                return SpfResult(
                    result=result_on_match,
                    domain_checked=domain,
                    ip_checked=sending_ip,
                    record_text=spf_text,
                    explanation=f"SPF include:{inc_domain} passed"
                )
            elif inc_res.result in ("permerror", "temperror"):
                return inc_res

        elif mech.startswith("redirect="):
            redir_domain = mech[9:]
            return evaluate_spf(redir_domain, sending_ip, lookup_count=lookup_count + 1)

    return SpfResult(
        result=default_mechanism,
        domain_checked=domain,
        ip_checked=sending_ip,
        record_text=spf_text,
        explanation="No mechanisms matched; fell through to default"
    )


def evaluate_dkim(
    raw_headers: Dict[str, Any],
    from_domain: Optional[str],
    raw_email_bytes: Optional[bytes] = None
) -> List[DkimResult]:
    results = []
    dkim_headers = raw_headers.get("DKIM-Signature", [])
    if isinstance(dkim_headers, str):
        dkim_headers = [dkim_headers]

    if not dkim_headers:
        return results

    for dkim_hdr in dkim_headers:
        d_match = re.search(r'\bd=([^;\s]+)', dkim_hdr)
        s_match = re.search(r'\bs=([^;\s]+)', dkim_hdr)
        
        signing_domain = d_match.group(1).lower().strip() if d_match else None
        selector = s_match.group(1).strip() if s_match else None

        aligned = False
        if signing_domain and from_domain:
            aligned = (signing_domain == from_domain or from_domain.endswith("." + signing_domain))

        valid = False
        details = "DKIM signature header present"
        
        # Check signature verification using dkimpy if available
        if raw_email_bytes:
            try:
                import dkim
                valid = dkim.verify(raw_email_bytes)
                details = "DKIM cryptographic signature verified" if valid else "DKIM verification failed (cryptographic mismatch)"
            except Exception as e:
                details = f"DKIM verification attempt: {str(e)}"
        else:
            # Fallback based on structure presence
            valid = True if signing_domain and selector else False
            details = "DKIM syntax valid"

        results.append(DkimResult(
            selector=selector,
            domain=signing_domain,
            valid=valid,
            aligned=aligned,
            details=details
        ))

    return results


def evaluate_dmarc(
    from_domain: Optional[str],
    spf_result: SpfResult,
    dkim_results: List[DkimResult]
) -> DmarcResult:
    if not from_domain:
        return DmarcResult(
            policy="none",
            spf_aligned=False,
            dkim_aligned=False,
            result="none",
            explanation="No From domain present"
        )

    txt_records = get_dns_txt_records(f"_dmarc.{from_domain}")
    dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        # Check parent domain if subdomain
        parts = from_domain.split(".")
        if len(parts) > 2:
            parent = ".".join(parts[1:])
            parent_records = [r for r in get_dns_txt_records(f"_dmarc.{parent}") if r.startswith("v=DMARC1")]
            if parent_records:
                dmarc_records = parent_records

    if not dmarc_records:
        return DmarcResult(
            policy="not_found",
            spf_aligned=False,
            dkim_aligned=False,
            result="none",
            explanation=f"No DMARC record found for _dmarc.{from_domain}"
        )

    dmarc_text = dmarc_records[0]
    
    # Parse policy
    p_match = re.search(r'\bp=(none|quarantine|reject)\b', dmarc_text, re.IGNORECASE)
    policy = p_match.group(1).lower() if p_match else "none"

    # Check alignment
    spf_aligned = (spf_result.result == "pass") and (
        spf_result.domain_checked == from_domain or
        (spf_result.domain_checked and from_domain.endswith("." + spf_result.domain_checked))
    )

    dkim_aligned = any(d.valid and d.aligned for d in dkim_results)

    dmarc_pass = spf_aligned or dkim_aligned

    return DmarcResult(
        policy=policy,
        spf_aligned=spf_aligned,
        dkim_aligned=dkim_aligned,
        result="pass" if dmarc_pass else "fail",
        record_text=dmarc_text,
        explanation=f"DMARC policy={policy}. SPF aligned: {spf_aligned}, DKIM aligned: {dkim_aligned}"
    )


def evaluate_arc(raw_headers: Dict[str, Any]) -> ArcResult:
    arc_seals = raw_headers.get("ARC-Seal", [])
    arc_results = raw_headers.get("ARC-Authentication-Results", [])
    arc_sigs = raw_headers.get("ARC-Message-Signature", [])

    if isinstance(arc_seals, str):
        arc_seals = [arc_seals]
    if isinstance(arc_results, str):
        arc_results = [arc_results]

    if not arc_seals:
        return ArcResult(present=False, chain_valid=False, hop_count=0, details="No ARC headers present")

    hop_count = len(arc_seals)
    # Check if all seals indicate cv=pass or valid
    cv_passes = all("cv=pass" in s.lower() or "cv=none" in s.lower() for s in arc_seals)
    
    return ArcResult(
        present=True,
        chain_valid=cv_passes,
        hop_count=hop_count,
        details=f"ARC chain with {hop_count} seal hops. Seal validation: {'VALID' if cv_passes else 'INVALID'}"
    )


def run_full_authentication(
    parsed: ParsedEmail,
    originating_ip: Optional[str] = None,
    raw_email_bytes: Optional[bytes] = None
) -> AuthResult:
    from_dom = parsed.headers_normalized.from_address.domain if parsed.headers_normalized.from_address else None
    
    # If originating IP not explicitly given, try from first external hop or headers
    if not originating_ip:
        # check X-Originating-IP or Authentication-Results header
        x_orig = parsed.headers_raw.get("X-Originating-IP", [])
        if x_orig:
            val = x_orig[0] if isinstance(x_orig, list) else x_orig
            ip_m = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', str(val))
            if ip_m:
                originating_ip = ip_m.group(0)

    spf = evaluate_spf(from_dom, originating_ip)
    dkim = evaluate_dkim(parsed.headers_raw, from_dom, raw_email_bytes)
    dmarc = evaluate_dmarc(from_dom, spf, dkim)
    arc = evaluate_arc(parsed.headers_raw)

    return AuthResult(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        arc=arc
    )
