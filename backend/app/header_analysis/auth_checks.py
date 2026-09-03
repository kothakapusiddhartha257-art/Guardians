import re
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from email.message import Message

from app.config import DNS_TIMEOUT_SECONDS
from app.models.schemas import AuthResult

VALID_RESULTS = {"pass", "fail", "none", "softfail", "neutral", "temperror", "permerror"}


def _from_authentication_results(message: Message) -> AuthResult | None:
    values = message.get_all("Authentication-Results", [])
    if not values:
        return None
    joined = " ".join(values)
    found = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{mechanism}\s*=\s*([a-zA-Z]+)", joined, re.I)
        found[mechanism] = match.group(1).lower() if match else "unknown"
        if found[mechanism] not in VALID_RESULTS:
            found[mechanism] = "unknown"
    return AuthResult(**found, source="authentication-results-header")


def _check_domain(domain: str) -> AuthResult:
    """Look up the domain's published DMARC policy with checkdmarc.

    checkdmarc 5.x has returned both a single mapping and a list depending on
    release/API mode. Keep this small adapter tolerant of both public shapes.
    """
    import checkdmarc

    results = checkdmarc.check_domains([domain], skip_tls=True, timeout=DNS_TIMEOUT_SECONDS)
    if isinstance(results, list):
        result = results[0]
    elif isinstance(results, Mapping) and "dmarc" not in results and domain in results:
        # Compatibility with versions returning {domain: DomainCheckResult}.
        result = results[domain]
    else:
        result = results

    dmarc = result.get("dmarc") if isinstance(result, Mapping) else getattr(result, "dmarc", None)
    dmarc_record = dmarc.get("record") if isinstance(dmarc, Mapping) else getattr(dmarc, "record", None)
    return AuthResult(spf="unknown", dkim="unknown", dmarc="pass" if dmarc_record else "none", source="checkdmarc")


def check_authentication(message: Message, from_domain: str | None, errors: list[str]) -> AuthResult:
    header_result = _from_authentication_results(message)
    if header_result:
        return header_result
    if not from_domain:
        return AuthResult(spf="unknown", dkim="unknown", dmarc="unknown", source="unavailable")
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_check_domain, from_domain)
    try:
        result = future.result(timeout=DNS_TIMEOUT_SECONDS)
        executor.shutdown(wait=False, cancel_futures=True)
        return result
    except TimeoutError:
        errors.append("DNS lookup timed out for DMARC check.")
    except Exception:
        errors.append("DNS lookup failed for DMARC check.")
    executor.shutdown(wait=False, cancel_futures=True)
    return AuthResult(spf="unknown", dkim="unknown", dmarc="unknown", source="unavailable")
