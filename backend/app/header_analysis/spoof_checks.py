from datetime import datetime, timezone
from email.message import Message
from email.utils import parsedate_to_datetime

from rapidfuzz import fuzz

from app.config import BRAND_DOMAINS, DATE_CHAIN_DIFFERENCE_SECONDS, TIMESTAMP_GAP_SECONDS
from app.models.schemas import ReceivedHop


def domain_mismatches(from_domain: str | None, **domains: str | None) -> list[str]:
    if not from_domain:
        return []
    labels = {"reply_to_domain": "reply_to_mismatch", "return_path_domain": "return_path_mismatch", "message_id_domain": "message_id_mismatch"}
    return [labels[key] for key, value in domains.items() if value and value != from_domain]


def typosquat(from_domain: str | None) -> tuple[bool, str | None]:
    if not from_domain or from_domain in BRAND_DOMAINS:
        return False, None
    for brand in BRAND_DOMAINS:
        if fuzz.ratio(from_domain, brand) > 85:
            return True, brand
    return False, None


def timestamp_anomaly(message: Message, hops: list[ReceivedHop]) -> bool:
    moments = []
    for hop in hops:
        if hop.timestamp_utc:
            try:
                moments.append(datetime.fromisoformat(hop.timestamp_utc.replace("Z", "+00:00")))
            except ValueError:
                pass
    if any(abs((right - left).total_seconds()) >= TIMESTAMP_GAP_SECONDS for left, right in zip(moments, moments[1:])):
        return True
    if moments and message.get("Date"):
        try:
            date = parsedate_to_datetime(message["Date"])
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            return abs((date.astimezone(timezone.utc) - moments[-1]).total_seconds()) >= DATE_CHAIN_DIFFERENCE_SECONDS
        except (TypeError, ValueError):
            return False
    return False
