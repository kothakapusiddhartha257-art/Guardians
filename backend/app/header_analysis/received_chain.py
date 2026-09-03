import ipaddress
import re
from datetime import timezone
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Optional

from app.models.schemas import ReceivedHop

IP_PATTERN = re.compile(r"(?<![\w:.])(?:\d{1,3}\.){3}\d{1,3}(?![\w:.])|(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]+")
HOST_PATTERN = re.compile(r"\bfrom\s+([^\s(;]+)", re.IGNORECASE)


def _ip_from_received(value: str) -> Optional[str]:
    parenthetical = re.findall(r"\(([^)]*)\)", value)
    for section in parenthetical + [value]:
        for candidate in IP_PATTERN.findall(section):
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
    return None


def _timestamp(value: str) -> Optional[str]:
    if ";" not in value:
        return None
    try:
        moment = parsedate_to_datetime(value.rsplit(";", 1)[1].strip())
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, IndexError):
        return None


def is_non_public(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return not address.is_global


def parse_received_chain(message: Message) -> tuple[list[ReceivedHop], Optional[str]]:
    raw_hops = list(reversed(message.get_all("Received", [])))
    hops: list[ReceivedHop] = []
    sender_ip = None
    for index, raw in enumerate(raw_hops):
        ip = _ip_from_received(raw)
        match = HOST_PATTERN.search(raw)
        private = bool(ip and is_non_public(ip))
        if ip and not private and sender_ip is None:
            sender_ip = ip
        hops.append(ReceivedHop(hop_index=index, ip=ip, is_private_ip=private,
                                claimed_hostname=match.group(1) if match else None,
                                timestamp_utc=_timestamp(raw)))
    return hops, sender_ip
