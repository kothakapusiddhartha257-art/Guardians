from email.message import Message
from email.utils import parseaddr
from typing import Optional


def domain_from_value(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    _name, address = parseaddr(value)
    candidate = address or value.strip().strip("<>")
    if "@" not in candidate:
        return None
    domain = candidate.rsplit("@", 1)[1].strip().strip("> ").lower()
    return domain or None


def extract_headers(message: Message) -> dict[str, Optional[str]]:
    from_value = message.get("From")
    _name, from_address = parseaddr(from_value or "")
    return {
        "from_address": from_address or None,
        "from_domain": domain_from_value(from_value),
        "reply_to_domain": domain_from_value(message.get("Reply-To")),
        "return_path_domain": domain_from_value(message.get("Return-Path")),
        "message_id_domain": domain_from_value(message.get("Message-ID")),
        "subject": message.get("Subject"),
        "date_header": message.get("Date"),
    }
