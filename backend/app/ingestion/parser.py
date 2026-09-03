from email import policy
from email.message import Message
from email.parser import BytesParser


class EmailParseError(ValueError):
    """Raised when the input cannot reasonably be treated as an RFC email."""


def parse_email(raw: bytes | str) -> Message:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    if not raw or not raw.strip():
        raise EmailParseError("Email input is empty.")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise EmailParseError("Email could not be parsed.") from exc
    # A header-less blob is almost certainly not a pasted raw email.
    if not message.keys():
        raise EmailParseError("Email could not be parsed: no headers were found.")
    return message
