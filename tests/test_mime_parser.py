import pytest
from backend.app.services.email_parser import parse_email_bytes
from backend.app.seeds.demo_emails import DEMO_BEC_EMAIL, DEMO_MALWARE_INVOICE_EMAIL


def test_parse_bec_email():
    parsed = parse_email_bytes(DEMO_BEC_EMAIL.encode("utf-8"))
    assert parsed.headers_normalized.from_address is not None
    assert parsed.headers_normalized.from_address.address == "john.smith@acme.com"
    assert parsed.headers_normalized.reply_to is not None
    assert parsed.headers_normalized.reply_to.address == "finance-executive@secure-exchange-transfer.xyz"
    assert "URGENT" in parsed.headers_normalized.subject
    assert len(parsed.received_chain_raw) == 3
    assert "Sarah" in parsed.body_text


def test_parse_malware_attachment():
    parsed = parse_email_bytes(DEMO_MALWARE_INVOICE_EMAIL.encode("utf-8"))
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "Overdue_Invoice_8821.pdf.exe"
    assert att.mime == "application/pdf"
    assert len(att.sha256) == 64
