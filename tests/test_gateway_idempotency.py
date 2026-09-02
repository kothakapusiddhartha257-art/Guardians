import pytest
import uuid
from backend.app.schemas.gateway import RawMessage
from backend.app.services.email_monitor import email_monitor
from backend.app.seeds.demo_emails import DEMO_BEC_EMAIL


@pytest.mark.asyncio
async def test_duplicate_webhook_idempotency():
    """Verify that duplicate notifications for the same message ID produce exactly 1 case."""
    msg_id = f"dedup_test_{uuid.uuid4().hex[:6]}"
    raw_msg = RawMessage(
        provider="imap",
        provider_message_id=msg_id,
        raw_rfc822=DEMO_BEC_EMAIL.encode("utf-8"),
        sender="john.smith@acme.com",
        recipient="sarah.c@acme.com",
        subject="URGENT: Vendor Payment Account Change"
    )

    # First arrival -> Processed & Case created
    first_record = await email_monitor.handle_incoming_raw_message(raw_msg)
    assert first_record is not None
    assert first_record.provider_message_id == msg_id
    assert first_record.threat_score >= 0.75

    initial_record_count = len(email_monitor.live_email_records)

    # Duplicate webhook arrival -> Must be dropped by idempotency guard
    second_record = await email_monitor.handle_incoming_raw_message(raw_msg)
    assert second_record is None
    assert len(email_monitor.live_email_records) == initial_record_count
