import pytest
from backend.app.services.pipeline import execute_analysis_dag
from backend.app.services.response_engine import evaluate_policy_and_overrides, CURRENT_POLICY
from backend.app.seeds.demo_emails import (
    DEMO_BEC_EMAIL, DEMO_MALWARE_INVOICE_EMAIL, DEMO_CLEAN_FORWARDED_EMAIL
)


@pytest.mark.asyncio
async def test_response_engine_bec_quarantine():
    bundle = await execute_analysis_dag(DEMO_BEC_EMAIL.encode("utf-8"), case_id="CASE-RESP-01")
    verdict, action, overrides = evaluate_policy_and_overrides(bundle)
    assert verdict == "MALICIOUS"
    assert action == "QUARANTINE"
    assert len(overrides) > 0


@pytest.mark.asyncio
async def test_response_engine_malware_quarantine_override():
    bundle = await execute_analysis_dag(DEMO_MALWARE_INVOICE_EMAIL.encode("utf-8"), case_id="CASE-RESP-02")
    verdict, action, overrides = evaluate_policy_and_overrides(bundle)
    assert verdict == "MALICIOUS"
    assert action == "QUARANTINE"
    # Should trigger OR-02 Disguised Executable
    assert any(o["rule_id"] == "OR-02" for o in overrides)


@pytest.mark.asyncio
async def test_response_engine_clean_delivery():
    bundle = await execute_analysis_dag(DEMO_CLEAN_FORWARDED_EMAIL.encode("utf-8"), case_id="CASE-RESP-03")
    verdict, action, overrides = evaluate_policy_and_overrides(bundle)
    assert verdict == "SAFE"
    assert action == "DELIVER"
    assert len(overrides) == 0
