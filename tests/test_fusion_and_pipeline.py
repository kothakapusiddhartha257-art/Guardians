import pytest
import pytest_asyncio
from backend.app.services.pipeline import execute_analysis_dag
from backend.app.seeds.demo_emails import DEMO_BEC_EMAIL, DEMO_CLEAN_FORWARDED_EMAIL


@pytest.mark.asyncio
async def test_full_pipeline_bec_email():
    bundle = await execute_analysis_dag(DEMO_BEC_EMAIL.encode("utf-8"), case_id="CASE-TEST-BEC")
    assert bundle.risk_score.threat_score >= 0.75
    assert bundle.risk_score.classification in ("BEC", "PHISHING", "IMPERSONATION")
    assert bundle.risk_score.infrastructure_confidence > 0.50
    assert len(bundle.risk_score.top_reasons) > 0
    assert len(bundle.chain_of_custody) >= 2


@pytest.mark.asyncio
async def test_full_pipeline_clean_email():
    bundle = await execute_analysis_dag(DEMO_CLEAN_FORWARDED_EMAIL.encode("utf-8"), case_id="CASE-TEST-CLEAN")
    assert bundle.risk_score.threat_score < 0.25
    assert bundle.risk_score.classification == "LEGITIMATE"
