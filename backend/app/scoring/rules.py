from app.config import SCORE_WEIGHTS

RULE_DESCRIPTIONS = {
    "spf_fail": "SPF authentication failed for sender domain", "spf_softfail": "SPF check returned softfail, indicating a weak or misconfigured sender policy", "spf_none": "No SPF policy was found for sender domain",
    "dkim_fail": "DKIM signature verification failed", "dkim_none": "No DKIM signature was present",
    "dmarc_fail": "DMARC authentication failed for sender domain", "dmarc_none": "No DMARC policy was found for sender domain",
    "reply_to_mismatch": "Reply-To domain differs from the From domain", "return_path_mismatch": "Return-Path domain differs from the From domain",
    "message_id_mismatch": "Message-ID domain differs from the From domain", "typosquat": "Sender domain closely resembles a commonly impersonated brand",
    "timestamp_anomaly": "Email timestamps contain an unusually large timing discrepancy",
}
