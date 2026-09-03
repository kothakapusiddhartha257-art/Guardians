MAX_EMAIL_BYTES = 10 * 1024 * 1024
DNS_TIMEOUT_SECONDS = 3
TIMESTAMP_GAP_SECONDS = 6 * 60 * 60
DATE_CHAIN_DIFFERENCE_SECONDS = 6 * 60 * 60

SCORE_WEIGHTS = {
    "spf_fail": 25, "spf_softfail": 15, "spf_none": 10, "dkim_fail": 20, "dkim_none": 10,
    "dmarc_fail": 20, "dmarc_none": 5, "reply_to_mismatch": 15,
    "return_path_mismatch": 10, "message_id_mismatch": 10,
    "typosquat": 30, "timestamp_anomaly": 10,
}

BRAND_DOMAINS = (
    "paypal.com", "microsoft.com", "google.com", "amazon.com", "apple.com",
    "bankofamerica.com", "chase.com", "netflix.com", "facebook.com",
    "instagram.com", "whatsapp.com", "linkedin.com", "dropbox.com",
    "docusign.com", "irs.gov", "outlook.com", "yahoo.com", "wellsfargo.com",
)
