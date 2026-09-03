export const MOCK_DASHBOARD_SUMMARY = {
  active_threats_count: 4,
  quarantined_count: 12,
  critical_count: 3,
  suspicious_count: 5,
  safe_count: 42,
  average_threat_score: 0.68,
  total_analyzed: 59,
  frontiers_breached: 8
};

export const MOCK_DASHBOARD_TREND = [
  { timestamp: '08:00', threats: 2, total: 10 },
  { timestamp: '10:00', threats: 5, total: 15 },
  { timestamp: '12:00', threats: 9, total: 24 },
  { timestamp: '14:00', threats: 14, total: 38 },
  { timestamp: '16:00', threats: 18, total: 47 },
  { timestamp: '18:00', threats: 21, total: 59 }
];

export const MOCK_RECENT_THREATS = [
  {
    email_id: 'eml-bec-wire-01',
    report_id: 'REP-2026-F98A1B',
    case_id: 'CAS-2026-901',
    subject: 'URGENT: Executive Wire Transfer Authorization Required ($50,000)',
    from_address: 'ceo-executive-alerts@m1crosoft-office.com',
    threat_score: 0.94,
    classification: 'MALICIOUS',
    received_at: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    primary_threat: 'BEC / Executive Impersonation'
  },
  {
    email_id: 'eml-cred-phish-02',
    report_id: 'REP-2026-C44E82',
    case_id: 'CAS-2026-902',
    subject: 'Action Required: Microsoft 365 Password Expiration in 2 Hours',
    from_address: 'no-reply@security-auth-check.net',
    threat_score: 0.86,
    classification: 'SUSPICIOUS',
    received_at: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    primary_threat: 'Credential Harvesting Homoglyph'
  },
  {
    email_id: 'eml-malware-pdf-03',
    report_id: 'REP-2026-B17D99',
    case_id: 'CAS-2026-903',
    subject: 'Overdue Invoice #INV-88192 attached for immediate settlement',
    from_address: 'billing@fast-pay-invoicing.xyz',
    threat_score: 0.98,
    classification: 'MALICIOUS',
    received_at: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    primary_threat: 'Masqueraded Binary (.pdf.exe)'
  },
  {
    email_id: 'eml-clean-digest-04',
    report_id: 'REP-2026-A01C33',
    case_id: 'CAS-2026-904',
    subject: 'Enterprise Cloud Security Weekly Digest & Compliance Checklist',
    from_address: 'security-bulletin@corp.internal',
    threat_score: 0.04,
    classification: 'SAFE',
    received_at: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
    primary_threat: 'None (Cryptographically Signed)'
  }
];

export const MOCK_INVESTIGATION_BUNDLE = {
  report_id: 'REP-2026-F98A1B',
  case_id: 'CAS-2026-901',
  email: {
    email_id: 'eml-bec-wire-01',
    headers_normalized: {
      from_address: { name: 'Executive Operations', address: 'ceo-alerts@m1crosoft-office.com' },
      to_addresses: [{ name: 'Finance Controller', address: 'controller@enterprise.com' }],
      subject: 'URGENT: Executive Wire Transfer Authorization Required ($50,000)',
      date: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
      message_id: '<msg-2026-09-03-8891@m1crosoft-office.com>',
      reply_to: [{ name: 'Private Wire Desk', address: 'offshore-wire@bulletproof-hosting.ru' }]
    },
    body_preview: 'Please process the attached urgent wire transfer instructions for our acquisition before market close today. Transfer $50,000 immediately.',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  },
  risk_score: {
    threat_score: 0.94,
    classification: 'MALICIOUS',
    confidence: 0.96,
    subscores: {
      header_anomaly: 0.92,
      auth_failure: 0.95,
      content_intent: 0.94,
      infrastructure_reputation: 0.88,
      attachment_risk: 0.70
    },
    top_reasons: [
      'Lookalike domain (m1crosoft-office.com) impersonates Microsoft',
      'Mismatched Reply-To address pointing to bulletproof host',
      'DKIM & SPF cryptographic authentication failure',
      'High-urgency wire transfer financial phrasing detected by NLP'
    ]
  },
  auth_results: {
    spf: { status: 'FAIL', details: 'IP 185.220.101.5 not authorized in SPF record for domain' },
    dkim: { status: 'FAIL', details: 'No valid DKIM signature found for sending domain' },
    dmarc: { status: 'FAIL', details: 'DMARC alignment failed; policy p=reject recommended' },
    arc: { status: 'NONE', details: 'No ARC authentication seal present' }
  },
  relay_hops: [
    {
      hop_index: 1,
      from_host: 'client-desktop.local',
      by_host: 'smtp-out.bulletproof-hosting.ru',
      ip: '185.220.101.5',
      geo: { country: 'Russia', city: 'Moscow', lat: 55.7558, lon: 37.6173 },
      is_trusted: false,
      delay_seconds: 2
    },
    {
      hop_index: 2,
      from_host: 'smtp-out.bulletproof-hosting.ru',
      by_host: 'relay-edge-01.frankfurt.net',
      ip: '194.26.29.11',
      geo: { country: 'Germany', city: 'Frankfurt', lat: 50.1109, lon: 8.6821 },
      is_trusted: false,
      delay_seconds: 4
    },
    {
      hop_index: 3,
      from_host: 'relay-edge-01.frankfurt.net',
      by_host: 'mx.enterprise-gateway.com',
      ip: '52.96.110.2',
      geo: { country: 'United States', city: 'Ashburn', lat: 39.0438, lon: -77.4874 },
      is_trusted: true,
      delay_seconds: 1
    }
  ],
  urls: [
    {
      original_url: 'http://185.220.101.5/wire-instructions.html',
      final_url: 'http://185.220.101.5/wire-instructions.html',
      is_suspicious: true,
      risk_score: 0.95,
      category: 'Phishing Portal / Financial Intercept'
    }
  ],
  attachments: [
    {
      filename: 'Wire_Confirmation_Notice.pdf.exe',
      sha256: '9f83c605d4cacf84b54c40f71b5dd5fa36d17d83ec094ff5ba67dcf35e5bf501',
      size_bytes: 428000,
      detected_type: 'application/x-dosexec',
      claimed_type: 'application/pdf',
      is_malicious: true,
      threat_name: 'Win32/TrojanDownloader.Masquerade'
    }
  ],
  threat_intel: {
    actor: 'UNC4819 (Financial Fraud Group)',
    campaign: 'CAM-2026-08 (Q3 Wire Redirect Directive)',
    tactics: ['Initial Access: Spearphishing Link', 'Defense Evasion: Masquerading', 'Credential Access: Brute Force']
  },
  nlp_intent: {
    primary_intent: 'BEC Wire Fraud Directive',
    urgency_score: 0.96,
    social_engineering_score: 0.92,
    deception_score: 0.95
  }
};

export const MOCK_CASES = [
  {
    case_id: 'CAS-2026-901',
    title: 'BEC Wire Transfer Directive targeting Corporate Controller',
    severity: 'CRITICAL',
    status: 'ACTIVE_INVESTIGATION',
    threat_score: 0.94,
    created_at: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    assigned_to: 'analyst_01',
    evidence_count: 4
  },
  {
    case_id: 'CAS-2026-902',
    title: 'Microsoft 365 Credential Harvesting Spoof Portal',
    severity: 'HIGH',
    status: 'QUARANTINED',
    threat_score: 0.86,
    created_at: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    assigned_to: 'analyst_02',
    evidence_count: 2
  },
  {
    case_id: 'CAS-2026-903',
    title: 'Masqueraded Invoice Binary Executable Payload (.pdf.exe)',
    severity: 'CRITICAL',
    status: 'BLOCKED',
    threat_score: 0.98,
    created_at: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    assigned_to: 'secops_lead',
    evidence_count: 6
  }
];

export const MOCK_CAMPAIGNS = [
  {
    campaign_id: 'CAM-2026-08',
    name: 'Executive Wire Transfer Blitz (Q3 Directive)',
    threat_actor: 'UNC4819',
    total_emails: 18,
    targeted_departments: ['Finance', 'Executive Suite', 'Treasury'],
    primary_origin_country: 'Russia',
    risk_level: 'CRITICAL',
    first_seen: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
    last_seen: new Date().toISOString()
  },
  {
    campaign_id: 'CAM-2026-04',
    name: 'M365 Zero-Point Password Expiry Phish',
    threat_actor: 'Storm-0821',
    total_emails: 43,
    targeted_departments: ['All Corporate Tenants'],
    primary_origin_country: 'Netherlands',
    risk_level: 'HIGH',
    first_seen: new Date(Date.now() - 1000 * 60 * 60 * 96).toISOString(),
    last_seen: new Date().toISOString()
  }
];
