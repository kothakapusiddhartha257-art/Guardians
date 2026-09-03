/**
 * TRACEGUARD AI - High-Fidelity Threat Scenarios for Extension Quick Scanner
 */

export const DEMO_SCENARIOS = {
  bec_wire_transfer: {
    id: 'bec_wire_transfer',
    title: 'BEC Wire Transfer Directive ($142.5K)',
    tag: 'CRITICAL BEC',
    description: 'CEO executive spoof with Reply-To redirection, new intermediary account request, and display name impersonation.',
    rawMime: `Received: from mail-relay.internal.acme.com (10.0.1.5) by mx.acme.com with ESMTP id m12345; Mon, 31 Aug 2026 10:22:02 +0000
Received: from mail.secure-exchange-transfer.xyz (185.23.11.4) by mail-relay.internal.acme.com with ESMTPS id b67890; Mon, 31 Aug 2026 10:21:58 +0000
Received: from unknown (192.168.1.100) by mail.secure-exchange-transfer.xyz with HTTP; Mon, 31 Aug 2026 10:21:50 +0000
From: "CEO John Smith" <john.smith@acme.com>
Reply-To: "Executive Remittance" <finance-executive@secure-exchange-transfer.xyz>
Return-Path: <bounce@secure-exchange-transfer.xyz>
To: "Sarah Connor - Accounts Payable" <sarah.c@acme.com>
Subject: URGENT: Vendor Payment Account Change & Wire Transfer Directive
Date: Mon, 31 Aug 2026 10:21:45 +0000
Message-ID: <20260831102145.98765@secure-exchange-transfer.xyz>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="----=_Part_BEC_12345"

------=_Part_BEC_12345
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

Sarah,

I am currently in board meetings and unavailable by phone. We have an urgent vendor payment of $142,500 that must be settled immediately before close of business today.

The vendor's standard banking details have been updated due to an annual audit. Do not use the old banking information on file. Please remit the wire transfer to our new designated intermediary escrow account right away:

Beneficiary: Apex Logistics Holding LLC
Routing Number: 021000021
Account Number: 884920194829
Amount: $142,500.00 USD

Please reply directly to this email with the wire confirmation receipt as soon as processed. Treat this with immediate priority.

Regards,
John Smith
Chief Executive Officer
Acme Corporation

------=_Part_BEC_12345
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

<html>
<body>
<p>Sarah,</p>
<p>I am currently in board meetings and unavailable by phone. We have an <b>urgent vendor payment of $142,500</b> that must be settled immediately before close of business today.</p>
<p>The vendor's standard banking details have been updated due to an annual audit. <b>Do not use the old banking information on file.</b> Please remit the wire transfer to our new designated intermediary escrow account right away:</p>
<div style="background:#f4f4f4; padding:10px; border-left:4px solid #cc0000;">
<p><b>Beneficiary:</b> Apex Logistics Holding LLC<br>
<b>Routing Number:</b> 021000021<br>
<b>Account Number:</b> 884920194829<br>
<b>Amount:</b> $142,500.00 USD</p>
</div>
<p>Please reply directly to this email with the wire confirmation receipt as soon as processed. Treat this with immediate priority.</p>
<p>Regards,<br>
<b>John Smith</b><br>
Chief Executive Officer<br>
Acme Corporation</p>
</body>
</html>
------=_Part_BEC_12345--`
  },

  m365_credential_harvest: {
    id: 'm365_credential_harvest',
    title: 'Microsoft 365 Credential Harvester',
    tag: 'PHISHING',
    description: 'Fake Microsoft security notification with urgency cues and anchor-text-to-IP redirect link.',
    rawMime: `Received: from inbound.acme.com (10.0.1.2) by mx.acme.com with ESMTP id p9876; Mon, 31 Aug 2026 09:15:00 +0000
Received: from mail.m365-security-update.top (194.26.29.112) by inbound.acme.com with ESMTPS id q5432; Mon, 31 Aug 2026 09:14:55 +0000
From: "Microsoft 365 Support Team" <admin@m365-security-update.top>
Reply-To: "Microsoft Account Security" <support@m365-security-update.top>
Return-Path: <bounce@m365-security-update.top>
To: "Employee" <staff@acme.com>
Subject: Action Required: Your Office 365 Password Expires in 24 Hours
Date: Mon, 31 Aug 2026 09:14:50 +0000
Message-ID: <00129384812@m365-security-update.top>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html>
<body>
<h2>Microsoft 365 Security Notice</h2>
<p>Your corporate Microsoft 365 access password will expire in 24 hours. To prevent account suspension and maintain uninterrupted email access, please verify your password immediately.</p>
<p><a href="http://194.26.29.112/auth/m365/login.php">https://login.microsoftonline.com/common/oauth2/authorize</a></p>
<p>If you do not verify your credentials within 24 hours, your mailbox will be locked by IT administration.</p>
<p>Microsoft Security Operations</p>
</body>
</html>`
  },

  malware_invoice_exe: {
    id: 'malware_invoice_exe',
    title: 'Ransomware Invoice (Double Extension PE)',
    tag: 'MALWARE / CRITICAL',
    description: 'Executable payload disguised with double extension (.pdf.exe) originating from Tor exit node.',
    rawMime: `Received: from mx.acme.com (10.0.1.1) by internal.acme.com id mal01; Mon, 31 Aug 2026 08:00:00 +0000
Received: from tor-relay.31173services.net (185.220.101.5) by mx.acme.com id mal02; Mon, 31 Aug 2026 07:59:50 +0000
From: "Billing Dept" <invoices@overdue-billing-notice.xyz>
To: "Accounting" <accounting@acme.com>
Subject: Overdue Invoice #88219 - Final Notice Before Legal Action
Date: Mon, 31 Aug 2026 07:59:40 +0000
Message-ID: <invoice-88219@overdue-billing-notice.xyz>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_MAL_99"

------=_Part_MAL_99
Content-Type: text/plain; charset=UTF-8

Attached is the final overdue invoice #88219. Please open the document and enable macros to calculate your total interest penalty.

------=_Part_MAL_99
Content-Type: application/pdf; name="Overdue_Invoice_8821.pdf.exe"
Content-Disposition: attachment; filename="Overdue_Invoice_8821.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
yAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0K
------=_Part_MAL_99--`
  },

  clean_newsletter: {
    id: 'clean_newsletter',
    title: 'Legitimate Enterprise Security Memo',
    tag: 'CLEAN / BENIGN',
    description: 'Legitimate technical digest passing SPF, DKIM, and ARC protocol validation.',
    rawMime: `Received: from mx.acme.com (10.0.1.1) by mailbox.acme.com id cln01; Mon, 31 Aug 2026 06:00:00 +0000
Received: from mail-sor-f41.google.com (209.85.220.41) by mx.acme.com with ESMTPS id cln02; Mon, 31 Aug 2026 05:59:58 +0000
Received: from newsletter-server.sendgrid.net (167.89.86.12) by mail-sor-f41.google.com id cln03; Mon, 31 Aug 2026 05:59:50 +0000
ARC-Seal: i=1; a=rsa-sha256; d=google.com; s=arc-20160816; cv=none; b=abc1234==
ARC-Authentication-Results: i=1; mx.google.com; dkim=pass header.i=@sendgrid.net header.s=s1 header.b=xyz; spf=pass (google.com: domain of bounces@sendgrid.net designates 167.89.86.12 as permitted sender)
From: "Tech Security Digest" <newsletter@cybersec-weekly.org>
Reply-To: <newsletter@cybersec-weekly.org>
Return-Path: <bounces@sendgrid.net>
To: "Subscriber" <subscriber@acme.com>
Subject: Cybersecurity Weekly Digest #412: Zero Trust Architecture Insights
Date: Mon, 31 Aug 2026 05:59:45 +0000
Message-ID: <digest-412@cybersec-weekly.org>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html>
<body>
<h1>Cybersecurity Weekly Digest</h1>
<p>Welcome to this week's issue covering protocol forensics, SMTP authentication, and zero trust architecture.</p>
<p><a href="https://cybersec-weekly.org/issues/412">Read the full issue online</a></p>
<p>To manage your preferences, <a href="https://cybersec-weekly.org/unsubscribe">unsubscribe here</a>.</p>
</body>
</html>`
  }
};
