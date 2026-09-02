/**
 * TRACEGUARD AI - Client-Side Detection Engine & Heuristics
 * Analyzes sender, subject, body content, and links for phishing & BEC indicators.
 */

const PhishingDetector = {
  urlShorteners: [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "v.gd"
  ],

  suspiciousTLDs: [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work",
    ".click", ".loan", ".racing", ".fit", ".rest", ".country", ".support"
  ],

  impersonatedBrands: [
    "paypal", "netflix", "apple", "microsoft", "office 365", "m365", "google", "amazon",
    "chase", "bank of america", "wellsfargo", "facebook", "meta",
    "instagram", "dhl", "fedex", "usps", "dropbox", "binance", "coinbase"
  ],

  urgencyKeywords: [
    "urgent", "immediately", "immediate action", "account locked",
    "account suspended", "suspended", "action required", "within 24 hours",
    "within 12 hours", "unauthorized access", "security alert", "critical alert",
    "compromised", "verify your account", "confirm identity", "last warning",
    "deactivation", "terminate", "final notice", "wire transfer immediately"
  ],

  financialKeywords: [
    "invoice", "wire transfer", "payment failed", "bank statement",
    "credit card", "billing update", "refund approved", "tax refund",
    "crypto", "bitcoin", "wallet", "payout", "claim reward", "won $",
    "gift card", "inheritance", "routing number"
  ],

  suspiciousPatterns: [
    /free\s+/i,
    /claim\s+your\s+/i,
    /congratulations\s+/i,
    /you\s+have\s+won/i,
    /exclusive\s+offer/i,
    /no\s*reply/i,
    /\d+%\s*off/i,
    /password\s+expires?/i,
    /unusual\s+login\s+activity/i
  ],

  parseEmail(rawSender) {
    if (!rawSender) return { isValid: false, address: "", displayName: "" };
    
    let displayName = "";
    let address = rawSender.trim();

    const nameMatch = rawSender.match(/^([^<]+)<([^>]+)>$/);
    if (nameMatch) {
      displayName = nameMatch[1].trim().replace(/^["']|["']$/g, '');
      address = nameMatch[2].trim();
    }

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    const isValid = emailRegex.test(address);

    return { isValid, address: address.toLowerCase(), displayName };
  },

  extractUrls(text) {
    if (!text) return [];
    const urlRegex = /https?:\/\/[^\s"'<>\)]+/gi;
    const matches = text.match(urlRegex) || [];
    return Array.from(new Set(matches));
  },

  analyzeUrl(url) {
    const findings = [];
    let isSuspicious = false;
    let weight = 0;

    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      const pathname = parsed.pathname.toLowerCase();

      if (this.urlShorteners.some(s => hostname.includes(s))) {
        findings.push({
          type: "SHORTENED_URL",
          severity: "HIGH",
          message: `Uses URL shortener (${hostname}) to hide destination.`
        });
        isSuspicious = true;
        weight += 30;
      }

      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipPattern.test(hostname)) {
        findings.push({
          type: "IP_BASED_URL",
          severity: "HIGH",
          message: `Direct IP address used instead of domain: ${hostname}`
        });
        isSuspicious = true;
        weight += 35;
      }

      if (this.suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
        findings.push({
          type: "SUSPICIOUS_TLD",
          severity: "MEDIUM",
          message: `Uses disposable/high-risk domain extension: ${hostname}`
        });
        isSuspicious = true;
        weight += 20;
      }

      const pathKeywords = ["login", "signin", "password", "verify", "update", "account", "security", "wallet", "banking"];
      for (const kw of pathKeywords) {
        if (pathname.includes(kw) || hostname.includes(kw)) {
          findings.push({
            type: "CREDENTIAL_URL",
            severity: "HIGH",
            message: `URL contains sensitive authentication keyword '${kw}'`
          });
          isSuspicious = true;
          weight += 25;
          break;
        }
      }

      const subdomains = hostname.split(".");
      if (subdomains.length > 4) {
        findings.push({
          type: "DECEPTIVE_SUBDOMAINS",
          severity: "HIGH",
          message: `Excessive subdomains detected (${hostname}), typical in domain spoofing.`
        });
        isSuspicious = true;
        weight += 25;
      }

    } catch (e) {
      findings.push({
        type: "MALFORMED_URL",
        severity: "LOW",
        message: `Malformed URL: ${url}`
      });
      weight += 10;
    }

    return { url, isSuspicious, findings, weight };
  },

  scanEmail(emailData) {
    const { sender = "", subject = "", body = "", links = [] } = emailData;
    const threats = [];
    let score = 0;

    // 1. SENDER VERIFICATION
    const parsedSender = this.parseEmail(sender);
    if (sender && !parsedSender.isValid) {
      threats.push({
        category: "Sender",
        severity: "HIGH",
        title: "Invalid Sender Email Address",
        description: `Sender address '${sender}' is malformed or invalid.`
      });
      score += 35;
    } else if (parsedSender.isValid) {
      const senderDomain = parsedSender.address.split("@")[1] || "";
      const lowerDisplayName = parsedSender.displayName.toLowerCase();
      for (const brand of this.impersonatedBrands) {
        if (lowerDisplayName.includes(brand) && !senderDomain.includes(brand)) {
          threats.push({
            category: "Sender",
            severity: "CRITICAL",
            title: "Sender Display Name Spoofing",
            description: `The display name claims to be '${brand}', but actual domain is '${senderDomain}'.`
          });
          score += 45;
          break;
        }
      }
    }

    // 2. SUBJECT ANALYSIS
    const lowerSubject = subject.toLowerCase();
    const subjectUrgencyMatches = this.urgencyKeywords.filter(k => lowerSubject.includes(k));
    if (subjectUrgencyMatches.length > 0) {
      threats.push({
        category: "Subject",
        severity: "HIGH",
        title: "Urgency / Pressure Keywords in Subject",
        description: `Subject contains urgency triggers: "${subjectUrgencyMatches.slice(0, 3).join(', ')}"`
      });
      score += 25;
    }

    const subjectFinMatches = this.financialKeywords.filter(k => lowerSubject.includes(k));
    if (subjectFinMatches.length > 0) {
      threats.push({
        category: "Subject",
        severity: "MEDIUM",
        title: "Financial or Billing Subject Line",
        description: `Subject references payment/financial terms: "${subjectFinMatches.slice(0, 3).join(', ')}"`
      });
      score += 20;
    }

    for (const pattern of this.suspiciousPatterns) {
      if (pattern.test(subject)) {
        threats.push({
          category: "Subject",
          severity: "MEDIUM",
          title: "Promotional or Bait Pattern",
          description: `Subject contains common phishing bait pattern: '${subject}'`
        });
        score += 20;
        break;
      }
    }

    // 3. BODY ANALYSIS
    const lowerBody = body.toLowerCase();
    const bodyUrgencyMatches = this.urgencyKeywords.filter(k => lowerBody.includes(k));
    if (bodyUrgencyMatches.length >= 2) {
      threats.push({
        category: "Content",
        severity: "HIGH",
        title: "Multiple Pressure / Panic Keywords in Body",
        description: `Email body pressures the reader with keywords: "${bodyUrgencyMatches.slice(0, 4).join(', ')}"`
      });
      score += 20;
    }

    const credKeywords = ["enter your password", "reset password", "verify your login", "confirm your account", "update billing info", "ssn", "credit card number", "bank account", "wire transfer"];
    const credMatches = credKeywords.filter(k => lowerBody.includes(k));
    if (credMatches.length > 0) {
      threats.push({
        category: "Content",
        severity: "CRITICAL",
        title: "Credential / Financial Directive Request",
        description: `Email asks user to supply sensitive credentials or execute financial transfers: "${credMatches.join(', ')}"`
      });
      score += 35;
    }

    // 4. URL ANALYSIS
    const allUrls = Array.from(new Set([...this.extractUrls(body), ...links]));
    let maliciousUrlCount = 0;

    for (const url of allUrls) {
      const urlAnalysis = this.analyzeUrl(url);
      if (urlAnalysis.isSuspicious) {
        maliciousUrlCount++;
        score += urlAnalysis.weight;
        urlAnalysis.findings.forEach(f => {
          threats.push({
            category: "Links",
            severity: f.severity,
            title: `Suspicious Link: ${url.length > 45 ? url.substring(0, 42) + '...' : url}`,
            description: f.message
          });
        });
      }
    }

    const finalScore = Math.min(100, Math.max(0, score));

    let riskLevel = "SAFE";
    let riskColor = "#10b981";
    let summaryText = "No significant phishing indicators found. This email appears legitimate.";

    if (finalScore >= 60) {
      riskLevel = "MALICIOUS";
      riskColor = "#ef4444";
      summaryText = "High probability of Phishing / BEC fraud! Do NOT click links or execute directives.";
    } else if (finalScore >= 25) {
      riskLevel = "SUSPICIOUS";
      riskColor = "#f59e0b";
      summaryText = "Suspicious indicators detected. Exercise caution before trusting sender.";
    }

    // Compute estimated 3-axis scores
    const threatScore = finalScore / 100.0;
    const infraConfidence = finalScore >= 50 ? 0.85 : 0.95;
    const attributionConfidence = finalScore >= 60 ? 0.55 : 0.90;

    return {
      score: finalScore,
      threatScore,
      infraConfidence,
      attributionConfidence,
      riskLevel,
      riskColor,
      summaryText,
      threats,
      urlCount: allUrls.length,
      maliciousUrlCount,
      timestamp: new Date().toISOString()
    };
  }
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = PhishingDetector;
}
