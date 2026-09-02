/**
 * Phishing Shield - Client-Side Detection Engine
 * Analyzes sender, subject, body content, and links for phishing indicators.
 */

const PhishingDetector = {
  // Common URL shorteners used in phishing attacks
  urlShorteners: [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "v.gd"
  ],

  // Suspicious Top Level Domains commonly associated with disposable phishing campaigns
  suspiciousTLDs: [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work",
    ".click", ".loan", ".racing", ".fit", ".rest", ".country", ".support"
  ],

  // High-value brand names often impersonated in phishing
  impersonatedBrands: [
    "paypal", "netflix", "apple", "microsoft", "google", "amazon",
    "chase", "bank of america", "wellsfargo", "facebook", "meta",
    "instagram", "dhl", "fedex", "usps", "dropbox", "binance", "coinbase"
  ],

  // Urgency & Fear tactics keywords
  urgencyKeywords: [
    "urgent", "immediately", "immediate action", "account locked",
    "account suspended", "suspended", "action required", "within 24 hours",
    "within 12 hours", "unauthorized access", "security alert", "critical alert",
    "compromised", "verify your account", "confirm identity", "last warning",
    "deactivation", "terminate", "final notice"
  ],

  // Financial & Credential harvesting keywords
  financialKeywords: [
    "invoice", "wire transfer", "payment failed", "bank statement",
    "credit card", "billing update", "refund approved", "tax refund",
    "crypto", "bitcoin", "wallet", "payout", "claim reward", "won $",
    "gift card", "inheritance", "lottery"
  ],

  // Suspicious subject & promotional patterns
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

  /**
   * Validate standard email format and extract name and clean address
   */
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

  /**
   * Extract all URLs from plaintext or HTML
   */
  extractUrls(text) {
    if (!text) return [];
    const urlRegex = /https?:\/\/[^\s"'<>\)]+/gi;
    const matches = text.match(urlRegex) || [];
    return Array.from(new Set(matches));
  },

  /**
   * Check if a URL looks malicious or deceptive
   */
  analyzeUrl(url) {
    const findings = [];
    let isSuspicious = false;
    let weight = 0;

    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      const pathname = parsed.pathname.toLowerCase();

      // Check URL Shorteners
      if (this.urlShorteners.some(shortener => hostname.includes(shortener))) {
        findings.push({
          type: "SHORTENED_URL",
          severity: "HIGH",
          message: `Uses URL shortener (${hostname}) to hide destination.`
        });
        isSuspicious = true;
        weight += 30;
      }

      // Check IP address hostname (e.g. http://192.168.1.1/login)
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipPattern.test(hostname)) {
        findings.push({
          type: "IP_BASED_URL",
          severity: "HIGH",
          message: `Direct IP address used instead of a domain name: ${hostname}`
        });
        isSuspicious = true;
        weight += 35;
      }

      // Check Suspicious TLDs
      if (this.suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
        findings.push({
          type: "SUSPICIOUS_TLD",
          severity: "MEDIUM",
          message: `Uses a suspicious or disposable domain extension: ${hostname}`
        });
        isSuspicious = true;
        weight += 20;
      }

      // Check for credential phishing keywords in URL path
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

      // Check excessive subdomains (e.g., paypal.com.evil-site.com)
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
      // Invalid URL format
      findings.push({
        type: "MALFORMED_URL",
        severity: "LOW",
        message: `Malformed URL: ${url}`
      });
      weight += 10;
    }

    return { url, isSuspicious, findings, weight };
  },

  /**
   * Main scan function: analyzes email metadata, body, and links
   */
  scanEmail(emailData) {
    const { sender = "", subject = "", body = "", links = [] } = emailData;
    
    const threats = [];
    let score = 0; // 0 = Clean, 100 = Definitive Phishing

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
      
      // Check Brand Impersonation in Display Name vs Actual Domain
      const lowerDisplayName = parsedSender.displayName.toLowerCase();
      for (const brand of this.impersonatedBrands) {
        if (lowerDisplayName.includes(brand) && !senderDomain.includes(brand)) {
          threats.push({
            category: "Sender",
            severity: "CRITICAL",
            title: "Sender Display Name Spoofing",
            description: `The display name claims to be '${brand}', but the actual sender domain is '${senderDomain}'.`
          });
          score += 45;
          break;
        }
      }
    }

    // 2. SUBJECT LINE ANALYSIS
    const lowerSubject = subject.toLowerCase();
    
    // Check urgency in subject
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

    // Check financial keywords in subject
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

    // Check regex patterns in subject
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

    // 3. BODY CONTENT ANALYSIS
    const lowerBody = body.toLowerCase();

    // Check body urgency keywords
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

    // Check credential harvesting terms
    const credKeywords = ["enter your password", "reset password", "verify your login", "confirm your account", "update billing info", "ssn", "credit card number"];
    const credMatches = credKeywords.filter(k => lowerBody.includes(k));
    if (credMatches.length > 0) {
      threats.push({
        category: "Content",
        severity: "CRITICAL",
        title: "Credential / Information Harvesting Request",
        description: `Email asks user to supply sensitive credentials: "${credMatches.join(', ')}"`
      });
      score += 35;
    }

    // 4. URL & EMBEDDED LINK ANALYSIS
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
            title: `Suspicious Link Detected: ${url.length > 50 ? url.substring(0, 47) + '...' : url}`,
            description: f.message
          });
        });
      }
    }

    // Normalize final score between 0 and 100
    const finalScore = Math.min(100, Math.max(0, score));

    // Determine status level
    let riskLevel = "SAFE";
    let riskColor = "#10b981"; // Green
    let summaryText = "No significant phishing indicators found. This email appears legitimate.";

    if (finalScore >= 60) {
      riskLevel = "DANGER";
      riskColor = "#ef4444"; // Red
      summaryText = "High probability of phishing or scam! Do NOT click links or supply personal info.";
    } else if (finalScore >= 25) {
      riskLevel = "CAUTION";
      riskColor = "#f59e0b"; // Yellow / Orange
      summaryText = "Suspicious indicators detected. Exercise caution before opening links.";
    }

    return {
      score: finalScore,
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

// Export for extension and background scripts
if (typeof module !== "undefined" && module.exports) {
  module.exports = PhishingDetector;
}
