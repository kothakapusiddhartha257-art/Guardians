/**
 * Phishing Shield - Background Service Worker (Manifest V3)
 */

importScripts("detector.js");

// Setup context menu on installation
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scan-selection",
    title: "🛡️ Scan Selection for Phishing",
    contexts: ["selection"]
  });

  chrome.contextMenus.create({
    id: "scan-link",
    title: "🔍 Inspect Link with Phishing Shield",
    contexts: ["link"]
  });

  console.log("[Phishing Shield] Background service worker registered & context menus created.");
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scan-selection") {
    const text = info.selectionText || "";
    const analysis = PhishingDetector.scanEmail({ body: text });

    // Store the scan result so the popup can display it
    chrome.storage.local.set({
      lastScan: {
        type: "Selection Scan",
        text: text.slice(0, 200),
        result: analysis
      }
    });

    // Update extension badge
    updateBadge(analysis.score, tab.id);

  } else if (info.menuItemId === "scan-link") {
    const url = info.linkUrl || "";
    const analysis = PhishingDetector.analyzeUrl(url);

    chrome.storage.local.set({
      lastScan: {
        type: "Link Scan",
        text: url,
        result: {
          score: analysis.isSuspicious ? analysis.weight : 0,
          riskLevel: analysis.isSuspicious ? "CAUTION" : "SAFE",
          riskColor: analysis.isSuspicious ? "#f59e0b" : "#10b981",
          summaryText: analysis.isSuspicious ? "Suspicious link attributes detected." : "Link appears normal.",
          threats: analysis.findings.map(f => ({
            category: "Link",
            severity: f.severity,
            title: f.type,
            description: f.message
          })),
          urlCount: 1,
          maliciousUrlCount: analysis.isSuspicious ? 1 : 0,
          timestamp: new Date().toISOString()
        }
      }
    });

    updateBadge(analysis.isSuspicious ? 50 : 0, tab.id);
  }
});

// Helper to update action badge
function updateBadge(score, tabId) {
  if (score >= 60) {
    chrome.action.setBadgeText({ text: "!", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId });
  } else if (score >= 25) {
    chrome.action.setBadgeText({ text: "?", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#f59e0b", tabId });
  } else {
    chrome.action.setBadgeText({ text: "✓", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#10b981", tabId });
  }
}
