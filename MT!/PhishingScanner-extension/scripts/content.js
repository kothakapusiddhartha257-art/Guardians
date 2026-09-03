/**
 * Phishing Shield - Content Script
 * Extracts email content from webmail providers (Gmail, Outlook, Yahoo) and communicates with the extension popup.
 */

(function () {
  console.log("[Phishing Shield] Content script initialized on:", window.location.hostname);

  // Helper to extract email data from Gmail
  function extractGmail() {
    let subject = "";
    let sender = "";
    let body = "";
    const links = [];

    // Subject
    const subjectEl = document.querySelector("h2.hP") || document.querySelector("div[role='main'] h2");
    if (subjectEl) subject = subjectEl.innerText.trim();

    // Sender
    const senderEl = document.querySelector("span.gD") || document.querySelector("span[email]");
    if (senderEl) {
      const emailAttr = senderEl.getAttribute("email");
      const name = senderEl.innerText || senderEl.getAttribute("name") || "";
      sender = emailAttr ? `${name} <${emailAttr}>` : name;
    }

    // Body
    const bodyEls = document.querySelectorAll("div.a3s.aiL");
    if (bodyEls.length > 0) {
      // Pick the most recent email body in the thread
      const lastBody = bodyEls[bodyEls.length - 1];
      body = lastBody.innerText.trim();

      // Links in body
      lastBody.querySelectorAll("a[href]").forEach(a => {
        const href = a.getAttribute("href");
        if (href && !href.startsWith("mailto:") && !href.startsWith("javascript:")) {
          links.push(href);
        }
      });
    }

    return { subject, sender, body, links, client: "Gmail" };
  }

  // Helper to extract email data from Outlook Web
  function extractOutlook() {
    let subject = "";
    let sender = "";
    let body = "";
    const links = [];

    // Subject
    const subjectEl = document.querySelector("div[role='heading'][aria-level='2']") || document.querySelector("div.rps_auto");
    if (subjectEl) subject = subjectEl.innerText.trim();

    // Sender
    const senderEl = document.querySelector("span[title*='@']") || document.querySelector("button[aria-haspopup='dialog'] span");
    if (senderEl) sender = senderEl.getAttribute("title") || senderEl.innerText.trim();

    // Body
    const bodyEl = document.querySelector("div[aria-label='Message body']") || document.querySelector("div.ItemPartView") || document.querySelector("div.rps_auto");
    if (bodyEl) {
      body = bodyEl.innerText.trim();
      bodyEl.querySelectorAll("a[href]").forEach(a => {
        const href = a.getAttribute("href");
        if (href && !href.startsWith("mailto:") && !href.startsWith("javascript:")) {
          links.push(href);
        }
      });
    }

    return { subject, sender, body, links, client: "Outlook" };
  }

  // Helper to extract generic page content
  function extractGeneric() {
    const subject = document.title || "";
    const sender = window.location.hostname;
    const body = (document.body ? document.body.innerText : "").slice(0, 5000);
    const links = [];
    document.querySelectorAll("a[href]").forEach(a => {
      const href = a.getAttribute("href");
      if (href && href.startsWith("http")) links.push(href);
    });

    return { subject, sender, body, links, client: "Webpage" };
  }

  // Unified extractor based on hostname
  function extractActiveEmail() {
    const host = window.location.hostname;
    if (host.includes("mail.google.com")) {
      return extractGmail();
    } else if (host.includes("outlook.live.com") || host.includes("outlook.office")) {
      return extractOutlook();
    } else {
      return extractGeneric();
    }
  }

  // Message listener for popup requests
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "EXTRACT_EMAIL_DATA") {
      try {
        const data = extractActiveEmail();
        sendResponse({ success: true, data });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    }
    return true; // Keep channel open for async response
  });
})();
