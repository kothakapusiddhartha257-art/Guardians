// TRACEGUARD AI - Extension Service Worker (Manifest V3)

chrome.runtime.onInstalled.addListener(() => {
  console.log("[TRACEGUARD AI] Background service worker initialized.");
  
  // Set initial badge
  chrome.action.setBadgeText({ text: "!" });
  chrome.action.setBadgeBackgroundColor({ color: "#EF4444" });
});

// Periodic badge update or notification handler
chrome.runtime.onStartup.addListener(() => {
  chrome.action.setBadgeText({ text: "!" });
  chrome.action.setBadgeBackgroundColor({ color: "#EF4444" });
});
