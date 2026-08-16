const API_URL = "http://127.0.0.1:8000/api/v1/inspect";

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || details.url.startsWith("chrome://") || details.url.startsWith("about:")) {
    return;
  }

  fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: details.url })
  })
  .then(res => res.json())
  .then(data => {
    chrome.storage.local.set({ [details.tabId]: data });

    if (data.verdict === "BLOCKED") {
      chrome.action.setBadgeText({ tabId: details.tabId, text: "RISK" });
      chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: "#D32F2F" });
    } else {
      chrome.action.setBadgeText({ tabId: details.tabId, text: "SAFE" });
      chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: "#388E3C" });
    }
  })
  .catch(err => {
    chrome.action.setBadgeText({ tabId: details.tabId, text: "ERR" });
    chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: "#757575" });
  });
});