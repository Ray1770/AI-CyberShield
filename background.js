function injectScanNotification(tabId) {
  chrome.scripting.executeScript({
    target: { tabId: tabId },
    func: () => {
      const existingNotification = document.getElementById("scanNotification");
      if (existingNotification) return;

      const scanNotification = document.createElement("div");
      scanNotification.id = "scanNotification";
      scanNotification.textContent = "Background Scan in Progress...";
      document.body.appendChild(scanNotification);

      setTimeout(() => {
        if (scanNotification) scanNotification.remove();
      }, 3000); // Notification disappears after 3 seconds
    },
  });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    injectScanNotification(tabId);
  }
});
