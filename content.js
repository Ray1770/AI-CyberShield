// Function to inject a notification banner for background scanning
function showScanNotification() {
  const existingNotification = document.getElementById("scanNotification");
  if (existingNotification) return; // Prevent duplicate notifications

  // Create the notification element
  const scanNotification = document.createElement("div");
  scanNotification.id = "scanNotification";
  scanNotification.textContent = "Background Scan in Progress...";
  
  // Style the notification element
  scanNotification.style.position = "fixed";
  scanNotification.style.top = "20px";
  scanNotification.style.left = "50%";
  scanNotification.style.transform = "translateX(-50%)";
  scanNotification.style.backgroundColor = "#007BFF";
  scanNotification.style.color = "#FFFFFF";
  scanNotification.style.padding = "10px 20px";
  scanNotification.style.borderRadius = "5px";
  scanNotification.style.boxShadow = "0 4px 6px rgba(0, 0, 0, 0.1)";
  scanNotification.style.fontSize = "14px";
  scanNotification.style.zIndex = "9999";
  
  // Append to the body
  document.body.appendChild(scanNotification);

  // Remove the notification after 3 seconds
  setTimeout(() => {
    if (scanNotification) scanNotification.remove();
  }, 3000);
}

// Check if the content script is running on a valid webpage
if (window.location.protocol.startsWith("http")) {
  console.log("Running content script on webpage...");
  showScanNotification();
}
