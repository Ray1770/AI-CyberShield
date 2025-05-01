document.addEventListener("DOMContentLoaded", () => {
    const backgroundScanResult = document.getElementById("backgroundScanResult");
    const advancedScanButton = document.getElementById("advancedScanButton");
    const advancedResult = document.getElementById("advancedResult");
    const sslInfoDiv = document.getElementById("sslInfo");
    const loader = document.getElementById("loader");

    loader.innerHTML = `<div class="spinner"></div>`;

    function getCurrentTabUrl(callback) {
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            const url = tabs[0].url;
            callback(url);
        });
    }

    function basicScan(url) {
        fetch('http://127.0.0.1:5000/predict-basic', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                backgroundScanResult.textContent = "Error: " + data.error;
                backgroundScanResult.style.color = "black";
            } else {
                const isMalicious = data.result === "malicious";
                backgroundScanResult.textContent = `Fast Scan: ${data.result.toUpperCase()} (${Math.round(data.malicious_probability * 100)}% suspicious)`;
                backgroundScanResult.style.color = isMalicious ? "red" : "green";
            }
        })
        .catch(err => {
            backgroundScanResult.textContent = "Scan failed.";
            backgroundScanResult.style.color = "black";
            console.error(err);
        });
    }

    function advancedScan(url) {
        loader.classList.remove("hidden");
        advancedResult.textContent = "";
        sslInfoDiv.innerHTML = "";

        fetch('http://127.0.0.1:5000/predict-advanced', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        })
        .then(response => response.json())
        .then(data => {
            loader.classList.add("hidden");

            if (data.error) {
                advancedResult.textContent = "Error: " + data.error;
                advancedResult.style.color = "black";
                return;
            }

            const isMalicious = data.result === "malicious";

            if (data.google_blacklisted) {
                advancedResult.innerHTML = `<span style="color:red;">🔔 Malicious (Google Safe Browsing Blacklist)</span>`;
            } else {
                advancedResult.innerHTML = `<span style="color:${isMalicious ? 'red' : 'green'};">
                ✅ Advanced AI: ${data.result.toUpperCase()} (${Math.round(data.malicious_probability * 100)}% suspicious)
                </span>`;
            }

            // SSL Info
            if (data.ssl_info) {
                sslInfoDiv.innerHTML = `
                    <div style="margin-top:10px; font-size:13px;">
                        <b>🔒 SSL Certificate:</b><br>
                        🏢 Issuer: ${formatIssuer(data.ssl_info.issuer)}<br>
                        📅 Valid From: ${data.ssl_info.valid_from}<br>
                        📅 Valid To: ${data.ssl_info.valid_to}
                    </div>
                `;
            }

            // VirusTotal Results
            if (data.virustotal_result) {
                const vt = data.virustotal_result;
                const vtDiv = document.createElement('div');
                vtDiv.style.marginTop = "15px";
                vtDiv.style.fontSize = "13px";
                vtDiv.innerHTML = `
                    <b>🛡️ VirusTotal Result:</b><br>
                    Engines flagged: <b>${vt.malicious}</b> malicious<br>
                    Engines suspicious: <b>${vt.suspicious}</b><br>
                    Engines harmless: <b>${vt.harmless}</b>
                `;
                sslInfoDiv.appendChild(vtDiv);
            }

        })
        .catch(err => {
            loader.classList.add("hidden");
            advancedResult.textContent = "Advanced Scan failed.";
            advancedResult.style.color = "black";
            console.error(err);
        });
    }

    function formatIssuer(issuerArray) {
        try {
            return issuerArray.map(entry => entry[0][1]).join(', ');
        } catch {
            return "Unknown";
        }
    }

    // Load basic scan when page loads
    getCurrentTabUrl((url) => {
        basicScan(url);
    });

    // Deep scan on button click
    advancedScanButton.addEventListener("click", () => {
        getCurrentTabUrl((url) => {
            advancedScan(url);
        });
    });
});
