chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only scan when the page is fully loaded
    if (changeInfo.status === 'complete' && tab.url) {
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: () => {
                const text = document.body.innerText.substring(0, 5000);
                // Send directly to your Python Backend
                fetch('http://127.0.0.1:5000/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: text })
                })
                .then(res => res.json())
                .then(data => {
                    if (data.status.includes("Phishing")) {
                        alert("⚠️ PhishGuard AI: WARNING! Potential phishing threat detected on this page.");
                    }
                });
            }
        });
    }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith("http")) {
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: () => document.body.innerText.substring(0, 5000)
        }, (results) => {
            if (!results || !results[0]) return;
            const text = results[0].result;
            
            // Call your backend...
            fetch('http://127.0.0.1:5000/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: text })
            })
            .then(res => res.json())
            .then(data => {
                if (data.status.includes("Phishing")) {
                    // Trigger a professional system notification
                    chrome.notifications.create({
                        type: 'basic',
                        iconUrl: 'icon.png',
                        title: '⚠️ PhishGuard Security Alert',
                        message: 'Potential phishing attempt detected. Proceed with caution!',
                        priority: 2
                    });
                }
            });
        });
    }
});

const TRUSTED_DOMAINS = ['google.com', 'wikipedia.org']; // Add sites to ignore

if (TRUSTED_DOMAINS.some(domain => tab.url.includes(domain))) {
    return; // Skip scanning these
}