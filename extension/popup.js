document.getElementById('scanBtn').addEventListener('click', async () => {
    const status = document.getElementById('result');
    status.innerText = "Analyzing...";

    // 1. Get the current active tab
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // 2. Execute script to get text
    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => document.body.innerText.substring(0, 5000)
    }, async (results) => {
        // Handle errors or empty results
        if (!results || !results[0]) {
            status.innerText = "Error: Could not read page.";
            return;
        }

        const pageData = results[0].result;
        
        try {
    const response = await fetch('http://127.0.0.1:5000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: pageData })
    });
    
    const result = await response.json();
    
    // Update UI with status AND details
    status.innerHTML = `<strong>${result.status}</strong><br>${result.details || ''}`;
    status.style.color = result.status === "Safe" ? "#10b981" : "#ef4444";
    
} catch (error) {
    status.innerText = "Error: Server is offline.";
}
    });
});