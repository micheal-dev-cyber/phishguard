// Popup script — check if we are on Gmail
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0]?.url || '';
    const status = document.querySelector('.status');

    if (url.includes('mail.google.com')) {
        status.innerHTML = `
            ✅ Gmail detected<br>
            <strong style="color:#60a5fa">Open an email and click Scan</strong>
        `;
    } else {
        status.innerHTML = `
            ⚠️ Go to Gmail first<br>
            <span style="color:#64748b">mail.google.com</span>
        `;
    }
});