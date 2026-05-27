const TRUSTED_DOMAINS = [
    "google.com", "gmail.com", "youtube.com", "wikipedia.org",
    "github.com", "stackoverflow.com", "microsoft.com", "apple.com",
];

function isTrusted(url) {
    try {
        const host = new URL(url).hostname;
        return TRUSTED_DOMAINS.some(d => host === d || host.endsWith("." + d));
    } catch {
        return false;
    }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== "complete" || !tab.url || !tab.url.startsWith("http")) return;
    if (isTrusted(tab.url)) return;

    chrome.scripting.executeScript({
        target: { tabId },
        func: () => document.body?.innerText?.substring(0, 5000) || "",
    }, (results) => {
        if (!results || !results[0] || !results[0].result) return;
        const text = results[0].result;

        const urgencyWords = [
            "urgent", "immediately", "act now", "expires", "final notice",
            "last warning", "asap", "limited time", "respond now",
        ];
        const threatWords = [
            "suspended", "terminated", "legal action", "unauthorized",
            "compromised", "hacked", "penalty", "blocked", "locked",
            "security breach", "unusual activity",
        ];
        const requestWords = [
            "confirm your password", "verify your identity", "click here",
            "login to confirm", "enter your credentials", "update payment",
            "provide your", "validate your account",
        ];
        const brands = [
            "paypal", "amazon", "microsoft", "apple", "google",
            "netflix", "bank", "irs", "fedex", "dhl", "chase",
            "coinbase", "binance",
        ];

        const lower = text.toLowerCase();
        const hits = [
            ...urgencyWords.filter(w => lower.includes(w)),
            ...threatWords.filter(w => lower.includes(w)),
            ...requestWords.filter(w => lower.includes(w)),
            ...brands.filter(w => lower.includes(w)),
        ];

        const urlPattern = /https?:\/\/[^\s]+/g;
        const urls = text.match(urlPattern) || [];
        const suspiciousUrls = urls.filter(u =>
            /bit\.ly|tinyurl|\.xyz|\.tk|\.ml|paypal\.[^c]|secure-|login-|verify-/i.test(u)
        );

        let score = 0;
        score += Math.min(urgencyWords.filter(w => lower.includes(w)).length * 8, 24);
        score += Math.min(threatWords.filter(w => lower.includes(w)).length * 8, 24);
        score += Math.min(requestWords.filter(w => lower.includes(w)).length * 8, 16);
        score += Math.min(brands.filter(w => lower.includes(w)).length * 5, 15);
        score += Math.min(suspiciousUrls.length * 15, 30);
        score = Math.min(score, 100);

        if (score >= 50 && hits.length >= 3) {
            chrome.notifications.create({
                type: "basic",
                iconUrl: "icons/icon128.png",
                title: "⚠️ PhishGuard Security Alert",
                message: `Potential phishing detected (Score: ${score}/100). Suspicious indicators: ${hits.slice(0, 3).join(", ")}.`,
                priority: 2,
            });
        }
    });
});

chrome.runtime.onInstalled.addListener(() => {
    console.log("PhishGuard AI installed. Protecting your inbox.");
});
