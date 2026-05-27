// Try local API gateway first, fall back to local analysis.
// To use HF Space instead: const PHISHGUARD_API = "https://huggingface.co/spaces/Sabersouihi/phishguard-ai";
// Note: HF Spaces don't expose a REST API, so the extension uses local analysis when offline.
const PHISHGUARD_API = "http://127.0.0.1:8080";

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

// ── Context menu: scan selected text ──────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "phishguard-scan-selection",
        title: "🔍 Scan with PhishGuard AI",
        contexts: ["selection"],
    });
    console.log("PhishGuard AI v3.0 installed. Right-click any text to scan.");
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === "phishguard-scan-selection" && info.selectionText) {
        const text = info.selectionText.substring(0, 5000);
        try {
            const resp = await fetch(`${PHISHGUARD_API}/api/v1/scan`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text }),
            });
            const result = await resp.json();
            const score = result.risk_score || 0;

            chrome.notifications.create({
                type: "basic",
                iconUrl: "icons/icon128.png",
                title: score >= 50 ? "⚠️ PhishGuard Alert" : "✅ PhishGuard Result",
                message: `Score: ${score}/100 | ${result.severity || "UNKNOWN"}${
                    result.total_keyword_hits
                        ? ` | ${result.total_keyword_hits} indicators`
                        : ""
                }`,
                priority: score >= 50 ? 2 : 0,
            });
        } catch (err) {
            // Fallback: local heuristic analysis
            const fallback = localAnalysis(text);
            chrome.notifications.create({
                type: "basic",
                iconUrl: "icons/icon128.png",
                title: "🛡️ PhishGuard (Offline Mode)",
                message: `Score: ${fallback.risk_score}/100 | ${fallback.severity}`,
                priority: fallback.risk_score >= 50 ? 2 : 0,
            });
        }
    }
});

// ── Passive page scan on untrusted sites ──────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== "complete" || !tab.url || !tab.url.startsWith("http")) return;
    if (isTrusted(tab.url)) return;

    chrome.scripting.executeScript({
        target: { tabId },
        func: () => document.body?.innerText?.substring(0, 5000) || "",
    }, (results) => {
        if (!results || !results[0] || !results[0].result) return;
        const text = results[0].result;
        const result = localAnalysis(text);

        if (result.risk_score >= 50 && result.total_keyword_hits >= 3) {
            chrome.notifications.create({
                type: "basic",
                iconUrl: "icons/icon128.png",
                title: "⚠️ PhishGuard Security Alert",
                message: `Potential phishing detected (Score: ${result.risk_score}/100).`,
                priority: 2,
            });
        }
    });
});

// ── Local heuristic analysis (offline fallback) ───────────────────────────
function localAnalysis(text) {
    const lower = text.toLowerCase();

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

    const urgencyHits = urgencyWords.filter(w => lower.includes(w));
    const threatHits = threatWords.filter(w => lower.includes(w));
    const requestHits = requestWords.filter(w => lower.includes(w));
    const brandHits = brands.filter(w => lower.includes(w));

    const urlPattern = /https?:\/\/[^\s]+/g;
    const urls = text.match(urlPattern) || [];
    const suspiciousUrls = urls.filter(u =>
        /bit\.ly|tinyurl|\.xyz|\.tk|\.ml|paypal\.[^c]|secure-|login-|verify-/i.test(u)
    );

    let score = 0;
    score += Math.min(urgencyHits.length * 8, 24);
    score += Math.min(threatHits.length * 8, 24);
    score += Math.min(requestHits.length * 8, 16);
    score += Math.min(brandHits.length * 5, 15);
    score += Math.min(suspiciousUrls.length * 15, 30);
    score = Math.min(score, 100);

    let severity;
    if (score >= 75) severity = "CRITICAL";
    else if (score >= 50) severity = "HIGH";
    else if (score >= 25) severity = "MEDIUM";
    else severity = "LOW";

    return {
        risk_score: score,
        severity: severity,
        total_keyword_hits: urgencyHits.length + threatHits.length + requestHits.length + brandHits.length,
        url_count: urls.length,
        suspicious_url_count: suspiciousUrls.length,
    };
}
