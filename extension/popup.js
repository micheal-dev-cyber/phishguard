const API_URL = "http://127.0.0.1:5000/analyze";

const urgencyWords = [
    "urgent", "immediately", "act now", "expires", "24 hours",
    "final notice", "last warning", "deadline", "right now",
    "asap", "limited time", "respond now",
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
    "wells fargo", "coinbase", "binance",
];

function localAnalysis(text) {
    const lower = text.toLowerCase();
    const urgencyHits = urgencyWords.filter(w => lower.includes(w));
    const threatHits = threatWords.filter(w => lower.includes(w));
    const requestHits = requestWords.filter(w => lower.includes(w));
    const brandHits = brands.filter(w => lower.includes(w));

    const urlPattern = /https?:\/\/[^\s]+/g;
    const urls = text.match(urlPattern) || [];
    const suspiciousUrls = urls.filter(u =>
        /bit\.ly|tinyurl|\.xyz|\.tk|\.ml|paypal\.[^c]|secure-|login-|verify-|update-/i.test(u)
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
        severity,
        total_keyword_hits: urgencyHits.length + threatHits.length + requestHits.length + brandHits.length,
        url_count: urls.length,
        suspicious_url_count: suspiciousUrls.length,
        urgency: urgencyHits,
        threats: threatHits,
        requests: requestHits,
        impersonation: brandHits,
        suspicious_urls: suspiciousUrls,
    };
}

function getStatusConfig(severity) {
    switch (severity) {
        case "CRITICAL":
            return { icon: "🔴", text: "CRITICAL THREAT", cls: "danger", detail: "Strong phishing indicators detected. Do not interact." };
        case "HIGH":
            return { icon: "🟠", text: "HIGH RISK", cls: "warning", detail: "Multiple suspicious indicators found. Exercise caution." };
        case "MEDIUM":
            return { icon: "🟡", text: "MEDIUM RISK", cls: "warning", detail: "Some suspicious elements detected. Verify before acting." };
        default:
            return { icon: "🟢", text: "LOW RISK", cls: "safe", detail: "No major threats detected. Stay vigilant." };
    }
}

function updateUI(results) {
    const cfg = getStatusConfig(results.severity);

    const card = document.getElementById("statusCard");
    card.className = "status-card " + cfg.cls;
    document.getElementById("statusIcon").textContent = cfg.icon;
    document.getElementById("statusText").textContent = cfg.text;
    document.getElementById("statusDetail").textContent = cfg.detail;

    const scoreEl = document.getElementById("metricScore");
    scoreEl.textContent = results.risk_score;
    scoreEl.className = "metric-value " + (results.risk_score >= 50 ? "danger" : results.risk_score >= 25 ? "warning" : "");

    document.getElementById("metricUrls").textContent = results.url_count;
    document.getElementById("metricKeywords").textContent = results.total_keyword_hits;
    document.getElementById("metricsContainer").style.display = "block";

    const details = document.getElementById("detailsContainer");
    details.innerHTML = "";

    const categories = [
        { label: "Urgency Tactics", items: results.urgency, color: "#ff8800" },
        { label: "Threat Language", items: results.threats, color: "#ff4444" },
        { label: "Suspicious Requests", items: results.requests, color: "#ffaa00" },
        { label: "Brand Impersonation", items: results.impersonation, color: "#60a5fa" },
    ];

    const activeCategories = categories.filter(c => c.items && c.items.length > 0);
    if (activeCategories.length > 0) {
        let html = '<div class="result-details">';
        for (const cat of activeCategories) {
            html += `<div class="detail-item"><strong style="color:${cat.color}">${cat.label}</strong>: `;
            html += cat.items.map(w => `<span class="tag">${w}</span>`).join(" ");
            html += "</div>";
        }
        if (results.suspicious_urls && results.suspicious_urls.length > 0) {
            html += `<div class="detail-item"><strong style="color:#ff4444">🚨 Suspicious URLs</strong>: `;
            html += results.suspicious_urls.slice(0, 3).map(u =>
                `<span class="tag" style="color:#ff8888;background:#2a0a0a;border-color:#ff444444">${u.length > 40 ? u.slice(0, 40) + "…" : u}</span>`
            ).join(" ");
            html += "</div>";
        }
        html += "</div>";
        details.innerHTML = html;
    }
}

function showError(msg) {
    document.getElementById("errorContainer").innerHTML =
        `<div class="error-box">⚠ ${msg}</div>`;
    document.getElementById("statusIcon").textContent = "⚠";
    document.getElementById("statusText").textContent = "Error";
    document.getElementById("statusDetail").textContent = msg;
    document.getElementById("statusCard").className = "status-card warning";
}

function setScanning(isScanning) {
    const btn = document.getElementById("scanBtn");
    btn.disabled = isScanning;
    btn.innerHTML = isScanning
        ? '<span class="spinner"></span> Scanning...'
        : "🔍 Scan This Page";
}

document.getElementById("scanBtn").addEventListener("click", async () => {
    setScanning(true);
    document.getElementById("metricsContainer").style.display = "none";
    document.getElementById("detailsContainer").innerHTML = "";
    document.getElementById("errorContainer").innerHTML = "";

    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => document.body?.innerText?.substring(0, 10000) || "",
        });

        if (!results || !results[0] || !results[0].result) {
            showError("Could not read page content. Try a different page.");
            setScanning(false);
            return;
        }

        const pageText = results[0].result;
        const analysis = localAnalysis(pageText);
        updateUI(analysis);

        try {
            const resp = await fetch(API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text: pageText }),
                signal: AbortSignal.timeout(5000),
            });
            if (resp.ok) {
                const serverResult = await resp.json();
                if (serverResult.risk_score !== undefined) {
                    updateUI(serverResult);
                }
            }
        } catch {
            // Server offline — local analysis already displayed
        }
    } catch (err) {
        showError("Scan failed: " + err.message);
    }

    setScanning(false);
});

document.addEventListener("DOMContentLoaded", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
        if (tab?.url?.startsWith("http")) {
            if (
                tab.url.includes("mail.google.com") ||
                (tab.title && tab.title.toLowerCase().includes("phishguard"))
            ) {
                document.getElementById("statusDetail").textContent =
                    "Gmail protection active. Scan button ready.";
            }
        }
    });
});
