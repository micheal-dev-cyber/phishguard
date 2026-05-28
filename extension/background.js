// ═════════════════════════════════════════════════════════════════════════════
// PhishGuard AI — Chrome Extension Service Worker (Manifest V3)
//
// Architecture:
//   1. User browses to a page → content script extracts page text
//   2. Background fetches active tab URL → sends to PhishGuard API
//   3. API returns multi-layered verdict (phishing score, AI-text prob, AitM)
//   4. Extension shows alert badge + optional notification
//
// Two API modes:
//   - LOCAL:  http://127.0.0.1:8080  (python api_proxy.py)
//   - CLOUD:  https://sabersouihi-phishguard-ai.hf.space/api/v1/scan
//
// ═════════════════════════════════════════════════════════════════════════════

// ── Configuration ───────────────────────────────────────────────────────────
const CONFIG = {
  LOCAL_API: "http://127.0.0.1:8080",
  CLOUD_API: "https://sabersouihi-phishguard-ai.hf.space",
  STORAGE_KEY: "phishguard_config",
  SCAN_TIMEOUT_MS: 15000,
  COOLDOWN_MS: 30000,           // No re-scan same tab within 30 s
  BADGE_COLORS: {
    CRITICAL: "#ff0000",
    HIGH: "#ff8800",
    MEDIUM: "#ffaa00",
    LOW: "#44aa44",
  },
};

// ── State ───────────────────────────────────────────────────────────────────
let scanCooldown = {};          // tabId → timestamp

// ═════════════════════════════════════════════════════════════════════════════
// INITIALISATION
// ═════════════════════════════════════════════════════════════════════════════

chrome.runtime.onInstalled.addListener(async () => {
  await initStorage();
  createContextMenus();
  console.log("[PhishGuard] Extension v3.0.0 installed.");
});

async function initStorage() {
  const existing = await chrome.storage.local.get(CONFIG.STORAGE_KEY);
  if (!existing[CONFIG.STORAGE_KEY]) {
    await chrome.storage.local.set({
      [CONFIG.STORAGE_KEY]: {
        apiMode: "cloud",          // "local" | "cloud"
        autoScan: true,            // passive scan on page load
        scanThreshold: 50,         // minimum risk to trigger notification
        showBadge: true,
      },
    });
  }
}

function createContextMenus() {
  chrome.contextMenus.removeAll();
  chrome.contextMenus.create({
    id: "phishguard-scan-selection",
    title: "🔍 Scan with PhishGuard AI",
    contexts: ["selection"],
  });
  chrome.contextMenus.create({
    id: "phishguard-scan-page",
    title: "🛡 Scan this page",
    contexts: ["page"],
  });
}

// ═════════════════════════════════════════════════════════════════════════════
// COMM  BLUEPRINT — Fetch active tab URL → PhishGuard API → Show alert
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Core communication pattern:
 *
 *   activeTab        background.js              PhishGuard API
 *   ────────         ─────────────              ──────────────
 *   1. User opens page ──→ onUpdated fires
 *   2.                  ──→ getActiveUrl()
 *   3.                  ──→ buildPayload(url, pageText)
 *   4.                  ──→ POST /api/v1/scan ──→ handle_scan_request()
 *   5.                  ←── JSON verdict  ←──── { verdict, layers, reputation }
 *   6.                  ──→ updateBadge(verdict)
 *   7.                  ──→ if risk>=threshold → showNotification()
 *
 * For cloud mode, POST to HF Spaces:
 *   fetch(`${CLOUD_API}/api/v1/scan`, { method:"POST", body: JSON.stringify({text, urls}) })
 */

// ── Context menu handler ────────────────────────────────────────────────────
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "phishguard-scan-selection" && info.selectionText) {
    const config = await getConfig();
    const result = await scanText(info.selectionText, config.apiMode);
    if (result) {
      showResultNotification(result, "selection");
    }
  }
  if (info.menuItemId === "phishguard-scan-page" && tab?.url) {
    const config = await getConfig();
    const pageText = await extractPageText(tab.id);
    const result = await scanUrlAndText(tab.url, pageText, config.apiMode);
    if (result) {
      showResultNotification(result, "page");
    }
  }
});

// ── Passive page scan ───────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab?.url) return;
  if (!tab.url.startsWith("http")) return;
  if (isTrustedDomain(tab.url)) return;

  const config = await getConfig();
  if (!config.autoScan) return;

  // Cooldown check
  const now = Date.now();
  if (scanCooldown[tabId] && now - scanCooldown[tabId] < CONFIG.COOLDOWN_MS) {
    return;
  }
  scanCooldown[tabId] = now;

  const pageText = await extractPageText(tabId);
  const result = await scanUrlAndText(tab.url, pageText, config.apiMode);
  if (result && result.verdict) {
    const v = result.verdict;
    if (config.showBadge) {
      updateBadge(tabId, v);
    }
    if (v.risk_score >= config.scanThreshold) {
      showResultNotification(result, "passive");
    }
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// CORE API FUNCTIONS
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Scan arbitrary text (e.g. selected text or email body).
 * Uses the multi-layered /api/v1/scan endpoint.
 */
async function scanText(text, apiMode = "cloud") {
  const apiUrl = apiMode === "local" ? CONFIG.LOCAL_API : CONFIG.CLOUD_API;
  const payload = { text: text.substring(0, 10000) };

  try {
    const resp = await fetchWithTimeout(`${apiUrl}/api/v1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }, CONFIG.SCAN_TIMEOUT_MS);

    if (!resp.ok) {
      console.warn("[PhishGuard] API returned", resp.status);
      return null;
    }
    return await resp.json();
  } catch (err) {
    // Fallback: local heuristic analysis
    console.warn("[PhishGuard] API unreachable, using local fallback:", err.message);
    if (apiMode === "cloud") {
      // Try local as fallback
      return scanText(text, "local");
    }
    return { verdict: localAnalysis(text), _fallback: true };
  }
}

/**
 * Scan a URL + optional page text.
 * Sends both to the API for URL reputation + AitM detection.
 */
async function scanUrlAndText(url, pageText, apiMode = "cloud") {
  const apiUrl = apiMode === "local" ? CONFIG.LOCAL_API : CONFIG.CLOUD_API;
  const payload = {
    text: (pageText || "").substring(0, 10000),
    urls: [url],
  };

  try {
    const resp = await fetchWithTimeout(`${apiUrl}/api/v1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }, CONFIG.SCAN_TIMEOUT_MS);

    if (!resp.ok) return null;
    return await resp.json();
  } catch (err) {
    console.warn("[PhishGuard] API unreachable:", err.message);
    if (apiMode === "cloud") {
      return scanUrlAndText(url, pageText, "local");
    }
    return { verdict: localAnalysis(pageText || url), _fallback: true };
  }
}

/**
 * Generic fetch with AbortController timeout.
 */
async function fetchWithTimeout(url, options, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...options, signal: controller.signal });
    return resp;
  } finally {
    clearTimeout(timer);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// UI UPDATES
// ═════════════════════════════════════════════════════════════════════════════

function updateBadge(tabId, verdict) {
  const score = verdict.risk_score || 0;
  const sev = verdict.severity || "LOW";
  const text = score >= 50 ? `${score}` : "";
  const color = CONFIG.BADGE_COLORS[sev] || CONFIG.BADGE_COLORS.LOW;

  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function showResultNotification(result, source) {
  const v = result.verdict || result;
  const score = v.risk_score || 0;
  const sev = v.severity || "UNKNOWN";

  const lines = [
    `Score: ${score}/100 | ${sev}`,
  ];
  if (v.ai_written_probability !== undefined) {
    lines.push(`AI-written: ${v.ai_written_probability}%`);
  }
  if (v.aitm_confidence !== undefined && v.aitm_confidence >= 35) {
    lines.push(`AitM: ${v.aitm_confidence}/100`);
  }

  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: score >= 50 ? "⚠️ PhishGuard Alert" : "✅ PhishGuard Result",
    message: lines.join(" · "),
    priority: score >= 50 ? 2 : 0,
  });
}

// ═════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═════════════════════════════════════════════════════════════════════════════

async function getConfig() {
  const data = await chrome.storage.local.get(CONFIG.STORAGE_KEY);
  return data[CONFIG.STORAGE_KEY] || {};
}

async function extractPageText(tabId) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => document.body?.innerText?.substring(0, 8000) || "",
    });
    return results?.[0]?.result || "";
  } catch {
    return "";
  }
}

const TRUSTED_DOMAINS = [
  "google.com", "gmail.com", "youtube.com", "wikipedia.org",
  "github.com", "stackoverflow.com", "microsoft.com", "apple.com",
];

function isTrustedDomain(url) {
  try {
    const host = new URL(url).hostname;
    return TRUSTED_DOMAINS.some(d => host === d || host.endsWith("." + d));
  } catch {
    return false;
  }
}

// ── Offline fallback heuristic (mirrors Python src/enterprise_api logic) ────
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

  const urls = text.match(/https?:\/\/[^\s]+/g) || [];
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
    severity,
    is_threat: score >= 50,
    _fallback: true,
  };
}
