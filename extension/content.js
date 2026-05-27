// ── PhishGuard AI — Gmail Content Script ──────────────────────────────────────

const PHISHGUARD_API = "https://phishguard-okmkdupa4om23rq6e78bad.streamlit.app";
const PHISHGUARD_APP = "https://phishguard-okmkdupa4om23rq6e78bad.streamlit.app";

let scanButtonInjected = false;

// ── Main observer — watches for email to open ──────────────────────────────────
function startObserver() {
    const observer = new MutationObserver(() => {
        tryInjectButton();
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true,
    });

    // Also try immediately
    tryInjectButton();
}


function tryInjectButton() {
    // Gmail uses several possible selectors — try all of them
    const emailSelectors = [
        '.a3s.aiL',           // Standard email body
        '.ii.gt',             // Alternative
        '.Am.Al.editable',    // Compose/reply area
        '[data-message-id]',  // Message container
    ];

    const toolbarSelectors = [
        '.G-atb',             // Main toolbar
        '.iH',                // Email header area
        '.nH.hx',             // Another toolbar
        '.ade',               // Action bar
    ];

    let emailBody = null;
    let toolbar   = null;

    for (const sel of emailSelectors) {
        emailBody = document.querySelector(sel);
        if (emailBody) break;
    }

    if (!emailBody) return;

    // Remove old button if email changed
    const existingBtn = document.getElementById('phishguard-btn');
    if (existingBtn) {
        // Check if it's still relevant
        const panel = document.getElementById('phishguard-panel');
        return;
    }

    // Try to find toolbar, if not found inject button near email
    for (const sel of toolbarSelectors) {
        toolbar = document.querySelector(sel);
        if (toolbar) break;
    }

    injectButton(emailBody, toolbar);
}


function injectButton(emailBody, toolbar) {
    // Remove any existing button
    const old = document.getElementById('phishguard-btn');
    if (old) old.remove();

    const btn = document.createElement('div');
    btn.id = 'phishguard-btn';
    btn.innerHTML = '🛡️ Scan This Email';
    btn.style.cssText = `
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #1e3a5f;
        color: #60a5fa;
        border: 2px solid #2563eb;
        border-radius: 8px;
        padding: 8px 16px;
        font-size: 13px;
        font-weight: 700;
        cursor: pointer;
        margin: 10px 0;
        font-family: -apple-system, BlinkMacSystemFont, sans-serif;
        transition: all 0.2s;
        z-index: 99999;
        position: relative;
        box-shadow: 0 2px 12px #2563eb44;
    `;

    btn.onmouseenter = () => {
        btn.style.background = '#2563eb';
        btn.style.color = 'white';
    };
    btn.onmouseleave = () => {
        btn.style.background = '#1e3a5f';
        btn.style.color = '#60a5fa';
    };

    btn.onclick = () => scanEmail(btn);

    // Insert button ABOVE the email body — most reliable approach
    if (emailBody && emailBody.parentNode) {
        emailBody.parentNode.insertBefore(btn, emailBody);
    } else if (toolbar) {
        toolbar.prepend(btn);
    }
}


function extractEmailContent() {
    const subject    = document.querySelector('h2.hP')?.innerText ||
                       document.querySelector('[data-thread-perm-id]')?.innerText || '';
    const sender     = document.querySelector('.gD')?.getAttribute('email') ||
                       document.querySelector('.go')?.innerText || '';
    const senderName = document.querySelector('.go')?.innerText || '';

    const bodySelectors = ['.a3s.aiL', '.ii.gt div', '.Am.Al'];
    let body = '';
    for (const sel of bodySelectors) {
        const el = document.querySelector(sel);
        if (el) { body = el.innerText; break; }
    }

    const links = [...document.querySelectorAll('.a3s.aiL a, .ii.gt a')]
        .map(a => a.href)
        .filter(href => href && href.startsWith('http'));

    const fullText = `
From: ${senderName} <${sender}>
Subject: ${subject}

${body}

Links:
${links.join('\n')}
    `.trim();

    return { subject, sender, body, links, fullText };
}


async function scanEmail(btn) {
    btn.innerHTML = '⏳ Scanning...';
    btn.style.background = '#111827';
    btn.style.color = '#94a3b8';

    const emailData = extractEmailContent();

    // Remove old panel
    const oldPanel = document.getElementById('phishguard-panel');
    if (oldPanel) oldPanel.remove();

    // Run local analysis (always works, no API needed)
    const results = localAnalysis(emailData.fullText);
    showResults(results, emailData);

    btn.innerHTML = '🛡️ Scan This Email';
    btn.style.background = '#1e3a5f';
    btn.style.color = '#60a5fa';
}


function localAnalysis(text) {
    const textLower = text.toLowerCase();

    const urgencyWords = [
        'urgent', 'immediately', 'act now', 'expires', '24 hours',
        'final notice', 'last warning', 'deadline', 'right now',
        'asap', 'limited time', 'respond now'
    ];
    const threatWords = [
        'suspended', 'terminated', 'legal action', 'unauthorized',
        'compromised', 'hacked', 'penalty', 'blocked', 'locked',
        'security breach', 'unusual activity'
    ];
    const requestWords = [
        'confirm your password', 'verify your identity', 'click here',
        'login to confirm', 'enter your credentials', 'update payment',
        'provide your', 'validate your account'
    ];
    const brands = [
        'paypal', 'amazon', 'microsoft', 'apple', 'google',
        'netflix', 'bank', 'irs', 'fedex', 'dhl', 'chase',
        'wells fargo', 'coinbase', 'binance'
    ];

    const urgencyHits  = urgencyWords.filter(w => textLower.includes(w));
    const threatHits   = threatWords.filter(w => textLower.includes(w));
    const requestHits  = requestWords.filter(w => textLower.includes(w));
    const brandHits    = brands.filter(w => textLower.includes(w));

    const urlPattern     = /https?:\/\/[^\s]+/g;
    const urls           = text.match(urlPattern) || [];
    const suspiciousUrls = urls.filter(url =>
        /bit\.ly|tinyurl|\.xyz|\.tk|\.ml|paypal\.[^c]|secure-|login-|verify-|update-/i.test(url)
    );

    const totalHits = urgencyHits.length + threatHits.length +
                      requestHits.length + brandHits.length;

    let score = 0;
    score += Math.min(urgencyHits.length  * 8, 24);
    score += Math.min(threatHits.length   * 8, 24);
    score += Math.min(requestHits.length  * 8, 16);
    score += Math.min(brandHits.length    * 5, 15);
    score += Math.min(suspiciousUrls.length * 15, 30);
    score  = Math.min(score, 100);

    let severity;
    if      (score >= 75) severity = 'CRITICAL';
    else if (score >= 50) severity = 'HIGH';
    else if (score >= 25) severity = 'MEDIUM';
    else                  severity = 'LOW';

    return {
        risk_score:           score,
        severity:             severity,
        total_keyword_hits:   totalHits,
        url_count:            urls.length,
        suspicious_url_count: suspiciousUrls.length,
        suspicious_urls:      suspiciousUrls.map(url => ({ url })),
        keyword_matches: {
            ...(urgencyHits.length  ? { urgency:       urgencyHits  } : {}),
            ...(threatHits.length   ? { threats:       threatHits   } : {}),
            ...(requestHits.length  ? { requests:      requestHits  } : {}),
            ...(brandHits.length    ? { impersonation: brandHits    } : {}),
        },
    };
}


function showResults(results, emailData) {
    const score    = results.risk_score;
    const severity = results.severity;

    const colors = {
        CRITICAL: { bg: '#2a0a0a', border: '#ff4444', text: '#ff4444' },
        HIGH:     { bg: '#2a1a0a', border: '#ff8800', text: '#ff8800' },
        MEDIUM:   { bg: '#2a2a0a', border: '#ffaa00', text: '#ffaa00' },
        LOW:      { bg: '#0a2a0a', border: '#44aa44', text: '#44aa44' },
    };
    const c = colors[severity] || colors.LOW;

    let keywordHTML = '';
    if (results.keyword_matches) {
        for (const [cat, words] of Object.entries(results.keyword_matches)) {
            const tags = (Array.isArray(words) ? words : [])
                .map(w => `<span style="background:#1e3a5f;color:#60a5fa;
                    padding:2px 8px;border-radius:4px;font-size:11px;
                    margin:2px;display:inline-block">${w}</span>`)
                .join(' ');
            keywordHTML += `
                <div style="margin-bottom:8px">
                    <div style="color:#94a3b8;font-size:11px;
                        text-transform:uppercase;margin-bottom:4px">${cat}</div>
                    <div>${tags}</div>
                </div>`;
        }
    }

    let urlHTML = '';
    if (results.suspicious_urls && results.suspicious_urls.length > 0) {
        urlHTML = `
            <div style="margin-top:12px">
                <div style="color:#ff4444;font-size:12px;
                    font-weight:700;margin-bottom:6px">🚨 Suspicious URLs</div>
                ${results.suspicious_urls.map(u => `
                    <div style="background:#1a0a0a;border:1px solid #ff444444;
                        border-radius:6px;padding:6px 10px;font-family:monospace;
                        font-size:11px;color:#ff8888;margin:4px 0;
                        word-break:break-all">
                        ${typeof u === 'string' ? u : u.url}
                    </div>`).join('')}
            </div>`;
    }

    const verdicts = {
        CRITICAL: '🔴 Do NOT click any links. Report to IT immediately.',
        HIGH:     '🟠 Treat with extreme caution. Verify the sender.',
        MEDIUM:   '🟡 Some suspicious elements. Verify before acting.',
        LOW:      '🟢 No major threats detected. Stay vigilant.',
    };

    const panel = document.createElement('div');
    panel.id    = 'phishguard-panel';
    panel.style.cssText = `
        background: #0a0e1a;
        border: 2px solid ${c.border};
        border-radius: 12px;
        padding: 20px;
        margin: 12px 0 20px 0;
        font-family: -apple-system, BlinkMacSystemFont, sans-serif;
        color: #e2e8f0;
        box-shadow: 0 4px 24px ${c.border}33;
        z-index: 99999;
        position: relative;
    `;

    panel.innerHTML = `
        <div style="display:flex;justify-content:space-between;
            align-items:center;margin-bottom:16px">
            <div style="display:flex;align-items:center;gap:10px">
                <span style="font-size:1.1rem;font-weight:800;color:#60a5fa">
                    🛡️ PhishGuard AI
                </span>
                <span style="background:${c.border}22;color:${c.text};
                    border:1px solid ${c.border};border-radius:6px;
                    padding:2px 10px;font-size:12px;font-weight:700">
                    ${severity}
                </span>
            </div>
            <button onclick="document.getElementById('phishguard-panel').remove()"
                style="background:none;border:none;color:#64748b;
                    cursor:pointer;font-size:18px;line-height:1">✕</button>
        </div>

        <div style="display:flex;align-items:center;gap:16px;
            background:${c.bg};border-radius:10px;padding:14px;
            margin-bottom:16px;border:1px solid ${c.border}44">
            <div style="font-size:2.4rem;font-weight:900;color:${c.text};
                min-width:60px;text-align:center">${score}</div>
            <div>
                <div style="font-size:0.75rem;color:#64748b;
                    text-transform:uppercase;letter-spacing:1px">
                    Risk Score / 100
                </div>
                <div style="color:${c.text};font-weight:700;margin-top:2px">
                    ${verdicts[severity]}
                </div>
            </div>
        </div>

        <div style="display:grid;grid-template-columns:repeat(3,1fr);
            gap:8px;margin-bottom:16px">
            <div style="background:#111827;border-radius:8px;
                padding:10px;text-align:center">
                <div style="font-size:1.4rem;font-weight:800;
                    color:#60a5fa">${results.url_count || 0}</div>
                <div style="font-size:11px;color:#64748b">URLs Found</div>
            </div>
            <div style="background:#111827;border-radius:8px;
                padding:10px;text-align:center">
                <div style="font-size:1.4rem;font-weight:800;
                    color:#ff4444">${results.suspicious_url_count || 0}</div>
                <div style="font-size:11px;color:#64748b">Suspicious</div>
            </div>
            <div style="background:#111827;border-radius:8px;
                padding:10px;text-align:center">
                <div style="font-size:1.4rem;font-weight:800;
                    color:#ffaa00">${results.total_keyword_hits || 0}</div>
                <div style="font-size:11px;color:#64748b">Keywords</div>
            </div>
        </div>

        ${keywordHTML ? `
        <div style="margin-bottom:12px">
            <div style="color:#60a5fa;font-size:12px;font-weight:700;
                border-left:3px solid #60a5fa;padding-left:8px;
                margin-bottom:10px">🎯 Phishing Indicators</div>
            ${keywordHTML}
        </div>` : ''}

        ${urlHTML}

        <div style="margin-top:16px;padding-top:12px;
            border-top:1px solid #1e3a5f;
            display:flex;justify-content:space-between;align-items:center">
            <span style="font-size:11px;color:#475569">
                Powered by PhishGuard AI
            </span>
            <a href="${PHISHGUARD_APP}"
                target="_blank"
                style="font-size:11px;color:#60a5fa;text-decoration:none">
                Full Analysis →
            </a>
        </div>
    `;

    // Insert panel right after the scan button
    const scanBtn = document.getElementById('phishguard-btn');
    if (scanBtn && scanBtn.parentNode) {
        scanBtn.parentNode.insertBefore(panel, scanBtn.nextSibling);
    } else {
        const emailBody = document.querySelector('.a3s.aiL, .ii.gt');
        if (emailBody && emailBody.parentNode) {
            emailBody.parentNode.insertBefore(panel, emailBody);
        }
    }
}

// Start
startObserver();