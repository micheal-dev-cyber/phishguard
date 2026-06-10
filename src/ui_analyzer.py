import json
import logging
import time as _tmod
from datetime import datetime

import plotly.graph_objects as go
import streamlit as st

from src.ai_analyzer import generate_ai_report
from src.aitm_detector import detect_aitm_harvester
from src.alerts import send_threat_alert
from src.attachment_scanner import scan_attachment
from src.audit_log import log_action
from src.auto_training import assign_training
from src.brand_impersonation import run_brand_impersonation_check as _run_brand_check
from src.database import consume_scan, record_valuation_metric, save_analysis
from src.database import get_spending_cap as _gsc
from src.database import record_scan as lb_record_scan
from src.detector import analyze_email
from src.email_parser import parse_email_file
from src.email_verify import is_email_verified
from src.header_auth import analyze_auth_headers
from src.honeypot_generator import generate_honeypot
from src.incident_response import IncidentResponder
from src.jury_engine import (
    compute_ensemble_score,
    evaluate_corporate_jury,
    evaluate_linguistic_jury,
)
from src.notification_channels import dispatch_to_channels
from src.notifications import push_notification
from src.osint import run_osint
from src.perplexity_analyzer import compute_perplexity_score
from src.phishing_dna import flagged_as_known_phishing
from src.ratelimit import check_rate_limit, get_rate_limit_remaining
from src.report_generator import generate_pdf_report
from src.siem_webhook import SIEMClient
from src.stix_exporter import build_enterprise_stix_bundle
from src.env import ENV
from src.tenants import PLANS, check_quota, log_usage
from src.threat_intel import check_multiple_urls, get_threat_summary
from src.threat_scorer import compute_combined_threat_score
from src.ui_design_system import section_title, stat_card, url_box
from src.webhook_gateway import send_alert
from src.xai_analyzer import analyze_psychological_triggers, format_xai_report

logger = logging.getLogger("ui-analyzer")


_EXAMPLE_EMAIL = """From: "Security Alert" <no-reply@secure-verify2738.xyz>
Subject: URGENT: Account Security Alert - Action Required

Dear Valued Customer,

We detected unusual activity on your account from an unrecognized device in Russia.

To prevent account suspension, please verify your identity immediately:

https://secure-verify2738.xyz/account/verify?token=29a8f1b3

Failure to verify within 24 hours will result in permanent account suspension.

This is an automated security message. Do not reply to this email."""


def render_analyzer_tab(username: str, plan: str):
    try:
        if not is_email_verified(username):
            from src.smtp_validation import smtp_configured
            if not smtp_configured():
                pass
            else:
                st.warning(
                    "📧 **Email not verified.** You must verify your email before scanning. "
                    "[Resend verification email](#) — check your inbox.",
                    icon="⚠️",
                )
                st.stop()
    except Exception as e:
        logger.error("Email verification check failed (proceeding without check): %s", e)

    q = check_quota(username, plan)
    if q["over_limit"] and plan != "enterprise":
        limit_val = q["limit"]
        st.error(
            f"🚫 Monthly limit reached ({limit_val} analyses). "
            "Upgrade your plan to continue."
        )
        st.stop()

    # Quick-start for first-time users
    if not st.session_state.get("checklist_first_scan", False):
        st.markdown(
            "<div style='background:linear-gradient(135deg,#0a1a2a,#0f1a2a);"
            "border:1px solid rgba(59,130,246,0.3);border-radius:14px;padding:20px 24px;margin-bottom:20px'>"
            "<div style='display:flex;align-items:center;gap:12px;flex-wrap:wrap'>"
            "<span style='font-size:2rem'>🚀</span>"
            "<div style='flex:1'>"
            "<div style='font-weight:700;color:#f0f6ff;font-size:1rem'>Quick Start — Scan your first email</div>"
            "<div style='color:#94a3b8;font-size:13px'>Not sure what to paste? Load an example phishing email to see what PhishGuard detects.</div>"
            "</div>"
            "<button onclick='document.querySelector(\"textarea\").value = `From: \"Security Alert\" <no-reply@secure-verify2738.xyz>\nSubject: URGENT: Account Security Alert\n\nDear Customer,\n\nWe detected unusual activity on your account.\nClick here to verify: https://secure-verify2738.xyz/verify`' "
            "style='background:#3b82f6;color:white;border:none;border-radius:8px;padding:8px 20px;font-weight:600;cursor:pointer'>📋 Load Example</button>"
            "</div></div>",
            unsafe_allow_html=True,
        )
        if st.button("📋 Load & Scan Example Email", use_container_width=True, type="primary", key="quickstart_load"):
            st.session_state["email_input"] = _EXAMPLE_EMAIL
            st.rerun()

    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.markdown("#### 📧 Paste Email Content")

        if "email_input" not in st.session_state:
            st.session_state["email_input"] = ""

        st.markdown("##### 📎 Or upload an email file")
        uploaded_file = st.file_uploader(
            "Upload .eml or .msg",
            type=["eml", "msg"],
            label_visibility="collapsed",
            key="email_uploader",
        )
        if uploaded_file:
            with st.spinner("Parsing email file..."):
                parsed = parse_email_file(uploaded_file.getvalue(), uploaded_file.name)
            if parsed.get("error"):
                st.error(f"Parse error: {parsed['error']}")
            else:
                combined = (
                    f"From: {parsed.get('from', '')}\n"
                    f"Subject: {parsed.get('subject', '')}\n"
                    f"To: {parsed.get('to', '')}\n\n"
                    f"{parsed.get('body', '')}"
                )
                if combined.strip() != st.session_state["email_input"].strip():
                    st.session_state["email_input"] = combined
                    st.rerun()

        batch_file = st.file_uploader(
            "📦 Batch upload CSV/JSON (one email per row/object)",
            type=["csv", "json"],
            key="batch_uploader",
        )
        if batch_file:
            try:
                import pandas as pd
                if batch_file.name.endswith(".json"):
                    batch_data = json.load(batch_file)
                else:
                    batch_data = pd.read_csv(batch_file).to_dict("records")
                if not batch_data:
                    st.warning("Batch file is empty.")
                else:
                    st.session_state["batch_inputs"] = batch_data
                    st.success(f"Loaded {len(batch_data)} emails for batch analysis.")
            except Exception as exc:
                st.error(f"Batch file error: {exc}")

        st.markdown("##### 🔒 Scan Attachment")
        att_file = st.file_uploader(
            "Upload an attachment to scan (PDF, DOCX, XLSX, ZIP, etc.)",
            type=["pdf", "docx", "xlsx", "pptx", "zip", "rar", "7z",
                  "exe", "dll", "ps1", "vbs", "js", "py", "scr", "bat",
                  "doc", "xls"],
            key="attachment_scanner",
            label_visibility="collapsed",
        )
        if att_file and "att_scan_result" not in st.session_state:
            with st.spinner(f"Hashing {att_file.name}..."):
                att_result = scan_attachment(att_file.getvalue(), att_file.name)
            st.session_state["att_scan_result"] = att_result
            st.rerun()
        if st.session_state.get("att_scan_result"):
            _att = st.session_state["att_scan_result"]
            if _att.get("error"):
                st.error(f"Scan error: {_att['error']}")
            else:
                _vt = _att.get("vt_reputation", {})
                _v = _vt.get("verdict", "unknown") if isinstance(_vt, dict) else "unknown"
                _c = {"clean": "#44aa44", "malicious": "#ff4444", "suspicious": "#ff8800", "unknown": "#94a3b8"}.get(_v, "#94a3b8")
                st.markdown(
                    f"<div style='background:#111827;border:1px solid #1e3a5f;border-radius:10px;padding:8px 14px;font-size:13px'>"
                    f"<b>📎 {_att['filename']}</b> ({_att['size']:,} bytes)<br>"
                    f"MD5: <code style='color:#60a5fa'>{_att.get('md5','')[:16]}…</code><br>"
                    f"SHA256: <code style='color:#60a5fa'>{_att.get('sha256','')[:20]}…</code><br>"
                    f"VT Verdict: <span style='color:{_c};font-weight:700'>{_v.upper()}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
            if st.button("✕ Clear Attachment", key="clear_att"):
                st.session_state.pop("att_scan_result", None)
                st.rerun()

        email_text = st.text_area(
            label="email", label_visibility="collapsed",
            placeholder="Paste the full email here — subject, headers, body, links...",
            height=260,
            key="email_input",
        )

    with col_right:
        st.markdown("#### ⚙ Options")
        st.checkbox("Analyze URLs", value=True)
        st.checkbox("Keyword Detection", value=True)
        st.checkbox("Social Engineering", value=True)
        enable_vt = st.checkbox("Threat Intelligence + OSINT", value=True)
        st.markdown("")
        enable_jury = st.checkbox("🧠 Multi-LLM Jury (ensemble scoring)", value=False,
                                   help="Routes text through linguistic and corporate context juries for weighted ensemble scoring")
        st.markdown("")
        analyze_btn = st.button("🔍 Analyze Email", use_container_width=True, type="primary")
        st.markdown("")
        batch_btn = st.button("📦 Batch Analyze", use_container_width=True,
                               help="Analyze all emails from CSV/JSON upload")

        st.markdown("")
        st.info("💡 Paste any suspicious email and click Analyze.")

    if batch_btn:
        batch_inputs = st.session_state.get("batch_inputs", [])
        if not batch_inputs:
            st.warning("Upload a CSV/JSON file with email data first.")
        else:
            rl_key = f"batch_{username}"
            if not check_rate_limit(rl_key, max_requests=3, window=60):
                st.error("⏳ Rate limit reached for batch (3/min).")
                st.stop()
            batch_results = []
            text_col = "text" if batch_inputs[0].get("text") else "email" if batch_inputs[0].get("email") else next(iter(batch_inputs[0].keys()), "text")
            progress = st.progress(0, text="Batch analysis in progress...")
            for i, row in enumerate(batch_inputs):
                t = (row.get(text_col) or "").strip()
                if t:
                    r = analyze_email(t)
                    save_analysis(r, t)
                    batch_results.append({"input": t[:80], "score": r["risk_score"], "severity": r["severity"]})
                progress.progress((i + 1) / len(batch_inputs), text=f"Analyzed {i + 1}/{len(batch_inputs)}")
            st.session_state["batch_results"] = batch_results
            st.success(f"✅ Batch complete — {len(batch_results)} emails analyzed.")
            st.rerun()

    if "batch_results" in st.session_state:
        with st.expander(f"📦 Batch Results ({len(st.session_state['batch_results'])} emails)", expanded=True):
            for br in st.session_state["batch_results"][-50:]:
                c = "#ff4444" if br["severity"] in ("CRITICAL","HIGH") else "#88cc88"
                st.markdown(f"<div style='font-size:12px;padding:4px 0'><span style='color:{c}'>{br['severity']:8}</span> {br['score']:3}/100 · {br['input']}</div>", unsafe_allow_html=True)
            if st.button("Clear Batch Results", key="clear_batch"):
                st.session_state.pop("batch_results", None)
                st.rerun()

    if analyze_btn:
        if not email_text.strip():
            st.warning("⚠ Please paste an email first.")
        else:
            rl_key = f"analyze_{username}"
            if not check_rate_limit(rl_key, max_requests=15, window=60):
                remaining = get_rate_limit_remaining(rl_key, max_requests=15, window=60)
                st.error(f"⏳ Rate limit reached. Please wait before submitting another analysis. ({remaining} remaining)")
                st.stop()
            with st.spinner("Scanning for threats..."):
                _scan_ok = consume_scan(username)
                _cap = _gsc(username)
                if not _scan_ok["allowed"]:
                    st.error(
                        "⛔ **Monthly scan limit reached.** "
                        f"({_scan_ok['used']}/{_scan_ok['limit']} used). "
                        "Purchase additional credits or upgrade your plan to continue."
                    )
                    st.stop()
                if _cap["paused"]:
                    st.error("⛔ **Hard spending cap reached.** Increase your cap in settings to continue.")
                    st.stop()
                _start_time = _tmod.time()
                results = analyze_email(email_text)
                save_analysis(results, email_text)
                st.session_state["checklist_first_scan"] = True
                try:
                    from src.analytics import track_scan, track_first_scan
                    track_scan(username, risk_score=results["risk_score"], severity=results["severity"])
                    if not st.session_state.get("_tracked_first_scan", False):
                        track_first_scan(username)
                        st.session_state["_tracked_first_scan"] = True
                except Exception:
                    pass
                log_usage(username, "analysis", results["risk_score"])
                lb_record_scan(
                    username,
                    severity=results["severity"],
                    score=results["risk_score"],
                )
                record_valuation_metric(
                    scan_latency_ms=int((_tmod.time() - _start_time) * 1000),
                    risk_score=results["risk_score"],
                    severity=results["severity"],
                    threat_category=",".join(results.get("keyword_matches", {}).keys()) or "none",
                    username=username,
                    user_tier=plan,
                    source="web",
                )
                user_email = st.session_state.get("email", "")
                if user_email and results["severity"] in ("CRITICAL", "HIGH"):
                    send_threat_alert(username, user_email, results)

                try:
                    ir = IncidentResponder()
                    ir_result = ir.respond(
                        verdict=results,
                        mailbox=user_email,
                        sender_email=results.get("headers", {}).get("From", ""),
                    )
                    if ir_result["actions"]:
                        st.toast(f"🛡 IR: {' → '.join(ir_result['actions'])}", icon="🛡")
                except Exception:
                    pass

                try:
                    siem = SIEMClient()
                    if siem.any_enabled:
                        siem.dispatch({
                            "timestamp": datetime.now().isoformat(),
                            "username": username,
                            "risk_score": results["risk_score"],
                            "severity": results["severity"],
                            "urls_found": results.get("urls_found", []),
                            "sender": results.get("headers", {}).get("From", ""),
                        })
                except Exception:
                    pass

                try:
                    if results["risk_score"] >= 40:
                        assign_training(username, results["risk_score"], results["severity"])
                except Exception:
                    pass

            vt_results = []
            vt_summary = {}
            osint_data = {}

            if enable_vt and results["urls_found"]:
                with st.spinner("Checking URLs against VirusTotal..."):
                    vt_results = check_multiple_urls(results["urls_found"])
                    vt_summary = get_threat_summary(vt_results)

            if enable_vt:
                with st.spinner("Running OSINT investigation..."):
                    osint_data = run_osint(email_text)

            jury_result = {}
            if enable_jury:
                with st.spinner("🧠 Multi-LLM Jury evaluating linguistic anomalies..."):
                    linguistic = evaluate_linguistic_jury(email_text)
                with st.spinner("🧠 Multi-LLM Jury evaluating corporate context..."):
                    corporate = evaluate_corporate_jury(email_text)
                jury_result = compute_ensemble_score(
                    linguistic, corporate,
                    heuristic_score=results.get("risk_score", 0),
                )

            header_auth = analyze_auth_headers(email_text)
            xai_result = analyze_psychological_triggers(email_text)
            dna_known, dna_match = flagged_as_known_phishing(email_text, st.session_state)
            perplexity_result = compute_perplexity_score(email_text)
            aitm_result = detect_aitm_harvester(
                email_text=email_text,
                urls=results.get("urls_found", []),
                osint_data=osint_data,
            )
            combined_score = compute_combined_threat_score(
                results.get("risk_score", 0),
                vt_results=vt_results,
            )

            wh_key = f"webhook_url_{username}"
            webhook_url = st.session_state.get(wh_key, "")
            webhook_result = None
            if webhook_url and (results.get("risk_score", 0) >= 75 or
                                combined_score.get("composite_score", 0) >= 75):
                triggers = []
                if xai_result.get("triggers"):
                    triggers = [t["label"] for t in xai_result["triggers"]]
                webhook_result = send_alert(
                    webhook_url,
                    score=results.get("risk_score", 0),
                    severity=results.get("severity", "HIGH"),
                    triggers=triggers,
                    snippet=email_text[:300],
                    action="Investigate and quarantine this email immediately.",
                    dashboard_url=ENV.APP_URL or "http://localhost:8501",
                )

            q_key = f"quarantine_threshold_{username}"
            q_thresh = st.session_state.get(q_key, 70)
            severity = results["severity"]
            if results["risk_score"] >= q_thresh and severity in ("HIGH", "CRITICAL"):
                q_list_key = f"quarantined_{username}"
                if q_list_key not in st.session_state:
                    st.session_state[q_list_key] = []
                st.session_state[q_list_key].append({
                    "score": results["risk_score"],
                    "severity": severity,
                    "preview": email_text[:60],
                    "time": datetime.now().strftime("%H:%M"),
                })

            if severity in ("HIGH", "CRITICAL") and results["risk_score"] >= 50:
                st.session_state.setdefault("notifications", []).append({
                    "severity": severity,
                    "message": f"Threat detected — Score {results['risk_score']}/100",
                    "time": datetime.now().strftime("%H:%M"),
                })
                try:
                    push_notification(
                        username,
                        f"🚨 {severity} Threat Detected",
                        f"Score {results['risk_score']}/100 — {email_text[:60]}...",
                        severity.lower(),
                    )
                except Exception:
                    pass

            _sender = results.get("headers", {}).get("From", "")
            _brand_result = _run_brand_check(email_text, sender=_sender)
            if _brand_result.get("impersonation_detected"):
                st.toast(f"🏷 Brand impersonation detected — risk {_brand_result['total_risk']}/100", icon="🏷")
                try:
                    dispatch_to_channels(username, f"🏷 Brand impersonation detected: {_brand_result}", severity="high")
                except Exception:
                    pass

            st.session_state["results"]         = results
            st.session_state["email_text"]       = email_text
            st.session_state["vt_results"]       = vt_results
            st.session_state["vt_summary"]       = vt_summary
            st.session_state["osint_data"]       = osint_data
            st.session_state["jury_result"]      = jury_result
            st.session_state["xai_result"]       = xai_result
            st.session_state["combined_score"]   = combined_score
            st.session_state["webhook_result"]   = webhook_result
            st.session_state["header_auth"]      = header_auth
            st.session_state["dna_match"]        = dna_match
            st.session_state["dna_known"]        = dna_known
            st.session_state["perplexity_result"] = perplexity_result
            st.session_state["aitm_result"]      = aitm_result
            st.session_state["brand_check"]      = _brand_result
            st.session_state.pop("ai_report", None)

    if "results" in st.session_state:
        results          = st.session_state["results"]
        email_text_saved = st.session_state["email_text"]
        vt_results       = st.session_state.get("vt_results", [])
        osint_data       = st.session_state.get("osint_data", {})
        header_auth      = st.session_state.get("header_auth", {})
        aitm_result      = st.session_state.get("aitm_result", {})

        user_tier = st.session_state.get("plan", "trial")
        is_restricted = user_tier in ("free", "trial", "starter") and results.get("risk_score", 0) >= 75
        _restricted_blur = is_restricted

        st.divider()

        score    = results["risk_score"]
        severity = results["severity"]
        color    = results["severity_color"]

        show_technical = st.checkbox("🔬 Show technical details", value=False, key="show_technical",
                                     help="Expand to see full analysis: email auth, OSINT, XAI, VT, etc.")

        q_key = f"quarantine_threshold_{username}"
        q_thresh = st.session_state.get(q_key, 70)
        is_quarantined = results["risk_score"] >= q_thresh and results.get("severity") in ("HIGH", "CRITICAL")
        sev_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","SAFE":"🟢"}.get(severity, "⚪")
        sev_label = {"CRITICAL":"Critical Threat","HIGH":"High Risk","MEDIUM":"Suspicious","LOW":"Low Risk","SAFE":"Safe"}.get(severity, severity)

        st.markdown(
            f"<div style='display:flex;align-items:center;justify-content:space-between;"
            f"background:#111827;border:1px solid #1e293b;border-radius:16px;padding:20px 24px;margin-bottom:16px'>"
            f"<div style='display:flex;align-items:center;gap:16px'>"
            f"<span style='font-size:2.5rem'>{sev_icon}</span>"
            f"<div><div style='font-size:1.2rem;font-weight:700;color:{color}'>{sev_label}</div>"
            f"<div style='font-size:0.8rem;color:#64748b;margin-top:2px'>Risk Score</div></div></div>"
            f"<div style='text-align:right'>"
            f"<div style='font-size:2.5rem;font-weight:800;color:{color};letter-spacing:-0.03em'>{score}<span style='font-size:1rem;color:#64748b'>/100</span></div>"
            + ("<span class='pg-badge pg-badge-critical' style='margin-top:4px'>🛡 Quarantined</span>" if is_quarantined else "") +
            "</div></div>",
            unsafe_allow_html=True
        )

        if not show_technical:
            st.markdown(section_title("Quick Assessment"), unsafe_allow_html=True)
            if score >= 75:
                st.error("🔴 **Critical Threat** — This email shows strong phishing indicators. Do not click any links, reply, or download attachments. We recommend quarantining it immediately.")
            elif score >= 50:
                st.error("🟠 **High Risk** — Multiple phishing indicators detected. Treat this email with caution. Verify the sender through a separate channel before taking any action.")
            elif score >= 25:
                st.warning("🟡 **Medium Risk** — Some suspicious elements found. Review carefully before responding or clicking links.")
            else:
                st.success("🟢 **Low Risk** — No significant phishing indicators detected. Always stay vigilant with unexpected emails.")

            st.markdown(section_title("Threat Overview"), unsafe_allow_html=True)
            col_m1, col_m2, col_m3, col_m4 = st.columns(4)
            with col_m1:
                st.markdown(stat_card(str(results["url_count"]), "URLs Found"), unsafe_allow_html=True)
            with col_m2:
                sc = results["suspicious_url_count"]
                sc_color = "#ef4444" if sc > 0 else "#22c55e"
                st.markdown(stat_card(str(sc), "Suspicious URLs", sc_color), unsafe_allow_html=True)
            with col_m3:
                st.markdown(stat_card(str(results["total_keyword_hits"]), "Keyword Hits"), unsafe_allow_html=True)
            with col_m4:
                _perplex = st.session_state.get("perplexity_result", {})
                _ai_prob = _perplex.get("ai_probability", 0)
                _pcolor = "#ef4444" if _ai_prob >= 70 else "#f59e0b" if _ai_prob >= 40 else "#22c55e"
                st.markdown(stat_card(f"{_ai_prob}%", "AI-Author Prob.", _pcolor), unsafe_allow_html=True)

            st.info("💡 Toggle **\"Show technical details\"** above for the full analysis including email authentication, OSINT, VirusTotal, psychological manipulation analysis, and more.")
            st.divider()

            col_ai, col_pdf, col_stix = st.columns(3)
            with col_ai:
                if st.button("🤖 AI Security Report", use_container_width=True, type="secondary", key="ai_simple"):
                    try:
                        with st.spinner("Writing security report..."):
                            ai_report = generate_ai_report(email_text_saved, results)
                        st.session_state["ai_report"] = ai_report
                        save_analysis(results, email_text_saved, ai_report)
                    except Exception as e:
                        st.error(f"AI analysis failed: {e}")
            with col_pdf:
                ai_report_text = st.session_state.get("ai_report", "")
                _has_wl = "white_label" in PLANS.get(user_tier, {}).get("features", [])
                wl_flag = st.session_state.get("whitelabel_pdf", False) and _has_wl
                wl_logo = st.session_state.get("consultant_logo_path") if _has_wl else None
                pdf_bytes = generate_pdf_report(results, email_text_saved, ai_report_text, white_label=wl_flag, custom_logo_path=wl_logo)
                sev_lower = results["severity"].lower()
                st.download_button(label="📥 Download PDF Report", data=pdf_bytes, file_name=f"phishguard_report_{sev_lower}.pdf", mime="application/pdf", use_container_width=True, type="primary", key="pdf_simple")
            with col_stix:
                _att_result = st.session_state.get("att_scan_result")
                _sender_anom = st.session_state.get("sender_anomaly")
                _perplex_s = st.session_state.get("perplexity_result")
                stix_bundle = build_enterprise_stix_bundle(email_text=email_text_saved, results=results, osint_data=osint_data, vt_results=vt_results, attachment_result=_att_result, sender_anomaly=_sender_anom, perplexity_result=_perplex_s)
                stix_json = json.dumps(stix_bundle, indent=2)
                st.download_button(label="📤 STIX 2.1 Export", data=stix_json, file_name=f"phishguard_stix_{sev_lower}.json", mime="application/json", use_container_width=True, type="secondary", key="stix_simple")
            if "ai_report" in st.session_state:
                st.divider()
                st.markdown(section_title("AI Security Analysis"), unsafe_allow_html=True)

        if show_technical:
            _restricted_blur = is_restricted
            st.markdown(section_title("Threat Overview"), unsafe_allow_html=True)
            col_m1, col_m2, col_m3, col_m4 = st.columns(4)
            with col_m1:
                st.markdown(stat_card(str(results["url_count"]), "URLs Found"), unsafe_allow_html=True)
            with col_m2:
                sc = results["suspicious_url_count"]
                sc_color = "#ef4444" if sc > 0 else "#22c55e"
                st.markdown(stat_card(str(sc), "Suspicious URLs", sc_color), unsafe_allow_html=True)
            with col_m3:
                st.markdown(stat_card(str(results["total_keyword_hits"]), "Keyword Hits"), unsafe_allow_html=True)
            with col_m4:
                _perplex = st.session_state.get("perplexity_result", {})
                _ai_prob = _perplex.get("ai_probability", 0)
                _pcolor = "#ef4444" if _ai_prob >= 70 else "#f59e0b" if _ai_prob >= 40 else "#22c55e"
                st.markdown(stat_card(f"{_ai_prob}%", "AI-Author Prob.", _pcolor), unsafe_allow_html=True)

            if _restricted_blur:
                st.markdown(
                    "<div style='position:relative;overflow:hidden'>"
                    "<div style='filter:blur(6px);pointer-events:none;user-select:none;opacity:0.3'>",
                    unsafe_allow_html=True,
                )

        _dna_known = st.session_state.get("dna_known", False)
        _dna_match = st.session_state.get("dna_match")
        if _dna_known and _dna_match:
            _sim_pct = round(_dna_match["similarity"] * 100, 1)
            st.markdown(
                f"<div class='pg-card-danger' style='display:flex;align-items:center;gap:12px;margin:12px 0'>"
                f"<span style='font-size:1.5rem'>🧬</span>"
                f"<div><strong style='color:#ef4444'>Known Phishing Campaign Variant Detected</strong><br>"
                f"<span style='color:#94a3b8;font-size:13px'>"
                f"{_sim_pct}% signature match — <code style='color:#60a5fa'>{_dna_match['match'].get('preview','')[:80]}</code></span></div>"
                f"</div>",
                unsafe_allow_html=True,
            )

        if aitm_result and aitm_result.get("detected"):
            _ac = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b", "LOW": "#94a3b8"}.get(
                aitm_result.get("severity", ""), "#94a3b8")
            _ai = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}.get(
                aitm_result.get("severity", ""), "⚪")
            st.markdown(
                f"<div style='background:linear-gradient(135deg,rgba(239,68,68,0.08),rgba(244,63,94,0.05));"
                f"border:1px solid {_ac}44;border-radius:12px;padding:14px 18px;margin:10px 0'>"
                f"<div style='display:flex;align-items:center;gap:12px'>"
                f"<span style='font-size:1.3rem'>{_ai} 🕵️</span>"
                f"<div><strong style='color:{_ac}'>{aitm_result.get('label', '')}</strong>"
                f"<br><span style='color:#94a3b8;font-size:13px'>"
                f"Confidence: {aitm_result['confidence']}/100 · "
                f"Score: {aitm_result.get('url_score',0)}/{aitm_result.get('body_score',0)}/{aitm_result.get('domain_score',0)}"
                f"</span></div></div>",
                unsafe_allow_html=True,
            )
            if aitm_result.get("indicators"):
                with st.expander(f"📋 AitM Indicators ({len(aitm_result['indicators'])})"):
                    for ind in aitm_result["indicators"]:
                        st.markdown(f"- {ind}")

        if header_auth:
            st.markdown(section_title("Email Authentication"), unsafe_allow_html=True)
            auth_overall = header_auth.get("overall", "")
            auth_color = {"PASS": "#22c55e", "WARNING": "#f59e0b", "FAIL": "#ef4444", "UNKNOWN": "#94a3b8"}.get(auth_overall, "#94a3b8")
            auth_icon = {"PASS": "✅", "WARNING": "⚠️", "FAIL": "🔴", "UNKNOWN": "❓"}.get(auth_overall, "❓")
            st.markdown(
                f"<div style='color:#64748b;font-size:0.85rem;margin-bottom:8px'>"
                f"{auth_icon} Overall: <span style='color:{auth_color};font-weight:700'>{auth_overall}</span>"
                f" · <span style='color:#475569'>+{header_auth.get('risk_contribution',0)} risk</span></div>",
                unsafe_allow_html=True
            )
            cols = st.columns(3)
            for col, (label, key, color_map) in zip(cols, [
                ("SPF", "spf_status", {"pass":"#22c55e","fail":"#ef4444","softfail":"#f59e0b","neutral":"#f59e0b","missing":"#94a3b8"}),
                ("DKIM", "dkim_status", {"pass":"#22c55e","fail":"#ef4444","signed":"#f59e0b","missing":"#94a3b8"}),
                ("DMARC", "dmarc_status", {"pass":"#22c55e","fail":"#ef4444","bestguesspass":"#86efac","missing":"#94a3b8"}),
            ]):
                val = header_auth.get(key, "missing")
                c = color_map.get(val, "#94a3b8")
                dot = "🟢" if val in ("pass",) else "🔴" if val in ("fail",) else "🟡"
                with col:
                    st.markdown(stat_card(f"{dot} {val.upper()}", label, c), unsafe_allow_html=True)
            st.caption(header_auth.get("details", ""))

        _perplex_data = st.session_state.get("perplexity_result", {})
        if _perplex_data.get("signals"):
            st.markdown(section_title("AI-Generated Text Analysis"), unsafe_allow_html=True)
            with st.expander(f"📝 {_perplex_data.get('summary','')} — AI Probability {_perplex_data.get('ai_probability',0)}%"):
                cols_perp = st.columns(4)
                cols_perp[0].metric("Burstiness", _perplex_data.get("burstiness",0), help="High = human-like")
                cols_perp[1].metric("Lexical Diversity", _perplex_data.get("lexical_diversity",0), help="Unique word ratio")
                cols_perp[2].metric("Avg Sentence Len", _perplex_data.get("avg_sentence_len",0))
                cols_perp[3].metric("Hedging Phrases", _perplex_data.get("hedging_count",0))
                st.caption("Signals: " + ", ".join(_perplex_data.get("signals", [])))

        if results["keyword_matches"]:
            st.markdown(section_title("Phishing Indicators"), unsafe_allow_html=True)
            for category, keywords in results["keyword_matches"].items():
                with st.expander(f"**{category.upper()}** — {len(keywords)} match(es)"):
                    tags = " ".join(f"<span class='pg-tag'>{kw}</span>" for kw in keywords)
                    st.markdown(tags, unsafe_allow_html=True)

        kit_data = results.get("kit_fingerprinting", {})
        if kit_data and kit_data.get("total_kits_detected", 0) > 0:
            st.markdown(section_title("Phishing Kit Fingerprinting"), unsafe_allow_html=True)
            for match in kit_data["matches"]:
                icon = "🔴" if match["confidence"] >= 70 else "🟡" if match["confidence"] >= 40 else "🟢"
                sev_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b"}.get(match["severity"], "#94a3b8")
                with st.expander(f"{icon} **{match['name']}** — {match['confidence']}% match", expanded=match["confidence"] >= 50):
                    st.caption(f"Severity: <span style='color:{sev_color}'>{match['severity']}</span> — {match['description']}", unsafe_allow_html=True)
                    mp = match["matched_patterns"]
                    cols = st.columns(6)
                    for i, (k, lb) in enumerate(zip(["html","css","form_fields","js","file_paths","headers"], ["HTML","CSS","Forms","JS","Paths","Headers"])):
                        cols[i].metric(lb, mp.get(k, 0))

        xai_result = st.session_state.get("xai_result")
        if xai_result and xai_result.get("triggers"):
            st.markdown(section_title("Psychological Manipulation Analysis"), unsafe_allow_html=True)
            xai_score = xai_result["total_manipulation_score"]
            xai_color = xai_result["overall_color"]
            col_x1, col_x2 = st.columns([1, 2])
            with col_x1:
                fig_xai = go.Figure(go.Indicator(
                    mode="gauge+number", value=xai_score,
                    domain={"x": [0, 1], "y": [0, 1]},
                    title={"text": "<b>Manipulation Score</b>", "font": {"color": xai_color, "size": 14}},
                    gauge={"axis": {"range": [0, 100], "tickcolor": "#94a3b8"}, "bar": {"color": xai_color},
                           "bgcolor": "#111827",
                           "steps": [{"range": [0,25],"color":"#0a2a0a"},{"range":[25,50],"color":"#2a2a0a"},{"range":[50,75],"color":"#2a1a0a"},{"range":[75,100],"color":"#2a0a0a"}],
                           "threshold": {"line": {"color": xai_color, "width": 3}, "thickness": 0.75, "value": xai_score}},
                    number={"font": {"color": xai_color, "size": 40}},
                ))
                fig_xai.update_layout(height=200, margin=dict(t=30,b=0,l=10,r=10), paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
                st.plotly_chart(fig_xai, use_container_width=True)
            with col_x2:
                triggers = xai_result["triggers"]
                categories = [t["label"] for t in triggers]
                raw_scores = [t["raw_score"] for t in triggers]
                fig_radar = go.Figure()
                fig_radar.add_trace(go.Scatterpolar(r=raw_scores + [raw_scores[0]], theta=categories + [categories[0]], fill="toself", name="Trigger Intensity", line_color="#3b82f6", fillcolor="rgba(59,130,246,0.15)"))
                fig_radar.update_layout(polar=dict(radialaxis=dict(visible=True,range=[0,100],tickcolor="#475569",gridcolor="#1e3a5f"),bgcolor="rgba(0,0,0,0)"), height=200, margin=dict(t=10,b=10,l=30,r=30), paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0", showlegend=False)
                st.plotly_chart(fig_radar, use_container_width=True)
            st.markdown(f"<p style='color:{xai_color};font-size:0.9rem;margin-bottom:12px'>{xai_result['trigger_count']} tactic(s) — {xai_result['overall_severity']} risk.</p>", unsafe_allow_html=True)
            for t in triggers:
                with st.expander(f"{t['icon']} {t['label']} — {t['raw_score']}/100 (<span style='color:{t['severity_color']}'>{t['severity']}</span>)", expanded=t["raw_score"] >= 50):
                    st.markdown(f"*{t['description']}*")
                    if t.get("key_phrases"):
                        st.markdown("**Patterns:** " + ", ".join(f"`{p}`" for p in t["key_phrases"][:6]))
                    if t.get("evidence"):
                        st.markdown("**Why flagged:**")
                        for ev in t["evidence"][:4]:
                            st.markdown(f"- {ev['explanation']}")
            st.markdown(f"<details><summary style='color:#3b82f6;font-size:0.85rem;cursor:pointer'>📋 Full XAI explanation</summary><div style='background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:16px;font-family:monospace;font-size:12px;color:#94a3b8;margin-top:8px;white-space:pre-wrap'>{format_xai_report(xai_result)}</div></details>", unsafe_allow_html=True)

        if results["suspicious_urls"]:
            st.markdown(section_title("Suspicious URLs"), unsafe_allow_html=True)
            for item in results["suspicious_urls"]:
                st.markdown(url_box(item["url"], True), unsafe_allow_html=True)
        elif results["urls_found"]:
            st.markdown(section_title("URLs Found"), unsafe_allow_html=True)
            for url in results["urls_found"]:
                st.markdown(url_box(url, False), unsafe_allow_html=True)

        combined_score = st.session_state.get("combined_score")
        if vt_results or (combined_score and combined_score.get("has_vt_data")):
            st.markdown(section_title("Threat Intelligence"), unsafe_allow_html=True)
            if combined_score and combined_score.get("has_vt_data"):
                col_cs1, col_cs2, col_cs3 = st.columns(3)
                with col_cs1:
                    st.metric("Composite Score", f"{combined_score['composite_score']}/100", delta=f"VT: +{combined_score['vt_contribution']:.0f}")
                with col_cs2:
                    st.metric("Malicious", combined_score["vt_malicious_count"])
                with col_cs3:
                    st.metric("Suspicious", combined_score["vt_suspicious_count"])
            for vt in (vt_results or []):
                status = vt.get("status", "error")
                url = vt.get("url", "")
                mal = vt.get("malicious", 0)
                total = vt.get("total_vendors", 0)
                vt_link = vt.get("vt_link", "")
                if status == "malicious":
                    st.markdown(url_box(f"🔴 MALICIOUS — {url[:70]} ({mal}/{total} vendors)", True), unsafe_allow_html=True)
                elif status == "suspicious":
                    st.markdown(url_box(f"🟠 SUSPICIOUS — {url[:70]}", True), unsafe_allow_html=True)
                elif status == "clean":
                    st.markdown(url_box(f"🟢 CLEAN — {url[:70]} ({total} vendors)", False), unsafe_allow_html=True)
                if vt_link and status != "error":
                    st.markdown(f"<a href='{vt_link}' target='_blank' style='font-size:11px;color:#3b82f6'>View on VirusTotal →</a>", unsafe_allow_html=True)

        if osint_data and osint_data.get("domain_results"):
            st.markdown(section_title("OSINT Investigation"), unsafe_allow_html=True)
            osint_risk = osint_data.get("osint_risk_score", 0)
            if osint_risk >= 75:
                st.error(f"🔴 OSINT Risk: {osint_risk}/100 — High confidence threat infrastructure")
            elif osint_risk >= 50:
                st.warning(f"🟠 OSINT Risk: {osint_risk}/100 — Suspicious infrastructure")
            elif osint_risk >= 25:
                st.warning(f"🟡 OSINT Risk: {osint_risk}/100 — Some indicators")
            else:
                st.success(f"🟢 OSINT Risk: {osint_risk}/100 — No concerns")
            for dr in osint_data["domain_results"]:
                with st.expander(f"🌐 **{dr['domain']}** — Risk: {dr['risk_score']}/100"):
                    dc1, dc2, dc3 = st.columns(3)
                    dc1.metric("Score", f"{dr['risk_score']}/100")
                    dc2.metric("Country", dr.get("country", "Unknown"))
                    dc3.metric("Age", f"{dr.get('domain_age_days', '?')}d")
                    for ind in dr.get("risk_indicators", []):
                        st.markdown(f"- {ind}")

        webhook_result = st.session_state.get("webhook_result")
        if webhook_result:
            if webhook_result.get("success"):
                st.success("🚨 Alert sent to your notification channel.")
            else:
                st.warning(f"Webhook failed: {webhook_result.get('error', 'Unknown')}")

        if results["has_attachments"]:
            st.warning("📎 Attachment detected — do NOT open from unverified senders.")
        header = results.get("header_analysis", {})
        if header.get("findings"):
            st.markdown(section_title("Header Analysis Findings"), unsafe_allow_html=True)
            for finding in header["findings"]:
                st.error("🚨 " + finding)
        attach = results.get("attachment_analysis", {})
        if attach.get("findings"):
            st.markdown(section_title("Attachment Analysis"), unsafe_allow_html=True)
            for finding in attach["findings"]:
                st.error("🚨 " + finding)
        lang = results.get("language_analysis", {})
        if lang.get("findings"):
            st.markdown(section_title("Language Analysis"), unsafe_allow_html=True)
            for finding in lang["findings"]:
                st.warning("⚠ " + finding)

        st.divider()
        st.markdown(section_title("Security Verdict"), unsafe_allow_html=True)
        if score >= 75:
            st.error("🔴 **CRITICAL THREAT** — Strong phishing indicators detected. Do not click any links.")
        elif score >= 50:
            st.error("🟠 **HIGH RISK** — Multiple phishing indicators found. Treat with extreme caution.")
        elif score >= 25:
            st.warning("🟡 **MEDIUM RISK** — Suspicious elements detected. Verify before acting.")
        else:
            st.success("🟢 **LOW RISK** — No major phishing indicators found. Stay vigilant.")

        jury_result = st.session_state.get("jury_result")
        if jury_result and "final_score" in jury_result:
            st.markdown(section_title("Multi-LLM Jury Consensus"), unsafe_allow_html=True)
            jr = jury_result
            col_j1, col_j2, col_j3 = st.columns(3)
            with col_j1:
                st.metric("Ensemble Score", f"{jr['final_score']:.0f}/100", delta=f"{jr.get('final_score',0)-score:+.0f} vs heuristic")
            with col_j2:
                st.metric("Linguistic Jury", f"{jr.get('linguistic_score',0):.0f}/100")
            with col_j3:
                st.metric("Corporate Jury", f"{jr.get('corporate_score',0):.0f}/100")
            if jr.get("final_score",0) > score + 15:
                st.warning("⚠️ Jury rates this **significantly higher** than heuristic — priority threat.")
            elif jr.get("final_score",0) < score - 15:
                st.info("ℹ️ Jury rates this **lower** — heuristic flags may be false positives.")

        if _restricted_blur:
            st.markdown("</div></div>", unsafe_allow_html=True)

        if score >= 50:
            st.divider()
            st.markdown(section_title("Counter-Measure Deployment"), unsafe_allow_html=True)
            if st.button("⚔️ Deploy Deception Payload", use_container_width=True, type="secondary", key="honeypot_btn"):
                with st.spinner("Generating deceptive payload..."):
                    honeypot = generate_honeypot(email_text_saved)
                st.session_state["honeypot"] = honeypot
                st.success("✅ Deception payload generated.")
                st.rerun()
            _hp = st.session_state.get("honeypot")
            if _hp:
                st.markdown(f"<div class='pg-card-success' style='margin:8px 0'><div style='color:#22c55e;font-weight:700'>{_hp.get('subject','')}</div><div style='color:#94a3b8;font-size:12px'>From: {_hp.get('sender_name','')} — {_hp.get('payload_type','')}</div></div>", unsafe_allow_html=True)
                if st.button("✕ Clear", key="clear_hp"):
                    st.session_state.pop("honeypot", None)
                    st.rerun()

            if _restricted_blur:
                st.divider()
                st.markdown(
                    "<div style='background:linear-gradient(145deg,#0a0f1a,#0f1a2a);border:2px solid #f59e0b;border-radius:20px;padding:32px 28px;text-align:center;margin:12px 0'>"
                    "<div style='font-size:2.5rem;margin-bottom:8px'>🔒</div>"
                    "<div style='color:#f1f5f9;font-size:1.3rem;font-weight:800;margin-bottom:4px'>Premium Analysis Restricted</div>"
                    "<div style='color:#94a3b8;font-size:0.85rem;margin-bottom:20px'>Upgrade to unlock AI Security Audit, Threat Links, and PDF Reports.</div>"
                    "<div style='background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.3);border-radius:14px;padding:20px;margin:0 auto 20px;max-width:400px'>"
                    "<div style='color:#f59e0b;font-weight:700;margin-bottom:12px'>💰 Breach Cost Calculator</div>"
                    "<div style='color:#94a3b8;font-size:12px;margin-bottom:8px'>Your company size:</div></div>",
                    unsafe_allow_html=True
                )
                breach_employees = st.slider("Employees", 10, 500, 50, key="breach_slider", label_visibility="collapsed")
                breach_cost = breach_employees * 900
                st.markdown(
                    f"<div style='text-align:center;background:#111827;border:1px solid #1e293b;border-radius:12px;padding:16px;max-width:400px;margin:0 auto'>"
                    f"<div style='color:#94a3b8;font-size:13px'>Cost of a single BEC breach:</div>"
                    f"<div style='color:#ef4444;font-size:2rem;font-weight:800'>${breach_cost:,}</div>"
                    f"</div>",
                    unsafe_allow_html=True
                )
            else:
                st.divider()
                st.markdown(section_title("Export & AI Analysis"), unsafe_allow_html=True)
                col_ai, col_pdf, col_stix = st.columns(3)
                with col_ai:
                    if st.button("🤖 AI Security Report", use_container_width=True, type="secondary"):
                        try:
                            with st.spinner("Writing security report..."):
                                ai_report = generate_ai_report(email_text_saved, results)
                            st.session_state["ai_report"] = ai_report
                            save_analysis(results, email_text_saved, ai_report)
                        except Exception as e:
                            st.error(f"AI analysis failed: {e}")
                with col_pdf:
                    ai_report_text = st.session_state.get("ai_report", "")
                    _has_wl = "white_label" in PLANS.get(user_tier, {}).get("features", [])
                    _wl_flag = st.session_state.get("whitelabel_pdf", False) and _has_wl
                    _wl_logo = st.session_state.get("consultant_logo_path") if _has_wl else None
                    pdf_bytes = generate_pdf_report(results, email_text_saved, ai_report_text, white_label=_wl_flag, custom_logo_path=_wl_logo)
                    sev_lower = results["severity"].lower()
                    st.download_button(label="📥 Download PDF Report", data=pdf_bytes, file_name=f"phishguard_report_{sev_lower}.pdf", mime="application/pdf", use_container_width=True, type="primary")
                with col_stix:
                    _att_result = st.session_state.get("att_scan_result")
                    _sender_anom = st.session_state.get("sender_anomaly")
                    _perplex_t = st.session_state.get("perplexity_result")
                    stix_bundle = build_enterprise_stix_bundle(email_text=email_text_saved, results=results, osint_data=osint_data, vt_results=vt_results, attachment_result=_att_result, sender_anomaly=_sender_anom, perplexity_result=_perplex_t)
                    stix_json = json.dumps(stix_bundle, indent=2)
                    st.download_button(label="📤 STIX 2.1 Export", data=stix_json, file_name=f"phishguard_stix_{sev_lower}.json", mime="application/json", use_container_width=True, type="secondary")
                if "ai_report" in st.session_state:
                    st.markdown(section_title("AI Security Analysis"), unsafe_allow_html=True)
                    st.markdown(st.session_state["ai_report"])

                # First-scan guidance
                if st.session_state.get("checklist_first_scan", False):
                    _guidance_shown = st.session_state.get("_guidance_shown", False)
                    if not _guidance_shown:
                        st.divider()
                        st.markdown("### 🎉 First scan complete! Here's what to do next")
                        _gs = results["risk_score"]
            if _gs >= 50:
                st.markdown(
                    "<div style='background:linear-gradient(145deg,#0a0f1a,#0f1a2a);border:1px solid #1e293b;"
                    "border-radius:14px;padding:20px;margin:8px 0'>"
                    "🔴 <strong>This email shows phishing indicators.</strong> Do not click any links. "
                    "Forward the email to your IT team and delete it from your inbox.<br><br>"
                    "📊 Explore the <strong>Dashboard</strong> tab to see your scan history and analytics.<br>"
                    "⬆ Consider <strong>upgrading</strong> for VirusTotal and OSINT analysis on every scan."
                    "</div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    "<div style='background:linear-gradient(145deg,#0a0f1a,#0f1a2a);border:1px solid #1e293b;"
                    "border-radius:14px;padding:20px;margin:8px 0'>"
                    "🟢 <strong>This email appears safe.</strong> Always verify unexpected attachments or links "
                    "before clicking — even from known senders.<br><br>"
                    "📊 Visit the <strong>Dashboard</strong> to see your scan history and track threats over time.<br>"
                    "📧 Try the <strong>Inbox Scanner</strong> to connect your email account and scan real messages."
                    "</div>",
                    unsafe_allow_html=True,
                )
            st.session_state["_guidance_shown"] = True
