                dot = "🟢" if val in ("pass",) else "🔴" if val in ("fail",) else "🟡"
                with col:
                    st.markdown(
                        f"<div style='background:#111827;border:1px solid #1e3a5f;border-radius:10px;"
                        f"padding:12px;text-align:center'>"
                        f"<div style='color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:.08em'>{label}</div>"
                        f"<div style='font-size:1.2rem;font-weight:700;color:{c}'>{dot} {val.upper()}</div>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )
            st.caption(header_auth.get("details", ""))

        # ── Perplexity Analyzer (AI-written text detector) ──────────────────
        _perplex_data = st.session_state.get("perplexity_result", {})
        if _perplex_data.get("signals"):
