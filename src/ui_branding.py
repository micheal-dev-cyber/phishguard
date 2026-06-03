import streamlit as st

from src.white_label import (
    enable_branding,
    get_branding,
    init_white_label,
    inject_branding_css,
    set_branding,
)


def render_branding_ui(username: str):
    st.markdown("#### 🎨 White-Label Branding")
    st.caption("Customize the look and feel with your company branding.")

    init_white_label()
    brand = get_branding(username)

    col_a, col_b = st.columns(2)
    with col_a:
        company = st.text_input("Company name", value=brand.get("company_name", ""),
                                key="wl_company")
        logo = st.text_input("Logo URL", value=brand.get("logo_url", ""),
                             key="wl_logo", help="URL to your logo image")
    with col_b:
        primary = st.color_picker("Primary color", value=brand.get("primary_color", "#2563eb"),
                                  key="wl_primary")
        secondary = st.color_picker("Secondary color", value=brand.get("secondary_color", "#1e3a5f"),
                                    key="wl_secondary")
        accent = st.color_picker("Accent color", value=brand.get("accent_color", "#60a5fa"),
                                 key="wl_accent")

    custom_css = st.text_area("Custom CSS (optional)", value=brand.get("custom_css", ""),
                              key="wl_css", height=80,
                              placeholder="/* Add custom CSS overrides */")

    if st.button("💾 Save Branding", type="primary", use_container_width=True):
        set_branding(username, company_name=company, logo_url=logo,
                     primary_color=primary, secondary_color=secondary,
                     accent_color=accent, custom_css=custom_css)
        st.success("Branding saved!")
        st.rerun()

    enabled = st.toggle("Enable White-Label", value=brand.get("enabled", False),
                        key="wl_enabled", help="Apply custom branding to the UI")
    if enabled != brand.get("enabled", False):
        enable_branding(username, enabled)
        st.rerun()

    if enabled and brand.get("company_name"):
        preview = inject_branding_css(username)
        st.markdown(preview, unsafe_allow_html=True)
