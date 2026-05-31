import streamlit as st
from src.domain_verify import (
    init_domain_verify, add_domain, verify_domain,
    get_user_domains, delete_domain, check_dns_records,
)


def render_domain_verify_ui(username: str):
    st.markdown("#### 📧 Domain Verification")
    st.caption("Verify domain ownership to improve sender reputation and enable custom sending.")

    init_domain_verify()
    domains = get_user_domains(username)

    col_a, col_b = st.columns([2, 1])
    with col_a:
        new_domain = st.text_input("Domain to verify", placeholder="example.com",
                                   key="dom_input")
    with col_b:
        if st.button("➕ Add Domain", type="primary", use_container_width=True) and new_domain:
            token = add_domain(username, new_domain)
            st.info(f"Add this TXT record to {new_domain}: `phishguard-verify={token}`")
            st.rerun()

    if domains:
        st.markdown("##### Your Domains")
        for d in domains:
            status = "✅ Verified" if d["verified"] else "⏳ Pending"
            col_a, col_b, col_c = st.columns([2, 1, 1])
            col_a.markdown(f"**{d['domain']}**")
            col_b.markdown(status)
            if not d["verified"]:
                token_input = st.text_input(f"Verification token for {d['domain']}",
                                            key=f"vt_{d['id']}", placeholder="Paste token", label_visibility="collapsed")
                if st.button("Verify", key=f"vfy_{d['id']}"):
                    if verify_domain(username, d["domain"], token_input):
                        st.success(f"{d['domain']} verified!")
                        st.rerun()
                    else:
                        st.error("Token mismatch. Check the TXT record value.")
            else:
                if st.button("Check DNS", key=f"dns_{d['id']}"):
                    dns_result = check_dns_records(d["domain"])
                    cols = st.columns(3)
                    cols[0].metric("SPF", dns_result["spf"])
                    cols[1].metric("DKIM", dns_result["dkim"])
                    cols[2].metric("DMARC", dns_result["dmarc"])
            if col_c.button("🗑", key=f"del_dom_{d['id']}"):
                delete_domain(username, d["domain"])
                st.rerun()
    else:
        st.info("No domains added yet. Add your first domain above.")
