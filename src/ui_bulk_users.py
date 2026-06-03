import streamlit as st

from src.bulk_users import export_template_csv, export_users_csv, import_users_csv


def render_bulk_users_ui():
    st.markdown("#### 👥 Bulk User Import/Export")
    st.caption("Import or export users in CSV format for mass management.")

    tab_exp, tab_imp = st.tabs(["📤 Export", "📥 Import"])

    with tab_exp:
        if st.button("📥 Download Users CSV", type="primary", use_container_width=True):
            csv_data = export_users_csv()
            st.download_button(
                "Download CSV",
                csv_data,
                file_name="phishguard_users_export.csv",
                mime="text/csv",
                use_container_width=True,
            )

        if st.button("📄 Download Template CSV", use_container_width=True):
            template = export_template_csv()
            st.download_button(
                "Download Template",
                template,
                file_name="phishguard_import_template.csv",
                mime="text/csv",
                use_container_width=True,
            )

    with tab_imp:
        uploaded = st.file_uploader("Upload users CSV", type=["csv"], key="bulk_csv")
        if uploaded:
            content = uploaded.getvalue().decode("utf-8")
            if st.button("🚀 Import Users", type="primary", use_container_width=True):
                result = import_users_csv(content)
                st.success(f"Imported: {result['imported']}, Skipped: {result['skipped']}")
                if result["errors"]:
                    for err in result["errors"][:10]:
                        st.warning(err)
                st.rerun()
