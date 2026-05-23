import streamlit as st # type: ignore

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ PhishGuard AI — Debug Mode")
st.success("✅ App is loading correctly")

# Test imports one by one
st.write("Testing imports...")

try:
    import json
    st.success("✅ json — OK")
except Exception as e:
    st.error(f"❌ json failed: {e}")

try:
    import re
    st.success("✅ re — OK")
except Exception as e:
    st.error(f"❌ re failed: {e}")

try:
    from pathlib import Path
    st.success("✅ pathlib — OK")
except Exception as e:
    st.error(f"❌ pathlib failed: {e}")

try:
    from src.detector import analyze_email
    st.success("✅ src.detector — OK")
except Exception as e:
    st.error(f"❌ src.detector failed: {e}")

try:
    from src.ai_analyzer import ai_analyze_email
    st.success("✅ src.ai_analyzer — OK")
except Exception as e:
    st.error(f"❌ src.ai_analyzer failed: {e}")

try:
    from src.database import init_db, save_analysis, get_history
    st.success("✅ src.database — OK")
except Exception as e:
    st.error(f"❌ src.database failed: {e}")

try:
    st.success("✅ plotly — OK")
except Exception as e:
    st.error(f"❌ plotly failed: {e}")

try:
    from fpdf import FPDF # type: ignore
    st.success("✅ fpdf2 — OK")
except Exception as e:
    st.error(f"❌ fpdf2 failed: {e}")

# Test data file
try:
    data_path = Path("data/phishing_keywords.json")
    if data_path.exists():
        with open(data_path) as f:
            data = json.load(f)
        st.success(f"✅ phishing_keywords.json — OK ({len(data)} categories loaded)")
    else:
        st.error("❌ data/phishing_keywords.json — FILE NOT FOUND")
except Exception as e:
    st.error(f"❌ keywords file failed: {e}")

st.write("---")
st.info("All tests done. Fix any ❌ above and push again.")