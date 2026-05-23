import os
from dotenv import load_dotenv # type: ignore

load_dotenv()

try:
    import streamlit as st # type: ignore
    # Check Streamlit Cloud secrets first, fall back to local environment variables
    OPENROUTER_API_KEY = st.secrets.get("OPENROUTER_API_KEY", os.getenv("OPENROUTER_API_KEY"))
except Exception:
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
AI_MODEL = "mistralai/mistral-7b-instruct:free"