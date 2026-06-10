#!/bin/bash
set -e

# Start Flask webhook on 8080
gunicorn webhook:app --bind 0.0.0.0:8080 --workers 1 --timeout 30 &
echo "Flask webhook started on 8080"

# Start Streamlit on 8502 (proxy listens on 8501 where HF routes)
streamlit run app.py --server.port=8502 --server.address=0.0.0.0 --server.headless=true &
echo "Streamlit started on 8502"

sleep 3

# Start Python proxy in foreground
python /app/scripts/proxy.py
