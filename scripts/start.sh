#!/bin/bash
set -e

# Start Flask webhook on 8080
gunicorn webhook:app --bind 0.0.0.0:8080 --workers 1 --timeout 30 &
echo "Flask webhook started on 8080"

# Start Streamlit on 8501
streamlit run app.py --server.port=8501 --server.address=0.0.0.0 --server.headless=true &
echo "Streamlit started on 8501"

sleep 3

# Start Python proxy in foreground
python /app/scripts/proxy.py
