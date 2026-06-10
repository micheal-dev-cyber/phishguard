#!/bin/bash
set -e

# Start Python proxy first (listens on 8501 — HF auto-detects this port)
python /app/scripts/proxy.py &
PROXY_PID=$!
echo "Proxy started on 8501 (PID $PROXY_PID)"

sleep 2

# Start Flask webhook on 8080
gunicorn webhook:app --bind 0.0.0.0:8080 --workers 1 --timeout 30 &
echo "Flask webhook started on 8080"

# Start Streamlit on 8502 (internal, not detected by HF)
streamlit run app.py --server.port=8502 --server.address=0.0.0.0 --server.headless=true &
echo "Streamlit started on 8502"

# Wait for any process to fail, keep container alive
wait
