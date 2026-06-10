#!/bin/bash
set -e

# Start Python proxy first (listens on 8501 — HF auto-detects this port)
python /app/scripts/proxy.py &
PROXY_PID=$!
echo "Proxy started on 8501 (PID $PROXY_PID)"

sleep 2

# Start Flask webhook on 8080 (localhost only)
gunicorn webhook:app --bind 127.0.0.1:8080 --workers 1 --timeout 30 &
echo "Flask webhook started on 8080"

# Start Streamlit on 8502 (localhost only — prevents HF from detecting this port)
streamlit run app.py --server.port=8502 --server.address=127.0.0.1 --server.headless=true &
echo "Streamlit started on 8502"

# Wait for any process to fail, keep container alive
wait
