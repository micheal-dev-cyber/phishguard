#!/bin/bash
set -e

PORT="${PORT:-7860}"

# Generate nginx config with correct port
sed "s/\${PORT}/$PORT/g" /app/nginx.conf.template > /tmp/nginx.conf

# Start Flask webhook on 8080
gunicorn webhook:app --bind 0.0.0.0:8080 --workers 1 --timeout 30 &
echo "Flask webhook started on 8080"

# Start Streamlit on 8501
streamlit run app.py --server.port=8501 --server.address=0.0.0.0 --server.headless=true &
echo "Streamlit started on 8501"

sleep 2

# Start nginx in foreground
nginx -c /tmp/nginx.conf -g "daemon off;"
