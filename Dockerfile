FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    nginx \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data \
    && chmod +x /app/scripts/start.sh \
    && rm -f /etc/nginx/sites-enabled/*

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/health')" || exit 1

CMD ["/app/scripts/start.sh"]
