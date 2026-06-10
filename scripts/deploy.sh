#!/usr/bin/env bash
set -euo pipefail

# PhishGuard AICOS deployment script
# Usage: ./scripts/deploy.sh [staging|production]

ENV="${1:-staging}"
DOCKER_IMAGE="phishguard-aicos:latest"
COMPOSE_FILE="docker-compose.yml"

echo "=== PhishGuard Deploy [${ENV}] ==="

if [ ! -f "${COMPOSE_FILE}" ]; then
    echo "ERROR: ${COMPOSE_FILE} not found"
    exit 1
fi

echo "Building Docker image..."
docker build -t "${DOCKER_IMAGE}" .

echo "Stopping existing containers..."
docker-compose -f "${COMPOSE_FILE}" down || true

echo "Starting fresh deployment..."
docker-compose -f "${COMPOSE_FILE}" up -d --build

echo "Waiting for health check..."
sleep 5

if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
    echo "Deployment successful! Service is healthy."
else
    echo "WARNING: Health check failed - check logs with: docker-compose logs"
fi
