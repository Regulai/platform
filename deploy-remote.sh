#!/bin/bash
# Script to run ON the server after copying files
# Copy this to server and run: bash deploy-remote.sh

set -e

cd /opt/regulai

echo "=========================================="
echo "  RegulAI Server Setup"
echo "=========================================="

echo ""
echo "[1/4] Installing Docker..."
if ! command -v docker &> /dev/null; then
    apt-get update
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

if ! docker compose version &> /dev/null; then
    apt-get install -y docker-compose-plugin
fi
echo "Docker ready!"

echo ""
echo "[2/4] Creating .env file..."
cat > .env << 'EOF'
DEBUG=False
DJANGO_SUPERUSER_USERNAME=admin
DJANGO_SUPERUSER_EMAIL=admin@regulai.local
DJANGO_SUPERUSER_PASSWORD=RegulAI2024!
ALLOWED_HOSTS=*
EOF

echo ""
echo "[3/4] Stopping existing containers..."
docker compose -f docker-compose.prod.yml down 2>/dev/null || true

echo ""
echo "[4/4] Building and starting containers..."
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d

echo ""
echo "Waiting for services..."
sleep 15

echo ""
docker compose -f docker-compose.prod.yml ps

echo ""
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "Access: http://$(hostname -I | awk '{print $1}')"
echo "Admin: admin / RegulAI2024!"
echo ""
