#!/bin/bash
# Deploy script for RegulAI
# Run this script from the project root directory

set -e

# Server configuration
SERVER_IP="2.29.154.106"
SERVER_USER="root"
REMOTE_DIR="/opt/regulai"

echo "=========================================="
echo "  RegulAI Production Deploy"
echo "=========================================="

# Check if sshpass is available (for password auth)
if ! command -v sshpass &> /dev/null; then
    echo "Note: sshpass not installed. You'll be prompted for password multiple times."
    echo "Install with: apt install sshpass (Linux) or brew install hudochenkov/sshpass/sshpass (Mac)"
    SSH_CMD="ssh"
    SCP_CMD="scp"
else
    read -sp "Enter server password: " SERVER_PASS
    echo
    SSH_CMD="sshpass -p $SERVER_PASS ssh"
    SCP_CMD="sshpass -p $SERVER_PASS scp"
fi

SSH_OPTS="-o StrictHostKeyChecking=no"

echo ""
echo "[1/5] Connecting to server and installing Docker..."
$SSH_CMD $SSH_OPTS $SERVER_USER@$SERVER_IP << 'ENDSSH'
# Update system
apt-get update

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

# Install Docker Compose plugin if not present
if ! docker compose version &> /dev/null; then
    echo "Installing Docker Compose..."
    apt-get install -y docker-compose-plugin
fi

# Create project directory
mkdir -p /opt/regulai
echo "Docker ready!"
ENDSSH

echo ""
echo "[2/5] Copying project files to server..."
# Create a temporary archive excluding unnecessary files
tar --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.env' \
    --exclude='db.sqlite3' \
    --exclude='staticfiles' \
    --exclude='media' \
    --exclude='node_modules' \
    --exclude='.venv' \
    --exclude='venv' \
    -czf /tmp/regulai-deploy.tar.gz .

$SCP_CMD $SSH_OPTS /tmp/regulai-deploy.tar.gz $SERVER_USER@$SERVER_IP:/tmp/
rm /tmp/regulai-deploy.tar.gz

echo ""
echo "[3/5] Extracting files on server..."
$SSH_CMD $SSH_OPTS $SERVER_USER@$SERVER_IP << ENDSSH
cd /opt/regulai
rm -rf * 2>/dev/null || true
tar -xzf /tmp/regulai-deploy.tar.gz
rm /tmp/regulai-deploy.tar.gz
ENDSSH

echo ""
echo "[4/5] Creating production .env file..."
$SSH_CMD $SSH_OPTS $SERVER_USER@$SERVER_IP << 'ENDSSH'
cat > /opt/regulai/.env << 'EOF'
DEBUG=False
DJANGO_SUPERUSER_USERNAME=admin
DJANGO_SUPERUSER_EMAIL=admin@regulai.local
DJANGO_SUPERUSER_PASSWORD=RegulAI2024!
ALLOWED_HOSTS=*
EOF
echo ".env file created"
ENDSSH

echo ""
echo "[5/5] Building and starting containers..."
$SSH_CMD $SSH_OPTS $SERVER_USER@$SERVER_IP << 'ENDSSH'
cd /opt/regulai

# Stop existing containers if running
docker compose -f docker-compose.prod.yml down 2>/dev/null || true

# Build and start
docker compose -f docker-compose.prod.yml build --no-cache
docker compose -f docker-compose.prod.yml up -d

# Wait for services to start
echo "Waiting for services to start..."
sleep 10

# Show status
docker compose -f docker-compose.prod.yml ps
ENDSSH

echo ""
echo "=========================================="
echo "  Deploy Complete!"
echo "=========================================="
echo ""
echo "Access the application at: http://$SERVER_IP"
echo ""
echo "Admin credentials:"
echo "  Username: admin"
echo "  Password: RegulAI2024!"
echo ""
echo "To view logs: ssh $SERVER_USER@$SERVER_IP 'cd /opt/regulai && docker compose -f docker-compose.prod.yml logs -f'"
echo ""
