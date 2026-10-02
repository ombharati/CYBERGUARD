#!/usr/bin/env bash
# ==============================================================================
# CYBERGUARD — Server Stopper
# Gracefully stops the FastAPI server, background worker, and Cloudflare tunnel.
# Usage:
#   ./scripts/stop_server.sh        # Stops API server, worker, and tunnel
#   ./scripts/stop_server.sh --all  # Also stops PostgreSQL and Redis containers
# ==============================================================================
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

echo "=========================================================="
echo "🛑 Stopping CYBERGUARD Services..."
echo "=========================================================="

# 1. Stop FastAPI server (port 8000 / uvicorn)
echo "[1/4] Stopping FastAPI API server (port 8000)..."
pkill -f "uvicorn app.backend.main:app" 2>/dev/null || true
fuser -k 8000/tcp 2>/dev/null || true
echo "  ✓ API server stopped."

# 2. Stop Background Worker
echo "[2/4] Stopping Background Worker..."
pkill -f "app.backend.services.worker" 2>/dev/null || true
echo "  ✓ Background worker stopped."

# 3. Stop Cloudflare Tunnel
echo "[3/4] Stopping Cloudflare Tunnel..."
docker stop cyberguard-tunnel 2>/dev/null || true
pkill -f "cloudflared" 2>/dev/null || true
echo "  ✓ Tunnel stopped."

# 4. Optional: Stop PostgreSQL & Redis containers if --all is passed
if [ "$1" == "--all" ] || [ "$1" == "-a" ]; then
    echo "[4/4] Stopping PostgreSQL and Redis Docker containers..."
    docker stop cyberguard-postgres cyberguard-redis 2>/dev/null || true
    echo "  ✓ Database and cache containers stopped."
else
    echo "[4/4] Preserving PostgreSQL & Redis containers for fast restart."
    echo "      (Pass --all to stop them as well: ./scripts/stop_server.sh --all)"
fi

echo ""
echo "=========================================================="
echo "✅ CYBERGUARD server is stopped."
echo "   To start again anytime: ./scripts/start_server.sh"
echo "=========================================================="
