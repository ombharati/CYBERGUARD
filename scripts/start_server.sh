set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

echo "=========================================================="
echo "🛡️  Starting Server"
echo "=========================================================="

# 1. Check or start PostgreSQL and Redis containers
echo "[1/5] Checking Docker infrastructure (PostgreSQL & Redis)..."
if ! docker ps | grep -q "cyberguard-postgres"; then
    echo "Starting cyberguard-postgres..."
    docker start cyberguard-postgres 2>/dev/null || docker compose -f infrastructure/compose/docker-compose.yml up -d postgres
fi

if ! docker ps | grep -q "cyberguard-redis"; then
    echo "Starting cyberguard-redis..."
    docker start cyberguard-redis 2>/dev/null || docker compose -f infrastructure/compose/docker-compose.yml up -d redis
fi

# 2. Check Ollama
echo "[2/5] Checking Ollama (qwen3:8b)..."
if curl -s http://localhost:11434/api/tags | grep -q "qwen3:8b"; then
    echo "  ✓ Ollama and qwen3:8b are active."
else
    echo "  ⚠️ Ollama or qwen3:8b not detected at http://localhost:11434. Local AI fallback will handle scans."
fi

# 3. Check Laya
echo "[3/5] Checking Laya (ModernBERT-large)..."
if [ -d "/home/om/laya-test/.venv" ]; then
    echo "  ✓ Laya environment verified at /home/om/laya-test."
else
    echo "  ⚠️ Laya path not found; using fallback heuristics."
fi

# 4. Start FastAPI server and background worker
echo "[4/5] Starting FastAPI API server and Background Worker..."
"$PROJECT_DIR/.venv/bin/python" -m uvicorn app.backend.main:app --host 0.0.0.0 --port 8000 &
SERVER_PID=$!

"$PROJECT_DIR/.venv/bin/python" -m app.backend.services.worker &
WORKER_PID=$!

sleep 2

# 5. Start Cloudflare Tunnel
echo "[5/5] Exposing public HTTPS subdomain via Cloudflare Tunnel..."
docker run --network host --rm cloudflare/cloudflared:latest tunnel --url http://127.0.0.1:8000 2>&1 | tee /tmp/cyberguard-tunnel.log &
TUNNEL_PID=$!

echo ""
echo "=========================================================="
echo "✨ CYBERGUARD is running live!"
echo "   - Local Dashboard: http://localhost:8000"
echo "   - API Docs:        http://localhost:8000/docs"
echo "   - Health Check:    http://localhost:8000/health"
echo "=========================================================="
echo "Waiting for public HTTPS tunnel link..."
for i in {1..20}; do
    TUNNEL_URL=$(grep -o 'https://[^ ]*\.trycloudflare\.com' /tmp/cyberguard-tunnel.log 2>/dev/null | head -n 1 || true)
    if [ -n "$TUNNEL_URL" ]; then
        echo ""
        echo "🌐 Public Subdomain URL: $TUNNEL_URL"
        echo "   Share this link with anyone or use in GitHub Pages!"
        echo "=========================================================="
        break
    fi
    sleep 1
done

trap "kill $SERVER_PID $WORKER_PID $TUNNEL_PID 2>/dev/null || true" EXIT
wait
