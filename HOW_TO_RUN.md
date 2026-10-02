# 🛡️ CYBERGUARD — How to Turn the Server On

This guide provides simple, step-by-step instructions to turn on the CYBERGUARD cybersecurity analysis platform on your machine.

---

## ⚡ Quick Start (One-Click)

The easiest way to start the entire server stack, local AI models, database, background worker, and public HTTPS tunnel is to run the automated starter script:

```bash
./scripts/start_server.sh
```

### What this does automatically:
1. **Starts Database & Cache**: Launches PostgreSQL 16 (port 5432) and Redis 7 (port 6379) in Docker.
2. **Verifies AI Engines**: Checks connection to Ollama (`qwen3:8b` on GPU) and Laya (`ModernBERT-large` on CPU).
3. **Starts FastAPI Server**: Hosts the API and frontend dashboard at `http://localhost:8000`.
4. **Starts Scan Worker**: Processes background analysis jobs from Redis.
5. **Generates Public HTTPS Subdomain**: Starts a Cloudflare Tunnel giving you a live public link (e.g. `https://*.trycloudflare.com`) accessible from any browser or phone.

---

## 🛠️ Step-by-Step Manual Start

If you prefer to start each service individually:

### 1. Start PostgreSQL and Redis (Docker)
```bash
docker start cyberguard-postgres cyberguard-redis 2>/dev/null || \
docker compose -f infrastructure/compose/docker-compose.yml up -d postgres redis
```

### 2. Verify Local AI Models
- **Ollama (`qwen3:8b` on GPU)**:
  ```bash
  curl -s http://localhost:11434/api/tags
  ```
  *(If Ollama is not running, start it with `ollama serve`)*

- **Laya (`ModernBERT-large` on CPU)**:
  Located at `/home/om/laya-test`. Loaded automatically by the backend in memory on CPU (~800MB RAM, 0 VRAM usage).

### 3. Run Database Migrations (First Run or Updates)
```bash
source .venv/bin/activate
alembic upgrade head
```

### 4. Start the FastAPI API Server
```bash
source .venv/bin/activate
python -m uvicorn app.backend.main:app --host 0.0.0.0 --port 8000
```
- Local Dashboard: [http://localhost:8000](http://localhost:8000)
- Interactive API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health Endpoint: [http://localhost:8000/health](http://localhost:8000/health)

### 5. Start the Background Scan Worker (In a separate terminal)
```bash
source .venv/bin/activate
python -m app.backend.services.worker
```

### 6. (Optional) Expose Public HTTPS Subdomain Tunnel
To access your laptop server from anywhere on the internet or connect it to GitHub Pages:
```bash
docker run --network host --rm cloudflare/cloudflared:latest tunnel --url http://127.0.0.1:8000
```
The terminal will display your live public tunnel URL:
`https://<random-subdomain>.trycloudflare.com`

---

## 🔍 How to Verify the Server is Healthy

Run:
```bash
curl -s http://localhost:8000/health | jq .
```

Expected response:
```json
{
  "status": "ok",
  "version": "0.1.0",
  "database": true,
  "redis": true,
  "ollama": true,
  "laya_available": true
}
```

---

## 🧪 Running Automated Tests

To run the complete test suite:
```bash
source .venv/bin/activate
pytest -v tests/
```

To run fast deterministic tests without live AI model execution:
```bash
pytest -v tests/test_url_detector.py tests/test_email_detection.py tests/test_risk_engine.py tests/test_api.py tests/test_worker_and_queue.py
```

---

## 🛑 How to Turn the Server Off

### If using `./scripts/start_server.sh`:
Simply press `Ctrl + C` in the terminal. All child processes and tunnels will shut down cleanly.

### If running in background:
```bash
# Stop Python processes
pkill -f "uvicorn app.backend.main:app"
pkill -f "app.backend.services.worker"

# Stop Docker containers
docker stop cyberguard-postgres cyberguard-redis
```

---

## 🌐 Public Deployments
- **GitHub Pages Subdomain**: [https://ombharati.github.io/CYBERGUARD/](https://ombharati.github.io/CYBERGUARD/)
- **GitHub Repository**: [https://github.com/ombharati/CYBERGUARD](https://github.com/ombharati/CYBERGUARD)
