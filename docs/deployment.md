# Deployment & Operations Guide

CYBERGUARD is designed as a **local-first cybersecurity platform**. It can be deployed in three flexible configurations depending on the environment:
1. **Native Host Server + Public Tunnel (Recommended for Hackathons & Demos)**
2. **Containerized Stack via Docker Compose**
3. **Decoupled Frontend on GitHub Pages with Laptop AI Backend**

---

## 1. Hardware Architecture & Model Allocation

CYBERGUARD is optimized for developer laptops (specifically calibrated on an **NVIDIA GeForce RTX 3050 Laptop GPU with 6 GB VRAM and 16 GB System RAM**):

| Service | Runtime Location | Memory / VRAM Impact |
| :--- | :--- | :--- |
| **Qwen 3 (8B)** | GPU via Ollama (`http://localhost:11434`) | ~4.7 GB VRAM |
| **Laya (`ModernBERT-large`)** | Host CPU (`torch` / device="cpu") | ~800 MB System RAM, **0 MB VRAM** |
| **FastAPI Backend** | Host or Docker container (Port `8000`) | ~120 MB RAM |
| **Background Worker** | Host or Docker container (Python process) | ~100 MB RAM |
| **PostgreSQL 16** | Docker container (Port `5432`) | ~60 MB RAM |
| **Redis 7** | Docker container (Port `6379`) | ~30 MB RAM |

> **Why Laya runs on CPU:** Loading both Qwen 8B (~4.8 GB) and Laya (~1.5 GB) concurrently onto a 6 GB VRAM GPU causes Out-Of-Memory (OOM) crashes. Running Laya on CPU gives lightning-fast ~80ms forward passes while reserving the entire GPU for Qwen's deep semantic reasoning.

---

## 2. Option A: One-Click Native Start + Public HTTPS Tunnel

This is the fastest method to turn your machine into a live server accessible from any phone, laptop, or browser.

```bash
./scripts/start_server.sh
```

### Behind the Scenes:
1. Checks for `cyberguard-postgres` and `cyberguard-redis` Docker containers and starts them.
2. Verifies Ollama is listening at `http://localhost:11434` with model `qwen3:8b`.
3. Verifies the local Laya environment in `/home/om/laya-test`.
4. Starts the FastAPI server (`0.0.0.0:8000`) and the background queue worker.
5. Launches a Cloudflare Tunnel container that creates an instant, secure public HTTPS subdomain (e.g. `https://*.trycloudflare.com`).

---

## 3. Option B: Docker Compose Deployment

To run the API, worker, PostgreSQL, and Redis in isolated containers:

```bash
# Start all services in the background
docker compose -f infrastructure/compose/docker-compose.yml up -d

# Check running status and health checks
docker compose -f infrastructure/compose/docker-compose.yml ps

# View live API logs
docker compose -f infrastructure/compose/docker-compose.yml logs -f api
```

### Reaching Host AI Models from Inside Docker
Containers communicate with the host machine's Ollama and Laya using `host.docker.internal`:
- Inside `docker-compose.yml`, `extra_hosts: ["host.docker.internal:host-gateway"]` maps the Docker host IP.
- The API accesses Ollama at `http://host.docker.internal:11434`.

---

## 4. Option C: GitHub Pages Frontend + Remote Laptop Server

The frontend is a lightweight Single-Page Application (HTML, Vanilla CSS, JS) that can be hosted on GitHub Pages while connecting to your laptop's backend:

- **Deployed URL**: `https://ombharati.github.io/CYBERGUARD/`
- **Deployment Workflow**: Configured in `.github/workflows/deploy-pages.yml`. Any push affecting `app/frontend/` automatically deploys to GitHub Pages.
- **Connecting GitHub Pages to Your Laptop**:
  In `app/frontend/script.js`, `getApiBaseUrl()` automatically uses the active Cloudflare Tunnel URL or custom `localStorage` setting:
  ```javascript
  // Set custom backend URL in browser console if using a new tunnel:
  localStorage.setItem("cyberguard_api_url", "https://your-tunnel-subdomain.trycloudflare.com");
  ```

---

## 5. Operations & Troubleshooting

### Port Conflicts
If port 5432 or 6379 is already in use by a host service:
```bash
# Check what process owns port 5432
sudo lsof -i :5432

# Stop conflicting host PostgreSQL service
sudo systemctl stop postgresql
```

### Checking Logs
```bash
# PostgreSQL logs
docker logs --tail 50 cyberguard-postgres

# Redis logs
docker logs --tail 50 cyberguard-redis

# Background worker process status
ps aux | grep "app.backend.services.worker"
```

### Resetting Local Database
```bash
# Caution: deletes existing scan records
docker compose -f infrastructure/compose/docker-compose.yml down -v
docker compose -f infrastructure/compose/docker-compose.yml up -d postgres redis
alembic upgrade head
```
