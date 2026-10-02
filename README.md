# CYBERGUARD

**Local-First AI Cybersecurity Threat, Phishing & Impersonation Detection**

`Cybersecurity` · `AI/ML` · `FastAPI` · `Laya` · `Qwen 3` · `PostgreSQL` · `Redis`

CYBERGUARD is a local-first cybersecurity platform combining deterministic heuristics with local neural models (**Laya** and **Qwen 3**) to deliver explainable, high-speed security assessments for URLs, emails, and suspicious content with zero mandatory cloud dependencies.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    HTML / CSS / JS Frontend                     │
│               (URL, Email, and Content Scan Modes)              │
└────────────────────────────────┬────────────────────────────────┘
                                 │ HTTP / JSON
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                          FastAPI API                            │
│           POST /api/v1/scans       GET /api/v1/scans/{id}       │
│           POST /api/scans          GET /api/scans               │
└─────────────────┬──────────────────────────────┬────────────────┘
                  │ Enqueue                      │ Read/Write
                  ▼                              ▼
      ┌───────────────────────┐      ┌────────────────────────┐
      │   Redis Job Queue     │      │   PostgreSQL Storage   │
      └───────────┬───────────┘      │ (scans, scan_findings) │
                  │ Dequeue          └────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Background Scan Worker                        │
│                                                                 │
│   1. Deterministic Heuristics (URL parsing, SSRF, keywords)     │
│   2. Laya Decision Engine (CPU - System 1 calibrated URL score) │
│   3. Qwen Semantic Analyzer (GPU via Ollama - System 2 insight) │
│   4. Optional External Intel (Isolated behind adapters)         │
│   5. Explainable Risk Engine (Deterministic 0–100 score)        │
└─────────────────────────────────────────────────────────────────┘
```

---

## AI Responsibilities & Hardware Strategy

Designed specifically for resource-conscious local execution (tested on RTX 3050 Laptop GPU 6 GB VRAM, 16 GB RAM):

| Model | Role | Runtime & Device | Purpose |
|---|---|---|---|
| **Laya** | URL Decision Model | **CPU** (`torch` / ModernBERT) | Fast System 1 calibrated probability classifier (~80ms). Never receives entire emails. |
| **Qwen 3 (8B)** | Semantic Analysis | **GPU** (Ollama `qwen3:8b`) | Deep System 2 contextual reasoning, urgency assessment, and explanation generation. |
| **Risk Engine** | Final Scoring | **Pure Deterministic Logic** | Synthesizes signals into an explainable 0–100 score. Never makes I/O or model calls. |

---

## Quickstart

> 🚀 **Quick Start**: Run `./scripts/start_server.sh` to automatically launch PostgreSQL, Redis, local AI models, FastAPI, the worker queue, and the public HTTPS tunnel.
>
> 🌐 **Live Web App**: [ombharati.github.io/CYBERGUARD](https://ombharati.github.io/CYBERGUARD/)  
> ⚡ **Live Server Subdomain**: [ali-caps-prostores-derby.trycloudflare.com](https://ali-caps-prostores-derby.trycloudflare.com)

### 1. Prerequisites
- Python 3.11+
- Docker & Docker Compose (for PostgreSQL and Redis)
- Ollama with `qwen3:8b` installed (`ollama run qwen3:8b`)

### 2. Start PostgreSQL & Redis
```bash
docker compose up -d postgres redis
```

### 3. Run Backend & Frontend Locally
```bash
# Setup virtual environment and dependencies
uv venv .venv
source .venv/bin/activate
uv pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start API server (serves frontend at http://localhost:8000)
python main.py
```

### 4. Run the Background Queue Worker (Optional for Async Queue)
```bash
python -m app.backend.services.worker
```

Open `http://localhost:8000` in your browser to interact with the CYBERGUARD dashboard.

---

## Automated Test Suite

CYBERGUARD includes 36 automated tests covering API validation, deterministic URL detection, SSRF protection, email parsing, AI adapters, risk scoring, queue fallback, and live integration:

```bash
# Run unit and API tests (fast)
pytest -k "not test_live_integration"

# Run complete test suite including live model integration
pytest
```

---

## API Endpoints

- `GET /health` — System status (Database, Redis, Ollama, Laya)
- `POST /api/v1/scans` — Queue a scan asynchronously (`?sync=true` for immediate result)
- `GET /api/v1/scans/{scan_id}` — Retrieve scan status and complete findings
- `GET /api/v1/scans` — List scan history
- `POST /api/scans` — Frontend compatibility endpoint (synchronous execution)
- `GET /api/scans` — Frontend scan history endpoint
- `GET /` — Serves the frontend user interface directly
