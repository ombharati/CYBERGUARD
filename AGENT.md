# CYBERGUARD — AI Agent Context & Guide

## 1. Project Overview & Mission
- **Name**: CYBERGUARD
- **Type**: Local-first Cybersecurity Analysis Platform (Hackathon Project).
- **Core Philosophy**: Fast, reliable, deterministic detection backed by local AI, with zero mandatory cloud dependencies. External threat intelligence (VirusTotal, urlscan, etc.) is strictly optional and must never fail a core scan.
- **Design Philosophy**: Prefer simple, solid, maintainable architecture over unnecessary enterprise complexity.

---

## 2. Hardware Environment & Resource Allocation
- **Machine**: Laptop with NVIDIA GeForce RTX 3050 Laptop GPU (6 GB VRAM total), 16 GB System RAM.
- **OS**: Linux (Fedora 44 / x86_64).
- **VRAM Strategy (Crucial)**:
  - **Qwen (`qwen3:8b`)**: Runs on **GPU (CUDA)** via **Ollama** (`http://localhost:11434`). The 8B quantized model requires ~4.5–5.2 GB VRAM.
  - **Laya (`ModernBERT-large`)**: Runs on **CPU** (`device="cpu"`). Laya is a non-autoregressive encoder (System 1 fast decision engine) taking only ~800MB RAM and runs in ~50–150ms on CPU. Running it on CPU avoids VRAM Out-Of-Memory (OOM) contention on the 6 GB RTX 3050.

---

## 3. Local AI Models
### Laya (System 1 Fast Decision Engine)
- **Location**: Installed in `/home/om/laya-test` (`.venv`).
- **Cached Weights**: `/home/om/.cache/huggingface/hub/models--convaiinnovations--laya` (~804 MB ModernBERT-large backbone).
- **Available Presets**: `guard` (jailbreak, prompt injection, sensitive data), `email` (phishing, spam, urgency), `triage`, `moderation`.
- **Invocation**: Direct Python import (`from laya import Agent, guard_questions, email_questions`) or CLI (`laya --preset guard --device cpu`).

### Qwen (System 2 Deep Reasoning & Reporting)
- **Runtime**: Ollama 0.33.2.
- **Exact Model Tag**: `qwen3:8b` (Format: GGUF Q4_K_M, size: 5.2 GB, context: 40k).
- **Endpoint**: `http://localhost:11434/api/generate` or `/api/chat`.
- **Role**: Explaining threats, correlating multiple suspicious indicators, and generating executive/technical summaries for end-users.

### Ollama Configuration (VRAM Optimization)
To prevent VRAM exhaustion on the 6GB RTX 3050 during concurrent scans, Ollama must be configured to process one request at a time and keep only one model loaded. This is enforced via systemd override at `/etc/systemd/system/ollama.service.d/override.conf`:

```ini
[Service]
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
```

**Why these are set:**
- `OLLAMA_NUM_PARALLEL=1`: Prevents the KV cache from being duplicated across concurrent requests, stopping OOM crashes.
- `OLLAMA_MAX_LOADED_MODELS=1`: Ensures only Qwen is resident in memory.
- `OLLAMA_FLASH_ATTENTION=1`: Reduces VRAM usage via Flash Attention.
- `OLLAMA_KV_CACHE_TYPE=q8_0`: Halves KV cache footprint with minimal quality loss.

**How to revert (e.g., for larger GPUs):**
Run `sudo rm /etc/systemd/system/ollama.service.d/override.conf`, then `sudo systemctl daemon-reload` and `sudo systemctl restart ollama`.

---

## 4. Frontend & API Contract
- **Frontend Location**: `app/frontend/` (served or opened via `index.html`).
  - Supports 3 modes: `url`, `email`, `content`.
  - Has built-in offline mock fallback if the backend is unavailable.
- **Expected Endpoints**:
  - `GET /health` -> `{ "status": "ok" }`
  - `POST /api/scans` -> Accepts:
    ```json
    {
      "input_type": "url" | "email" | "content",
      "data": "string or email object {sender, subject, body}"
    }
    ```
  - Response Schema:
    ```json
    {
      "id": "CG-001",
      "type": "URL" | "Email" | "Content",
      "target": "string",
      "score": 75,
      "classification": "Safe" | "Suspicious" | "High Risk",
      "summary": "string",
      "findings": [
        { "severity": "low" | "medium" | "high", "title": "...", "description": "..." }
      ],
      "signals": [
        { "name": "Pattern analysis", "value": 75 },
        { "name": "Content indicators", "value": 70 },
        { "name": "Risk aggregation", "value": 75 }
      ],
      "explanation": "string",
      "timestamp": "ISO-8601 string"
    }
    ```
  - `GET /api/scans` -> Returns array of past scans (history).

- **Authentication (API Key)**:
  - If the `CYBERGUARD_API_KEY` env var is set on the backend, all `/api/v1/scans` endpoints require an `X-API-Key` header matching the value.
  - The frontend can be configured via the Settings modal or by appending `?key=YOUR_KEY` to the URL. The key is stored in `localStorage` as `cyberguard_api_key`.
  - The `/health` endpoint is always exempt from authentication.

---

## 5. Technology Stack & Tools
- **Backend**: FastAPI (Python 3.14 / uv).
- **Database**: PostgreSQL (Docker container).
- **Queue/Cache**: Redis (eventual scan queue / caching via Docker).
- **Package Management**: `uv` or project venv.
- **Containerization**: Docker Compose (`infrastructure/compose/docker-compose.yml`).

---

## 6. Access Control & Tunneling (Hackathon Demo)
To make the local API accessible to the GitHub Pages frontend during a live demo, it is exposed via a Cloudflare Quick Tunnel.

### Configuration
Start the tunnel with the following command:
```bash
cloudflared tunnel --url http://localhost:8000
```

### Access & Protection
- **No Access Control**: The quick tunnel URL is public by design to reduce demo friction.
- **Protection**: The API semaphore (Layer 1) and Ollama configuration (Layer 2) are the primary protections against concurrent load, preventing GPU exhaustion even if the URL is accessed globally.
- **URL Changes**: The quick tunnel URL is ephemeral and changes on every restart. You must update the GitHub Pages frontend (via the settings modal) with the new URL each time the tunnel is restarted.

---

## 6. Directory Structure
```text
CYBERGUARD/
├── AGENT.md               # Context & instructions for AI assistants
├── app/
│   ├── frontend/          # HTML/CSS/JS user interface
│   └── backend/           # FastAPI application
│       ├── api/           # Endpoints and routers
│       ├── core/          # Config, logging, security
│       ├── models/        # SQLAlchemy / SQLModel database models
│       ├── schemas/       # Pydantic request/response schemas
│       └── services/      # Business logic & scan orchestrators
├── database/              # Schema definitions and migrations
├── detection/             # Deterministic detection engines (URL, domain, email, heuristics)
├── docs/                  # Architecture and specs
├── infrastructure/        # Docker and docker-compose configurations
└── tests/                 # Unit and integration test suites
```

# Project Memory — CYBERGUARD
> 20 notes | Score threshold: >40

## Safety — Never Run Destructive Commands

> Dangerous commands are actively monitored.
> Critical/high risk commands trigger error notifications in real-time.

- **NEVER** run `rm -rf`, `del /s`, `rmdir`, `format`, or any command that deletes files/directories without EXPLICIT user approval.
- **NEVER** run `DROP TABLE`, `DELETE FROM`, `TRUNCATE`, or any destructive database operation.
- **NEVER** run `git push --force`, `git reset --hard`, or any command that rewrites history.
- **NEVER** run `npm publish`, `docker rm`, `terraform destroy`, or any irreversible deployment/infrastructure command.
- **NEVER** pipe remote scripts to shell (`curl | bash`, `wget | sh`).
- **ALWAYS** ask the user before running commands that modify system state, install packages, or make network requests.
- When in doubt, **show the command first** and wait for approval.

**Stack:** Unknown stack

## 📝 NOTE: 1 uncommitted file(s) in working tree.\n\n## Project Standards

- convention in .gitignore
- Version your API from day 1 (/api/v1/)
- Use consistent response format across all endpoints
- Implement soft delete for important data — don't hard delete without confirmation
- Handle timezone correctly — store UTC, display in user's timezone
- Make layouts responsive from the start — mobile-first approach
- Disable submit button during form submission — prevent double-submit
- Always add empty states ("No items yet" with call-to-action)

## Verified Best Practices

- Agent generates new migration for every change (squash related changes)
- Agent installs packages without checking if already installed

## Available Tools (ON-DEMAND only)
- `sys_core_01(q)` — Deep search when stuck
- `sys_core_05(query)` — Full-text lookup
> Context above IS your context. Do NOT call sys_core_14() at startup.
