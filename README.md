# CYBERGUARD

A local-first, privacy-preserving cybersecurity analysis platform designed for security analysts and developers to investigate suspicious URLs, emails, authentication logs, and digital content without sending sensitive data to external clouds.

subgraph group_entry["User Entry"]
  node_frontend["Web Dashboard<br/>[script.js]"]
  node_api["FastAPI Application<br/>[main.py]"]
  node_v1api["Scan API<br/>[scans.py]"]
  node_compatapi["Compatibility API<br/>[frontend_compat.py]"]
  node_schemas["Request Schemas<br/>[scan.py]"]
end

subgraph group_lifecycle["Scan Lifecycle"]
  node_service["Scan Service<br/>[scan_service.py]"]
  node_queue["Redis Job Queue<br/>[queue.py]"]
  node_worker["Background Worker<br/>[worker.py]"]
  node_orchestrator["Scan Orchestrator<br/>[orchestrator.py]"]
end

subgraph group_analysis["Threat Analysis"]
  node_url["URL Heuristics<br/>[detector.py]"]
  node_ssrf["SSRF Validation<br/>[ssrf.py]"]
  node_emailparser["Email Parser<br/>[parser.py]"]
  node_emailheuristics["Email Heuristics<br/>[heuristics.py]"]
  node_risk["Risk Engine<br/>[risk_engine.py]"]
  node_intel["External Threat Intel<br/>[external_intel.py]"]
end

subgraph group_persistence["Storage and Config"]
  node_config["Runtime Settings<br/>[config.py]"]
  node_database["Database Sessions<br/>[database.py]"]
  node_models[("Scan Records<br/>[scan.py]")]
end

subgraph group_integrations["Model Integrations"]
  node_laya["Laya Adapter<br/>[laya_adapter.py]"]
  node_qwen["Qwen Adapter<br/>[qwen_adapter.py]"]
end

node_user(("User / Browser"))
node_ollama["Ollama Service"]
node_postgres[("PostgreSQL")]
node_redis[("Redis")]

node_user -->|"uses"| node_frontend
node_frontend -->|"sends HTTP scans"| node_api
node_api -->|"routes requests"| node_v1api
node_api -->|"routes requests"| node_compatapi
node_api -->|"serves assets"| node_frontend
node_v1api -->|"validates and responds"| node_schemas
node_v1api -->|"delegates scans"| node_service
node_compatapi -->|"validates and responds"| node_schemas
node_compatapi -->|"delegates scans"| node_service
node_service -->|"creates scan"| node_models
node_service -->|"executes synchronously"| node_orchestrator
node_service -->|"enqueues scan"| node_queue
node_worker -->|"dequeues scan"| node_queue
node_worker -->|"executes scan"| node_orchestrator
node_orchestrator -->|"analyzes URLs"| node_url
node_url -->|"validates host"| node_ssrf
node_orchestrator -->|"parses email"| node_emailparser
node_orchestrator -->|"checks email"| node_emailheuristics
node_emailheuristics -->|"uses parsed email"| node_emailparser
node_orchestrator -->|"scores URLs"| node_laya
node_orchestrator -->|"analyzes content"| node_qwen
node_orchestrator -.->|"queries intelligence"| node_intel
node_orchestrator -->|"calculates risk"| node_risk
node_orchestrator -->|"persists findings"| node_models
node_qwen -->|"requests inference"| node_ollama
node_api -->|"loads settings"| node_config
node_api -->|"checks database"| node_database
node_database -->|"configures connection"| node_config
node_models -->|"uses ORM base"| node_database
node_database -->|"connects to"| node_postgres
node_queue -->|"stores jobs"| node_redis
node_api -->|"checks availability"| node_queue

click node_frontend "https://github.com/ombharati/cyberguard/blob/main/app/frontend/script.js"
click node_api "https://github.com/ombharati/cyberguard/blob/main/app/backend/main.py"
click node_v1api "https://github.com/ombharati/cyberguard/blob/main/app/backend/api/v1/scans.py"
click node_compatapi "https://github.com/ombharati/cyberguard/blob/main/app/backend/api/frontend_compat.py"
click node_schemas "https://github.com/ombharati/cyberguard/blob/main/app/backend/schemas/scan.py"
click node_service "https://github.com/ombharati/cyberguard/blob/main/app/backend/services/scan_service.py"
click node_queue "https://github.com/ombharati/cyberguard/blob/main/app/backend/services/queue.py"
click node_worker "https://github.com/ombharati/cyberguard/blob/main/app/backend/services/worker.py"
click node_orchestrator "https://github.com/ombharati/cyberguard/blob/main/app/backend/services/orchestrator.py"
click node_url "https://github.com/ombharati/cyberguard/blob/main/detection/url/detector.py"
click node_ssrf "https://github.com/ombharati/cyberguard/blob/main/detection/url/ssrf.py"
click node_emailparser "https://github.com/ombharati/cyberguard/blob/main/detection/email/parser.py"
click node_emailheuristics "https://github.com/ombharati/cyberguard/blob/main/detection/email/heuristics.py"
click node_risk "https://github.com/ombharati/cyberguard/blob/main/app/backend/services/risk_engine.py"
click node_intel "https://github.com/ombharati/cyberguard/blob/main/app/backend/services/external_intel.py"
click node_laya "https://github.com/ombharati/cyberguard/blob/main/app/backend/services/ai/laya_adapter.py"
click node_qwen "https://github.com/ombharati/cyberguard/blob/main/app/backend/services/ai/qwen_adapter.py"
click node_config "https://github.com/ombharati/cyberguard/blob/main/app/backend/core/config.py"
click node_database "https://github.com/ombharati/cyberguard/blob/main/app/backend/core/database.py"
click node_models "https://github.com/ombharati/cyberguard/blob/main/app/backend/models/scan.py"

classDef toneNeutral fill:#f8fafc,stroke:#334155,stroke-width:1.5px,color:#0f172a
classDef toneBlue fill:#dbeafe,stroke:#2563eb,stroke-width:1.5px,color:#172554
classDef toneAmber fill:#fef3c7,stroke:#d97706,stroke-width:1.5px,color:#78350f
classDef toneMint fill:#dcfce7,stroke:#16a34a,stroke-width:1.5px,color:#14532d
classDef toneRose fill:#ffe4e6,stroke:#e11d48,stroke-width:1.5px,color:#881337
classDef toneIndigo fill:#e0e7ff,stroke:#4f46e5,stroke-width:1.5px,color:#312e81
classDef toneTeal fill:#ccfbf1,stroke:#0f766e,stroke-width:1.5px,color:#134e4a
class node_frontend,node_api,node_v1api,node_compatapi,node_schemas,node_user toneBlue
class node_service,node_queue,node_worker,node_orchestrator,node_postgres,node_redis toneAmber
class node_url,node_ssrf,node_emailparser,node_emailheuristics,node_risk,node_intel toneMint
class node_config,node_database,node_models toneRose
class node_laya,node_qwen,node_ollama toneIndigo

## What it does
- **URL Threat Analysis**: Detects lookalike domains, brand impersonation, high-entropy paths, homoglyphs, credential harvester patterns, and RFC 1918 / loopback SSRF attempts.
- **Email Phishing Inspection**: Parses RFC 822 and structured emails, extracting embedded links, urgency markers, wire transfer keywords, and malicious attachment indicators.
- **Identity & Header Verification**: Audits raw email headers for SPF, DKIM, and DMARC alignment, display name spoofing, and Reply-To diversions.
- **Authentication Log Analysis**: Ingests system and auth logs to identify brute-force bursts, distributed password spraying, impossible travel, and privilege escalation events.
- **Plain-English Security Reports**: Automatically synthesizes findings into an executive summary, itemized evidence weights, and actionable remediation steps.

## Architecture
CYBERGUARD is built around a decoupled pipeline that separates deterministic signal extraction, neural inference, and risk scoring into isolated boundaries.

```text
┌─────────────────────────────────────────────────────────────┐
│                         CLIENT                              │
│              HTML / CSS / JavaScript Frontend               │
└────────────────────────────┬────────────────────────────────┘
                             │
                         HTTP / JSON
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                         API LAYER                            │
│                         FastAPI                              │
│                                                             │
│ API Key Auth │ Request Validation │ Routing │ Error Handling│
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                       SERVICE LAYER                          │
│                                                             │
│                    Scan Orchestrator                         │
│                             │                               │
│          ┌──────────────────┼──────────────────┐            │
│          ▼                  ▼                  ▼            │
│     URL Analysis       Email Analysis     Content Analysis │
└──────────┬──────────────────┬──────────────────┬────────────┘
           │                  │                  │
           └──────────────────┼──────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      DETECTION LAYER                         │
│                                                             │
│  Heuristic Rules │ Domain Analysis │ Pattern Detection      │
└────────────────────────────┬────────────────────────────────┘
                             │
                             │ Findings / Signals
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                     INTELLIGENCE LAYER                       │
│                                                             │
│  Laya Adapter │ Qwen Adapter │ Threat Intel │ DNS Analysis   │
└────────────────────────────┬────────────────────────────────┘
                             │
                             │ Normalized Signals
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                       RISK ENGINE                            │
│                                                             │
│  Signal Normalization → Aggregation → Score → Classification│
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                       REPORTING                              │
│                                                             │
│  Template Report (Instant) │ Narrative Report (Qwen Async)  │
└─────────────────────────────────────────────────────────────┘
```

- **Client**: Vanilla HTML/CSS/JavaScript single-page interface with live status polling and report exports.
- **API Layer**: FastAPI application providing REST endpoints, input validation, and optional API key middleware.
- **Service Layer**: Scan orchestrator managing synchronous and asynchronous scan execution via Redis and workers.
- **Detection Layer**: Deterministic rules extracting structural indicators, Shannon entropy, homoglyphs, and SSRF.
- **Intelligence Layer**: Local model adapters (Laya on CPU, Qwen on GPU via Ollama) and optional threat intelligence.
- **Risk Engine**: Deterministic synthesis engine aggregating verified evidence into a 0–100 risk score and tier.
- **Reporting**: Immediate template report generation followed by asynchronous plain-English narrative reports.

## The two models

| Component | Architecture & Runtime | Role | Characteristics |
|---|---|---|---|
| **Laya** | ModernBERT-large (CPU) | URL Classifier | Fast (~80ms), structured signals only (phishing probability, brand impersonation). |
| **Qwen 3 8B** | Quantized 8B via Ollama (GPU) | Semantic Threat Reasoner | Contextual reasoning, intent analysis, and narrative report generation. |
| **Risk Engine** | Pure Python Logic (No I/O) | Final Scoring & Classification | Mathematical aggregation and evidence weighting. No model calls. |

Neither model decides the final score. The Risk Engine does.

## How to run

### Option A: Docker Compose (Recommended)
Spins up PostgreSQL, Redis, FastAPI, and the background worker in an isolated network:

```bash
docker compose up -d
```
The application dashboard is available at `http://localhost:8000`.

To stop all services:
```bash
docker compose down
```

### Option B: Local / Manual Execution

1. **Prerequisites & Infrastructure**:
   Ensure PostgreSQL, Redis, and Ollama are running locally:
   ```bash
   docker compose up -d postgres redis
   ollama run qwen3:8b
   ```

2. **Environment & Dependencies**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Database Migrations**:
   ```bash
   alembic upgrade head
   ```

4. **Start API Server**:
   ```bash
   python main.py
   ```

5. **Start Background Worker** (in a separate terminal):
   ```bash
   python -m app.backend.services.worker
   ```

### Environment Variables
Configure via `.env` or system environment variables:
- `DATABASE_URL` — PostgreSQL connection string (default: `postgresql+psycopg://cyberguard:cyberguard@localhost:5432/cyberguard`)
- `REDIS_URL` — Redis connection string (default: `redis://localhost:6379/0`)
- `OLLAMA_BASE_URL` — Ollama API endpoint (default: `http://localhost:11434`)
- `OLLAMA_MODEL` — Ollama model name (default: `qwen3:8b`)
- `API_KEY` — Optional shared-secret API key required via `X-API-Key` header (default: unset / disabled)
- `ALLOWED_ORIGINS` — Allowed CORS origins (default: `*`)

## Design decisions
- **Detection produces evidence; Risk Engine decides**: Models and heuristic detectors output raw evidence observations; the deterministic Risk Engine computes scores and bounds.
- **Local-first AI (no data leaves the machine)**: Sensitive URLs, credentials, and internal logs are processed entirely on-device with zero telemetry sent to cloud LLM providers.
- **Failure boundaries**: If Ollama or Laya is offline or times out, the engine gracefully falls back to deterministic heuristics without breaking the scan.
- **Explainable**: Every finding displays its exact contributing weight and supporting signal evidence, avoiding black-box verdicts.

## Limitations
- Qwen 8B is small and occasionally produces observations that fail evidence validation against the submitted input.
- Laya's confidence score is uncalibrated out of the box and requires local threshold tuning.
- Designed as a single-user security analyst tool, not for multi-tenant high-throughput production workloads.
- External threat intelligence adapters (e.g., VirusTotal, URLScan) are optional and disabled by default.

## Tech stack
Python, FastAPI, PostgreSQL, Redis, background worker, Ollama, vanilla JS frontend, Docker Compose.

## License
MIT
