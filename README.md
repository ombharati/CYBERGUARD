# CYBERGUARD

A local-first, privacy-preserving cybersecurity analysis platform designed for security analysts and developers to investigate suspicious URLs, emails, authentication logs, and digital content without sending sensitive data to external clouds.

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
