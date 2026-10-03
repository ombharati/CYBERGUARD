# Developer Guide & Local Workflow

This guide covers setting up your local environment, code conventions, test execution, and architectural rules for contributing to CYBERGUARD.

---

## 1. Environment Setup

### Prerequisites
- Linux / macOS (Fedora, Ubuntu, or Debian recommended)
- Python 3.11+ (Python 3.14 supported)
- Docker & Docker Compose
- [Ollama](https://ollama.com/) with model `qwen3:8b` (`ollama pull qwen3:8b`)

### Initial Workspace Setup
```bash
# Clone the repository
git clone https://github.com/ombharati/CYBERGUARD.git
cd CYBERGUARD

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install application and testing dependencies
pip install -r requirements.txt pytest pytest-asyncio

# Configure environment variables
cp .env.example .env
```

---

## 2. Directory Structure

```text
CYBERGUARD/
├── app/
│   ├── frontend/                 # Static vanilla JS, HTML, and CSS UI
│   └── backend/
│       ├── api/
│       │   ├── v1/               # Versioned REST endpoints (/api/v1/scans)
│       │   └── frontend_compat.py # Direct endpoints (/api/scans) for script.js
│       ├── core/                 # Config (pydantic-settings), DB engine, logging
│       ├── models/               # SQLAlchemy 2.0 models (Scan, ScanFinding)
│       ├── schemas/              # Pydantic validation models
│       └── services/
│           ├── ai/               # Laya (CPU) and Qwen (Ollama GPU) adapters
│           ├── external_intel.py # Non-blocking VirusTotal / urlscan adapters
│           ├── orchestrator.py   # Pipeline coordinator
│           ├── queue.py          # Redis job queue client
│           ├── risk_engine.py    # Pure mathematical risk calculation (0-100)
│           ├── scan_service.py   # Service layer coordinating DB and workers
│           └── worker.py         # Asynchronous background job consumer
├── database/
│   └── migrations/               # Alembic version migrations
├── detection/
│   ├── url/                      # URL feature extraction & SSRF checks
│   └── email/                    # RFC 822 parser & threat heuristics
├── infrastructure/
│   └── compose/                  # Docker Compose manifests
├── scripts/                      # Startup scripts (start_server.sh)
└── tests/                        # Automated unit and integration test suite
```

---

## 3. Testing Strategy

CYBERGUARD maintains a comprehensive **45-test** suite designed to run quickly without mandatory network or GPU access during CI:

### Running Fast Deterministic Unit Tests (~4 seconds)
These tests mock AI models and verify URL parsing, SSRF subnets, email heuristics, risk scoring math, and API route validation:
```bash
pytest -v \
  tests/test_url_detector.py \
  tests/test_email_detection.py \
  tests/test_risk_engine.py \
  tests/test_api.py \
  tests/test_ai_adapters.py \
  tests/test_worker_and_queue.py \
  tests/test_large_inputs.py
```

### Running Live Model Integration Tests (~30 seconds)
Requires running PostgreSQL, Redis, and host Ollama (`qwen3:8b`):
```bash
pytest -v tests/test_live_integration.py
```

### Mocking AI Models in Tests
The AI adapters support constructor dependency injection:
```python
from unittest.mock import AsyncMock
from app.backend.services.ai.laya_adapter import LayaAdapter
from app.backend.services.ai.qwen_adapter import QwenAdapter

# Mock Laya without loading ModernBERT
mock_laya = LayaAdapter(available=True)
mock_laya.analyze_url = lambda url: {"available": True, "signals": {"laya_phishing_probability": 0.05}, "findings": []}

# Mock Qwen without Ollama running
mock_qwen = QwenAdapter()
mock_qwen.analyze_content = AsyncMock(return_value={"available": True, "signals": {}, "findings": []})
```

---

## 4. Architectural Rules & Best Practices

1. **Deterministic First**: Always extract objective features (scheme, IP address, subdomain count, file extensions, keywords) before calling AI models.
2. **Strict Separation of Concerns**:
   - Routes (`app/backend/api/`) handle HTTP validation and response codes only.
   - The Risk Engine (`app/backend/services/risk_engine.py`) is a pure function: **zero I/O, no DB calls, no HTTP requests, no model calls**.
   - External intelligence services are strictly optional and must never fail a scan on timeout.
3. **Commit Messages**: Follow Conventional Commits format:
   - `feat(api): add export endpoint`
   - `fix(queue): resolve socket timeout`
   - `perf(ai): cache singleton encoder`
   - `docs(readme): update setup steps`
4. **Non-Blocking Reports**: Never re-introduce synchronous sequential Qwen calls in the scan pipeline. The latency budget is ~20s. Narrative reports are generated asynchronously via `_background_generate_report` and polled by the frontend.
5. **GPU Serialization**: All Ollama calls must be serialized through `_gpu_lock` to prevent VRAM OOM on the 6 GB RTX 3050.
