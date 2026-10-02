# System Requirements & Specifications

CYBERGUARD is a local-first cybersecurity analysis engine designed to evaluate suspicious URLs, phishing emails, and raw digital text. It delivers fast, deterministic threat intelligence backed by localized neural models—operating entirely on commodity developer hardware without mandatory cloud subscriptions or third-party data leakage.

---

## 1. Problem Statement & Motivation

Modern security triage workflows frequently suffer from three primary bottlenecks:
1. **Cloud Latency & Subscription Costs**: Relying on external cloud APIs (e.g. VirusTotal, commercial sandbox vendors) for every suspicious link introduces multi-second network roundtrips and steep API tier expenses.
2. **Data Privacy & Compliance Risks**: Submitting internal emails, sensitive employee correspondence, or proprietary staging URLs to external cloud vendors violates corporate privacy policies and regulatory frameworks (e.g. GDPR, HIPAA).
3. **Over-Reliance on Probabilistic AI**: Using unconstrained Large Language Models directly to generate risk scores leads to hallucinated verdicts, prompt injection vulnerabilities, and unpredictable false positives.

CYBERGUARD solves this by combining **fast deterministic rule engines**, an **efficient CPU encoder (Laya)**, and an **on-device reasoning LLM (Qwen)** governed by a mathematical risk engine.

---

## 2. Hardware Budget & System Constraints

CYBERGUARD is calibrated to operate smoothly on developer laptops without thermal throttling or Out-Of-Memory (OOM) failures:

| Hardware Resource | Allocation / Budget | Role & Justification |
| :--- | :--- | :--- |
| **GPU (NVIDIA CUDA)** | 6.0 GB VRAM Total<br>(Target: ~4.7–5.2 GB used) | Exclusively reserved for Ollama running `qwen3:8b` (quantized GGUF Q4_K_M, 40k context window). |
| **System RAM** | 16.0 GB Total<br>(Target: ~2.5–3.5 GB used) | Accommodates Laya (`ModernBERT-large` taking ~800 MB on CPU), FastAPI process, PostgreSQL 16 container, Redis 7 container, and OS buffers. |
| **CPU Execution** | Multi-threaded CPU (`device="cpu"`) | Host-side execution for Laya inference (~80–120ms forward pass), regex parsing, and URL tokenization to prevent GPU VRAM contention. |
| **Storage** | ~8 GB Disk Space | Includes Ollama model weights (~5.2 GB), Hugging Face model cache (~804 MB), and Docker container images. |
| **Operating System** | Linux (Fedora, Ubuntu, Debian) or macOS | Direct POSIX socket support, low-overhead container virtualization, and local CUDA acceleration. |

---

## 3. Functional Requirements (FR)

### FR-1: Multi-Modal Target Intake & Normalization
- The system must accept three primary input types:
  - `url`: Single web addresses (HTTP, HTTPS).
  - `email`: Structured email objects (with `sender`, `subject`, and `body`) or raw RFC-822 formatted message headers and content.
  - `content`: Unstructured text excerpts, SMS/smishing messages, or customer support transcripts.
- Input must be normalized before processing: whitespace trimming, URL scheme resolution, email header extraction, and URL extraction from message bodies.

### FR-2: Deterministic Heuristic Detection
- Every scan must execute objective, deterministic pattern checks before any neural inference:
  - **URL Engine**: IP address literals as hostnames, excessive subdomains (>= 3), high Shannon entropy in paths/queries, suspicious Top-Level Domains (TLDs), credential harvester keywords (`login`, `verify`, `banking`, `secure`, `update`), homoglyph/typosquatting indicators, and SSRF subnet validation.
  - **Email Engine**: Display name vs. header mismatches, urgency markers (`immediate`, `suspended`, `unauthorized`), suspicious attachment extensions (`.exe`, `.scr`, `.vbs`, `.iso`, `.zip`), and extraction of all embedded hyperlinks.
- All detected patterns must be emitted as distinct, timestamped findings with associated severity tags (`low`, `medium`, `high`).

### FR-3: Tiered Local AI Intelligence
- **Tier 1 (Fast Classifier - Laya)**:
  - System 1 fast decision encoder running on CPU.
  - Receives compact, focused URL strings and lexical context.
  - Evaluates phishing probability and brand impersonation in under 150ms.
  - Generates normalized probability signals (`0.0` to `1.0`). Never receives entire raw email bodies.
- **Tier 2 (Deep Reasoner - Qwen)**:
  - System 2 contextual reasoning engine running on GPU via local Ollama (`qwen3:8b`).
  - Evaluates complex social engineering narratives, pretexting, urgency framing, and multi-link email bodies.
  - Emits structured JSON findings and plain-English narrative explanations.
  - Constrained by strict generation limits (max 200 tokens) to ensure rapid completion.

### FR-4: Centralized Mathematical Risk Engine
- Risk decisions must be decoupled from individual detectors.
- The Risk Engine must aggregate deterministic findings, neural probability signals, and optional external threat intel into a normalized composite score between `0` and `100`.
- The engine must enforce **hard compound rule floors**:
  - Confirmed SSRF / private network target: minimum score `75`.
  - Brand spoofing combined with credential keywords and urgency: minimum score `80`.
  - High neural phishing probability (> 0.85): minimum score `70`.
- Final scores must map deterministically to three standard classification tiers:
  - `Safe`: Score `0` to `44`
  - `Suspicious`: Score `45` to `74`
  - `High Risk`: Score `75` to `100`

### FR-5: Audit Trail & Scan Persistence
- Every completed or failed scan must be persisted to PostgreSQL 16.
- The schema must store parent scan metadata (ID, target, score, classification, summary, signals, duration) and child findings (severity, title, description, category) with foreign key cascade guarantees.
- The API must support querying scan history and individual scan reports by ID.

### FR-6: Telemetry & Executive Reporting
- Reports must provide an executive summary, granular findings list, human-readable explanation, and multidimensional radar telemetry:
  - Pattern analysis (deterministic rule strength)
  - Content indicators (lexical/semantic triggers)
  - Risk aggregation (composite weighted score)
  - Reputation signals (domain/IP pedigree)

---

## 4. Non-Functional Requirements (NFR)

### NFR-1: Performance & Latency Budgets
- **Fast Deterministic Path**: Scans relying purely on heuristics and Laya CPU inference must complete in **under 250 milliseconds**.
- **Deep Reasoning Path**: Scans requiring Qwen GPU evaluation must complete in **under 4.0 seconds**.
- **Database Query Latency**: Scan history retrieval must return in **under 15 milliseconds** via indexed queries.

### NFR-2: Offline Independence & Zero-Cloud Mandate
- The system must function completely without internet access.
- Optional external intelligence adapters (VirusTotal, urlscan) must have strict 5-second timeouts and run in non-blocking async tasks.
- If an external adapter fails or is unreachable, the core scan must finish successfully using local detection logic.

### NFR-3: Asynchronous Queueing & Concurrency
- The system must support both direct synchronous execution and decoupled queue-based processing via Redis 7.
- Under heavy burst loads, incoming requests must be accepted with HTTP `202 Accepted` and enqueued for worker execution, preventing HTTP connection starvation.
- If Redis is unavailable, the application must gracefully degrade to in-process synchronous execution.

### NFR-4: Data Privacy & Security Guardrails
- **No Remote Telemetry**: Analyzed employee emails, credentials, and network URLs must never be transmitted to external telemetry endpoints.
- **SSRF Immunity**: The system must never initiate HTTP requests or DNS queries to private networks, loopback addresses, or cloud metadata endpoints.
- **Prompt Injection Resilience**: User content passed to LLMs must be isolated inside structured quotation envelopes. LLMs cannot modify risk scores or dismiss objective security findings.

---

## 5. Explicit Non-Goals & System Boundaries

To maintain focus and high operational reliability, CYBERGUARD explicitly defines what it is **not**:

1. **Not an Active Network Proxy or Firewall**: CYBERGUARD does not perform inline packet filtering or automated DNS blackhole routing. It acts as an analysis and triage service called by upstream mail transfer agents (MTAs), webhooks, or SOC analysts.
2. **Not a Dynamic Malware Sandbox**: CYBERGUARD analyzes textual, lexical, and structural features of URLs, emails, and content. It does not spin up Windows virtual machines or execute compiled binaries (`.exe`, `.dll`, `.elf`).
3. **Not a Full-Scale SIEM**: While CYBERGUARD maintains a complete history of its own scans, it does not ingest syslog feeds, firewall traffic logs, or endpoint EDR telemetry.
