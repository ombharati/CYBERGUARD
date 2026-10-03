# CYBERGUARD Architecture

## 1. Architectural Overview

CYBERGUARD follows a layered architecture where each subsystem has a defined responsibility.

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
│  Request Validation  │  Routing  │  Error Handling  │ CORS  │
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
│       Findings │ Evidence │ Explanation │ Final Result      │
└────────────────────────────┬────────────────────────────────┘
                             │
                    ┌────────┴────────┐
                    ▼                 ▼
              PostgreSQL          API Response
                    │                 │
                    ▼                 ▼
               Scan History        Frontend
                                     │
                              (polls for report
                               upgrade via
                               /report endpoint)
```

### Two-Phase Report Generation

1. **Phase 1 (Synchronous)**: Upon scan completion, a deterministic **template-based report** is generated instantly from findings, signals, and metadata. This is stored as the initial `report_text` and the scan is marked `completed`.
2. **Phase 2 (Asynchronous)**: A background task (`_background_generate_report`) calls Qwen to produce a **plain-English narrative report** (~400–600 words). When ready, it replaces the template in the database. The frontend polls `GET /api/scans/{id}/report` to transparently upgrade the displayed report.

---

## 2. Layer Responsibilities

| Layer | Responsibility |
|---|---|
| **Client** | Collect input and present analysis results |
| **API** | Validate requests, expose endpoints, return structured responses |
| **Services** | Coordinate the analysis workflow |
| **Detection** | Generate deterministic findings from input |
| **Intelligence** | Provide AI, DNS, reputation, and external signals |
| **Risk Engine** | Normalize and combine signals into the final risk assessment |
| **Reporting** | Convert analysis results into a consistent report |
| **Database** | Persist scans and findings |

Each layer should depend on defined interfaces rather than implementation details of another layer.

---

## 3. Analysis Pipeline

A scan moves through the system in a fixed logical sequence:

```text
Input
  │
  ▼
Validation
  │
  ▼
Normalization
  │
  ▼
Signal Extraction
  │
  ├───────────────┬────────────────┐
  ▼               ▼                ▼
Rules             AI          External Intel
  │               │                │
  └───────────────┴────────────────┘
                  │
                  ▼
            Signal Normalization
                  │
                  ▼
             Risk Engine
                  │
          ┌───────┴────────┐
          ▼                ▼
       Findings          Score
          │                │
          └───────┬────────┘
                  ▼
              Classification
                  │
                  ▼
               Report
                  │
          ┌───────┴───────┐
          ▼               ▼
      PostgreSQL       API Response
```

The pipeline separates **detection** from **decision-making**.

Detection produces evidence. The Risk Engine determines how that evidence contributes to the final assessment.

---

## 4. Component Boundaries

### API

Owns:

```text
HTTP
Request validation
Response schemas
Routing
Error handling
```

Does not own detection logic or scoring formulas.

### Service Layer

Owns:

```text
Scan orchestration
Dependency coordination
Analysis workflow
Persistence coordination
```

It determines **which components execute and in what order**.

### Detection

Owns:

```text
URL rules
Email heuristics
Content indicators
Domain analysis
Finding generation
```

A detector should return structured findings rather than directly modifying the final risk score.

### Intelligence Adapters

External systems are isolated behind adapters.

```text
                Internal Interface
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   Laya Adapter   Qwen Adapter   VirusTotal
   (CPU)           (GPU/Ollama)      Adapter       urlscan
```

The rest of CYBERGUARD should not depend directly on external SDKs.

---

## 5. Risk Engine

The Risk Engine is the central decision boundary.

```text
              Detection Findings
                      │
                      │
                AI Signals
                      │
                      │
              External Signals
                      │
                      ▼
             ┌─────────────────┐
             │  Normalization   │
             └────────┬────────┘
                      ▼
             ┌─────────────────┐
             │   Aggregation   │
             └────────┬────────┘
                      ▼
                Score 0–100
                      │
                      ▼
               Classification
                      │
                      ▼
                  Report
```

Its responsibilities are limited to:

1. Normalize heterogeneous signals.
2. Apply the scoring model.
3. Produce the composite score.
4. Map the score to a classification.
5. Preserve the evidence used to reach the result.

It should not perform HTTP requests, database operations, or model inference.

---

## 6. Data Model

The initial persistence model contains two core entities:

```text
┌──────────────────────┐
│        scans         │
├──────────────────────┤
│ id                   │
│ input_type           │
│ input_data           │
│ risk_score           │
│ classification       │
│ summary              │
│ explanation          │
│ status               │
│ created_at           │
└──────────┬───────────┘
           │
           │ 1:N
           ▼
┌──────────────────────┐
│    scan_findings     │
├──────────────────────┤
│ id                   │
│ scan_id              │
│ severity             │
│ title                │
│ description          │
│ created_at           │
└──────────────────────┘
```

The schema is intentionally limited until the core scan lifecycle is stable.

---

## 7. Dependency Direction

Dependencies should flow toward internal application abstractions.

```text
Frontend
   │
   ▼
API
   │
   ▼
Services
   │
   ├──────────────► Detection
   │
   ├──────────────► Intelligence Interfaces
   │                         │
   │                         ├── Laya
   │                         ├── VirusTotal
   │                         └── urlscan
   │
   ├──────────────► Risk Engine
   │
   └──────────────► Persistence
```

External implementations remain at the boundary.

This prevents vendor-specific models, response formats, and failures from propagating through the application.

---

## 8. Failure Boundaries

Optional dependencies must not become mandatory failure points.

```text
                    Scan
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
        Rules       Laya     Threat Intel
          │          │          │
          │          X          X
          │       unavailable  timeout
          │          │          │
          └──────────┴──────────┘
                     │
                     ▼
                Risk Engine
                     │
                     ▼
               Valid Report
```

Local deterministic analysis should remain capable of producing a result when optional intelligence providers are unavailable.

---

## 9. Context-Aware Detection Philosophy

Detection rules follow a **context-aware** rather than **keyword-matching** model.

A signal like `/login` in a URL path is only meaningful when combined with a domain or behavior mismatch. Each rule asks three questions:

1. **Identity Check**: Does the domain match the claimed brand?
2. **Behavior Check**: Is this action expected in context?
3. **Request Check**: Is something being asked that a real service wouldn't ask?

If all three are clean, the keyword is noise. This prevents false positives on legitimate banking, SaaS, and payment URLs.
