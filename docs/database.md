# Database Architecture & Schema

CYBERGUARD uses **PostgreSQL 16** as its primary persistence engine. The schema is intentionally kept normalized, compact, and relational, separating high-level scan records from their detailed individual findings while supporting flexible telemetry through JSON columns.

---

## 1. Entity Relationship Overview

```text
┌─────────────────────────────────┐
│              scans              │
├─────────────────────────────────┤
│ id (PK, VARCHAR)                │◄───┐
│ input_type (VARCHAR)            │    │
│ target (TEXT)                   │    │ 1-to-Many
│ status (VARCHAR)                │    │ (CASCADE DELETE)
│ risk_score (INTEGER)            │    │
│ classification (VARCHAR)        │    │
│ summary (TEXT)                  │    │
│ explanation (TEXT)              │    │
│ signals (JSON)                  │    │
│ error_message (TEXT)            │    │
│ retries (INTEGER)               │    │
│ created_at (TIMESTAMPTZ)        │    │
│ updated_at (TIMESTAMPTZ)        │    │
└─────────────────────────────────┘    │
                                       │
┌─────────────────────────────────┐    │
│          scan_findings          │    │
├─────────────────────────────────┤    │
│ id (PK, INTEGER)                │    │
│ scan_id (FK, VARCHAR)           │────┘
│ severity (VARCHAR)              │
│ title (VARCHAR)                 │
│ description (TEXT)              │
│ category (VARCHAR)              │
│ created_at (TIMESTAMPTZ)        │
└─────────────────────────────────┘
```

---

## 2. Table Definitions

### 2.1 `scans`
Stores the overall scan execution metadata, user input target, aggregated risk metrics, and synthesized executive summary.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `VARCHAR(32)` | `PRIMARY KEY` | Custom identifier formatted as `CG-<8-hex-chars>` (e.g. `CG-B85CBFEB`). |
| `input_type` | `VARCHAR(16)` | `NOT NULL` | Analysis category: `URL`, `EMAIL`, or `CONTENT`. Indexed for filtering. |
| `target` | `TEXT` | `NOT NULL` | Sanitized submitted URL, email subject/sender, or content excerpt. |
| `status` | `VARCHAR(16)` | `NOT NULL`, `DEFAULT 'queued'` | Scan lifecycle state: `queued`, `processing`, `completed`, `failed`. |
| `risk_score` | `INTEGER` | `NOT NULL`, `DEFAULT 0` | Final aggregated score between `0` and `100`. |
| `classification` | `VARCHAR(16)` | `NOT NULL`, `DEFAULT 'Safe'` | Risk label: `Safe` (0–44), `Suspicious` (45–74), `High Risk` (75–100). |
| `summary` | `TEXT` | `NULLABLE` | Concise sentence describing key warning signs or benign baseline. |
| `explanation` | `TEXT` | `NULLABLE` | Detailed narrative analysis explaining the risk verdict to end users. |
| `signals` | `JSON` | `NULLABLE` | Structured array of radar telemetry (e.g. `[{"name": "Pattern analysis", "value": 70}]`). |
| `error_message` | `TEXT` | `NULLABLE` | Stack trace or exception message if the scan status is `failed`. |
| `retries` | `INTEGER` | `NOT NULL`, `DEFAULT 0` | Number of worker execution attempts before marking permanently failed. |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL` | Timestamp scan was submitted (UTC). Indexed for history ordering. |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL` | Timestamp of last status change or result persistence (UTC). |

---

### 2.2 `scan_findings`
Stores granular, individual threat findings produced by deterministic detectors, Laya, or Qwen.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `INTEGER` | `PRIMARY KEY`, Auto-increment | Unique finding ID. |
| `scan_id` | `VARCHAR(32)` | `FK -> scans(id)`, `ON DELETE CASCADE` | Associated parent scan identifier. |
| `severity` | `VARCHAR(16)` | `NOT NULL` | Severity tier: `low`, `medium`, or `high`. |
| `title` | `VARCHAR(255)` | `NOT NULL` | Short title of the indicator (e.g. "SSRF / Private Network Target"). |
| `description` | `TEXT` | `NOT NULL` | Human-readable explanation and captured evidence for the finding. |
| `category` | `VARCHAR(64)` | `NOT NULL` | Source engine tag: `deterministic_url`, `email_heuristics`, `laya_ai`, `qwen_ai`. |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL` | Timestamp finding was recorded (UTC). |

---

## 3. Indexing Strategy

To maintain sub-10ms response times for history queries and worker polling:

```sql
-- Fast sorting and pagination for recent scans
CREATE INDEX ix_scans_created_at ON scans (created_at DESC);

-- Fast lookup for background worker job processing
CREATE INDEX ix_scans_status ON scans (status);

-- Filtering scans by category (URL vs Email)
CREATE INDEX ix_scans_input_type ON scans (input_type);

-- Join index for finding lookups by scan
CREATE INDEX ix_scan_findings_scan_id ON scan_findings (scan_id);
```

---

## 4. Database Migrations (Alembic)

Database schema changes are versioned using **Alembic**. Migration scripts reside in `database/migrations/versions/`.

### Migration Commands

```bash
# Check current migration version
alembic current

# Apply all pending migrations to PostgreSQL
alembic upgrade head

# Rollback the last applied migration
alembic downgrade -1

# Generate a new migration after modifying models in app/backend/models/
alembic revision --autogenerate -m "add_new_column_to_scans"
```

---

## 5. Connection Pooling & Resilience

The SQLAlchemy engine is configured in `app/backend/core/database.py` with safe defaults:
- **Pool Type**: `QueuePool` with pool size `5` and `max_overflow=10` to avoid exhausting connection limits on developer hardware.
- **Connection Pre-Ping (`pool_pre_ping=True`)**: Emits `SELECT 1` before checking out connections from the pool to automatically recycle connections dropped during Docker restarts.
- **Timezone**: All timestamps are persisted as timezone-aware UTC (`DateTime(timezone=True)`).
