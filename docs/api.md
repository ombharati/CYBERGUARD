# API Reference

The CYBERGUARD API provides endpoints for analyzing suspicious URLs, emails, and raw digital content. It combines deterministic pattern detection, local encoder models (Laya), and deep reasoning LLMs (Qwen) into a single unified JSON interface.

---

## 1. Overview & Routing Strategy

The API is structured into two route sets:
1. **Versioned API (`/api/v1/scans`)**: Follows REST conventions for production clients. Scan submissions are enqueued to Redis and return `202 Accepted` with a scan ID for asynchronous status polling.
2. **Frontend Compatibility API (`/api/scans`)**: Provides synchronous endpoints expected by the vanilla JavaScript frontend, returning the completed scan report immediately without requiring client-side polling.

All endpoints accept and return UTF-8 JSON payloads.

---

## 2. Endpoints

### 2.1 Health & Telemetry Check
Returns the operational status of the service and its local dependencies.

- **Method**: `GET`
- **Path**: `/health`
- **Response**: `200 OK`

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

### 2.2 Create Scan (Synchronous / Direct)
Accepts an input target, runs the full analysis pipeline synchronously, persists the result to PostgreSQL, and returns the finished evaluation.

- **Method**: `POST`
- **Path**: `/api/scans` (or `/api/v1/scans?sync=true`)
- **Headers**: `Content-Type: application/json`

#### Request Body (URL Analysis)
```json
{
  "input_type": "url",
  "data": "https://secure-login-paypal.com/verify-account"
}
```

#### Request Body (Email Analysis - Structured)
```json
{
  "input_type": "email",
  "data": {
    "sender": "security-alerts@paypa1.com",
    "subject": "URGENT: Your account has been suspended",
    "body": "Your account was locked. Verify your identity immediately at https://paypa1-verify-login.xyz/auth"
  }
}
```

#### Request Body (Email Analysis - Raw RFC 822)
```json
{
  "input_type": "email",
  "data": "From: billing@unknown-host.net\nSubject: Invoice Overdue\n\nPlease find attached invoice: http://192.168.1.10/invoice.exe"
}
```

#### Response (`200 OK`)
```json
{
  "id": "CG-B85CBFEB",
  "type": "URL",
  "target": "https://secure-login-paypal.com/verify-account",
  "status": "completed",
  "score": 70,
  "classification": "Suspicious",
  "summary": "The analyzed URL exhibits anomalous patterns warranting caution. Notable warning signs: AI Detected High Phishing Probability (Laya), Multiple Security-Sensitive Keywords.",
  "findings": [
    {
      "severity": "high",
      "title": "AI Detected High Phishing Probability (Laya)",
      "description": "Laya neural classification evaluated this URL with a 95.5% phishing probability.",
      "category": "laya_ai"
    },
    {
      "severity": "medium",
      "title": "Multiple Security-Sensitive Keywords",
      "description": "The URL contains keywords often targeted by phishing kits: verify, secure, login, account, paypal.",
      "category": "deterministic_url"
    },
    {
      "severity": "medium",
      "title": "Potential Brand Spoofing Detected by AI (Laya)",
      "description": "Laya identified language and structural patterns characteristic of brand impersonation.",
      "category": "laya_ai"
    }
  ],
  "signals": [
    { "name": "Pattern analysis", "value": 70 },
    { "name": "Content indicators", "value": 90 },
    { "name": "Risk aggregation", "value": 70 },
    { "name": "Reputation signals", "value": 50 }
  ],
  "explanation": "Multiple security indicators were triggered during heuristic and neural analysis. While not confirmed actively destructive, the input deviates from verified benign patterns.",
  "timestamp": "2026-10-02T13:34:19.004772Z"
}
```

---

### 2.3 Create Scan (Asynchronous / Queue Mode)
Pushes the scan request to the Redis job queue (`cyberguard:scans`) for background worker consumption.

- **Method**: `POST`
- **Path**: `/api/v1/scans`
- **Headers**: `Content-Type: application/json`
- **Response**: `202 Accepted`

```json
{
  "id": "CG-4E10C8A2",
  "type": "URL",
  "target": "https://suspicious-target.com",
  "status": "queued",
  "score": 0,
  "classification": "Pending",
  "summary": "Scan enqueued for background worker processing.",
  "findings": [],
  "signals": [],
  "explanation": "Analysis pending in queue.",
  "timestamp": "2026-10-02T14:15:00.000000Z"
}
```

---

### 2.4 Get Scan Report by ID
Retrieves an existing scan report and all associated findings from PostgreSQL.

- **Method**: `GET`
- **Path**: `/api/v1/scans/{scan_id}`
- **Parameters**: `scan_id` (string, e.g. `CG-B85CBFEB`)
- **Responses**:
  - `200 OK`: Returns the complete `ScanResponse` object, including `report_text` and `report_generated_by` fields.
  - `404 Not Found`: If no scan with the given ID exists.

> **Note**: The response includes `report_text` (the narrative report body) and `report_generated_by` (`"template"` for the instant deterministic report, `"qwen"` after the async Qwen narrative upgrade completes).

---

### 2.5 Poll Narrative Report Upgrade
Check if a scan's report has been upgraded from the instant template to the full Qwen-generated narrative. Designed for frontend polling after initial scan completion.

- **Method**: `GET`
- **Path**: `/api/scans/{scan_id}/report` or `/api/v1/scans/{scan_id}/report`
- **Parameters**: `scan_id` (string)
- **Response**: `200 OK`

```json
{
  "report_text": "## CYBERGUARD Security Analysis Report\n\n### 1. Executive Summary\n...",
  "report_generated_by": "qwen"
}
```

If the Qwen narrative is not yet available, `report_generated_by` will be `"template"`.

---

### 2.6 List Scan History
Returns a reverse-chronological list of recent scans.

- **Method**: `GET`
- **Path**: `/api/scans` or `/api/v1/scans`
- **Query Parameters**:
  - `limit` (optional integer, default `50`, maximum `100`)
- **Response**: `200 OK` (Array of `ScanResponse` objects)

---

## 3. Error Responses

The API uses standard HTTP status codes:

| Status Code | Reason | Example Response |
| :--- | :--- | :--- |
| **`400 Bad Request`** | Input validation failure (e.g. empty target, URL exceeds 2048 chars, email body exceeds 20KB). | `{"detail": "URL exceeds maximum length of 2048 characters."}` |
| **`404 Not Found`** | Resource does not exist. | `{"detail": "Scan CG-UNKNOWN not found."}` |
| **`422 Unprocessable Entity`** | Pydantic schema validation failure. | Standard FastAPI error detailing offending field. |
| **`500 Internal Server Error`** | Unrecoverable backend fault. | `{"detail": "Analysis failed: connection lost"}` |

---

## 4. cURL Usage Examples

### Submit URL Analysis
```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"input_type": "url", "data": "https://www.wikipedia.org"}'
```

### Submit Email Analysis
```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "input_type": "email",
    "data": {
      "sender": "support@chase-verify.com",
      "subject": "Action Required: Suspicious Login Detected",
      "body": "Please login to your account immediately at http://192.168.1.1/login.php"
    }
  }'
```

### Check System Health
```bash
curl -s http://localhost:8000/health
```
