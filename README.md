# CYBERGUARD

**AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection**

`WIP` · `Cybersecurity` · `AI/ML` · `FastAPI`

CYBERGUARD explores how AI/ML-assisted analysis and security-focused rules can be combined to identify potentially malicious or impersonated digital content.

<img width="2752" height="1536" alt="Design_cybersecurity_investigati…_2K_20260922210616" src="https://github.com/user-attachments/assets/dfe6e131-e6db-4bbe-8a33-c28ad7d32c8f" />

## What CYBERGUARD Does

```text
INPUT
  │
  ├── URL
  ├── Email
  └── Content
       │
       ▼
   ANALYSIS
       │
       ├── Rules
       └── ML
       │
       ▼
   RISK ASSESSMENT
       │
       ▼
   RESULT / REPORT
```

Planned capabilities:

* Phishing detection
* Suspicious URL analysis
* Digital impersonation detection
* Threat analysis
* Risk scoring
* Scan history
* Security reports
* Threat intelligence integration

## Stack

| Component  | Stack          |
| ---------- | -------------- |
| API        | FastAPI        |
| Language   | Python         |
| Database   | PostgreSQL     |
| ORM        | SQLAlchemy     |
| Validation | Pydantic       |
| Frontend   | React          |
| Detection  | Rules + ML     |
| Containers | Docker         |
| CI/CD      | GitHub Actions |
| Testing    | Pytest         |

## Structure

```text
CYBERGUARD/
│
├── app/
│   ├── backend/
│   │   ├── api/
│   │   ├── core/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   └── main.py
│   │
│   |── frontend/
|   ├── index.html
|   ├── style.css
|   ├── script.js
|   └── assets/
|       ├── logo.svg
|       └── icons/
│
├── detection/
│   ├── models/
│   ├── rules/
│   ├── inference/
│   └── tests/
│
├── database/
│   └── migrations/
│
├── infrastructure/
│   ├── docker/
│   └── compose/
│
├── docs/
├── tests/
│
├── .github/
│   └── workflows/
│
├── .env.example
├── .gitignore
├── docker-compose.yml
└── README.md
```

The repository is intentionally divided into application, detection, data, infrastructure, and documentation areas.

## Status

| Area         | Status   |
| ------------ | -------- |
| Requirements | Planning |
| Backend      | Planned  |
| Frontend     | Planned  |
| Detection    | Planned  |
| Database     | Planned  |
| Testing      | Planned  |
| Docker       | Planned  |
| CI/CD        | Planned  |
| Deployment   | Planned  |

## Documentation

Technical documentation will live in [`docs/`](docs/).

```text
requirements
architecture
api
development
database
security
deployment
```

## Disclaimer

CYBERGUARD is an educational and experimental cybersecurity project.

Detection results are probabilistic and should not be treated as definitive proof that content is malicious or safe.
