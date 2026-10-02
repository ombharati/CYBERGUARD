# CYBERGUARD Requirements

## Functional

- Accept **URL**, **email**, and **text/content** as analysis inputs.
- Validate and normalize submitted input.
- Run deterministic security detection rules.
- Support AI-assisted classification through **Laya**.
- Collect and preserve evidence for detected signals.
- Calculate a **0-100 risk score**.
- Classify results as:
  - Safe
  - Suspicious
  - High Risk
- Generate a structured security report.
- Store scan results and findings in PostgreSQL.
- Provide scan history and individual scan reports.
- Support optional external threat intelligence providers.
- Expose analysis through a FastAPI backend.

## Technical

- FastAPI backend with Pydantic validation.
- PostgreSQL with migrations.
- Separated detection, risk, reporting, and persistence layers.
- External tools accessed through adapters.
- Deterministic risk aggregation.
- Automated unit and integration tests.
- Environment-based configuration.
- Docker-based local deployment.
- CI checks through GitHub Actions.

## Security

- Do not expose secrets or API keys.
- Validate all external and user-provided input.
- Apply request and dependency timeouts.
- Treat external intelligence as optional.
- Preserve evidence behind every risk decision.
- Do not allow AI output to directly bypass the risk engine.

## External Projects

- **AI Decision Model**  
  https://github.com/NandhaKishorM/laya

- **Phishing / URL Detection**  
  https://github.com/phishdetect/phishdetect

- **Typosquatting / Domain Permutation**  
  https://github.com/elceef/dnstwist

- **VirusTotal Python SDK**  
  https://github.com/VirusTotal/vt-py

- **URL Investigation**  
  https://github.com/urlscan/urlscan-python

- **Email Parsing**  
  https://github.com/SpamScope/mail-parser

- **DNS Toolkit**  
  https://github.com/rthalley/dnspython

- **Detection Rule Format**  
  https://github.com/SigmaHQ/sigma

- **MITRE ATT&CK STIX Data**  
  https://github.com/mitre-attack/attack-stix-data

- **MITRE ATT&CK Data Model**  
  https://github.com/mitre-attack/attack-data-model

- **Threat Intelligence Platform**  
  https://github.com/MISP/MISP

- **Threat Intelligence Platform**  
  https://github.com/OpenCTI-Platform/opencti