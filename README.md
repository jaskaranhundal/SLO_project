# SLO_project

Security reliability monitoring toolkit that combines uptime checks, encryption posture checks, HTTP security header checks, and WAF/DDoS-oriented reporting.

## Problem
Security teams need repeatable service-level and control-level evidence to track whether key protections stay effective over time. Point-in-time checks are not enough for operational confidence.

## Security Context
- Tracks service reliability and control effectiveness.
- Produces evidence artifacts useful for security reviews and compliance conversations.
- Supports continuous visibility of HTTPS posture, encryption behavior, and protection coverage.

## Architecture/Flow
Flow summary:
1. `main.py` launches monitoring/reporting scripts in parallel processes.
2. Domain-specific scripts collect data (uptime, encryption, headers, WAF/DDoS signals).
3. Scripts generate PDF reports and derived findings.
4. Outputs are used as operational and audit evidence.

## Setup
```bash
git clone git@github.com:jaskaranhundal/SLO_project.git
cd SLO_project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

## Example Output
```text
[main] started slo_encryptions_main.py
[main] started slo_http-https-security_main.py
[main] started slo_uptime_main.py
[main] started slo_waf_main.py
[main] started uptime_violations.py
All scripts have completed.
```

## Limitations
- Report workflows are script-driven and require environment-specific tuning.
- Some scripts assume accessible target endpoints and local dependencies.
- Unified configuration and centralized logging can be improved.

## Roadmap
- Add a single config file for target scope and thresholds.
- Add CI validation for report generation and script linting.
- Add structured output mode (JSON/CSV) for SIEM or dashboard ingestion.
- Add containerized execution profile for portable runs.
