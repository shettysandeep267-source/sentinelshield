# 🛡️ SentinelShield

Advanced Intrusion Detection & Web Protection System — a small SOC/IDS
platform built as a portfolio project.

> **Status:** scaffold only. Almost every module below contains
> `raise NotImplementedError` with a `TODO` describing what to build.
> This is intentional — build it stage by stage yourself; see "Build
> order" below.

## Architecture

```
Network Traffic (Scapy) ─┐
Nginx Access Logs ────────┼──> Collectors ──> Detection Engine ──> Risk Scoring ──> Alert Manager ──> SQLite ──> Flask Dashboard
Linux System/Auth Logs ──┘                                                                       └──> Suricata (eve.json) ─┘
```

## Project layout

```
sentinelshield/
├── app/
│   ├── main.py                 # entry point: wires everything together, runs Flask
│   ├── collectors/              # gather raw telemetry
│   │   ├── network.py           # Scapy packet capture
│   │   ├── web_logs.py          # Nginx access log tailing/parsing
│   │   └── system.py            # auth log tailing + file hashing
│   ├── detectors/                # turn events into findings
│   │   ├── port_scan.py
│   │   ├── brute_force.py
│   │   ├── web_attack.py
│   │   └── file_integrity.py
│   ├── core/
│   │   ├── models.py             # Event / Alert / Severity / AlertStatus
│   │   ├── database.py           # SQLite schema + helpers
│   │   ├── risk.py                # 0-100 risk scoring
│   │   └── alerts.py              # alert lifecycle management
│   └── dashboard/
│       ├── routes.py              # Flask Blueprint
│       ├── templates/             # Jinja2 HTML
│       └── static/                # CSS/JS
├── config/
│   └── config.yaml                # all tunables live here
├── database/                      # sentinelshield.db lives here (gitignored)
├── logs/                          # runtime logs (gitignored)
├── rules/
│   └── detection_rules.yaml       # regex rules for web attack detection
├── tests/                         # pytest, currently mostly @skip until implemented
├── scripts/
│   ├── setup_lab.sh                # bootstrap a fresh Ubuntu lab VM
│   └── generate_report.py          # Stage 16 reporting
└── requirements.txt
```

## Getting started

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt --break-system-packages   # or omit the flag inside a venv

python -m app.core.database     # initializes database/sentinelshield.db
pytest                          # everything currently skipped except test_classify_bands
```

## ⚠️ Lab safety

Only ever run the network collector, web-attack simulations, and
brute-force tests against machines and networks you own and control —
ideally a second VM in the same isolated VirtualBox host-only network.
Never point this at a public site or a network you don't have
authorization to test.

## Build order (do not skip ahead)

1. Linux VM + development environment
2. Python project structure *(this scaffold)*
3. SQLite event database — implement `app/core/database.py`
4. Network collector — implement `app/collectors/network.py`
5. Port-scan detector — implement `app/detectors/port_scan.py`
6. Nginx + web-log collector — implement `app/collectors/web_logs.py`
7. Web attack detection — implement `app/detectors/web_attack.py`
8. Auth/brute-force detection — implement `app/collectors/system.py` (auth log) + `app/detectors/brute_force.py`
9. File-integrity monitoring — implement `app/detectors/file_integrity.py`
10. Risk-scoring engine — implement `app/core/risk.py`
11. Alert management — implement `app/core/alerts.py`
12. Flask dashboard — implement `app/dashboard/routes.py` + templates
13. Suricata integration
14. Controlled attack simulation / testing — flesh out `tests/`
15. Investigation / reporting — implement `scripts/generate_report.py`
16. GitHub + documentation + screenshots
17. Resume + interview preparation

## License

Choose a license before publishing (MIT is a common default for
portfolio projects).
