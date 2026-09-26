"""
Core services shared across the whole application:
- database.py : SQLite schema, connection handling, CRUD helpers
- risk.py     : risk-scoring engine (0-100 -> LOW/MEDIUM/HIGH/CRITICAL)
- alerts.py   : alert lifecycle management (NEW -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED)
"""
