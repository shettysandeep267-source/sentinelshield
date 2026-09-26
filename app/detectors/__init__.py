"""
Detectors implement the actual detection logic that turns raw
collector events into security findings:
- port_scan.py     : port-scan / connection-sweep detection
- brute_force.py   : authentication brute-force detection
- web_attack.py     : SQLi / XSS / traversal / command-injection detection
- file_integrity.py : SHA-256 baseline + drift detection for watched files
"""
