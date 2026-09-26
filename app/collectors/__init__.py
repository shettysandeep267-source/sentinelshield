"""
Collectors gather raw telemetry from the environment:
- network.py   : live packet capture (Scapy)
- web_logs.py  : Nginx access log tailing/parsing
- system.py    : Linux system/auth log + file integrity events
"""
