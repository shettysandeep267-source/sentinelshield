"""
Generate a SentinelShield security report from the current database
(Stage 16 in the build plan).

Usage (once implemented):
    python scripts/generate_report.py --since 24h --out report.md

TODO:
    - pull alerts from core.database.get_alerts() for the requested window
    - aggregate: incident counts by severity, top source IPs, attack-type breakdown
    - render into report sections:
        Executive Summary / Incident Statistics / Top Source IPs /
        Detected Attack Types / Critical Incidents / Evidence /
        Recommended Remediation
    - write out as Markdown (and optionally convert to PDF/HTML)
"""

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a SentinelShield security report")
    parser.add_argument("--since", default="24h", help="Time window, e.g. 24h, 7d")
    parser.add_argument("--out", default="report.md", help="Output file path")
    args = parser.parse_args()

    raise NotImplementedError(
        f"TODO: build report for window={args.since!r} -> {args.out!r}"
    )


if __name__ == "__main__":
    main()
