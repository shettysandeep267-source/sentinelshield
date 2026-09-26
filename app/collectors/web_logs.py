"""
SentinelShield Web Log Collector.

Reads Nginx access-log entries and converts them into normalized
SentinelShield HTTP_REQUEST Events.

Pipeline:

    Nginx Access Log
          ↓
      parse_line()
          ↓
      HTTP_REQUEST Event
          ↓
      DetectionPipeline
          ↓
      Web Attack / Rate Limit Detection
"""

import re
import time
from pathlib import Path
from typing import Callable, Optional

from app.core.models import Event, EngineSource


# ============================================================================
# Nginx log format
# ============================================================================

LOG_LINE_RE = re.compile(
    r'(?P<ip>\S+) - (?P<time>\S+) '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<http_version>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


# ============================================================================
# Parse one log line
# ============================================================================

def parse_line(
    line: str,
) -> Optional[Event]:
    """
    Parse one Nginx access-log line.

    Returns:
        Event if the line matches the expected format.
        None if the line cannot be parsed.
    """

    line = line.strip()

    if not line:
        return None

    match = LOG_LINE_RE.match(
        line
    )

    if not match:
        return None

    data = match.groupdict()

    # ------------------------------------------------------------------------
    # Extract fields
    # ------------------------------------------------------------------------

    source_ip = data["ip"]
    timestamp = data["time"]
    method = data["method"]
    path = data["path"]
    http_version = data["http_version"]
    status = int(data["status"])
    bytes_sent = int(data["bytes"])

    referer = data["referer"]
    user_agent = data["user_agent"]

    # ------------------------------------------------------------------------
    # Create normalized HTTP event
    # ------------------------------------------------------------------------

    description = (
        f"{method} {path} "
        f"{http_version} "
        f"status={status}"
    )

    raw_data = (
        f"method={method}; "
        f"path={path}; "
        f"http_version={http_version}; "
        f"status={status}; "
        f"bytes={bytes_sent}; "
        f"referer={referer}; "
        f"user_agent={user_agent}"
    )

    return Event(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=None,
        source_port=None,
        destination_port=80,
        protocol="HTTP",
        event_type="HTTP_REQUEST",
        description=description,
        raw_data=raw_data,
        engine=EngineSource.SENTINELSHIELD,
    )


# ============================================================================
# Follow Nginx access log
# ============================================================================

def tail_log(
    path: Path,
    on_event: Callable[[Event], None],
    poll_interval: float = 0.5,
) -> None:
    """
    Follow an Nginx access log like `tail -f`.

    New log entries are parsed and passed to on_event().
    """

    print(
        f"[SentinelShield] Monitoring web log: {path}"
    )

    # ------------------------------------------------------------------------
    # Wait until log exists
    # ------------------------------------------------------------------------

    while not path.exists():

        print(
            f"[SentinelShield] Waiting for log file: {path}"
        )

        time.sleep(
            poll_interval
        )

    # ------------------------------------------------------------------------
    # Open log
    # ------------------------------------------------------------------------

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as log_file:

        # Start from the end.
        log_file.seek(
            0,
            2,
        )

        current_inode = (
            path.stat().st_ino
        )

        while True:

            line = log_file.readline()

            # ---------------------------------------------------------------
            # New log entry
            # ---------------------------------------------------------------

            if line:

                event = parse_line(
                    line
                )

                if event is not None:

                    try:

                        on_event(
                            event
                        )

                    except Exception as exc:

                        print(
                            "[SentinelShield] "
                            f"Web event callback error: {exc}"
                        )

                continue

            # ---------------------------------------------------------------
            # No new line — check for log rotation
            # ---------------------------------------------------------------

            try:

                new_inode = path.stat().st_ino

                if new_inode != current_inode:

                    print(
                        "[SentinelShield] "
                        "Nginx log rotation detected. "
                        "Reopening log."
                    )

                    log_file.close()

                    with path.open(
                        "r",
                        encoding="utf-8",
                        errors="replace",
                    ) as new_log:

                        # Move the existing file handle to the new file
                        # by copying its contents through the callback.
                        for new_line in new_log:

                            event = parse_line(
                                new_line
                            )

                            if event is not None:

                                on_event(
                                    event
                                )

                    current_inode = new_inode

            except FileNotFoundError:

                # Log may briefly disappear during rotation.
                time.sleep(
                    poll_interval
                )
                continue

            time.sleep(
                poll_interval
            )


# ============================================================================
# Manual parser test
# ============================================================================

if __name__ == "__main__":

    print("==========================================")
    print(" SentinelShield Web Log Parser Test")
    print("==========================================")
    print()

    sample = (
        '192.168.56.101 - 2026-08-28T13:40:00+00:00 '
        '"GET /index.html HTTP/1.1" '
        '200 1024 "-" "Mozilla/5.0"'
    )

    event = parse_line(
        sample
    )

    if event:

        print("Parser: OK")
        print()
        print(f"Timestamp:   {event.timestamp}")
        print(f"Source IP:   {event.source_ip}")
        print(f"Protocol:    {event.protocol}")
        print(f"Event Type:  {event.event_type}")
        print(f"Description: {event.description}")
        print(f"Raw Data:    {event.raw_data}")

    else:

        print(
            "Parser test failed."
        )