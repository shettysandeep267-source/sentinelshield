"""
System collector.

Two responsibilities:
1. Tail Linux auth logs (e.g. /var/log/auth.log on Debian/Ubuntu) to feed
   the brute-force detector (Stage 7).
2. Periodically hash a configured set of important files to feed the
   file-integrity detector (Stage 9).
"""

import hashlib
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional

from app.core.models import Event

DEFAULT_WATCHED_PATHS = [
    "/etc/ssh/sshd_config",
    "/etc/nginx/nginx.conf",
    "/etc/passwd",
]


def parse_auth_line(line: str) -> Optional[Event]:
    """Parse a single auth.log line into an Event.

    TODO:
        - match "Failed password for ..." -> event_type="AUTH_FAILURE"
        - match "Accepted password for ..." / "Accepted publickey for ..."
          -> event_type="AUTH_SUCCESS"
        - extract source IP with a regex on the trailing "from <ip>"
    """
    raise NotImplementedError


def tail_auth_log(path: Path, on_event: Callable[[Event], None]) -> None:
    """Follow the auth log and emit AUTH_FAILURE / AUTH_SUCCESS events.

    TODO: same tail -f pattern as collectors/web_logs.py:tail_log.
    """
    raise NotImplementedError


def hash_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file's contents."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def build_baseline(paths: Iterable[str] = DEFAULT_WATCHED_PATHS) -> Dict[str, str]:
    """Compute the initial SHA-256 baseline for all watched files."""
    return {p: hash_file(Path(p)) for p in paths if Path(p).exists()}


def check_integrity(baseline: Dict[str, str]) -> Iterable[Event]:
    """Re-hash watched files and yield an Event for anything that changed.

    TODO:
        for path, old_hash in baseline.items():
            if not Path(path).exists():
                yield Event(event_type="FILE_MISSING", description=path)
                continue
            new_hash = hash_file(Path(path))
            if new_hash != old_hash:
                yield Event(event_type="FILE_MODIFIED", description=path)
    """
    raise NotImplementedError


if __name__ == "__main__":
    baseline = build_baseline()
    print(f"Baseline computed for {len(baseline)} files.")
