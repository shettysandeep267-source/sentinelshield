"""
File-integrity detector.

Thin wrapper around collectors/system.py's hashing utilities: holds the
in-memory baseline and turns any drift into a FILE_INTEGRITY_VIOLATION
Event for the detection engine / risk scorer.

Stage 9 in the build plan.
"""

from typing import Dict, Iterable, Optional

from app.collectors.system import DEFAULT_WATCHED_PATHS, build_baseline, hash_file
from app.core.models import Event


class FileIntegrityDetector:
    def __init__(self, watched_paths: Iterable[str] = DEFAULT_WATCHED_PATHS) -> None:
        self.watched_paths = list(watched_paths)
        self.baseline: Dict[str, str] = {}

    def establish_baseline(self) -> None:
        """Compute and store the initial SHA-256 baseline for watched files."""
        self.baseline = build_baseline(self.watched_paths)

    def check(self) -> Iterable[Event]:
        """Compare current file hashes against the baseline.

        TODO:
            for path, old_hash in self.baseline.items():
                new_hash = hash_file(Path(path))
                if new_hash != old_hash:
                    yield Event(event_type="FILE_INTEGRITY_VIOLATION", description=path)
                    self.baseline[path] = new_hash  # re-baseline after alerting
        """
        raise NotImplementedError
