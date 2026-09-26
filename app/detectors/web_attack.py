"""
SentinelShield Web Attack Detector.

Inspects HTTP_REQUEST events against defensive regex rules loaded from
rules/detection_rules.yaml.

Supported categories:
    SQL_INJECTION
    XSS
    DIRECTORY_TRAVERSAL
    COMMAND_INJECTION

The detector only identifies suspicious input. It does not execute
or send attack payloads.
"""

import re
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

import yaml

from app.core.models import Event, EngineSource


RULES_PATH = (
    Path(__file__).resolve().parents[2]
    / "rules"
    / "detection_rules.yaml"
)


CATEGORY_NAMES = {
    "sql_injection": "SQL_INJECTION",
    "xss": "XSS",
    "directory_traversal": "DIRECTORY_TRAVERSAL",
    "command_injection": "COMMAND_INJECTION",
}


class WebAttackDetector:
    """
    Rule-based HTTP attack detector.
    """

    def __init__(
        self,
        rules_path: Path = RULES_PATH,
    ) -> None:

        self.rules_path = rules_path
        self.rules = {}

    # ------------------------------------------------------------------
    # Load detection rules
    # ------------------------------------------------------------------

    def load_rules(self) -> None:
        """Load and compile regex rules from YAML."""

        if not self.rules_path.exists():
            raise FileNotFoundError(
                f"Detection rules file not found: {self.rules_path}"
            )

        with self.rules_path.open(
            "r",
            encoding="utf-8",
        ) as file:

            raw = yaml.safe_load(file) or {}

        compiled_rules = {}

        for category, rules in raw.items():

            if not isinstance(rules, list):
                continue

            compiled_rules[category] = []

            for rule in rules:

                if not isinstance(rule, dict):
                    continue

                pattern = rule.get("pattern")

                if not pattern:
                    continue

                try:

                    regex = re.compile(
                        pattern,
                        re.IGNORECASE,
                    )

                except re.error as exc:

                    raise ValueError(
                        f"Invalid regex for rule "
                        f"{rule.get('id', 'unknown')}: "
                        f"{pattern}"
                    ) from exc

                compiled_rules[category].append(
                    {
                        "id": rule.get(
                            "id",
                            "unknown_rule",
                        ),
                        "regex": regex,
                        "severity_hint": rule.get(
                            "severity_hint",
                            "MEDIUM",
                        ),
                        "description": rule.get(
                            "description",
                            "Suspicious web request pattern",
                        ),
                    }
                )

        self.rules = compiled_rules

    # ------------------------------------------------------------------
    # Normalize request
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(text: str) -> str:
        """
        URL-decode request content.

        Multiple decoding passes help identify encoded traversal
        or other encoded suspicious input.
        """

        normalized = text

        for _ in range(2):

            decoded = unquote(
                normalized
            )

            if decoded == normalized:
                break

            normalized = decoded

        return normalized

    # ------------------------------------------------------------------
    # Process HTTP event
    # ------------------------------------------------------------------

    def process(
        self,
        event: Event,
    ) -> Optional[Event]:
        """
        Inspect an HTTP_REQUEST event.

        Returns a detection Event when a rule matches.
        Returns None for normal traffic.
        """

        if event.event_type != "HTTP_REQUEST":
            return None

        if not self.rules:
            self.load_rules()

        # Combine request information.
        request_text = " ".join(
            part
            for part in [
                event.description,
                event.raw_data,
            ]
            if part
        )

        normalized_text = self._normalize(
            request_text
        )

        # --------------------------------------------------------------
        # Check rules
        # --------------------------------------------------------------

        for category, rules in self.rules.items():

            event_type = CATEGORY_NAMES.get(
                category,
                category.upper(),
            )

            for rule in rules:

                match = rule["regex"].search(
                    normalized_text
                )

                if not match:
                    continue

                matched_text = match.group(
                    0
                )

                evidence = (
                    f"Rule ID: {rule['id']}; "
                    f"Category: {event_type}; "
                    f"Severity Hint: "
                    f"{rule['severity_hint']}; "
                    f"Matched: "
                    f"{matched_text[:200]}; "
                    f"Description: "
                    f"{rule['description']}"
                )

                return Event(
                    event_type=event_type,
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    source_port=event.source_port,
                    destination_port=event.destination_port,
                    protocol=event.protocol or "HTTP",
                    description=(
                        f"{event_type} detected: "
                        f"{rule['description']}"
                    ),
                    raw_data=evidence,
                    engine=EngineSource.SENTINELSHIELD,
                )

        return None


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    print("==========================================")
    print(" SentinelShield Web Attack Detector")
    print("==========================================")
    print()

    detector = WebAttackDetector()

    detector.load_rules()

    total_rules = sum(
        len(rules)
        for rules in detector.rules.values()
    )

    print(
        f"Loaded categories: "
        f"{len(detector.rules)}"
    )

    print(
        f"Loaded rules: {total_rules}"
    )

    print()

    # These strings are harmless test representations used to
    # verify the defensive pattern-matching engine.
    test_cases = [
        (
            "SQL_INJECTION",
            "HTTP request test: union select marker",
        ),
        (
            "XSS",
            "HTTP request test: <script> marker",
        ),
        (
            "DIRECTORY_TRAVERSAL",
            "HTTP request test: ../ marker",
        ),
        (
            "COMMAND_INJECTION",
            "HTTP request test: ; whoami marker",
        ),
    ]

    for expected, description in test_cases:

        event = Event(
            event_type="HTTP_REQUEST",
            source_ip="192.168.56.101",
            destination_ip="192.168.56.10",
            protocol="HTTP",
            description=description,
        )

        result = detector.process(
            event
        )

        detected = (
            result.event_type
            if result
            else "NO MATCH"
        )

        print(
            f"Expected: {expected:<25} "
            f"Detected: {detected}"
        )

        if result:

            print(
                f"  Evidence: {result.raw_data}"
            )

        print()