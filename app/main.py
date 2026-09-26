"""
SentinelShield entry point.

Architecture:

    Network Collector
          ↓
        Event
          ↓
    Detection Pipeline
          ↓
      Detectors
          ↓
      Risk Scoring
          ↓
        Alert
          ↓
       SQLite
          ↓
      Flask Dashboard

Local usage:
    python -m app.main
    python -m app.main --config config/config.yaml

Production usage:
    gunicorn --bind 0.0.0.0:$PORT app.main:app
"""

import argparse
import logging
from pathlib import Path
from threading import Thread

import yaml
from flask import Flask

from app.core.database import init_db
from app.dashboard.routes import bp as dashboard_bp


# ============================================================================
# Logging
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

log = logging.getLogger("sentinelshield")


# ============================================================================
# Configuration
# ============================================================================

def load_config(config_path: Path) -> dict:
    """
    Load SentinelShield configuration from YAML.
    """

    if not config_path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}"
        )

    with config_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        config = yaml.safe_load(file)

    if config is None:
        config = {}

    return config


# ============================================================================
# Flask Application
# ============================================================================

def create_app(config: dict) -> Flask:
    """
    Create and configure the SentinelShield Flask dashboard.
    """

    app = Flask(
        __name__,
        template_folder="dashboard/templates",
        static_folder="dashboard/static",
    )

    app.config["SENTINELSHIELD_CONFIG"] = config

    app.register_blueprint(
        dashboard_bp
    )

    return app


# ============================================================================
# Production Flask Application
# ============================================================================

# Load the normal SentinelShield configuration when the module is imported.
#
# This is required by Gunicorn:
#
#     gunicorn --bind 0.0.0.0:$PORT app.main:app
#
# The local command `python -m app.main` still uses main() below.
# The production server does NOT start Scapy packet capture automatically.

DEFAULT_CONFIG_PATH = Path(
    "config/config.yaml"
)

production_config = load_config(
    DEFAULT_CONFIG_PATH
)

init_db()

app = create_app(
    production_config
)


# ============================================================================
# Network Collector
# ============================================================================

def start_background_collectors(
    config: dict,
) -> None:
    """
    Start SentinelShield background security collectors.

    Network traffic is sent into the DetectionPipeline.

    Pipeline:

        Scapy
          ↓
        Event
          ↓
        DetectionPipeline
          ↓
        PortScanDetector
          ↓
        Alert
          ↓
        SQLite
    """

    from app.collectors.network import start_capture
    from app.core.pipeline import DetectionPipeline

    # ------------------------------------------------------------------------
    # Read network configuration
    # ------------------------------------------------------------------------

    network_config = config.get(
        "network",
        {},
    )

    interface = network_config.get(
        "interface"
    )

    # ------------------------------------------------------------------------
    # If no interface is configured
    # ------------------------------------------------------------------------

    if not interface:

        log.warning(
            "No network interface configured."
        )

        log.warning(
            "Live network capture is disabled."
        )

        return

    # ------------------------------------------------------------------------
    # Create detection pipeline
    # ------------------------------------------------------------------------

    pipeline = DetectionPipeline()

    # ------------------------------------------------------------------------
    # Event callback
    # ------------------------------------------------------------------------

    def handle_event(event):
        """
        Receive normalized network events and send them
        to the SentinelShield detection pipeline.
        """

        try:

            alert = pipeline.process_event(
                event
            )

            if alert:

                log.warning(
                    "SECURITY ALERT | "
                    "ID=%s | "
                    "TYPE=%s | "
                    "SOURCE=%s | "
                    "SEVERITY=%s | "
                    "RISK=%s",
                    alert.id,
                    alert.event_type,
                    alert.source_ip,
                    alert.severity.value,
                    alert.risk_score,
                )

        except Exception:

            log.exception(
                "Error processing network event."
            )

    # ------------------------------------------------------------------------
    # Start collector in background thread
    # ------------------------------------------------------------------------

    collector_thread = Thread(
        target=start_capture,
        args=(
            interface,
            handle_event,
        ),
        daemon=True,
        name="sentinelshield-network",
    )

    collector_thread.start()

    log.info(
        "Network collector started."
    )

    log.info(
        "Monitoring interface: %s",
        interface,
    )


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    """
    Start the complete SentinelShield application locally.
    """

    # ------------------------------------------------------------------------
    # Command-line arguments
    # ------------------------------------------------------------------------

    parser = argparse.ArgumentParser(
        description=(
            "SentinelShield IDS/SOC platform"
        )
    )

    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help=(
            "Path to SentinelShield "
            "configuration file"
        ),
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help=(
            "Flask dashboard host"
        ),
    )

    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help=(
            "Flask dashboard port"
        ),
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------------
    # Load configuration
    # ------------------------------------------------------------------------

    config_path = Path(
        args.config
    )

    log.info(
        "Loading configuration from: %s",
        config_path,
    )

    config = load_config(
        config_path
    )

    log.info(
        "Configuration loaded successfully."
    )

    # ------------------------------------------------------------------------
    # Initialize database
    # ------------------------------------------------------------------------

    init_db()

    log.info(
        "Database initialized successfully."
    )

    # ------------------------------------------------------------------------
    # Start collectors
    # ------------------------------------------------------------------------

    start_background_collectors(
        config
    )

    # ------------------------------------------------------------------------
    # Create Flask application
    # ------------------------------------------------------------------------

    local_app = create_app(
        config
    )

    # ------------------------------------------------------------------------
    # Start dashboard
    # ------------------------------------------------------------------------

    log.info(
        "Starting SentinelShield dashboard "
        "on %s:%s",
        args.host,
        args.port,
    )

    local_app.run(
        host=args.host,
        port=args.port,
        debug=config.get(
            "debug",
            False,
        ),
    )


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    main()