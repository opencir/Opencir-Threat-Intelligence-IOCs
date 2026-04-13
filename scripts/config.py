#!/usr/bin/env python3
"""
Shared configuration for the IOC collection pipeline.
"""

from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FEEDS_DIR = ROOT / "feeds"
CONSOLIDATED_DIR = ROOT / "consolidated"

FEEDS_DIR.mkdir(parents=True, exist_ok=True)
CONSOLIDATED_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 30

HEADERS = {
    "User-Agent": "ThreatIntel-Collector/1.0 (github-actions; public IOC collection lab)"
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
