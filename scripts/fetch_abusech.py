#!/usr/bin/env python3
"""
fetch_abusech.py — Collector for Abuse.ch threat intelligence feeds.

Feeds covered:
  - Feodo Tracker  : Botnet C2 IP blocklist
  - URLhaus        : Malicious URLs
  - ThreatFox      : Multi-type IOCs (IPs, domains, URLs, hashes)
  - MalwareBazaar  : Malware file hashes (SHA256 / MD5)

Outputs raw feed data to the feeds/ directory as JSON/CSV.
"""

import csv
import io
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("fetch_abusech")

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
FEEDS_DIR = ROOT / "feeds"
FEEDS_DIR.mkdir(parents=True, exist_ok=True)

# ── Constants ─────────────────────────────────────────────────────────────────
TIMEOUT = 30  # seconds per request
NOW_ISO = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

HEADERS = {
    "User-Agent": "ThreatIntel-Collector/1.0 (github-actions; contact: security@example.com)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Feodo Tracker — Botnet C2 IPs
# ─────────────────────────────────────────────────────────────────────────────

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def fetch_feodo() -> list[dict[str, Any]]:
    """Fetch Feodo Tracker botnet C2 IP blocklist (JSON format)."""
    log.info("Fetching Feodo Tracker C2 blocklist …")
    resp = requests.get(FEODO_URL, headers=HEADERS, timeout=TIMEOUT)
    resp.raise_for_status()
    raw: list[dict] = resp.json()

    iocs: list[dict[str, Any]] = []
    for entry in raw:
        iocs.append(
            {
                "type": "ip",
                "value": entry.get("ip_address", "").strip(),
                "source": "feodo_tracker",
                "first_seen": entry.get("first_seen", ""),
                "last_seen": entry.get("last_seen", ""),
                "malware": entry.get("malware", ""),
                "confidence": 90,
                "fetched_at": NOW_ISO,
            }
        )

    out_path = FEEDS_DIR / "abusech_feodo.json"
    out_path.write_text(json.dumps(iocs, indent=2))
    log.info("Feodo: %d IPs → %s", len(iocs), out_path)
    return iocs


# ─────────────────────────────────────────────────────────────────────────────
# URLhaus — Malicious URLs
# ─────────────────────────────────────────────────────────────────────────────

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"


def fetch_urlhaus() -> list[dict[str, Any]]:
    """Fetch recent malicious URLs from URLhaus API."""
    log.info("Fetching URLhaus recent URLs …")
    resp = requests.post(URLHAUS_URL, headers=HEADERS, timeout=TIMEOUT)
    resp.raise_for_status()
    data = resp.json()

    if data.get("query_status") != "ok":
        log.warning("URLhaus returned non-ok status: %s", data.get("query_status"))
        return []

    iocs: list[dict[str, Any]] = []
    for entry in data.get("urls", []):
        iocs.append(
            {
                "type": "url",
                "value": entry.get("url", "").strip(),
                "source": "urlhaus",
                "first_seen": entry.get("date_added", ""),
                "last_seen": "",
                "threat": entry.get("threat", ""),
                "url_status": entry.get("url_status", ""),
                "tags": entry.get("tags") or [],
                "confidence": 85,
                "fetched_at": NOW_ISO,
            }
        )

    out_path = FEEDS_DIR / "abusech_urlhaus.json"
    out_path.write_text(json.dumps(iocs, indent=2))
    log.info("URLhaus: %d URLs → %s", len(iocs), out_path)
    return iocs


# ─────────────────────────────────────────────────────────────────────────────
# ThreatFox — Multi-type IOCs
# ─────────────────────────────────────────────────────────────────────────────

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_threatfox(days: int = 7) -> list[dict[str, Any]]:
    """
    Query ThreatFox for IOCs from the past *days* days.
    Covers IPs, domains, URLs, and hashes.
    """
    log.info("Fetching ThreatFox IOCs (last %d days) …", days)
    payload = json.dumps({"query": "get_iocs", "days": days})
    resp = requests.post(
        THREATFOX_URL,
        data=payload,
        headers={**HEADERS, "Content-Type": "application/json"},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()

    if data.get("query_status") != "ok":
        log.warning("ThreatFox returned non-ok status: %s", data.get("query_status"))
        return []

    iocs: list[dict[str, Any]] = []
    for entry in data.get("data", []) or []:
        ioc_type_raw = entry.get("ioc_type", "")

        # Normalise type label
        if ioc_type_raw in ("ip:port",):
            norm_type = "ip"
            value = entry.get("ioc", "").split(":")[0]  # strip port
        elif ioc_type_raw == "domain":
            norm_type = "domain"
            value = entry.get("ioc", "").strip()
        elif ioc_type_raw == "url":
            norm_type = "url"
            value = entry.get("ioc", "").strip()
        elif ioc_type_raw in ("sha256_hash", "md5_hash"):
            norm_type = "hash"
            value = entry.get("ioc", "").strip()
        else:
            norm_type = ioc_type_raw
            value = entry.get("ioc", "").strip()

        iocs.append(
            {
                "type": norm_type,
                "value": value,
                "ioc_type_raw": ioc_type_raw,
                "source": "threatfox",
                "malware": entry.get("malware", ""),
                "malware_printable": entry.get("malware_printable", ""),
                "first_seen": entry.get("first_seen", ""),
                "last_seen": entry.get("last_seen", ""),
                "confidence": entry.get("confidence_level", 0),
                "reporter": entry.get("reporter", ""),
                "tags": entry.get("tags") or [],
                "fetched_at": NOW_ISO,
            }
        )

    out_path = FEEDS_DIR / "abusech_threatfox.json"
    out_path.write_text(json.dumps(iocs, indent=2))
    log.info("ThreatFox: %d IOCs → %s", len(iocs), out_path)
    return iocs


# ─────────────────────────────────────────────────────────────────────────────
# MalwareBazaar — File Hashes
# ─────────────────────────────────────────────────────────────────────────────

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"


def fetch_malwarebazaar(limit: int = 1000) -> list[dict[str, Any]]:
    """
    Fetch recent malware samples from MalwareBazaar.
    Returns SHA256 / MD5 / SHA1 hashes with metadata.
    """
    log.info("Fetching MalwareBazaar recent samples (limit=%d) …", limit)
    payload = f"query=get_recent&selector=time"
    resp = requests.post(
        MALWAREBAZAAR_URL,
        data=payload,
        headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()

    if data.get("query_status") != "ok":
        log.warning(
            "MalwareBazaar returned non-ok status: %s", data.get("query_status")
        )
        return []

    iocs: list[dict[str, Any]] = []
    for entry in (data.get("data") or [])[:limit]:
        iocs.append(
            {
                "type": "hash",
                "value": entry.get("sha256_hash", "").strip(),
                "md5": entry.get("md5_hash", "").strip(),
                "sha1": entry.get("sha1_hash", "").strip(),
                "sha256": entry.get("sha256_hash", "").strip(),
                "source": "malwarebazaar",
                "file_name": entry.get("file_name", ""),
                "file_type": entry.get("file_type", ""),
                "file_size": entry.get("file_size", 0),
                "signature": entry.get("signature", ""),
                "first_seen": entry.get("first_seen", ""),
                "tags": entry.get("tags") or [],
                "confidence": 90,
                "fetched_at": NOW_ISO,
            }
        )

    out_path = FEEDS_DIR / "abusech_malwarebazaar.json"
    out_path.write_text(json.dumps(iocs, indent=2))
    log.info("MalwareBazaar: %d hashes → %s", len(iocs), out_path)
    return iocs


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def run() -> dict[str, list]:
    results: dict[str, list] = {}

    try:
        results["feodo"] = fetch_feodo()
    except Exception as exc:
        log.error("Feodo fetch failed: %s", exc)
        results["feodo"] = []

    try:
        results["urlhaus"] = fetch_urlhaus()
    except Exception as exc:
        log.error("URLhaus fetch failed: %s", exc)
        results["urlhaus"] = []

    try:
        results["threatfox"] = fetch_threatfox()
    except Exception as exc:
        log.error("ThreatFox fetch failed: %s", exc)
        results["threatfox"] = []

    try:
        results["malwarebazaar"] = fetch_malwarebazaar()
    except Exception as exc:
        log.error("MalwareBazaar fetch failed: %s", exc)
        results["malwarebazaar"] = []

    totals = {k: len(v) for k, v in results.items()}
    log.info("Abuse.ch collection complete: %s", totals)
    return results


if __name__ == "__main__":
    run()
