#!/usr/bin/env python3
"""
fetch_otx.py — Collector for AlienVault Open Threat Exchange (OTX).

Requires a free OTX API key: https://otx.alienvault.com/api

Set the environment variable:
    OTX_API_KEY=<your_key>

Fetches:
  - Subscribed pulses (curated threat intelligence bundles)
  - IOC types collected: IPs, domains, URLs, file hashes, CVEs, email addresses
"""

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import requests

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("fetch_otx")

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
FEEDS_DIR = ROOT / "feeds"
FEEDS_DIR.mkdir(parents=True, exist_ok=True)

# ── Constants ──────────────────────────────────────────────────────────────────
TIMEOUT = 30
NOW_ISO = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# Map OTX indicator types → our normalised type labels
OTX_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "hash",
    "FileHash-SHA1": "hash",
    "FileHash-SHA256": "hash",
    "CVE": "cve",
    "email": "email",
    "CIDR": "cidr",
    "Mutex": "mutex",
    "Yara": "yara",
}

HEADERS = {
    "User-Agent": "ThreatIntel-Collector/1.0 (github-actions; contact: security@example.com)"
}


# ─────────────────────────────────────────────────────────────────────────────
# OTX API client (thin wrapper)
# ─────────────────────────────────────────────────────────────────────────────

class OTXClient:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update(
            {**HEADERS, "X-OTX-API-KEY": api_key}
        )

    def get(self, path: str, params: Optional[dict] = None) -> dict:
        url = f"{OTX_BASE_URL}{path}"
        resp = self.session.get(url, params=params or {}, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def get_subscribed_pulses(self, modified_since: Optional[str] = None, limit: int = 20) -> list[dict]:
        """
        Retrieve pulses the user is subscribed to.
        *modified_since* should be an ISO-8601 datetime string (UTC).
        Returns all pages up to *limit* pulses.
        """
        pulses: list[dict] = []
        params: dict[str, Any] = {"limit": min(limit, 20)}
        if modified_since:
            params["modified_since"] = modified_since

        next_url: Optional[str] = f"{OTX_BASE_URL}/pulses/subscribed"
        fetched = 0

        while next_url and fetched < limit:
            resp = self.session.get(next_url, params=params if "subscribed" in next_url else {}, timeout=TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("results", [])
            pulses.extend(batch)
            fetched += len(batch)
            next_url = data.get("next")
            params = {}  # pagination uses full URL — no extra params needed

        return pulses[:limit]


# ─────────────────────────────────────────────────────────────────────────────
# IOC extraction from pulses
# ─────────────────────────────────────────────────────────────────────────────

def _extract_iocs_from_pulse(pulse: dict) -> list[dict[str, Any]]:
    """Flatten all indicators from a single OTX pulse into IOC records."""
    pulse_id = pulse.get("id", "")
    pulse_name = pulse.get("name", "")
    pulse_tags = pulse.get("tags", [])
    pulse_tlp = pulse.get("tlp", "white")
    pulse_author = pulse.get("author_name", "")
    pulse_created = pulse.get("created", "")
    pulse_modified = pulse.get("modified", "")
    adversary = pulse.get("adversary", "")
    targeted_countries = pulse.get("targeted_countries", [])

    iocs: list[dict[str, Any]] = []
    for indicator in pulse.get("indicators", []):
        raw_type = indicator.get("type", "")
        norm_type = OTX_TYPE_MAP.get(raw_type, raw_type.lower())
        value = indicator.get("indicator", "").strip()
        if not value:
            continue

        iocs.append(
            {
                "type": norm_type,
                "value": value,
                "raw_type": raw_type,
                "source": "otx",
                "pulse_id": pulse_id,
                "pulse_name": pulse_name,
                "tags": pulse_tags,
                "tlp": pulse_tlp,
                "author": pulse_author,
                "adversary": adversary,
                "targeted_countries": targeted_countries,
                "first_seen": indicator.get("created", pulse_created),
                "last_seen": pulse_modified,
                "description": indicator.get("description", ""),
                "confidence": 75,  # community-sourced; lower than vendor feeds
                "fetched_at": NOW_ISO,
            }
        )
    return iocs


# ─────────────────────────────────────────────────────────────────────────────
# Main fetch function
# ─────────────────────────────────────────────────────────────────────────────

def fetch_otx(
    api_key: str,
    days_back: int = 7,
    max_pulses: int = 200,
) -> list[dict[str, Any]]:
    """
    Fetch OTX subscribed pulses modified in the last *days_back* days and
    return a flat list of normalised IOC records.
    """
    client = OTXClient(api_key)

    modified_since = (
        datetime.now(timezone.utc) - timedelta(days=days_back)
    ).strftime("%Y-%m-%dT%H:%M:%S")

    log.info("Fetching OTX pulses modified since %s …", modified_since)
    try:
        pulses = client.get_subscribed_pulses(
            modified_since=modified_since,
            limit=max_pulses,
        )
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 403:
            log.error(
                "OTX API key invalid or missing (HTTP 403). "
                "Set OTX_API_KEY in your environment / GitHub Secrets."
            )
        raise

    log.info("OTX: %d pulses retrieved", len(pulses))

    iocs: list[dict[str, Any]] = []
    for pulse in pulses:
        iocs.extend(_extract_iocs_from_pulse(pulse))

    # Persist
    out_path = FEEDS_DIR / "otx_pulses.json"
    out_path.write_text(json.dumps(iocs, indent=2))
    log.info("OTX: %d IOCs from %d pulses → %s", len(iocs), len(pulses), out_path)
    return iocs


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def run() -> dict[str, list]:
    api_key = os.environ.get("OTX_API_KEY", "").strip()
    if not api_key:
        log.warning(
            "OTX_API_KEY not set — skipping OTX collection. "
            "Get a free key at https://otx.alienvault.com/api"
        )
        return {"otx": []}

    results: dict[str, list] = {}
    try:
        results["otx"] = fetch_otx(api_key)
    except Exception as exc:
        log.error("OTX fetch failed: %s", exc)
        results["otx"] = []

    log.info("OTX collection complete: %d IOCs", len(results["otx"]))
    return results


if __name__ == "__main__":
    run()
