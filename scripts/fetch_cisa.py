#!/usr/bin/env python3
"""
fetch_cisa.py — Collector for the CISA Known Exploited Vulnerabilities (KEV) catalog.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
API:    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The KEV catalog lists CVEs that are actively exploited in the wild.
We store:
  - CVE IDs          → for SIEM / vuln-scanner correlation
  - Affected vendors / products
  - Patch deadlines
  - CVSS scores (enriched if available)
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("fetch_cisa")

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
FEEDS_DIR = ROOT / "feeds"
FEEDS_DIR.mkdir(parents=True, exist_ok=True)

# ── Constants ──────────────────────────────────────────────────────────────────
TIMEOUT = 30
NOW_ISO = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

HEADERS = {
    "User-Agent": "ThreatIntel-Collector/1.0 (github-actions; contact: security@example.com)"
}


# ─────────────────────────────────────────────────────────────────────────────
# Fetch & parse
# ─────────────────────────────────────────────────────────────────────────────

def fetch_cisa_kev() -> list[dict[str, Any]]:
    """
    Download the CISA KEV JSON catalog and normalise entries into our
    standard IOC schema (type=cve).
    """
    log.info("Fetching CISA KEV catalog …")
    resp = requests.get(CISA_KEV_URL, headers=HEADERS, timeout=TIMEOUT)
    resp.raise_for_status()
    catalog: dict = resp.json()

    catalog_version = catalog.get("catalogVersion", "unknown")
    date_released = catalog.get("dateReleased", "")
    total = catalog.get("count", 0)
    log.info(
        "KEV catalog version=%s  dateReleased=%s  total=%d",
        catalog_version,
        date_released,
        total,
    )

    iocs: list[dict[str, Any]] = []
    for vuln in catalog.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "").strip()
        if not cve_id:
            continue

        iocs.append(
            {
                "type": "cve",
                "value": cve_id,
                "source": "cisa_kev",
                "vendor_project": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "vulnerability_name": vuln.get("vulnerabilityName", ""),
                "date_added": vuln.get("dateAdded", ""),
                "short_description": vuln.get("shortDescription", ""),
                "required_action": vuln.get("requiredAction", ""),
                "due_date": vuln.get("dueDate", ""),
                "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                "notes": vuln.get("notes", ""),
                "confidence": 100,  # CISA-confirmed exploitation
                "fetched_at": NOW_ISO,
                "catalog_version": catalog_version,
            }
        )

    out_path = FEEDS_DIR / "cisa_kev.json"
    out_path.write_text(json.dumps(iocs, indent=2))
    log.info("CISA KEV: %d CVEs → %s", len(iocs), out_path)
    return iocs


def get_recent_kev(days: int = 30) -> list[dict[str, Any]]:
    """
    Return only KEV entries added in the last *days* days.
    Useful for generating a 'newly exploited' alert feed.
    """
    all_entries = fetch_cisa_kev()
    cutoff = datetime.now(timezone.utc)
    recent: list[dict[str, Any]] = []

    for entry in all_entries:
        date_added = entry.get("date_added", "")
        if not date_added:
            continue
        try:
            added_dt = datetime.fromisoformat(date_added)
            if added_dt.tzinfo is None:
                from datetime import timezone as tz
                added_dt = added_dt.replace(tzinfo=tz.utc)
            delta = (cutoff - added_dt).days
            if delta <= days:
                recent.append(entry)
        except ValueError:
            pass  # malformed date — skip

    log.info("CISA KEV (last %d days): %d entries", days, len(recent))
    return recent


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def run() -> dict[str, list]:
    results: dict[str, list] = {}

    try:
        results["cisa_kev"] = fetch_cisa_kev()
    except Exception as exc:
        log.error("CISA KEV fetch failed: %s", exc)
        results["cisa_kev"] = []

    log.info("CISA collection complete: %d CVEs", len(results["cisa_kev"]))
    return results


if __name__ == "__main__":
    run()
