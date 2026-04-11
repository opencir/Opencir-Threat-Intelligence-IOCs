#!/usr/bin/env python3
"""
consolidate.py — Merge, deduplicate, validate, and export all IOC feeds.

Reads every JSON file from feeds/, runs validation, deduplicates by
(type, normalised_value), then writes:

  consolidated/
    malicious_ips.txt        plain IP list      (firewall EDL / blocklist)
    malicious_domains.txt    plain domain list
    malicious_urls.txt       plain URL list
    malicious_hashes.csv     SHA256, MD5, type, source, first_seen
    cve_watchlist.txt        CVE-YYYY-NNNN lines
    master_iocs.json         full structured dataset
    stix_bundle.json         STIX 2.1 bundle (indicators + observed-data)
    run_stats.json           pipeline run statistics

Usage:
    python scripts/consolidate.py
"""

import csv
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Local validation helpers
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate import filter_iocs, normalise_ioc

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("consolidate")

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
FEEDS_DIR = ROOT / "feeds"
CONSOLIDATED_DIR = ROOT / "consolidated"
CONSOLIDATED_DIR.mkdir(parents=True, exist_ok=True)

NOW_ISO = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Load all feed JSON files
# ─────────────────────────────────────────────────────────────────────────────

def load_feeds() -> list[dict[str, Any]]:
    """Read every *.json file in feeds/ and return a flat list of IOC records."""
    all_iocs: list[dict[str, Any]] = []
    feed_files = sorted(FEEDS_DIR.glob("*.json"))

    if not feed_files:
        log.warning("No feed JSON files found in %s", FEEDS_DIR)
        return []

    for path in feed_files:
        try:
            data = json.loads(path.read_text())
            if isinstance(data, list):
                all_iocs.extend(data)
                log.info("Loaded %d IOCs from %s", len(data), path.name)
            else:
                log.warning("Unexpected format (not a list) in %s — skipping", path.name)
        except (json.JSONDecodeError, OSError) as exc:
            log.error("Failed to load %s: %s", path.name, exc)

    log.info("Total raw IOCs loaded: %d", len(all_iocs))
    return all_iocs


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Validate + normalise
# ─────────────────────────────────────────────────────────────────────────────

def validate_and_normalise(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run type-aware validation then normalise each IOC's value field."""
    valid, _ = filter_iocs(iocs)
    normalised = [normalise_ioc(ioc) for ioc in valid]
    return normalised


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Deduplicate
# ─────────────────────────────────────────────────────────────────────────────

def deduplicate(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Deduplicate by (type, value).
    When duplicates exist, keep the record with the highest confidence score
    and merge the source list so provenance is not lost.
    """
    seen: dict[tuple[str, str], dict[str, Any]] = {}

    for ioc in iocs:
        key = (ioc.get("type", "").lower(), ioc.get("value", ""))
        if key not in seen:
            # Ensure sources is always a list
            ioc = {**ioc, "sources": [ioc.get("source", "unknown")]}
            seen[key] = ioc
        else:
            existing = seen[key]
            # Merge sources
            sources = list(set(existing.get("sources", []) + [ioc.get("source", "unknown")]))
            # Keep highest confidence
            conf = max(existing.get("confidence", 0), ioc.get("confidence", 0))
            seen[key] = {**existing, "sources": sources, "confidence": conf}

    deduped = list(seen.values())
    log.info("After deduplication: %d unique IOCs", len(deduped))
    return deduped


# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Split by type
# ─────────────────────────────────────────────────────────────────────────────

def split_by_type(
    iocs: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for ioc in iocs:
        t = ioc.get("type", "unknown").lower()
        buckets.setdefault(t, []).append(ioc)
    for t, lst in buckets.items():
        log.info("  %-12s : %d", t, len(lst))
    return buckets


# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — Write outputs
# ─────────────────────────────────────────────────────────────────────────────

def write_plain_list(iocs: list[dict[str, Any]], filename: str, header: str = "") -> Path:
    """Write a plain-text one-per-line blocklist (firewall / DNS-sink format)."""
    path = CONSOLIDATED_DIR / filename
    lines = [
        f"# {header}",
        f"# Generated: {NOW_ISO}",
        f"# Total: {len(iocs)}",
        "#",
    ]
    for ioc in sorted(iocs, key=lambda x: x.get("value", "")):
        lines.append(ioc["value"])
    path.write_text("\n".join(lines) + "\n")
    log.info("Wrote %d entries → %s", len(iocs), path.name)
    return path


def write_hash_csv(iocs: list[dict[str, Any]], filename: str = "malicious_hashes.csv") -> Path:
    """
    Write a CSV of file hashes suitable for direct import into
    CrowdStrike Falcon / SentinelOne custom IOC lists.
    """
    path = CONSOLIDATED_DIR / filename
    fieldnames = [
        "sha256",
        "md5",
        "sha1",
        "file_name",
        "file_type",
        "signature",
        "malware",
        "source",
        "first_seen",
        "confidence",
        "tags",
    ]
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for ioc in sorted(iocs, key=lambda x: x.get("value", "")):
            writer.writerow(
                {
                    "sha256": ioc.get("sha256") or (ioc["value"] if len(ioc["value"]) == 64 else ""),
                    "md5": ioc.get("md5") or (ioc["value"] if len(ioc["value"]) == 32 else ""),
                    "sha1": ioc.get("sha1") or (ioc["value"] if len(ioc["value"]) == 40 else ""),
                    "file_name": ioc.get("file_name", ""),
                    "file_type": ioc.get("file_type", ""),
                    "signature": ioc.get("signature", ""),
                    "malware": ioc.get("malware", "") or ioc.get("malware_printable", ""),
                    "source": ",".join(ioc.get("sources", [ioc.get("source", "")])),
                    "first_seen": ioc.get("first_seen", ""),
                    "confidence": ioc.get("confidence", 0),
                    "tags": ",".join(ioc.get("tags") or []),
                }
            )
    log.info("Wrote %d hashes → %s", len(iocs), path.name)
    return path


def write_master_json(iocs: list[dict[str, Any]]) -> Path:
    """Write the full structured dataset as a single JSON file."""
    path = CONSOLIDATED_DIR / "master_iocs.json"
    output = {
        "generated_at": NOW_ISO,
        "total": len(iocs),
        "iocs": iocs,
    }
    path.write_text(json.dumps(output, indent=2))
    log.info("Wrote master JSON: %d IOCs → %s", len(iocs), path.name)
    return path


def write_stix_bundle(iocs: list[dict[str, Any]]) -> Path:
    """
    Generate a minimal STIX 2.1 bundle containing Indicator objects.
    Full STIX 2.1 spec: https://docs.oasis-open.org/cti/stix/v2.1/
    """
    path = CONSOLIDATED_DIR / "stix_bundle.json"

    # STIX pattern templates per IOC type
    def _stix_pattern(ioc: dict) -> str | None:
        t = ioc.get("type", "")
        v = ioc.get("value", "").replace("'", "\\'")
        patterns = {
            "ip": f"[ipv4-addr:value = '{v}']",
            "domain": f"[domain-name:value = '{v}']",
            "url": f"[url:value = '{v}']",
            "hash": f"[file:hashes.'SHA-256' = '{v}']" if len(v) == 64 else f"[file:hashes.MD5 = '{v}']",
            "email": f"[email-addr:value = '{v}']",
            "cve": f"[vulnerability:name = '{v}']",
        }
        return patterns.get(t)

    indicators = []
    for ioc in iocs:
        pattern = _stix_pattern(ioc)
        if not pattern:
            continue
        name = f"{ioc.get('type', 'ioc').upper()}: {ioc.get('value', '')}"
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": ioc.get("first_seen") or NOW_ISO,
            "modified": NOW_ISO,
            "name": name[:512],
            "description": ioc.get("vulnerability_name") or ioc.get("malware_printable") or "",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.get("first_seen") or NOW_ISO,
            "confidence": ioc.get("confidence", 0),
            "labels": ioc.get("tags") or [],
            "external_references": [
                {
                    "source_name": src,
                }
                for src in ioc.get("sources", [ioc.get("source", "unknown")])
            ],
        }
        indicators.append(indicator)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "created": NOW_ISO,
        "objects": indicators,
    }
    path.write_text(json.dumps(bundle, indent=2))
    log.info("Wrote STIX 2.1 bundle: %d indicators → %s", len(indicators), path.name)
    return path


def write_run_stats(
    total_raw: int,
    total_valid: int,
    total_deduped: int,
    buckets: dict[str, list],
) -> Path:
    """Write a JSON stats file for pipeline monitoring / dashboards."""
    path = CONSOLIDATED_DIR / "run_stats.json"
    stats = {
        "run_at": NOW_ISO,
        "total_raw": total_raw,
        "total_valid": total_valid,
        "total_deduped": total_deduped,
        "filtered": total_raw - total_valid,
        "duplicates_removed": total_valid - total_deduped,
        "by_type": {t: len(lst) for t, lst in buckets.items()},
    }
    path.write_text(json.dumps(stats, indent=2))
    log.info("Run stats → %s", path.name)
    return path


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def run() -> None:
    log.info("=== Consolidation pipeline starting ===")

    # 1. Load
    raw_iocs = load_feeds()
    total_raw = len(raw_iocs)
    if not raw_iocs:
        log.warning("No IOCs to consolidate — exiting")
        return

    # 2. Validate + normalise
    valid_iocs = validate_and_normalise(raw_iocs)
    total_valid = len(valid_iocs)

    # 3. Deduplicate
    deduped = deduplicate(valid_iocs)
    total_deduped = len(deduped)

    # 4. Split
    log.info("IOC type breakdown:")
    buckets = split_by_type(deduped)

    # 5. Write outputs
    if buckets.get("ip"):
        write_plain_list(
            buckets["ip"],
            "malicious_ips.txt",
            "Malicious IP Blocklist — firewall EDL / ACL import",
        )

    if buckets.get("domain"):
        write_plain_list(
            buckets["domain"],
            "malicious_domains.txt",
            "Malicious Domain Blocklist — DNS sinkhole / firewall FQDN",
        )

    if buckets.get("url"):
        write_plain_list(
            buckets["url"],
            "malicious_urls.txt",
            "Malicious URL Blocklist — proxy / web gateway import",
        )

    if buckets.get("hash"):
        write_hash_csv(buckets["hash"])

    if buckets.get("cve"):
        write_plain_list(
            buckets["cve"],
            "cve_watchlist.txt",
            "Actively Exploited CVEs (CISA KEV + ThreatFox)",
        )

    write_master_json(deduped)
    write_stix_bundle(deduped)
    write_run_stats(total_raw, total_valid, total_deduped, buckets)

    log.info(
        "=== Pipeline complete: %d raw → %d valid → %d unique IOCs ===",
        total_raw,
        total_valid,
        total_deduped,
    )


if __name__ == "__main__":
    run()
