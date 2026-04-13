#!/usr/bin/env python3
"""
consolidate.py — Merge, deduplicate, validate, and export all IOC feeds.

Reads every JSON file from feeds/, runs validation, deduplicates by
(type, normalised_value), then writes:

  consolidated/
    malicious_ips.txt        plain IP list      (firewall EDL / blocklist)
    malicious_domains.txt    plain domain list
    malicious_urls.txt       plain URL list
    malicious_hashes.csv     hash,type,malware,source,first_seen
    cve_watchlist.txt        CVE-YYYY-NNNN lines
    ioc_master.json          full structured dataset
    stix_bundle.json         STIX 2.1 bundle (indicators + observed-data)
    run_stats.json           pipeline run statistics

Usage:
    python scripts/consolidate.py
"""

import csv
import json
import logging
import uuid
from pathlib import Path
from typing import Any

from config import CONSOLIDATED_DIR, FEEDS_DIR, now_iso
from validate import filter_iocs, normalise_ioc

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("consolidate")


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
            sources = sorted(set(existing.get("sources", []) + [ioc.get("source", "unknown")]))
            tags = sorted(set((existing.get("tags") or []) + (ioc.get("tags") or [])))
            first_seen_values = [v for v in [existing.get("first_seen", ""), ioc.get("first_seen", "")] if v]
            last_seen_values = [v for v in [existing.get("last_seen", ""), ioc.get("last_seen", "")] if v]
            # Keep highest confidence
            conf = max(existing.get("confidence", 0), ioc.get("confidence", 0))
            seen[key] = {
                **existing,
                "sources": sources,
                "tags": tags,
                "confidence": conf,
                "first_seen": min(first_seen_values) if first_seen_values else "",
                "last_seen": max(last_seen_values) if last_seen_values else "",
            }

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

def write_plain_list(iocs: list[dict[str, Any]], filename: str):
    """Write a plain-text one-per-line blocklist."""
    path = CONSOLIDATED_DIR / filename
    values = [ioc["value"] for ioc in sorted(iocs, key=lambda x: x.get("value", ""))]
    path.write_text("\n".join(values) + ("\n" if values else ""))
    log.info("Wrote %d entries → %s", len(iocs), path.name)
    return path


def write_hash_csv(iocs: list[dict[str, Any]], filename: str = "malicious_hashes.csv") -> Path:
    """
    Write a CSV of file hashes suitable for direct import into
    CrowdStrike Falcon / SentinelOne custom IOC lists.
    """
    path = CONSOLIDATED_DIR / filename
    fieldnames = ["hash", "type", "malware", "source", "first_seen"]
    rows: list[dict[str, str]] = []
    seen_rows: set[tuple[str, str]] = set()

    for ioc in sorted(iocs, key=lambda x: x.get("value", "")):
        malware = ioc.get("malware", "") or ioc.get("malware_printable", "") or ioc.get("signature", "")
        source = ",".join(ioc.get("sources", [ioc.get("source", "")]))
        first_seen = ioc.get("first_seen", "")
        candidates = [
            ("md5", ioc.get("md5")),
            ("sha1", ioc.get("sha1")),
            ("sha256", ioc.get("sha256") or ioc.get("value")),
        ]
        for hash_type, hash_value in candidates:
            clean_hash = (hash_value or "").strip().lower()
            expected_length = {"md5": 32, "sha1": 40, "sha256": 64}[hash_type]
            if len(clean_hash) != expected_length:
                continue
            dedupe_key = (clean_hash, hash_type)
            if dedupe_key in seen_rows:
                continue
            seen_rows.add(dedupe_key)
            rows.append(
                {
                    "hash": clean_hash,
                    "type": hash_type,
                    "malware": malware,
                    "source": source,
                    "first_seen": first_seen,
                }
            )

    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    log.info("Wrote %d hash rows → %s", len(rows), path.name)
    return path


def write_master_json(iocs: list[dict[str, Any]]) -> Path:
    """Write the full structured dataset as a single JSON file."""
    path = CONSOLIDATED_DIR / "ioc_master.json"
    output = {
        "generated_at": now_iso(),
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
    current_time = now_iso()

    # STIX pattern templates per IOC type
    def _stix_pattern(ioc: dict) -> str | None:
        t = ioc.get("type", "")
        v = ioc.get("value", "").replace("'", "\\'")
        patterns = {
            "ip": f"[ipv6-addr:value = '{v}']" if ":" in v else f"[ipv4-addr:value = '{v}']",
            "domain": f"[domain-name:value = '{v}']",
            "url": f"[url:value = '{v}']",
            "hash": (
                f"[file:hashes.'SHA-256' = '{v}']"
                if len(v) == 64
                else f"[file:hashes.'SHA-1' = '{v}']"
                if len(v) == 40
                else f"[file:hashes.MD5 = '{v}']"
            ),
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
            "created": ioc.get("first_seen") or current_time,
            "modified": current_time,
            "name": name[:512],
            "description": ioc.get("vulnerability_name") or ioc.get("malware_printable") or "",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.get("first_seen") or current_time,
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
        "created": current_time,
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
        "run_at": now_iso(),
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
        write_run_stats(0, 0, 0, {})
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
        )

    if buckets.get("domain"):
        write_plain_list(
            buckets["domain"],
            "malicious_domains.txt",
        )

    if buckets.get("url"):
        write_plain_list(
            buckets["url"],
            "malicious_urls.txt",
        )

    if buckets.get("hash"):
        write_hash_csv(buckets["hash"])

    if buckets.get("cve"):
        write_plain_list(
            buckets["cve"],
            "cve_watchlist.txt",
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
