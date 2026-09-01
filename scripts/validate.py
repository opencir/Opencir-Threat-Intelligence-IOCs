#!/usr/bin/env python3
"""
validate.py — IOC validation and sanitisation utilities.

Provides per-type validators that return True for valid, actionable IOCs and
filter out:
  - Private / reserved IP ranges (RFC 1918, loopback, link-local, etc.)
  - Malformed IP addresses, domains, URLs, and hashes
  - Known benign domains and IPs (common CDNs, DNS resolvers, etc.)
  - Placeholder / example values

Import this module from consolidate.py; all functions are pure (no I/O).
"""

import ipaddress
import logging
import re
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("validate")

# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns
# ─────────────────────────────────────────────────────────────────────────────

# Relaxed domain regex (labels 1–63 chars, TLD 2–24 chars)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}$"
)

# Valid MD5 / SHA1 / SHA256 / SHA512
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$")

# CVE pattern
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Email pattern (permissive but sane)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ─────────────────────────────────────────────────────────────────────────────
# Allowlists / noise filters
# ─────────────────────────────────────────────────────────────────────────────

# Well-known benign IPs to exclude (public resolvers, CDNs, etc.)
_BENIGN_IPS: frozenset[str] = frozenset(
    {
        "8.8.8.8",       # Google DNS
        "8.8.4.4",       # Google DNS
        "1.1.1.1",       # Cloudflare DNS
        "1.0.0.1",       # Cloudflare DNS
        "9.9.9.9",       # Quad9 DNS
        "208.67.222.222",# OpenDNS
        "208.67.220.220",# OpenDNS
        "4.2.2.1",       # Level3 DNS
        "4.2.2.2",       # Level3 DNS
    }
)

# Domains that appear in threat feeds but are benign infrastructure
_BENIGN_DOMAIN_SUFFIXES: tuple[str, ...] = (
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "youtube.com",
    "facebook.com",
    "amazon.com",
    "amazonaws.com",
    "microsoft.com",
    "windows.com",
    "apple.com",
    "icloud.com",
    "cloudflare.com",
    "akamaiedge.net",
    "fastly.net",
    "cloudfront.net",
)

# ─────────────────────────────────────────────────────────────────────────────
# Private / reserved network blocks
# ─────────────────────────────────────────────────────────────────────────────

_PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in [
        # IPv4
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",       # loopback
        "169.254.0.0/16",    # link-local
        "100.64.0.0/10",     # CGN (RFC 6598)
        "198.18.0.0/15",     # benchmarking
        "192.0.0.0/24",      # IETF protocol
        "192.0.2.0/24",      # TEST-NET-1
        "198.51.100.0/24",   # TEST-NET-2
        "203.0.113.0/24",    # TEST-NET-3
        "224.0.0.0/4",       # multicast
        "240.0.0.0/4",       # reserved
        "0.0.0.0/8",         # "this" network
        # IPv6
        "::1/128",            # loopback
        "fe80::/10",          # link-local
        "fc00::/7",           # unique-local
        "ff00::/8",           # multicast
        "::/128",             # unspecified
    ]
)


def _is_private_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr in net for net in _PRIVATE_NETWORKS)


# ─────────────────────────────────────────────────────────────────────────────
# Per-type validators
# ─────────────────────────────────────────────────────────────────────────────

def is_valid_ip(value: str) -> bool:
    """Return True if *value* is a public, routable IP address."""
    if not value:
        return False
    host = value.strip().strip("[]")
    if host.count(":") == 1 and "." in host.split(":")[0]:
        host = host.split(":", 1)[0]
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    if _is_private_ip(addr):
        log.debug("Filtered private IP: %s", value)
        return False
    if str(addr) in _BENIGN_IPS:
        log.debug("Filtered benign IP: %s", value)
        return False
    return True


def is_valid_domain(value: str) -> bool:
    """Return True if *value* is a syntactically valid, non-benign domain."""
    if not value or len(value) > 253:
        return False
    # Strip trailing dot (fully-qualified)
    clean = value.rstrip(".")
    if not _DOMAIN_RE.match(clean):
        return False
    # Reject IP addresses masquerading as domains
    try:
        ipaddress.ip_address(clean)
        return False  # it's an IP, not a domain
    except ValueError:
        pass
    # Check benign suffix
    lower = clean.lower()
    if any(lower == s or lower.endswith("." + s) for s in _BENIGN_DOMAIN_SUFFIXES):
        log.debug("Filtered benign domain: %s", value)
        return False
    # Reject single-label "domains" (no TLD)
    if "." not in clean:
        return False
    return True


def is_valid_url(value: str) -> bool:
    """Return True if *value* is a syntactically valid HTTP/HTTPS URL with a routable host.
    Accepts schemeless URLs (e.g. 'example.com/path') by prepending 'https://'."""
    if not value:
        return False
    # Prepend scheme if missing so urlparse works correctly
    normalised = value.strip()
    if not normalised.startswith(("http://", "https://")):
        normalised = "https://" + normalised
    try:
        parsed = urlparse(normalised)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname or ""
    if not host:
        return False
    # Validate the host as either a domain or a public IP
    return is_valid_domain(host) or is_valid_ip(host)


def is_valid_hash(value: str) -> bool:
    """Return True if *value* is a valid hex hash (MD5/SHA1/SHA256/SHA512)."""
    if not value:
        return False
    v = value.strip().lower()
    # Filter obvious placeholders
    if v in {"0" * 32, "0" * 40, "0" * 64, "f" * 32, "f" * 40, "f" * 64}:
        return False
    return bool(_HASH_RE.match(v))


def is_valid_cve(value: str) -> bool:
    """Return True if *value* matches the CVE-YYYY-NNNNN pattern."""
    return bool(value and _CVE_RE.match(value.strip()))


def is_valid_email(value: str) -> bool:
    """Return True if *value* looks like a valid email address."""
    return bool(value and _EMAIL_RE.match(value.strip()))


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────────────────────────────────────

_VALIDATORS = {
    "ip": is_valid_ip,
    "domain": is_valid_domain,
    "url": is_valid_url,
    "hash": is_valid_hash,
    "cve": is_valid_cve,
    "email": is_valid_email,
    "cidr": lambda v: True,   # pass CIDR through; light validation only
    "mutex": lambda v: bool(v),
    "yara": lambda v: bool(v),
}


def is_valid_ioc(ioc: dict[str, Any]) -> bool:
    """
    Validate a single IOC record dictionary.
    Returns True if the IOC is considered actionable and valid.
    """
    ioc_type = ioc.get("type", "").lower()
    value = ioc.get("value", "").strip()
    if not value:
        return False
    validator = _VALIDATORS.get(ioc_type)
    if validator is None:
        # Unknown type — pass through with a warning
        log.debug("Unknown IOC type '%s' for value '%s' — passing through", ioc_type, value)
        return True
    return validator(value)


def filter_iocs(iocs: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """
    Filter a list of IOC records and return (valid_iocs, n_filtered).
    Logs a summary at INFO level.
    """
    valid: list[dict[str, Any]] = []
    n_filtered = 0
    for ioc in iocs:
        if is_valid_ioc(ioc):
            valid.append(ioc)
        else:
            n_filtered += 1
            log.debug(
                "Filtered IOC type=%s value=%s",
                ioc.get("type"),
                ioc.get("value"),
            )
    log.info(
        "Validation: %d/%d passed (%d filtered)",
        len(valid),
        len(iocs),
        n_filtered,
    )
    return valid, n_filtered


# ─────────────────────────────────────────────────────────────────────────────
# Normalisation helpers
# ─────────────────────────────────────────────────────────────────────────────

def normalise_ip(value: str) -> str:
    """Canonicalise an IP address string (strips port, normalises IPv6)."""
    host = value.strip().strip("[]")
    if host.count(":") == 1 and "." in host.split(":")[0]:
        host = host.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return value


def normalise_domain(value: str) -> str:
    """Lowercase and strip trailing dot from a domain."""
    return value.strip().rstrip(".").lower()


def normalise_hash(value: str) -> str:
    """Lowercase a hash string."""
    return value.strip().lower()


def normalise_url(value: str) -> str:
    """Lowercase scheme/host, strip trailing whitespace, and ensure scheme prefix."""
    clean = value.strip()
    # Add https:// if scheme is missing
    if not clean.startswith(("http://", "https://")):
        clean = "https://" + clean
    parsed = urlparse(clean)
    if not parsed.scheme or not parsed.netloc:
        return value.strip()
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return value.strip()
    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"
    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth = f"{auth}:{parsed.password}"
        netloc = f"{auth}@{netloc}"
    return parsed._replace(scheme=parsed.scheme.lower(), netloc=netloc).geturl()


_CONFIDENCE_LEVELS: dict[str, int] = {
    "confirmed": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
}


def normalise_confidence(value: Any) -> int:
    """Coerce a confidence score to an int on the 0-100 scale.

    Feeds report confidence inconsistently (some as ints, others as
    qualitative labels like "high"); collapse both onto one scale so
    downstream comparisons (e.g. max()) never mix str and int.
    """
    if isinstance(value, bool):
        return 100 if value else 0
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        mapped = _CONFIDENCE_LEVELS.get(value.strip().lower())
        if mapped is not None:
            return mapped
        try:
            return int(float(value.strip()))
        except ValueError:
            return 0
    return 0


def normalise_ioc(ioc: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *ioc* with the value field normalised."""
    ioc_type = ioc.get("type", "").lower()
    value = ioc.get("value", "")
    normalisers = {
        "ip": normalise_ip,
        "domain": normalise_domain,
        "hash": normalise_hash,
        "url": normalise_url,
    }
    normaliser = normalisers.get(ioc_type)
    result = {**ioc, "value": normaliser(value)} if normaliser else dict(ioc)
    result["confidence"] = normalise_confidence(ioc.get("confidence", 0))
    return result


def validate_feed_directory(feeds_dir: Path) -> dict[str, Any]:
    """Validate all JSON feed files and return a summary."""
    files = sorted(feeds_dir.glob("*.json"))
    total_raw = 0
    total_valid = 0
    by_file: dict[str, dict[str, int]] = {}

    for path in files:
        raw_text = path.read_text().strip()
        if not raw_text:
            continue
        data = json.loads(raw_text)
        if not isinstance(data, list):
            continue
        total_raw += len(data)
        valid, filtered = filter_iocs(data)
        total_valid += len(valid)
        by_file[path.name] = {
            "raw": len(data),
            "valid": len(valid),
            "filtered": filtered,
        }

    return {
        "feed_files": len(files),
        "total_raw": total_raw,
        "total_valid": total_valid,
        "total_filtered": total_raw - total_valid,
        "by_file": by_file,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Validate IOC feed files.")
    parser.add_argument(
        "--feeds-dir",
        default=str(Path(__file__).resolve().parent.parent / "feeds"),
        help="Directory containing feed JSON files.",
    )
    args = parser.parse_args()
    summary = validate_feed_directory(Path(args.feeds_dir))
    print(json.dumps(summary, indent=2))
