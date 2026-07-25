#!/usr/bin/env python3
"""
fetch_msft.py — Collector for Microsoft Threat Intelligence blog IOCs.

Crawls:
    https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/
    ?sort-by=newest-oldest

For each article the script:
  1. Locates the "Indicators of compromise" section (or falls back to the
     full article body).
  2. Refangs defanged indicators (hxxp → http, evil[.]com → evil.com, etc.).
  3. Applies regex extractors for IPs, domains, URLs, file hashes, and CVEs.
  4. Filters private IPs, benign domains, and placeholder hashes.

Discovery strategy:
  • Tries the WordPress REST API first (fast, structured, no HTML parsing).
  • Falls back to BeautifulSoup HTML scraping of the topic listing page when
    the API is inaccessible or returns no results.

Output → feeds/msft_threat_intel.json   (flat JSON array of IOC records)

IOC record schema:
    type          : ip | domain | url | hash | cve
    value         : normalised indicator value
    source        : "microsoft-threat-intel"
    confidence    : 75 (int, 0-100 scale)
    tags          : ["threat-intelligence", "microsoft"]
    first_seen    : ISO-8601 publish date of the source article (UTC)
    fetched_at    : ISO-8601 timestamp when this script ran (UTC)
    article_url   : permalink of the source article
    article_title : title of the source article
"""

import ipaddress
import json
import logging
import re
import time
from typing import Any

import requests
from bs4 import BeautifulSoup, Tag

from config import FEEDS_DIR, HEADERS, TIMEOUT, now_iso

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("fetch_msft")

# ── Config ────────────────────────────────────────────────────────────────────
BLOG_BASE          = "https://www.microsoft.com/en-us/security/blog"
TOPIC_URL          = (f"{BLOG_BASE}/topic/threat-intelligence/?sort-by=newest-oldest")
WP_API_POSTS       = f"{BLOG_BASE}/wp-json/wp/v2/posts"
REQUEST_DELAY      = 2.0   # seconds between requests — be polite
MAX_INDEX_PAGES    = 10    # index pages to walk (≈ 10 × 10 articles = 100)
ARTICLES_PER_PAGE  = 10

# ── IOC regex patterns (applied AFTER defanging) ──────────────────────────────
_RE_IPv4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# Common TLDs seen in threat-intel reports — narrow list keeps noise low
_TLD = (
    "com|net|org|io|gov|edu|mil|info|biz|co|uk|de|fr|ru|cn|br|jp|nl|"
    "onion|top|xyz|club|site|online|pro|app|dev|cloud|live|me|cc|pw|tk|"
    "gq|cf|ga|ml|us|ca|au|in|eu|to|ac|id|ir|su|pk|ng|za|lk|th|vn|"
    # Additional ccTLDs and gTLDs commonly seen in threat-intel articles
    "es|it|pl|cz|ro|hu|bg|gr|pt|se|no|fi|dk|at|ch|be|ie|nz|sg|hk|tw|"
    "shop|store|click|link|run|tech|work|space|fun|ink|best|win|bid|trade|"
    "webcam|review|party|date|faith|accountant|download|loan|racing"
)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,5}"
    r"(?:" + _TLD + r")\b",
    re.IGNORECASE,
)

_RE_URL    = re.compile(r"https?://[^\s<>\"'\]\[)(,;]+")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_SHA1   = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_MD5    = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_CVE    = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Heading text hinting that the next section contains IOCs.
# Deliberately specific to avoid false matches like "Drive-by compromise".
_IOC_HEADING_RE = re.compile(
    r"indicators?\s+(of\s+)?compromise"   # "Indicators of compromise"
    r"|\biocs?\b"                          # standalone "IOC" / "IOCs"
    r"|^indicators?$",                     # heading that is just "Indicators"
    re.IGNORECASE,
)

# ── Noise / allowlist filters ─────────────────────────────────────────────────
_BENIGN_IPS: frozenset[str] = frozenset({
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
    "208.67.222.222", "208.67.220.220",
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
})

_BENIGN_DOMAIN_SUFFIXES: tuple[str, ...] = (
    # Microsoft infrastructure — appear in articles as attribution, not IOCs
    "microsoft.com", "windows.com", "azure.com", "live.com", "office.com",
    "msn.com", "bing.com", "visualstudio.com", "microsoftonline.com",
    "windowsupdate.com", "update.microsoft.com",
    # Common CDN / resolver infrastructure
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "cloudflare.com", "akamaiedge.net", "fastly.net", "cloudfront.net",
    "amazon.com", "amazonaws.com",
    "apple.com", "icloud.com",
    "github.com", "githubusercontent.com",
    "twitter.com", "x.com", "linkedin.com", "facebook.com",
)

# Placeholder / trivial hashes that are not real IOCs
_RE_ZERO_HASH = re.compile(r"^[0a]{32,}$", re.IGNORECASE)

# Private / reserved network ranges
_PRIVATE_NETS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(c)
    for c in [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4", "0.0.0.0/8",
        "::1/128", "fe80::/10", "fc00::/7", "ff00::/8", "::/128",
    ]
)


# ── Utility helpers ───────────────────────────────────────────────────────────
def _refang(text: str) -> str:
    """Restore defanged indicators to their canonical form."""
    text = re.sub(r"\bhxxps://", "https://", text, flags=re.IGNORECASE)
    text = re.sub(r"\bhxxp://",  "http://",  text, flags=re.IGNORECASE)
    text = re.sub(r"\[\.?\]|\(\.?\)", ".", text)
    text = re.sub(r"\[dot\]|\(dot\)", ".", text, flags=re.IGNORECASE)
    text = text.replace("[@]", "@")
    return text


def _is_routable_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        if any(addr in net for net in _PRIVATE_NETS):
            return False
        return value not in _BENIGN_IPS
    except ValueError:
        return False


def _is_benign_domain(value: str) -> bool:
    lower = value.lower().rstrip(".")
    return any(lower == s or lower.endswith("." + s) for s in _BENIGN_DOMAIN_SUFFIXES)


def _make_ioc(
    itype:   str,
    value:   str,
    meta:    dict[str, str],
    first_seen: str = "",
    last_seen:  str = "",
    description: str = "",
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "type":          itype,
        "value":         value,
        "source":        "microsoft-threat-intel",
        "confidence":    75,
        "tags":          ["threat-intelligence", "microsoft"],
        "first_seen":    first_seen or meta.get("published") or meta["fetched_at"],
        "fetched_at":    meta["fetched_at"],
        "article_url":   meta["url"],
        "article_title": meta["title"],
    }
    if last_seen:
        record["last_seen"] = last_seen
    if description:
        record["description"] = description
    return record


# ── IOC table parser (structured Microsoft IOC tables) ───────────────────────
# Microsoft TI articles use a WordPress table with columns:
#   Indicator | Type | Description | First seen | Last seen
_TABLE_TYPE_MAP: dict[str, str] = {
    "ip address":  "ip",
    "ipv4":        "ip",
    "ipv6":        "ip",
    "domain":      "domain",
    "fqdn":        "domain",
    "url":         "url",
    "md5":         "hash",
    "sha1":        "hash",
    "sha256":      "hash",
    "file hash":   "hash",
    "hash":        "hash",
    "cve":         "cve",
    "email":       "email",
}


def extract_iocs_from_table(
    soup_section: "BeautifulSoup | Tag",
    meta: dict[str, str],
) -> list[dict[str, Any]]:
    """
    Parse structured IOC tables embedded in the IOC section of an article.

    Handles the standard Microsoft format:
        Indicator | Type | Description | First seen | Last seen

    Returns a list of IOC records with first_seen/last_seen from the table.
    """
    iocs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for table in soup_section.find_all("table"):
        rows = table.find_all("tr")
        if not rows:
            continue

        # Detect header row and column positions
        header_cells = [td.get_text(strip=True).lower() for td in rows[0].find_all(["th", "td"])]
        if "indicator" not in header_cells and "ioc" not in header_cells:
            continue  # not an IOC table

        col: dict[str, int] = {}
        for i, cell in enumerate(header_cells):
            if "indicator" in cell or cell == "ioc":
                col["value"] = i
            elif "type" in cell:
                col["type"] = i
            elif "description" in cell or "detail" in cell:
                col["description"] = i
            elif "first" in cell:
                col["first_seen"] = i
            elif "last" in cell:
                col["last_seen"] = i

        if "value" not in col:
            continue

        for row in rows[1:]:
            cells = row.find_all(["td", "th"])
            if not cells:
                continue

            def cell_text(idx: int) -> str:
                return _refang(cells[idx].get_text(strip=True)) if idx < len(cells) else ""

            raw_value = cell_text(col["value"])
            if not raw_value:
                continue

            raw_type  = cell_text(col.get("type", -1)).lower()
            itype     = _TABLE_TYPE_MAP.get(raw_type, "")
            first_seen = cell_text(col.get("first_seen", -1))
            last_seen  = cell_text(col.get("last_seen", -1))
            description = cell_text(col.get("description", -1))

            # If type column missing or unrecognised, auto-detect
            if not itype:
                itype = _auto_type(raw_value)
            if not itype:
                continue

            # Normalise value
            value = raw_value.strip().rstrip(".")
            if itype == "domain":
                value = value.lower()
            elif itype == "ip":
                if not _is_routable_ip(value):
                    continue

            key = (itype, value.lower())
            if key in seen:
                continue
            seen.add(key)
            iocs.append(_make_ioc(itype, value, meta, first_seen, last_seen, description))

    return iocs


def _auto_type(value: str) -> str:
    """Heuristically determine IOC type from value when the Type column is absent."""
    if _RE_SHA256.fullmatch(value):
        return "hash"
    if _RE_SHA1.fullmatch(value):
        return "hash"
    if _RE_MD5.fullmatch(value):
        return "hash"
    if _RE_CVE.fullmatch(value):
        return "cve"
    if _RE_IPv4.fullmatch(value):
        return "ip"
    if "/" in value or value.startswith("http"):
        return "url"
    if _RE_DOMAIN.search(value):
        return "domain"
    return ""


# ── IOC extraction from text ──────────────────────────────────────────────────
def extract_iocs_from_text(
    text:     str,
    meta:     dict[str, str],
) -> list[dict[str, Any]]:
    """
    Apply all regex patterns to *text* (caller must refang first).
    Returns a deduplicated list of IOC records.
    """
    iocs:      list[dict[str, Any]] = []
    seen:      set[tuple[str, str]] = set()

    def add(itype: str, value: str) -> None:
        key = (itype, value.lower())
        if key not in seen:
            seen.add(key)
            iocs.append(_make_ioc(itype, value, meta))

    # ── URLs first (track spans to skip domain re-matching inside URLs) ───────
    url_spans: list[tuple[int, int]] = []
    for m in _RE_URL.finditer(text):
        v = m.group().rstrip(".,;:)\">")
        url_spans.append((m.start(), m.end()))
        add("url", v)

    # ── IP addresses ──────────────────────────────────────────────────────────
    for m in _RE_IPv4.finditer(text):
        if _is_routable_ip(m.group()):
            add("ip", m.group())

    # ── Domains (skip text already captured inside a URL match) ───────────────
    for m in _RE_DOMAIN.finditer(text):
        if any(s <= m.start() and m.end() <= e for s, e in url_spans):
            continue
        v = m.group().lower().rstrip(".")
        if not _is_benign_domain(v):
            add("domain", v)

    # ── Hashes — longest first so SHA1/MD5 are not matched inside SHA256 ──────
    sha256_spans: list[tuple[int, int]] = []
    for m in _RE_SHA256.finditer(text):
        v = m.group().lower()
        if not _RE_ZERO_HASH.match(v):
            add("hash", v)
            sha256_spans.append((m.start(), m.end()))

    sha1_spans: list[tuple[int, int]] = []
    for m in _RE_SHA1.finditer(text):
        if any(s <= m.start() and m.end() <= e for s, e in sha256_spans):
            continue
        v = m.group().lower()
        if not _RE_ZERO_HASH.match(v):
            add("hash", v)
            sha1_spans.append((m.start(), m.end()))

    all_longer = sha256_spans + sha1_spans
    for m in _RE_MD5.finditer(text):
        if any(s <= m.start() and m.end() <= e for s, e in all_longer):
            continue
        v = m.group().lower()
        if not _RE_ZERO_HASH.match(v):
            add("hash", v)

    # ── CVEs ──────────────────────────────────────────────────────────────────
    for m in _RE_CVE.finditer(text):
        add("cve", m.group().upper())

    return iocs


# ── Per-article: locate IOC section → extract text ───────────────────────────
def _get_article_text(soup: BeautifulSoup) -> str:
    """
    Return the text most likely to contain IOCs from *soup*.

    Strategy:
      1. Prefer the narrowest content container: .entry-content / .post-content /
         .wp-block-post-content. Fall back to <article>, then <main>, then <body>.
      2. Look for a heading that mentions "indicators" / "IOC" / "compromise"
         (matched via get_text(), not the raw string, so nested-tag headings work).
         If found, collect siblings until the next same/higher non-IOC heading.
      3. If no IOC-specific heading exists, return the full body text.
    """
    # Prefer the narrowest content container first to avoid navigation noise
    body: Tag | None = (
        soup.find(class_=re.compile(
            r"wp-block-post-content|entry[\-_]content|post[\-_]content|article[\-_]body",
            re.I,
        ))
        or soup.find("article")
        or soup.find("main")
        or soup.body
    )
    if body is None:
        return ""

    # Strip non-content elements
    for tag in body.select("nav, footer, aside, header, script, style, "
                           ".related-posts, .newsletter, .comments"):
        tag.decompose()

    # Find IOC heading by get_text() so nested-tag headings are matched correctly
    ioc_heading: Tag | None = None
    for candidate in body.find_all(re.compile(r"^h[2-4]$")):
        if _IOC_HEADING_RE.search(candidate.get_text()):
            ioc_heading = candidate
            break

    if ioc_heading:
        parts: list[str] = []
        for sib in ioc_heading.next_siblings:
            if not isinstance(sib, Tag):
                continue
            # Stop at the next heading of equal or higher level that is NOT
            # itself an IOC heading
            if (
                re.match(r"^h[2-4]$", sib.name)
                and not _IOC_HEADING_RE.search(sib.get_text())
            ):
                break
            parts.append(sib.get_text(separator=" "))
        section_text = " ".join(parts).strip()
        if section_text:
            return section_text

    # Full body fallback
    return body.get_text(separator="\n")


# ── Article-level fetcher ─────────────────────────────────────────────────────
def _fetch_content_via_api(session: requests.Session, slug: str) -> str:
    """
    Try to retrieve rendered article HTML from the WP REST API using the URL
    slug.  Returns an empty string if the API is unreachable or returns nothing.
    """
    try:
        resp = session.get(
            WP_API_POSTS,
            params={"slug": slug, "_fields": "content"},
            timeout=TIMEOUT,
        )
        if resp.ok:
            posts = resp.json()
            if posts:
                return posts[0].get("content", {}).get("rendered", "")
    except Exception:
        pass
    return ""


def _fetch_article_iocs(
    session:    requests.Session,
    url:        str,
    title:      str,
    published:  str,
    fetched_at: str,
) -> list[dict[str, Any]]:
    meta = {"url": url, "title": title, "published": published, "fetched_at": fetched_at}
    slug = url.rstrip("/").split("/")[-1]

    # ── Preferred: WP REST API rendered content (avoids JS-gated HTML) ───────
    api_html = _fetch_content_via_api(session, slug)
    if api_html:
        soup = BeautifulSoup(api_html, "lxml")

        # Table-based extraction (structured, highest fidelity)
        table_iocs = extract_iocs_from_table(soup, meta)

        # Text-based extraction (regex fallback / supplement)
        raw  = _get_article_text(soup)
        if not raw:
            raw = soup.get_text(separator="\n")
        text_iocs = extract_iocs_from_text(_refang(raw), meta)

        iocs = _merge_dedup(table_iocs, text_iocs)
        if iocs:
            log.info("  [API] %-62s → %d IOCs (%d table, %d text)",
                     title[:62], len(iocs), len(table_iocs), len(text_iocs))
            return iocs

    # ── Fallback: fetch the article HTML page directly ─────────────────────
    try:
        resp = session.get(url, timeout=TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        log.warning("Could not fetch article %s: %s", url, exc)
        return []

    soup = BeautifulSoup(resp.text, "lxml")
    table_iocs = extract_iocs_from_table(soup, meta)
    raw  = _get_article_text(soup)
    text_iocs = extract_iocs_from_text(_refang(raw), meta)
    iocs = _merge_dedup(table_iocs, text_iocs)
    log.info("  [HTML] %-61s → %d IOCs (%d table, %d text)",
             title[:61], len(iocs), len(table_iocs), len(text_iocs))
    return iocs


def _merge_dedup(
    primary: list[dict[str, Any]],
    secondary: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return primary + any secondary entries not already in primary (by type+value)."""
    seen = {(r["type"], r["value"].lower()) for r in primary}
    result = list(primary)
    for r in secondary:
        k = (r["type"], r["value"].lower())
        if k not in seen:
            seen.add(k)
            result.append(r)
    return result


# ── Article discovery: WordPress REST API (preferred) ─────────────────────────
def _discover_via_api(session: requests.Session) -> list[dict[str, str]]:
    """
    Try the WordPress REST API to enumerate articles.
    Returns [] if the API is unavailable or yields no posts.
    We do NOT pre-filter by topic via the API because the taxonomy slug varies
    across blog configurations; instead we collect recent posts and rely on
    the IOC-section detector to produce empty results for non-TI articles.
    """
    articles: list[dict[str, str]] = []

    for page in range(1, MAX_INDEX_PAGES + 1):
        try:
            resp = session.get(
                WP_API_POSTS,
                params={
                    "per_page": ARTICLES_PER_PAGE,
                    "page":     page,
                    "_fields":  "id,date,title,link",
                    "orderby":  "date",
                    "order":    "desc",
                },
                timeout=TIMEOUT,
            )
            # 400 = page out of range
            if resp.status_code == 400:
                break
            resp.raise_for_status()
        except requests.RequestException as exc:
            log.debug("WP REST API not accessible: %s", exc)
            return []

        posts = resp.json()
        if not isinstance(posts, list) or not posts:
            break

        for post in posts:
            articles.append({
                "url":       post.get("link", ""),
                "title":     post.get("title", {}).get("rendered", ""),
                "published": post.get("date", ""),
            })

        log.info("WP API page %d: retrieved %d posts", page, len(posts))

        if len(posts) < ARTICLES_PER_PAGE:
            break
        time.sleep(REQUEST_DELAY / 2)

    return articles


# ── Article discovery: HTML scraping (fallback) ───────────────────────────────
def _discover_via_html(session: requests.Session) -> list[dict[str, str]]:
    """
    Walk the threat-intelligence topic page and follow pagination.
    Parses <article> cards from the listing and extracts URL / title / date.
    """
    articles: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    next_url: str | None = TOPIC_URL
    page = 0

    while next_url and page < MAX_INDEX_PAGES:
        page += 1
        log.info("HTML index page %d: %s", page, next_url)
        try:
            resp = session.get(next_url, timeout=TIMEOUT)
            resp.raise_for_status()
        except requests.RequestException as exc:
            log.warning("Failed to fetch index page %s: %s", next_url, exc)
            break

        soup = BeautifulSoup(resp.text, "lxml")

        for card in soup.find_all("article"):
            link_tag: Tag | None = card.find("a", href=True)
            if not link_tag:
                continue
            href: str = link_tag["href"]
            if not href.startswith("http"):
                href = "https://www.microsoft.com" + href
            if href in seen_urls:
                continue
            seen_urls.add(href)

            heading = card.find(re.compile(r"^h[1-6]$"))
            title   = heading.get_text(strip=True) if heading else link_tag.get_text(strip=True)
            time_tag: Tag | None = card.find("time")
            published = time_tag.get("datetime", "") if time_tag else ""

            articles.append({"url": href, "title": title, "published": published})

        # Pagination — try rel="next" or a visually labelled "Next" link
        next_link: Tag | None = (
            soup.find("a", rel=lambda v: v and "next" in v)
            or soup.find("a", string=re.compile(r"^(next|›|»|load more)$", re.I))
        )
        if next_link and next_link.get("href"):
            nh: str = next_link["href"]
            next_url = nh if nh.startswith("http") else ("https://www.microsoft.com" + nh)
        else:
            next_url = None

        time.sleep(REQUEST_DELAY)

    log.info("HTML discovery: found %d articles over %d pages", len(articles), page)
    return articles


# ── Main ──────────────────────────────────────────────────────────────────────
def fetch_all() -> list[dict[str, Any]]:
    fetched_at = now_iso()
    session = requests.Session()
    session.headers.update(HEADERS)

    # Article discovery: WP API → HTML fallback
    log.info("Attempting WordPress REST API discovery …")
    articles = _discover_via_api(session)
    if not articles:
        log.info("WP API returned no results — using HTML scraping fallback …")
        articles = _discover_via_html(session)

    if not articles:
        log.warning("No articles discovered. Check network connectivity.")
        return []

    log.info("Processing %d articles for IOC extraction …", len(articles))
    all_iocs: list[dict[str, Any]] = []

    for idx, art in enumerate(articles, 1):
        log.info("[%d/%d] %s", idx, len(articles), art["url"])
        iocs = _fetch_article_iocs(
            session,
            url=art["url"],
            title=art["title"],
            published=art["published"],
            fetched_at=fetched_at,
        )
        all_iocs.extend(iocs)
        time.sleep(REQUEST_DELAY)

    log.info("Total IOCs extracted from Microsoft TI blog: %d", len(all_iocs))
    return all_iocs


if __name__ == "__main__":
    results = fetch_all()
    out_path = FEEDS_DIR / "msft_threat_intel.json"
    out_path.write_text(json.dumps(results, indent=2))
    log.info("Wrote %d IOCs → %s", len(results), out_path)
