#!/usr/bin/env python3
"""
fetch_msft_research.py — Collector for Microsoft Security research blog IOCs.

Crawls:
    https://www.microsoft.com/en-us/security/blog/search/?ep_filter_content-type=research

For each research article the script:
  1. Discovers article URLs from the search/listing page (pagination-aware).
  2. Fetches each article via the WordPress REST API (falls back to HTML).
  3. Locates the "Indicators of compromise" section (or scans full body).
  4. Refangs defanged indicators and applies regex extractors for IPs,
     domains, URLs, file hashes, and CVEs.
  5. Writes one Markdown file per article into microsoft-security-blog/.
  6. Writes a combined feeds/msft_research.json JSON feed.

This is a legitimate cybersecurity lab collecting IOCs from public Microsoft
Security research blogs for threat-intelligence and firewall blocking purposes.

Usage:
    python scripts/fetch_msft_research.py [--max-pages N]
"""

import argparse
import html
import json
import logging
import re
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests
from bs4 import BeautifulSoup, Tag

from config import FEEDS_DIR, HEADERS, TIMEOUT, now_iso
from fetch_msft import (
    WP_API_POSTS,
    ARTICLES_PER_PAGE,
    REQUEST_DELAY,
    _fetch_article_iocs,
    _refang,
    extract_iocs_from_table,
    extract_iocs_from_text,
    _get_article_text,
    _merge_dedup,
)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("fetch_msft_research")

# ── Config ────────────────────────────────────────────────────────────────────
BLOG_BASE        = "https://www.microsoft.com/en-us/security/blog"
RESEARCH_URL     = f"{BLOG_BASE}/search/?ep_filter_content-type=research"
OUTPUT_DIR       = Path(__file__).resolve().parent.parent / "microsoft-security-blog"
MAX_INDEX_PAGES  = 20


def _slugify(text: str, max_len: int = 60) -> str:
    """Convert a title string to a safe file-name slug."""
    slug = re.sub(r"[^\w\s-]", "", text.lower())
    slug = re.sub(r"[\s_-]+", "-", slug).strip("-")
    return slug[:max_len]


def _article_markdown_path(article: dict[str, str], out_dir: Path) -> Path:
    """Return the expected Markdown path for a scraped article."""
    published = article.get("published", "")[:10] or "undated"
    return out_dir / f"{published}_{_slugify(article['title'])}.md"


def _defang_dotted(value: str) -> str:
    """Defang dotted domains/IPs without altering non-dotted values."""
    return value.replace(".", "[.]") if "." in value else value


def defang(value: str, ioc_type: str) -> str:
    """Defang IOC values for safe publication in Markdown and JSON outputs."""
    if not value:
        return value

    itype = (ioc_type or "").lower()
    canonical = re.sub(r"\bhxxps\[://\]", "https://", value, flags=re.IGNORECASE)
    canonical = re.sub(r"\bhxxp\[://\]", "http://", canonical, flags=re.IGNORECASE)
    canonical = re.sub(r"\bhttps\[://\]", "https://", canonical, flags=re.IGNORECASE)
    canonical = re.sub(r"\bhttp\[://\]", "http://", canonical, flags=re.IGNORECASE)
    canonical = re.sub(r"\bhxxps\[:\]//", "https://", canonical, flags=re.IGNORECASE)
    canonical = re.sub(r"\bhxxp\[:\]//", "http://", canonical, flags=re.IGNORECASE)
    canonical = re.sub(r"\bhttps\[:\]//", "https://", canonical, flags=re.IGNORECASE)
    canonical = re.sub(r"\bhttp\[:\]//", "http://", canonical, flags=re.IGNORECASE)
    canonical = _refang(canonical)
    if "@" in canonical and itype in {"domain", "email"}:
        local, sep, domain = canonical.rpartition("@")
        return f"{local}{sep}{_defang_dotted(domain)}"

    if itype in {"domain", "ip"}:
        return _defang_dotted(canonical)

    if itype != "url":
        return canonical

    match = re.match(
        r"^(?:(?P<scheme>[a-z][a-z0-9+\-.]*):\/\/)?(?P<authority>[^\/?#]+)(?P<rest>[\/?#].*)?$",
        canonical,
        flags=re.IGNORECASE,
    )
    if not match:
        return canonical.replace("://", "[://]", 1)

    scheme = match.group("scheme") or ""
    authority = match.group("authority") or ""
    rest = match.group("rest") or ""

    auth = ""
    hostport = authority
    if "@" in authority:
        auth, hostport = authority.rsplit("@", 1)
        auth += "@"

    host = hostport
    port = ""
    wrapped = False
    if hostport.startswith("[") and "]" in hostport:
        end = hostport.index("]")
        host = hostport[1:end]
        port = hostport[end + 1:]
        wrapped = True
    elif ":" in hostport:
        maybe_host, maybe_port = hostport.rsplit(":", 1)
        if maybe_port.isdigit():
            host = maybe_host
            port = f":{maybe_port}"

    defanged_host = _defang_dotted(host)
    if wrapped:
        defanged_host = f"[{defanged_host}]"

    defanged_authority = f"{auth}{defanged_host}{port}"
    if not scheme:
        return f"{defanged_authority}{rest}"
    return f"{scheme}[://]{defanged_authority}{rest}"


# ── Article discovery: WordPress REST API ─────────────────────────────────────
def _discover_via_api(session: requests.Session, max_pages: int) -> list[dict[str, str]]:
    """
    Query the WP REST API filtering for posts tagged/categorised as 'research'.
    Returns a list of {url, title, published} dicts.
    """
    articles: list[dict[str, str]] = []

    for page in range(1, max_pages + 1):
        try:
            resp = session.get(
                WP_API_POSTS,
                params={
                    "per_page": ARTICLES_PER_PAGE,
                    "page":     page,
                    "_fields":  "id,date,title,link",
                    "orderby":  "date",
                    "order":    "desc",
                    # Filter by content-type 'research' category/tag if supported
                    "categories_exclude": "",
                },
                timeout=TIMEOUT,
            )
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
                "title":     html.unescape(post.get("title", {}).get("rendered", "")),
                "published": post.get("date", ""),
            })

        log.info("WP API page %d: retrieved %d posts", page, len(posts))
        if len(posts) < ARTICLES_PER_PAGE:
            break
        time.sleep(REQUEST_DELAY / 2)

    return articles


# ── Article discovery: HTML scraping ─────────────────────────────────────────
def _discover_via_html(session: requests.Session, max_pages: int) -> list[dict[str, str]]:
    """
    Walk the research search/listing pages and extract article links.
    Handles both traditional pagination and load-more/query-string patterns.
    """
    articles: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    next_url: str | None = RESEARCH_URL
    page = 0

    while next_url and page < max_pages:
        page += 1
        log.info("HTML index page %d: %s", page, next_url)
        try:
            resp = session.get(next_url, timeout=TIMEOUT)
            resp.raise_for_status()
        except requests.RequestException as exc:
            log.warning("Failed to fetch index page %s: %s", next_url, exc)
            break

        soup = BeautifulSoup(resp.text, "lxml")

        # Collect article cards
        for card in soup.find_all("article"):
            link_tag: Tag | None = card.find("a", href=True)
            if not link_tag:
                continue
            href: str = link_tag["href"]
            if not href.startswith("http"):
                href = "https://www.microsoft.com" + href
            # Only keep microsoft.com/security/blog URLs
            if "microsoft.com" not in href or "/security/blog/" not in href:
                continue
            if href in seen_urls:
                continue
            seen_urls.add(href)

            heading = card.find(re.compile(r"^h[1-6]$"))
            title   = heading.get_text(strip=True) if heading else link_tag.get_text(strip=True)
            time_tag: Tag | None = card.find("time")
            published = time_tag.get("datetime", "") if time_tag else ""

            articles.append({"url": href, "title": title, "published": published})

        # Also look for plain article links (some search pages use a list layout)
        for a in soup.select("a[href*='/security/blog/']"):
            href = a["href"]
            if not href.startswith("http"):
                href = "https://www.microsoft.com" + href
            # Must be a blog post path (at least 4 segments after /security/blog/)
            path_parts = href.rstrip("/").replace("https://www.microsoft.com/en-us/security/blog", "").split("/")
            if len(path_parts) < 4:
                continue
            if href in seen_urls:
                continue
            seen_urls.add(href)
            title = a.get_text(strip=True) or href.rstrip("/").split("/")[-1].replace("-", " ").title()
            articles.append({"url": href, "title": title, "published": ""})

        # Pagination
        next_link: Tag | None = (
            soup.find("a", rel=lambda v: v and "next" in v)
            or soup.find("a", string=re.compile(r"^(next|›|»|load\s+more)$", re.I))
        )
        if next_link and next_link.get("href"):
            nh: str = next_link["href"]
            next_url = nh if nh.startswith("http") else ("https://www.microsoft.com" + nh)
            # Avoid circular pagination (next link wrapping back to base URL)
            if next_url == RESEARCH_URL:
                next_url = None
        else:
            # Try paged URL pattern
            if page < max_pages:
                paged = f"{RESEARCH_URL}&paged={page + 1}"
                next_url = paged
            else:
                next_url = None

        time.sleep(REQUEST_DELAY)

    log.info("HTML discovery: found %d articles over %d pages", len(articles), page)
    return articles


# ── Markdown writer ───────────────────────────────────────────────────────────
def _write_markdown(
    article: dict[str, str],
    iocs: list[dict],
    out_dir: Path,
) -> Path:
    """
    Write a Markdown file for a single article with an IOC table.
    Returns the path of the written file.
    """
    title     = article["title"]
    url       = article["url"]
    published = article.get("published", "")[:10]  # YYYY-MM-DD

    out_path  = _article_markdown_path(article, out_dir)

    lines: list[str] = [
        f"# {title}",
        "",
        f"**Source:** <{url}>",
        f"**Published:** {published or 'unknown'}",
        f"**IOC count:** {len(iocs)}",
        "",
        "> Collected for legitimate threat-intelligence purposes: building an IOC "
        "database and firewall blocking rules from publicly available Microsoft "
        "Security research blog posts.",
        "",
    ]

    if iocs:
        lines += [
            "## Indicators of Compromise",
            "",
            "| # | Type | Value | Description | First Seen | Last Seen |",
            "|---|------|-------|-------------|------------|-----------|",
        ]
        for i, ioc in enumerate(iocs, 1):
            itype = ioc.get("type", "")
            val   = ioc.get("value", "")
            desc  = ioc.get("description", "")
            fs    = ioc.get("first_seen", "")
            ls    = ioc.get("last_seen", "")
            lines.append(f"| {i} | {itype} | `{val}` | {desc} | {fs} | {ls} |")
        lines.append("")
    else:
        lines += [
            "## Indicators of Compromise",
            "",
            "_No IOCs were extracted from this article._",
            "",
        ]

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


# ── Index writer ──────────────────────────────────────────────────────────────
def _write_index(articles_meta: list[dict], out_dir: Path) -> None:
    """
    Write/overwrite README.md inside microsoft-security-blog/ with a table
    linking to every generated markdown file.
    """
    lines: list[str] = [
        "# Microsoft Security Research Blog — IOC Index",
        "",
        "Extracted Indicators of Compromise from Microsoft Security research blog posts.",
        "",
        f"**Source filter:** <https://www.microsoft.com/en-us/security/blog/search/?ep_filter_content-type=research>",
        "",
        "> This is a legitimate cybersecurity lab collecting public IOCs for threat "
        "intelligence and firewall blocking. All data is sourced from publicly "
        "available Microsoft Security research articles.",
        "",
        "| Date | Article | IOC Count | File |",
        "|------|---------|-----------|------|",
    ]

    for meta in sorted(articles_meta, key=lambda m: m.get("published", ""), reverse=True):
        date   = meta.get("published", "")[:10] or "—"
        title  = meta.get("title", "")
        url    = meta.get("url", "")
        count  = meta.get("ioc_count", 0)
        if count <= 0:
            continue
        fname  = meta.get("filename", "")
        lines.append(f"| {date} | [{title}]({url}) | {count} | [{fname}]({fname}) |")

    lines.append("")
    (out_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


# Known placeholder/example values to exclude from IOC output
_FALSE_POSITIVE_VALUES: frozenset[str] = frozenset({
    "127.0.0.1", "0.0.0.0", "localhost", "evil.com", "example.com",
    "attacker.example", "attacker.com", "victim.com", "test.com",
    "http://localhost", "http://127.0.0.1", "https://evil.com",
    "http://evil.com", "https://example.com", "http://example.com",
    # With port
    "http://localhost:3000", "http://127.0.0.1:8080",
})

# Known legitimate domains that should never be treated as IOCs
_FALSE_POSITIVE_DOMAINS: tuple[str, ...] = (
    "whitehouse.gov", "cisa.gov", "nist.gov", "nvd.nist.gov",
    "nsa.gov", "fbi.gov", "dhs.gov",
)


def _filter_false_positives(iocs: list[dict]) -> list[dict]:
    """Remove known placeholder/benign values that are not real IOCs."""
    result = []
    for ioc in iocs:
        # Strip ASCII and Unicode quote/punctuation from both ends before comparing
        val = ioc.get("value", "").lower().strip("\"'\u201c\u201d\u2018\u2019.,;")
        if val in _FALSE_POSITIVE_VALUES:
            continue
        if ioc.get("type") in ("domain", "url"):
            if any(val == d or val.endswith("." + d) for d in _FALSE_POSITIVE_DOMAINS):
                continue
        result.append(ioc)
    return result


# ── Main ──────────────────────────────────────────────────────────────────────
def fetch_all(max_pages: int = MAX_INDEX_PAGES) -> list[dict]:
    fetched_at = now_iso()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers.update(HEADERS)

    # Article discovery
    log.info("Attempting WordPress REST API discovery for research articles …")
    articles = _discover_via_api(session, max_pages)

    if not articles:
        log.info("WP API returned no results — using HTML scraping …")
        articles = _discover_via_html(session, max_pages)

    if not articles:
        log.warning("No articles discovered. Check network connectivity.")
        return []

    log.info("Processing %d articles …", len(articles))
    all_iocs: list[dict] = []
    index_meta: list[dict] = []

    for idx, art in enumerate(articles, 1):
        log.info("[%d/%d] %s", idx, len(articles), art["url"])

        iocs = _fetch_article_iocs(
            session=session,
            url=art["url"],
            title=art["title"],
            published=art["published"],
            fetched_at=fetched_at,
        )
        time.sleep(REQUEST_DELAY)

        # Override source label for research blog and add tags
        for ioc in iocs:
            ioc["source"] = "microsoft-security-research"
            ioc["tags"] = list({*ioc.get("tags", []), "research", "microsoft-security-blog"})

        # Filter out known false positives
        iocs = _filter_false_positives(iocs)

        if not iocs:
            md_path = _article_markdown_path(art, OUTPUT_DIR)
            if md_path.exists():
                md_path.unlink()
                log.info("  Removed %s (0 IOCs)", md_path.name)
            else:
                log.info("  Skipped %s (0 IOCs)", md_path.name)
            continue

        output_iocs = [
            {**ioc, "value": defang(ioc.get("value", ""), ioc.get("type", ""))}
            for ioc in iocs
        ]

        all_iocs.extend(output_iocs)

        md_path = _write_markdown(art, output_iocs, OUTPUT_DIR)
        log.info("  Wrote %s (%d IOCs)", md_path.name, len(output_iocs))

        index_meta.append({
            "title":     art["title"],
            "url":       art["url"],
            "published": art.get("published", ""),
            "ioc_count": len(output_iocs),
            "filename":  md_path.name,
        })

    # Write index README
    _write_index(index_meta, OUTPUT_DIR)
    log.info("Wrote index → %s", OUTPUT_DIR / "README.md")

    # Write JSON feed
    out_json = FEEDS_DIR / "msft_research.json"
    out_json.write_text(json.dumps(all_iocs, indent=2), encoding="utf-8")
    log.info("Wrote %d IOCs → %s", len(all_iocs), out_json)

    return all_iocs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Fetch Microsoft Security research blog posts and extract IOCs. "
            "Outputs per-article Markdown files to microsoft-security-blog/ "
            "and a combined JSON feed to feeds/msft_research.json."
        )
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=MAX_INDEX_PAGES,
        help=f"Maximum index pages to walk (default: {MAX_INDEX_PAGES})",
    )
    args = parser.parse_args()

    results = fetch_all(max_pages=args.max_pages)
    print(f"\nDone — {len(results)} IOCs extracted from Microsoft Security research blog.")
