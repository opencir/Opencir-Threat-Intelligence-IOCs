#!/usr/bin/env python3
"""
fetch_article.py — Fetch and extract IOCs from a single Microsoft Security Blog article.

Usage:
    python scripts/fetch_article.py <article_url> [--out feeds/my_output.json]

Example:
    python scripts/fetch_article.py \
        https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests
from fetch_msft import WP_API_POSTS, _fetch_article_iocs
from config import FEEDS_DIR, HEADERS, TIMEOUT, now_iso


def fetch_single(url: str, out_path=None):
    fetched_at = now_iso()
    slug = url.rstrip("/").split("/")[-1]
    title = slug.replace("-", " ").title()
    published = ""

    session = requests.Session()
    session.headers.update(HEADERS)

    # Resolve metadata from WP REST API
    try:
        resp = session.get(
            WP_API_POSTS,
            params={"slug": slug, "_fields": "title,date,link"},
            timeout=TIMEOUT,
        )
        if resp.ok:
            posts = resp.json()
            if posts:
                title = posts[0].get("title", {}).get("rendered", title)
                published = posts[0].get("date", "")
    except Exception:
        pass

    print(f"\nSource  : {url}")
    print(f"Title   : {title}")
    print(f"Date    : {published or '(not resolved)'}\n")

    iocs = _fetch_article_iocs(
        session=session,
        url=url,
        title=title,
        published=published,
        fetched_at=fetched_at,
    )

    if out_path is None:
        out_path = FEEDS_DIR / f"msft_{slug[:50]}.json"
    else:
        out_path = Path(out_path)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(iocs, indent=2))
    print(f"Wrote {len(iocs)} IOCs  →  {out_path}\n")

    if iocs:
        col_w = 58
        print(f"{'#':<4} {'TYPE':<10} {'VALUE':<{col_w}} {'FIRST SEEN'}")
        print("-" * (4 + 10 + col_w + 14))
        for i, ioc in enumerate(iocs, 1):
            print(f"{i:<4} {ioc['type']:<10} {ioc['value']:<{col_w}} {ioc.get('first_seen','')}")
    else:
        print("No IOCs extracted.")

    return iocs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract IOCs from a single Microsoft Security Blog article."
    )
    parser.add_argument("url", help="Full URL of the blog article")
    parser.add_argument("--out", default=None, help="Output JSON path")
    args = parser.parse_args()
    results = fetch_single(args.url, args.out)
    print(f"\nDone — {len(results)} IOCs extracted.")
