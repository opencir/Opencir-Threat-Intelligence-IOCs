# Consolidate Blog IOCs into a Single Feed File (skill)

## Purpose
Turn the per-article Markdown IOC tables in `microsoft-security-blog/` (or an
equivalent per-article Markdown folder) into **one flat JSON array** of
network/host-actionable IOCs — domain, url, ip, hash only — instead of leaving
them split across per-article files.

## When to use
- "Add/consolidate all domain/URL/IP/hash IOCs from the [Microsoft] blog into
  a single file."
- Any similar ask for one combined feed built from published per-article
  Markdown, as opposed to the fragmented one-file-per-article structure.

## Inputs
- Source dir: `microsoft-security-blog/*.md`, skip `README.md` (that's the
  index, not an article).
- Expected per-article layout (written by `scripts/fetch_msft_research.py`):
  - Title: first line, `# Title`
  - `**Source:** <article_url>`
  - `**Published:** date`
  - `## Indicators of Compromise` table:
    `| # | Type | Value | Description | First Seen | Last Seen |`
  - `Value` cells are wrapped in backticks and already defanged.

## Procedure
1. List all `*.md` files in the source dir except `README.md`.
2. Per file, extract `article_title` (the `# ` heading) and `article_url`
   (the `**Source:** <...>` line).
3. Parse each `| # | type | `value` | description | first_seen | last_seen |`
   row with a regex anchored on the leading `| <int> |` cell.
4. Keep only rows where `type` ∈ `{domain, url, ip, hash}` — drop
   `cve`/`email`/`mutex`/`yara`/anything else. (If the user wants those
   included too, adjust the allow-set — don't silently include them by default,
   since the last ask was explicitly scoped to network-blockable types.)
5. Emit one record per kept row with this exact schema and field order
   (no `confidence` field — this output intentionally omits it):
   ```json
   {
     "type": "domain",
     "value": "example[.]com",
     "source": "microsoft-security-research",
     "tags": ["microsoft", "research", "threat-intelligence", "microsoft-security-blog"],
     "first_seen": "...",
     "fetched_at": "<ISO-8601 UTC timestamp of this consolidation run>",
     "article_url": "...",
     "article_title": "...",
     "last_seen": "...",
     "description": "..."
   }
   ```
   `value` is copied as-is from the table cell (already defanged) — don't
   re-defang or refang it.
6. Do **not** dedupe across articles unless asked — the same IOC reused by two
   campaigns is a legitimate signal, not noise. Do run a sanity check for
   accidental exact `(type, value)` duplicates and report the count.
7. Write the full list as one JSON array to `feeds/<name>.json`.

## Output file naming — always confirm, never assume
There's no fixed convention yet for this consolidated-single-file output.
**Ask the user which file to target before writing.** Specifically, do not:
- dump into a campaign-scoped file like `feeds/msft_clickfix.json` (name
  implies one campaign, not the whole blog), or
- silently overwrite `feeds/msft_research.json` (that file is the
  script-owned output of `fetch_msft_research.py`'s own combined-feed logic,
  not this manual consolidation path — regenerating it via the script and
  hand-building it here can drift out of sync).

Prior precedent: `feeds/msft_security_blog_iocs.json` (created 2026-08-07,
321 records: 146 domain / 101 hash / 53 url / 21 ip, across 19 of 21 articles
— 2 articles had zero domain/url/ip/hash rows and were skipped).

## Known caveats — carry forward, don't silently "fix"
- Some articles have `first_seen`/`last_seen` populated with the description
  text instead of a real date (e.g. `"Index.js (from redhat-cloud-services/
  remediations-client)"`). This is a pre-existing bug in how
  `fetch_msft_research.py` extracts those two columns when an article has no
  real per-IOC date — not something introduced by this consolidation step.
  Preserve the value as-is and flag it to the user; don't invent a date.
- Articles with zero domain/url/ip/hash rows (all-CVE, or genuinely IOC-less)
  are expected and should be skipped, not treated as a parse failure.

## Verification checklist
- [ ] Record count and per-type breakdown reported back to the user.
- [ ] No duplicate `(type, value)` pairs, unless intentionally allowed.
- [ ] First record's field order/shape spot-checked against the user's
      requested template.
- [ ] `git status` shows only the new/changed feed file touched — nothing
      else in the repo was modified as a side effect.

See also: [`-IOCs-collection-skills.md`](-IOCs-collection-skills.md) for the
underlying defanging/validation/type rules this consolidation output must
still honor.
