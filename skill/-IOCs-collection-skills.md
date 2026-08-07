# IOCs Collection Skill (Threat Intelligence IOC Pipeline)

## Project note
This is a legitimate cybersecurity lab that builds an IOC database from public
threat-intelligence blogs and advisories, for firewall/EDR/DNS blocking use.
When acting as a coworker agent fetching public blog/advisory content, it's fine
to state that this is legitimate IOC-collection activity if a source asks.

## Scope
Applies to any IOC ingestion, extraction, defanging, validation, or publishing
work in this repo, including:
- Script-based collectors: `scripts/fetch_msft.py`, `scripts/fetch_msft_research.py`,
  `scripts/fetch_cisa.py`, `scripts/fetch_article.py` (single-URL ad hoc fetch).
- The shared validation/normalisation/consolidation layer: `scripts/validate.py`,
  `scripts/consolidate.py`.
- Manually curated, non-scripted source folders under
  `Indicators of Compromise (IOCs) Source/` (e.g. Google Threat Intelligence
  Mandiant, CrowdStrike) — see [Manual / non-script sources](#manual--non-script-sources).
- Per-article Markdown output in `microsoft-security-blog/`.
- Related history: `copilot/fix-defanging-issue`, `copilot/microsoft-security-blog`,
  PR https://github.com/opencir/Opencir-Threat-Intelligence-IOCs/pull/4.

## Goal
Produce deterministic, safe-to-publish IOC outputs — correctly defanged, validated,
deduplicated, and schema-consistent — and avoid publishing empty/low-value or
false-positive records.

## IOC Types Collected

| Type | Format | Validated by `validate.py` | Use Case |
|---|---|---|---|
| IP Address | IPv4/IPv6 | Public/routable only — RFC1918, loopback, link-local, CGN, TEST-NET-1/2/3, multicast, reserved ranges rejected; known public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9, etc.) rejected | Firewall blocklists / EDL (C2 servers, malicious hosts) |
| Domain | FQDN | Must match label/TLD regex, must not be an IP literal, must have a TLD; benign infra suffixes rejected (google.com, microsoft.com, cloudflare.com, amazonaws.com, etc., incl. subdomains) | DNS sinkholing, proxy blocking |
| URL | Full `http(s)://` URL | Host must independently validate as a domain or a public IP | Secure web gateway blocking |
| File Hash | MD5 (32 hex) / SHA1 (40 hex) / SHA256 (64 hex) / SHA512 (128 hex) | All-zero and all-`f` placeholder hashes rejected | EDR blocking (CrowdStrike, SentinelOne custom IOC upload) |
| CVE | `CVE-YYYY-NNNN+` | Regex `^CVE-\d{4}-\d{4,}$` | Vulnerability watchlist, patch prioritization |
| Email | `user@domain.tld` | Basic `local@host.tld` pattern | Phishing sender blocklist, mail gateway rules |
| CIDR | `a.b.c.d/n` | Passed through (light validation only) | Bulk blocklisting of malicious hosting ranges |
| Mutex | string | Non-empty | Host-based detection engineering |
| YARA | rule name/string | Non-empty | Detection engineering reference |

Type strings must be lowercase and exactly one of
`ip | domain | url | hash | cve | email | cidr | mutex | yara`. Anything else is
**passed through unvalidated** with a debug warning (see `_VALIDATORS.get()` in
`validate.py`) rather than rejected — don't invent new type strings without adding
a matching validator, or bad data will silently reach `consolidated/`.

## Core Rules

### 1) Defang at publish/write time
Apply defanging only when serializing output (Markdown/JSON), never during
extraction/matching — matching must run against the refanged/canonical value.

- Domain: `example.com` → `example[.]com`
- IP: `192.168.1.1` → `192[.]168[.]1[.]1`
- CIDR: `1.2.3.0/24` → `1[.]2[.]3[.]0/24` (defang the address, keep the `/n` suffix)
- URL: `https://host.tld/path` → `https[://]host[.]tld/path` — scheme uses
  `[://]`, not `[:]//`; only the host is dot-defanged, the path is untouched
- Email: preserve local-part, defang domain only
  `user.name@example.com` → `user.name@example[.]com`

### 2) Normalize mixed inputs
If input is already defanged or partially defanged (`hxxp`, `hxxps`, `[.]`,
`[:]//`, etc.), refang to canonical form first, then re-serialize so output
format stays consistent. See `defang()` / `_refang()` in
`scripts/fetch_msft_research.py` for the canonicalization regexes.

### 3) Keep safe exceptions
Do **not** transform:
- Hashes
- CVEs
- Mutex names
- YARA rule identifiers

None of these are network-reachable strings, so defanging them adds no safety
value and would corrupt the value.

### 4) Filter false positives and noise
Before an IOC is written to any output, it must survive both the collector's
inline filter and `validate.py`:
- Drop private/reserved/loopback/link-local/CGN/TEST-NET/multicast IPs and
  known public DNS resolvers (`_BENIGN_IPS`, `_PRIVATE_NETWORKS`).
- Drop benign infrastructure domains and their subdomains (`_BENIGN_DOMAIN_SUFFIXES`:
  google/microsoft/apple/cloudflare/amazonaws/cloudfront/fastly/akamaiedge, etc.),
  and known-benign government domains (`_FALSE_POSITIVE_DOMAINS`: cisa.gov,
  nist.gov, whitehouse.gov, etc.).
- Drop placeholder values: `example.com`, `evil.com`, `test.com`, `localhost`,
  `127.0.0.1`, `0.0.0.0`, and their `http(s)://` variants (`_FALSE_POSITIVE_VALUES`).
- Drop placeholder hashes (all-zero / all-`f`).
- Do this filtering before defanging, on the canonical value, so comparisons
  against the allow/deny lists are exact.

### 5) Zero-IOC pruning
If an article resolves to zero retained IOCs:
- skip per-article Markdown generation
- remove previously generated stale zero-IOC files during regeneration
- exclude from index/README listing

### 6) IOC record schema
Every emitted IOC dict should carry a consistent set of fields so
`consolidate.py` can merge and sort correctly:

```
type          : ip | domain | url | hash | cve | email | cidr | mutex | yara
value         : normalised/canonical value (defang only at serialization time)
source        : collector/source label, e.g. "microsoft-threat-intel"
confidence    : 0-100 int, or a qualitative label ("high"/"medium"/"low"/"confirmed")
                normalised via normalise_confidence() — never mix str/int downstream
tags          : list[str]
first_seen    : ISO-8601 date/time (UTC)
last_seen     : ISO-8601 date/time (UTC), if applicable
fetched_at    : ISO-8601 timestamp when the collector ran (UTC)
article_url   : permalink of the source article
article_title : title of the source article
```

### 7) Deduplication
`consolidate.py` dedupes on `(type.lower(), value)` after normalisation. On a
collision it merges `sources` and `tags` (set union), keeps the **highest**
confidence, the **earliest** `first_seen`, and the **latest** `last_seen`. Don't
pre-dedupe or reformat values upstream in a way that would defeat this key
(e.g. inconsistent hash casing, trailing dots on domains, mixed defang state).

### 8) Regeneration consistency
When scraper or validation logic changes, regenerate everything downstream in
one pass so repository artifacts match runtime behavior:
- `feeds/*.json` (per-collector)
- per-article Markdown in `microsoft-security-blog/`
- `microsoft-security-blog/README.md` index
- `consolidated/*` (`malicious_ips.txt`, `malicious_domains.txt`,
  `malicious_urls.txt`, `malicious_hashes.csv`, `cve_watchlist.txt`,
  `ioc_master.json`, `stix_bundle.json`, `run_stats.json`) via `consolidate.py`

## Validation Checklist (before publish)
- [ ] All published domains/IPs/URLs/CIDRs/emails are defanged consistently;
      hashes, CVEs, mutexes, and YARA identifiers are left untouched.
- [ ] No extraction-time logic depends on defanged values.
- [ ] Private/reserved IPs, public DNS resolver IPs, and benign infrastructure
      domains are excluded.
- [ ] Placeholder values (`example.com`, `evil.com`, `127.0.0.1`, all-zero/all-`f`
      hashes, etc.) are excluded.
- [ ] IOC type strings are restricted to the known set (§ IOC Types Collected).
- [ ] Every IOC record has `type`/`value`/`source`/`confidence`/`tags`/`first_seen`/
      `fetched_at` populated (empty string/list if genuinely unknown — not a
      missing key).
- [ ] No zero-IOC article files remain in the output directory; README/index
      excludes zero-IOC entries.
- [ ] `feeds/*.json`, per-article Markdown, `consolidated/*`, and `docs/index.html`
      all reflect the same run.

## Operational Notes for Scheduled Tasks
Run in this order:
1. Collect: `python scripts/fetch_msft.py`, `python scripts/fetch_msft_research.py`,
   `python scripts/fetch_cisa.py` — or `python scripts/fetch_article.py <url>` for
   a single ad hoc article.
2. Optionally sanity-check: `python scripts/validate.py` (prints a pass/filter
   summary across all `feeds/*.json`, no writes).
3. Consolidate: `python scripts/consolidate.py` — merges, validates, dedupes, and
   writes every `consolidated/*` artifact from the current `feeds/*.json` files.
4. Treat output normalization as deterministic and idempotent — re-running the
   pipeline on unchanged inputs should produce byte-identical `consolidated/*`
   outputs.
5. Fail the task if any publish artifact contains refanged URL/domain/IP values
   (bare `http://`/`https://` or un-defanged dotted IPs/domains outside of
   hash/CVE/mutex/YARA fields) in `consolidated/` or `microsoft-security-blog/*.md`.

## Manual / non-script sources
Some sources (e.g. `Indicators of Compromise (IOCs) Source/Google Threat
Intelligence Mandiant/IOCs.md`, `.../crowdstrike/*.md`) are curated by hand
because no scraper exists yet for that vendor. For these:
- Still apply the defang and false-positive rules above.
- If an article has zero technical IOCs but references malware family names,
  threat-actor (UNC/APT) identifiers, or affected package/ecosystem names,
  record them in a separate "Non-technical indicators" section instead of
  fabricating IPs/domains/hashes to fill the table — useful for correlation,
  not directly firewall-actionable.
- State the checked date and source/feed URL at the top of the file so re-checks
  can be scheduled.
- This mirrors the existing pattern in
  `Indicators of Compromise (IOCs) Source/Google Threat Intelligence Mandiant/IOCs.md`.
