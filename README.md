# Unified Threat Intelligence IOC Platform

Automated collection, consolidation, validation, and distribution of Indicators of
Compromise (IOCs) from public threat intelligence feeds.

## IOC Types Collected

| Type | Format | Use Case |
|---|---|---|
| IP Addresses | IPv4/IPv6 | Firewall blocklists (C2 servers, malicious hosts) |
| File Hashes | MD5, SHA1, SHA256 | EDR blocking (CrowdStrike, SentinelOne) |
| Domains | FQDN | DNS sinkholing, proxy blocking |
| URLs | Full URL | Web gateway blocking |

## Feed Sources

| Source | Feed | IOC Types | Update Frequency |
|---|---|---|---|
| [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/?sort-by=newest-oldest) | Threat intelligence blog IOCs | IPs, Domains, Hashes, URLs | Every 6 hours |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited CVEs | CVEs | Every 6 hours |

Here's a comprehensive reference — starting with what's visible in the screenshot, then expanding to the full ecosystem of threat intelligence and IOC sources used by the community.Here's a breakdown of what's in the screenshot and the broader ecosystem:

**From your screenshot**, the tool appears to monitor six categories — Government (CISA, CERT Bund, JPCERT, Cyber.mil), News Outlets (THN, TechPoint, Dark Reading), Security Blogs (ZDNet, Trend Micro, and a researcher blog), Vulnerability DBs (NVD, MalwareBazaar, Qualys), Vendor Advisories (Microsoft, AWS, Cisco, Oracle), and Social Media (X, YouTube, Mastodon, Reddit).

**Beyond the screenshot**, the most commonly referenced sources in the community for threat hunting and fresh IOCs are:

The **abuse.ch ecosystem** (ThreatFox, URLhaus, MalwareBazaar) is probably the most used free community IOC source. **AlienVault OTX** is another staple for pulling structured threat pulses. **VirusTotal** and **Any.run** are standard for file/URL enrichment.

For **blog-quality research with embedded IOCs**, the heavy hitters are Microsoft Security Blog (the URL you mentioned is a great example), Mandiant/Google TAG, Palo Alto Unit 42, Cisco Talos, SentinelOne Labs, and Elastic Security Labs — these routinely publish full campaigns with hashes, IPs, and YARA rules attached.

For **APT tracking** specifically, Malpedia and the MITRE ATT&CK framework are essential reference points alongside Recorded Future and CrowdStrike's adversary intelligence.

The **#threatintel** hashtag on X/Twitter is genuinely useful for catching IOCs hours before they hit formal feeds, though quality varies by researcher.

## Repository Structure

```
threat-intel-iocs/
├── feeds/
│   ├── msft_threat_intel.json
│   └── cisa_kev.json
├── consolidated/
│   ├── malicious_ips.txt
│   ├── malicious_domains.txt
│   ├── malicious_urls.txt
│   ├── malicious_hashes.csv
│   ├── cve_watchlist.txt
│   ├── ioc_master.json
│   ├── stix_bundle.json
│   └── run_stats.json
├── scripts/
│   ├── config.py
│   ├── fetch_msft.py
│   ├── fetch_cisa.py
│   ├── consolidate.py
│   └── validate.py
├── .github/workflows/
│   └── update_iocs.yml
├── requirements.txt
└── README.md
```

## Quick Start

### Run locally

```bash
pip install -r requirements.txt

# Fetch from all feeds
python scripts/fetch_msft.py
python scripts/fetch_cisa.py

# Optional validation summary
python scripts/validate.py

# Consolidate into unified lists
python scripts/consolidate.py
```

### GitHub Actions

The workflow in `.github/workflows/update_iocs.yml` runs every 6 hours
automatically.

## Output Formats for Integration

### Firewalls (Palo Alto, Fortinet, pfSense)

Use the raw URL of `consolidated/malicious_ips.txt` as an External Dynamic List:

```
https://raw.githubusercontent.com/<owner>/<repo>/main/consolidated/malicious_ips.txt
```

### EDR Platforms (CrowdStrike, SentinelOne)

Import `consolidated/malicious_hashes.csv` via custom IOC upload or API
integration. The CSV uses the columns:

```csv
hash,type,malware,source,first_seen
```

### SIEM (Splunk, Elastic)

Ingest `consolidated/ioc_master.json` via scheduled lookup or API pull.

## Validation Logic

`validate.py` filters out malformed or low-value data, including:

- private/reserved IP ranges and common public resolver IPs
- known benign infrastructure domains
- malformed domains, URLs, hashes, and CVE identifiers
- placeholder hash values

## Roadmap

- [x] Phase 1 — Feed research & architecture
- [x] Phase 2 — GitHub-based IOC collection
- [ ] Phase 3 — OpenCTI deployment with STIX/TAXII
- [ ] Phase 4 — Distribution APIs & integrations
- [ ] Phase 5 — Enrichment, scoring & MITRE ATT&CK tagging
