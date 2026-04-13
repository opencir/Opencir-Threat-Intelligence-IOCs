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
| [AlienVault OTX](https://otx.alienvault.com/) | Community threat intel | All types | Every 6 hours |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited CVEs | CVEs | Every 6 hours |

## Repository Structure

```
threat-intel-iocs/
├── feeds/
│   ├── msft_threat_intel.json
│   ├── otx_pulses.json
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
│   ├── fetch_otx.py
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
export OTX_API_KEY=<your_otx_key>           # optional unless fetching OTX

python scripts/fetch_msft.py
python scripts/fetch_cisa.py
python scripts/fetch_otx.py      # Requires OTX_API_KEY env var

# Optional validation summary
python scripts/validate.py

# Consolidate into unified lists
python scripts/consolidate.py
```

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `OTX_API_KEY` | For OTX feed | Free API key from otx.alienvault.com |

### GitHub Actions

The workflow in `.github/workflows/update_iocs.yml` runs every 6 hours
automatically. Set `OTX_API_KEY` as a repository secret.

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
