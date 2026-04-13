# threat-intel-iocs
# Unified Threat Intelligence IOC Platform

Automated collection, consolidation, and distribution of Indicators of Compromise (IOCs) from public threat intelligence feeds.

## IOC Types Collected

| Type | Format | Use Case |
|------|--------|----------|
| IP Addresses | IPv4/IPv6 | Firewall blocklists (C2 servers, malicious hosts) |
| File Hashes | MD5, SHA1, SHA256 | EDR blocking (CrowdStrike, SentinelOne) |
| Domains | FQDN | DNS sinkholing, proxy blocking |
| URLs | Full URL | Web gateway blocking |

## Feed Sources

| Source | Feed | IOC Types | Update Frequency |
|--------|------|-----------|-----------------|
| [Abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) | Botnet C2 IPs | IPs | Every 5 min |
| [Abuse.ch URLhaus](https://urlhaus.abuse.ch/) | Malware distribution URLs | URLs, Domains | Every 5 min |
| [Abuse.ch MalwareBazaar](https://bazaar.abuse.ch/) | Malware samples | Hashes | Continuous |
| [Abuse.ch ThreatFox](https://threatfox.abuse.ch/) | IOCs from malware | IPs, Domains, Hashes | Continuous |
| [AlienVault OTX](https://otx.alienvault.com/) | Community threat intel | All types | Continuous |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited CVEs | CVEs | Weekly |

## Repository Structure

```
threat-intel-iocs/
├── feeds/                      # Raw data from each feed source
│   ├── abusech_feodo.json
│   ├── abusech_urlhaus.json
│   ├── abusech_threatfox.json
│   ├── abusech_malwarebazaar.json
│   ├── otx_pulses.json
│   └── cisa_kev.json
├── consolidated/               # Deduplicated, merged IOC lists
│   ├── malicious_ips.txt       # Plain list — import into firewalls
│   ├── malicious_domains.txt   # Plain list — import into DNS/proxy
│   ├── malicious_urls.txt      # Plain list — import into web gateways
│   ├── malicious_hashes.csv    # hash,type,malware,source,first_seen
│   └── ioc_master.json         # Full structured dataset (all IOCs)
├── scripts/
│   ├── fetch_abusech.py        # Abuse.ch collector (Feodo, URLhaus, ThreatFox, MalwareBazaar)
│   ├── fetch_otx.py            # AlienVault OTX collector
│   ├── fetch_cisa.py           # CISA KEV collector
│   ├── consolidate.py          # Merge & deduplicate all feeds
│   ├── validate.py             # IOC validation & quality checks
│   └── config.py               # Shared configuration
├── .github/workflows/
│   └── update_iocs.yml         # Scheduled GitHub Actions workflow
├── requirements.txt
└── README.md
```

## Quick Start

### Run Locally
```bash
pip install -r requirements.txt

# Fetch from all feeds
python scripts/fetch_abusech.py
python scripts/fetch_cisa.py
python scripts/fetch_otx.py      # Requires OTX_API_KEY env var

# Consolidate into unified lists
python scripts/consolidate.py
```

### Environment Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `OTX_API_KEY` | For OTX feed | Free API key from otx.alienvault.com |

### GitHub Actions (Automated)
The workflow in `.github/workflows/update_iocs.yml` runs every 6 hours automatically. Set `OTX_API_KEY` as a repository secret.

## Output Formats for Integration

### Firewalls (Palo Alto, Fortinet, pfSense)
Use the raw URL of `consolidated/malicious_ips.txt` as an External Dynamic List (EDL):
```
https://raw.githubusercontent.com/<owner>/threat-intel-iocs/main/consolidated/malicious_ips.txt
```

### EDR Platforms (CrowdStrike, SentinelOne)
Import `consolidated/malicious_hashes.csv` via custom IOC upload or API integration.

### SIEM (Splunk, Elastic)
Ingest `consolidated/ioc_master.json` via scheduled lookup or API pull.

## Roadmap
- [x] Phase 1 — Feed research & architecture
- [ ] Phase 2 — GitHub-based IOC collection (current)
- [ ] Phase 3 — OpenCTI deployment with STIX/TAXII
- [ ] Phase 4 — Distribution APIs & integrations
- [ ] Phase 5 — Enrichment, scoring & MITRE ATT&CK tagging

## License
MIT
