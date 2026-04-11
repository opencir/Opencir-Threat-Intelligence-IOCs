# Threat Intelligence IOC Distribution Platform — Phase 2 MVP

Automated collection, validation, deduplication, and distribution of threat
intelligence Indicators of Compromise (IOCs) from public feeds.

> **Phase 3 note:** When you're ready to move to OpenCTI, the `stix_bundle.json`
> output pipes directly into OpenCTI via a STIX/TAXII connector — no schema changes needed.

---

## Feeds

| Feed | IOC Types | Update Frequency |
|---|---|---|
| **Abuse.ch Feodo Tracker** | Botnet C2 IPs | Every 6 h |
| **Abuse.ch URLhaus** | Malicious URLs | Every 6 h |
| **Abuse.ch ThreatFox** | IPs, domains, URLs, hashes | Every 6 h |
| **Abuse.ch MalwareBazaar** | SHA256 / MD5 / SHA1 hashes | Every 6 h |
| **CISA KEV** | Actively exploited CVEs | Every 6 h |
| **AlienVault OTX** | IPs, domains, URLs, hashes, CVEs | Every 6 h |

---

## Repository Structure

```
threat-intel-iocs/
├── feeds/                        Raw feed data (auto-updated)
│   ├── abusech_feodo.json
│   ├── abusech_urlhaus.json
│   ├── abusech_threatfox.json
│   ├── abusech_malwarebazaar.json
│   ├── cisa_kev.json
│   └── otx_pulses.json
├── consolidated/                 Processed & deduplicated outputs
│   ├── malicious_ips.txt         → Firewall EDL / ACL import
│   ├── malicious_domains.txt     → DNS sinkhole / FQDN blocklist
│   ├── malicious_urls.txt        → Proxy / web gateway import
│   ├── malicious_hashes.csv      → CrowdStrike / SentinelOne IOC list
│   ├── cve_watchlist.txt         → Vuln scanner / SIEM correlation
│   ├── master_iocs.json          → Full structured dataset
│   ├── stix_bundle.json          → STIX 2.1 bundle (Phase 3 input)
│   └── run_stats.json            → Pipeline statistics
├── scripts/
│   ├── fetch_abusech.py          Abuse.ch collector (4 feeds)
│   ├── fetch_cisa.py             CISA KEV collector
│   ├── fetch_otx.py              AlienVault OTX collector
│   ├── validate.py               IOC validation & normalisation library
│   └── consolidate.py            Merge / dedup / export pipeline
├── .github/workflows/
│   └── update_iocs.yml           Scheduled GitHub Actions workflow
└── requirements.txt
```

---

## Quick Start

### 1. Clone and set up

```bash
git clone https://github.com/<your-org>/threat-intel-iocs.git
cd threat-intel-iocs
pip install -r requirements.txt
```

### 2. Add your OTX API key

Get a free key at [otx.alienvault.com](https://otx.alienvault.com/api), then:

**For GitHub Actions** — add a repository secret named `OTX_API_KEY`:
`Settings → Secrets and variables → Actions → New repository secret`

**For local runs:**
```bash
export OTX_API_KEY=<your_key>
```

### 3. Run locally

```bash
# Collect all feeds
python scripts/fetch_abusech.py
python scripts/fetch_cisa.py
python scripts/fetch_otx.py       # requires OTX_API_KEY

# Merge, validate, deduplicate, and export
python scripts/consolidate.py
```

### 4. Trigger the GitHub Actions workflow

Either push a commit or use `Actions → Update IOC Feeds → Run workflow` in the
GitHub UI. The workflow runs automatically every 6 hours.

---

## Consuming the Outputs

### Palo Alto / Fortinet / pfSense — IP & domain blocklists

Point your External Dynamic List (EDL) at the GitHub **raw** URL:

```
https://raw.githubusercontent.com/<org>/<repo>/main/consolidated/malicious_ips.txt
https://raw.githubusercontent.com/<org>/<repo>/main/consolidated/malicious_domains.txt
```

### CrowdStrike Falcon — Custom IOC import

Import `consolidated/malicious_hashes.csv` via:
`Falcon Console → Intelligence → Custom IOCs → Import`

### SentinelOne — Custom IOC list

Import `consolidated/malicious_hashes.csv` via:
`Singularity Console → Visibility → IOCs → Import`

### Splunk / Elastic SIEM

Ingest `consolidated/master_iocs.json` as a lookup table or use the raw feed
files as threat intelligence sources.

### OpenCTI (Phase 3)

Upload `consolidated/stix_bundle.json` via the OpenCTI UI or TAXII push
connector. All STIX 2.1 Indicator objects map cleanly to OpenCTI's schema.

---

## Validation Logic

`validate.py` filters out:

- Private / RFC 1918 IP addresses (10.x, 172.16.x, 192.168.x, loopback, link-local)
- Known-benign IPs (public DNS resolvers: 8.8.8.8, 1.1.1.1, etc.)
- Known-benign domain suffixes (google.com, microsoft.com, cloudflare.com, etc.)
- Malformed domains, URLs, hashes, and placeholder values
- Hash strings of all-zeros or all-`f`s

---

## Roadmap

- **Phase 3** — Deploy OpenCTI with Docker Compose, migrate feed connectors
- **Phase 4** — TAXII 2.1 server endpoint, REST API, MISP sync
- **Phase 5** — Confidence scoring, IOC aging/expiry, GreyNoise enrichment, MITRE ATT&CK tagging
