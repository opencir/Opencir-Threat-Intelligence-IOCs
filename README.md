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

Understood. You want the OSINT sources organized only by these high-level categories:

1. **Government & CERT**
2. **Security News Outlets**
3. **Security Research Blogs**

Here is the mapped table with official links and source types.

# OSINT Threat Intelligence Source Mapping

## 1. Government & CERT

| Provider           | Country / Region | Official Link                                                                                                        | Source Type       | Intelligence Value                             |
| ------------------ | ---------------- | -------------------------------------------------------------------------------------------------------------------- | ----------------- | ---------------------------------------------- |
| CISA               | United States    | [https://www.cisa.gov/](https://www.cisa.gov/)                                                                       | Advisory / Alerts | Vulnerabilities, ransomware, APT activity, KEV |
| FBI Cyber Division | United States    | [https://www.fbi.gov/investigate/cyber](https://www.fbi.gov/investigate/cyber)                                       | Advisory          | Cybercrime, threat actor alerts                |
| NSA Cybersecurity  | United States    | [https://www.nsa.gov/Cybersecurity/](https://www.nsa.gov/Cybersecurity/)                                             | Advisory          | Nation-state threats, defensive guidance       |
| US-CERT            | United States    | [https://www.cisa.gov/topics/cyber-threats-and-advisories](https://www.cisa.gov/topics/cyber-threats-and-advisories) | Advisory          | Security alerts                                |
| CERT-EU            | European Union   | [https://cert.europa.eu/](https://cert.europa.eu/)                                                                   | Advisory          | EU cybersecurity alerts                        |
| ENISA              | European Union   | [https://www.enisa.europa.eu/](https://www.enisa.europa.eu/)                                                         | Report / Advisory | Threat landscape reports                       |
| CERT Bund (BSI)    | Germany          | [https://www.bsi.bund.de/](https://www.bsi.bund.de/)                                                                 | Advisory          | Vulnerabilities, malware, incidents            |
| ANSSI              | France           | [https://www.ssi.gouv.fr/](https://www.ssi.gouv.fr/)                                                                 | Advisory          | Security advisories                            |
| NCSC UK            | United Kingdom   | [https://www.ncsc.gov.uk/](https://www.ncsc.gov.uk/)                                                                 | Advisory          | Threat reports, guidance                       |
| NCSC Canada        | Canada           | [https://www.cyber.gc.ca/](https://www.cyber.gc.ca/)                                                                 | Advisory          | Canadian cyber alerts                          |
| ACSC               | Australia        | [https://www.cyber.gov.au/](https://www.cyber.gov.au/)                                                               | Advisory          | Threat intelligence, alerts                    |
| JPCERT/CC          | Japan            | [https://www.jpcert.or.jp/english/](https://www.jpcert.or.jp/english/)                                               | Advisory          | Incident reports                               |
| Singapore CSA      | Singapore        | [https://www.csa.gov.sg/](https://www.csa.gov.sg/)                                                                   | Advisory          | Cyber alerts                                   |
| CERT.at            | Austria          | [https://www.cert.at/](https://www.cert.at/)                                                                         | Advisory          | Security incidents                             |
| CERT Polska        | Poland           | [https://www.cert.pl/](https://www.cert.pl/)                                                                         | Advisory          | Malware and phishing intelligence              |

---

# 2. Security News Outlets

| Provider              | Official Link                                                                    | Source Type | Intelligence Value                   |
| --------------------- | -------------------------------------------------------------------------------- | ----------- | ------------------------------------ |
| The Hacker News       | [https://thehackernews.com/](https://thehackernews.com/)                         | News / RSS  | Breaking threats, vulnerabilities    |
| BleepingComputer      | [https://www.bleepingcomputer.com/](https://www.bleepingcomputer.com/)           | News / RSS  | Malware, ransomware, incidents       |
| SecurityWeek          | [https://www.securityweek.com/](https://www.securityweek.com/)                   | News        | Vulnerabilities, enterprise security |
| Dark Reading          | [https://www.darkreading.com/](https://www.darkreading.com/)                     | News        | Enterprise security news             |
| CyberScoop            | [https://cyberscoop.com/](https://cyberscoop.com/)                               | News        | Government cyber news                |
| The Record            | [https://therecord.media/](https://therecord.media/)                             | News        | Cybercrime investigations            |
| KrebsOnSecurity       | [https://krebsonsecurity.com/](https://krebsonsecurity.com/)                     | Blog / News | Investigative security reporting     |
| Help Net Security     | [https://www.helpnetsecurity.com/](https://www.helpnetsecurity.com/)             | News        | Security industry updates            |
| SC Media              | [https://www.scmagazine.com/](https://www.scmagazine.com/)                       | News        | Cybersecurity news                   |
| Infosecurity Magazine | [https://www.infosecurity-magazine.com/](https://www.infosecurity-magazine.com/) | News        | Security trends                      |
| Security Affairs      | [https://securityaffairs.com/](https://securityaffairs.com/)                     | News        | Threat reports                       |
| CSO Online            | [https://www.csoonline.com/](https://www.csoonline.com/)                         | News        | Security operations                  |

---

# 3. Security Research Blogs

| Provider                            | Official Link                                                                                                        | Source Type         | Intelligence Value                |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------- | --------------------------------- |
| Palo Alto Unit 42                   | [https://unit42.paloaltonetworks.com/](https://unit42.paloaltonetworks.com/)                                         | Research Blog       | APT, malware, IOC reports         |
| Cisco Talos                         | [https://blog.talosintelligence.com/](https://blog.talosintelligence.com/)                                           | Research Blog       | Malware, botnets, vulnerabilities |
| Google Mandiant Threat Intelligence | [https://cloud.google.com/blog/topics/threat-intelligence](https://cloud.google.com/blog/topics/threat-intelligence) | Research Blog       | Nation-state, APT intelligence    |
| Microsoft Security Blog             | [https://www.microsoft.com/security/blog/](https://www.microsoft.com/security/blog/)                                 | Research Blog       | Threat actors, vulnerabilities    |
| Google TAG                          | [https://blog.google/threat-analysis-group/](https://blog.google/threat-analysis-group/)                             | Research Blog       | Advanced threat groups            |
| CrowdStrike Blog                    | [https://www.crowdstrike.com/blog/](https://www.crowdstrike.com/blog/)                                               | Research Blog       | Threat intelligence               |
| SentinelLabs                        | [https://www.sentinelone.com/labs/](https://www.sentinelone.com/labs/)                                               | Research Blog       | Malware analysis                  |
| Sophos X-Ops                        | [https://news.sophos.com/en-us/category/x-ops/](https://news.sophos.com/en-us/category/x-ops/)                       | Research Blog       | Threat research                   |
| FortiGuard Labs                     | [https://www.fortiguard.com/blog](https://www.fortiguard.com/blog)                                                   | Research Blog       | Malware and exploits              |
| Check Point Research                | [https://research.checkpoint.com/](https://research.checkpoint.com/)                                                 | Research Blog       | Threat campaigns                  |
| Trend Micro Research                | [https://www.trendmicro.com/en_us/research.html](https://www.trendmicro.com/en_us/research.html)                     | Research Blog       | Malware research                  |
| ESET Research                       | [https://www.welivesecurity.com/](https://www.welivesecurity.com/)                                                   | Research Blog       | APT and malware                   |
| Securelist (Kaspersky)              | [https://securelist.com/](https://securelist.com/)                                                                   | Research Blog       | Malware intelligence              |
| Elastic Security Labs               | [https://www.elastic.co/security-labs](https://www.elastic.co/security-labs)                                         | Research Blog       | Detection research                |
| Rapid7 Labs                         | [https://www.rapid7.com/blog/](https://www.rapid7.com/blog/)                                                         | Research Blog       | Vulnerabilities and threats       |
| Huntress                            | [https://www.huntress.com/blog](https://www.huntress.com/blog)                                                       | Research Blog       | Threat hunting                    |
| Red Canary                          | [https://redcanary.com/blog/](https://redcanary.com/blog/)                                                           | Research Blog       | Detection engineering             |
| Proofpoint Threat Research          | [https://www.proofpoint.com/us/blog/threat-insight](https://www.proofpoint.com/us/blog/threat-insight)               | Research Blog       | Email threats, APT                |
| Arctic Wolf Labs                    | [https://arcticwolf.com/resources/blog/](https://arcticwolf.com/resources/blog/)                                     | Research Blog       | MDR threat research               |
| VMware Threat Labs                  | [https://blogs.vmware.com/security/](https://blogs.vmware.com/security/)                                             | Research Blog       | Cloud and endpoint threats        |
| SANS Internet Storm Center          | [https://isc.sans.edu/](https://isc.sans.edu/)                                                                       | Research Blog       | Internet threat monitoring        |
| Project Zero                        | [https://googleprojectzero.blogspot.com/](https://googleprojectzero.blogspot.com/)                                   | Research Blog       | Zero-day vulnerabilities          |
| DFIR Report                         | [https://thedfirreport.com/](https://thedfirreport.com/)                                                             | Research Blog       | Real-world intrusion analysis     |
| Malware Traffic Analysis            | [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/)                               | Research Blog       | PCAP and IOC analysis             |
| VX-Underground                      | [https://vx-underground.org/](https://vx-underground.org/)                                                           | Research Repository | Malware samples                   |

---

# Recommended OSINT Collection Priority

| Priority | Category                | Examples                             |
| -------- | ----------------------- | ------------------------------------ |
| Tier 1   | Government & CERT       | CISA, CERT-EU, NCSC, CERT Bund       |
| Tier 2   | Security Research Blogs | Unit 42, Talos, Mandiant, Microsoft  |
| Tier 3   | Security News           | BleepingComputer, Hacker News, Krebs |
| Tier 4   | Community Sources       | GitHub, Reddit, X/Twitter            |

---

# Recommended Data Ingestion Methods

| Source Type     | Collection Method                                |
| --------------- | ------------------------------------------------ |
| Government CERT | RSS, TAXII, API, STIX                            |
| Security News   | RSS, Web Scraping                                |
| Research Blogs  | RSS, HTML extraction, IOC parser                 |
| Reports         | PDF extraction, NLP enrichment                   |
| IOC Articles    | Automated IOC extraction (IP, Domain, Hash, CVE) |

This structure is suitable for a **Threat Intelligence Platform OSINT ingestion layer** and can be directly mapped into OpenCTI/MISP connectors.


| Source | Feed | IOC Types | Update Frequency |
|---|---|---|---|
| [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/?sort-by=newest-oldest) | Threat intelligence blog IOCs | IPs, Domains, Hashes, URLs | Monthly |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited CVEs | CVEs | Monthly |

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

The workflow in `.github/workflows/update_iocs.yml` runs monthly
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
