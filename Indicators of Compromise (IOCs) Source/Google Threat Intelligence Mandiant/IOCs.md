# Google Threat Intelligence / Mandiant — IOCs

Source: public blog analysis (RSS feed)
Feed: https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v
Purpose: Legitimate threat-intel collection for building IOC databases and firewall blocking rules.

## Summary
The three most recent items in the Google Threat Intelligence / Mandiant feed as of 2026-08-05 are strategic/policy posts (supply chain mitigation guidance, a threat-actor naming taxonomy update, and AI-assisted vulnerability management guidance). None contain technical indicators (file hashes, IP addresses, domains, URLs, or CVEs) suitable for firewall blocking.

The supply chain mitigation article does reference specific malware families, threat-actor (UNC) identifiers, and affected package ecosystems in the course of describing recent incidents. These are recorded below as context/tracking indicators — not directly actionable for network blocking, but useful for correlation and detection engineering.

---

## Non-technical indicators (malware families / threat actors / affected ecosystems)

Source article: https://cloud.google.com/blog/topics/threat-intelligence/mitigation-guidance-for-supply-chain-compromise/

| Malware / Component | Indicator type | Value | Notes |
|---|---:|---|---|
| Credential stealer | Malware name | `SANDCLOCK` | Deployed by UNC6780 across PyPI, npm, Docker Hub, Feb–May 2026 |
| Supply chain actor | Threat actor (UNC) | `UNC6780` (aka "TeamPCP") | Abused `pull_request_target` GitHub Actions trigger; deploys SANDCLOCK |
| Backdoor | Malware name | `WAVESHAPER.V2` | Dropped via malicious dependency injected into npm `axios` package, March 2026 |
| North Korean actor | Threat actor | `MIDNIGHT NEPTUNE` (formerly UNC1069) | Attributed to the `axios` npm supply chain compromise |
| Compromised npm package | Package name | `axios` | Maintainer account compromised via social engineering; malicious versions live ~3 hours; 100M+ weekly downloads |
| Hosting infra compromise | Threat actor (UNC) | `UNC6688` | Compromised Notepad++ update hosting infrastructure, Jun–Dec 2025 (South Korea, France) |
| Reconnaissance/profiling malware | Malware name | `SLICKDEMON` | Deployed by UNC6863 via compromised DAEMON Tools installers, early 2026 |
| Shellcoded loader | Malware name | `BADFALL` | Bridges SLICKDEMON profiling to QUIC RAT deployment; UNC6863 campaign |
| Advanced RAT | Malware name | `QUIC RAT` | Delivered in later stage of UNC6863 DAEMON Tools campaign |
| DAEMON Tools compromise actor | Threat actor (UNC) | `UNC6863` | Targeted government/scientific entities in Russia, Brazil, Turkey; follow-on in Belarus, Thailand |
| Web3 wallet frontend compromise | Threat actor (UNC) | `UNC4899` | North Korean actor; social-engineered developer access; injected malicious code into smart-contract frontend; ~$1.4B USD theft |
| RAT / infostealer | Malware name | `SHADOWLADDER` (aka SectopRAT) | Delivered via ClickFix lures on compromised automotive dealership websites |
| Historical reference (SolarWinds) | Threat actor | `ICE RELIC` (formerly APT29) | Russian actor; 2020 SolarWinds/SUNBURST compromise, cited as watershed supply chain incident |
| Historical reference (3CX) | Threat actor | `UNC4736` | North Korean actor; 2023 3CX compromise, cited as watershed supply chain incident |

---

## Related articles reviewed with no extractable indicators
- Updated Cyber Threat Actor Naming System — https://cloud.google.com/blog/topics/threat-intelligence/updated-cyber-threat-actor-naming-system/
- Demystifying AI Exploits: A Blueprint for AI-Assisted Vulnerability Management — https://cloud.google.com/blog/topics/threat-intelligence/ai-assisted-vulnerability-management/

_Checked: 2026-08-05. No hash/IP/domain-level IOCs present in current feed items; re-check feed periodically for new technical alerts._
