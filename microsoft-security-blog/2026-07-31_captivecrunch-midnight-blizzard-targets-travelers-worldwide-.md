# CaptiveCrunch: Midnight Blizzard targets travelers worldwide for malware delivery and credential theft

**Source:** <https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/>
**Published:** 2026-07-31
**IOC count:** 12

> Collected for legitimate threat-intelligence purposes: building an IOC database and firewall blocking rules from publicly available Microsoft Security research blog posts.

## Indicators of Compromise

| # | Type | Value | Description | First Seen | Last Seen |
|---|------|-------|-------------|------------|-----------|
| 1 | domain | `ms365-device.com` | CaptiveCrunch DCF redirect | 2026-07-23 | 2026-07-23 |
| 2 | domain | `ms365-live.com` | CaptiveCrunch DCF redirect | 2026-05-14 | 2026-05-14 |
| 3 | domain | `m365-owa.com` | CaptiveCrunch AitM infrastructure | 2026-07-20 | 2026-07-20 |
| 4 | domain | `owa-ms365.com` | CaptiveCrunch AitM infrastructure | 2026-07-16 | 2026-07-16 |
| 5 | ip | `31.57.243.154` | CaptiveCrunch AitM infrastructure | 2026-07-16 | 2026-07-16 |
| 6 | ip | `38.146.28.75` | CaptiveCrunch AitM infrastructure | 2026-07-01 | 2026-07-01 |
| 7 | ip | `38.146.28.132` | CaptiveCrunch DNS Resolver | 2026-07-15 | 2026-07-15 |
| 8 | ip | `104.194.159.150` | CaptiveCrunch AitM infrastructure | 2026-04-28 | 2026-04-28 |
| 9 | ip | `107.189.26.194` | ChocoShell C2 / CaptiveCrunch DNS Resolver | 2026-02-27 | 2026-02-27 |
| 10 | ip | `213.145.86.112` | ChocoShell C2 | 2026-07-01 | 2026-07-01 |
| 11 | hash | `918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593` | CornFlake | 2026-07-03 | 2026-07-03 |
| 12 | hash | `be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c` | ChocoShell | 2026-07-10 | 2026-07-10 |
