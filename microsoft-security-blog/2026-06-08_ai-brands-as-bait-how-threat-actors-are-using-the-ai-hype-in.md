# AI brands as bait: How threat actors are using the AI hype in social engineering

**Source:** <https://www.microsoft.com/en-us/security/blog/2026/06/08/ai-brands-as-bait-how-threat-actors-are-using-the-ai-hype-in-social-engineering/>
**Published:** 2026-06-08
**IOC count:** 15

> Collected for legitimate threat-intelligence purposes: building an IOC database and firewall blocking rules from publicly available Microsoft Security research blog posts.

## Indicators of Compromise

| # | Type | Value | Description | First Seen | Last Seen |
|---|------|-------|-------------|------------|-----------|
| 1 | hash | `791efb555eefb7215e96659a1353a97416743b66bdd72705493129c64057d40e` | File hash for attachmentFill and Sign Claude Appeal Form.pdf | 2026-04-20 | 2026-04-20 |
| 2 | url | `http://dash.awaydouble.org/0v2auth` | URL inside the PDF attachment | 2026-04-20 | 2026-04-20 |
| 3 | url | `https://github.com/shippingtechnologymovie/AI-techVideos/releases/download/13123/ProFluxeFlowAi-win-Setup.exe` | Fraudulent GitHub repository (taken down) hosting malware executable | 2026-03-13 | 2026-03-14 |
| 4 | hash | `c7c5072df9f83f4c440a5c3bb4be1d5f6c67bbf78f196406ca20d27b43b975b8` | File hash forProFluxeFlowAi-win-Setup.exe | 2026-03-13 | 2026-03-14 |
| 5 | hash | `4f5c5b3ef45cfff7721754487a86aeff9a2e6e32` | Certificate | 2026-03-13 | 2026-03-14 |
| 6 | domain | `brokeapt.com` | Attacker-controlled C2 domain for Python loader | 2026-03-10 | 2026-05-20 |
| 7 | domain | `pan.ssffaa19.xyz` | Vidar C2 | 2026-03-13 | 2026-03-14 |
| 8 | domain | `pan.rongtv.xyz` | Vidar C2 | 2026-03-13 | 2026-03-14 |
| 9 | url | `https://github.com/DeepSeek-V4/deepseek-V4/releases/download/deepseek-V4/deepseek-v4-pro_x64.7z` | Fraudulent GitHub repository (taken down) hosting malware executable | 2026-04-24 | 2026-04-28 |
| 10 | hash | `0a26238f6c516de5885457c93042531aa59bc206a9537cebf5267cedc6c68531` | deepseek-v4-pro_x64.7z(v1) | 2026-04-24 | 2026-05-18 |
| 11 | hash | `8610d4fb0ec5b525071c2aaec4df0f8fcbb3673aba58a7e1959fc44e83c0e2ca` | deepseek-v4-flash_x64.7z(v1) | 2026-04-24 | 2026-04-28 |
| 12 | hash | `99231deb373997364381d1eb513d2d42231d418c3a2db9007c5af9bd56ab9371` | deepseek-v4-flash_x64.7z(v2) | 2026-04-26 | 2026-04-28 |
| 13 | hash | `25270cc429ada8028b5b33220ed412c47907ecceea7377d608fac5af01bed56a` | deepseek-v4-pro_x64.7z(v2) | 2026-04-26 | 2026-04-28 |
| 14 | hash | `56d722b0331bf0aaa86bb37483486c6dff6ad9427fc473ed7c3226c21a9bdd23` | DeepSeek-specific extracted PE (deepseek-v4-pro_x64.exe,deepseek-v4-flash_x64.exe,VectorEngine.exe) | 2026-04-26 | 2026-04-28 |
| 15 | hash | `5455341ed1bbe75a664fca2dd0794c508e1874f75360253a7ff5bc119bc92d80` | Shared loader, observed under multiple AI-brand lure names | 2026-04-12 | 2026-05-21 |
