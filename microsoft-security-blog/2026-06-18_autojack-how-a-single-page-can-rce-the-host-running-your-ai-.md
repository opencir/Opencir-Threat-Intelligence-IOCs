# AutoJack: How a single page can RCE the host running your AI agent 

**Source:** <https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/>
**Published:** 2026-06-18
**IOC count:** 19

> Collected for legitimate threat-intelligence purposes: building an IOC database and firewall blocking rules from publicly available Microsoft Security research blog posts.

## Indicators of Compromise

| # | Type | Value | Description | First Seen | Last Seen |
|---|------|-------|-------------|------------|-----------|
| 1 | url | `http://attacker.example/websocket-interactive` |  | 2026-06-18T17:17:54 |  |
| 2 | url | `https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection` |  | 2026-06-18T17:17:54 |  |
| 3 | url | `https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-threat-protection` |  | 2026-06-18T17:17:54 |  |
| 4 | url | `https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-security-posture` |  | 2026-06-18T17:17:54 |  |
| 5 | url | `https://learn.microsoft.com/en-us/azure/foundry/concepts/ai-red-teaming-agent` |  | 2026-06-18T17:17:54 |  |
| 6 | url | `https://github.com/microsoft/PyRIT` |  | 2026-06-18T17:17:54 |  |
| 7 | url | `https://learn.microsoft.com/en-us/defender-endpoint/` |  | 2026-06-18T17:17:54 |  |
| 8 | url | `https://learn.microsoft.com/en-us/defender-endpoint/network-protection` |  | 2026-06-18T17:17:54 |  |
| 9 | url | `https://learn.microsoft.com/en-us/defender-endpoint/web-content-filtering` |  | 2026-06-18T17:17:54 |  |
| 10 | url | `https://learn.microsoft.com/en-us/defender-vulnerability-management/` |  | 2026-06-18T17:17:54 |  |
| 11 | url | `https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview` |  | 2026-06-18T17:17:54 |  |
| 12 | url | `https://www.microsoft.com/en-us/security/blog/2025/05/19/announcing-microsoft-entra-agent-id-secure-and-manage-your-ai-agents/` |  | 2026-06-18T17:17:54 |  |
| 13 | url | `https://learn.microsoft.com/en-us/defender-for-identity/what-is` |  | 2026-06-18T17:17:54 |  |
| 14 | url | `https://learn.microsoft.com/en-us/azure/dev-box/overview-what-is-microsoft-dev-box` |  | 2026-06-18T17:17:54 |  |
| 15 | url | `https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview` |  | 2026-06-18T17:17:54 |  |
| 16 | url | `https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-devops-introduction` |  | 2026-06-18T17:17:54 |  |
| 17 | url | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview` |  | 2026-06-18T17:17:54 |  |
| 18 | url | `https://learn.microsoft.com/en-us/copilot/security/microsoft-security-copilot` |  | 2026-06-18T17:17:54 |  |
| 19 | domain | `msft.net` |  | 2026-06-18T17:17:54 |  |
