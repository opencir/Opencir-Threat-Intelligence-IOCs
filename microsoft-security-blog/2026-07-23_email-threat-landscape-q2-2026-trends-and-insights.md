# Email threat landscape: Q2 2026 trends and insights

**Source:** <https://www.microsoft.com/en-us/security/blog/2026/07/23/email-threat-landscape-q2-2026-trends-and-insights/>
**Published:** 2026-07-23
**IOC count:** 25

> Collected for legitimate threat-intelligence purposes: building an IOC database and firewall blocking rules from publicly available Microsoft Security research blog posts.

## Indicators of Compromise

| # | Type | Value | Description | First Seen | Last Seen |
|---|------|-------|-------------|------------|-----------|
| 1 | domain | `9i6pokerdepot.com` | Sending domain; DKIM-signed by the operator | 2026-06-15 | 2026-06-15 |
| 2 | domain | `customer.service@9i6pokerdepot.com` | Campaign sender address | 2026-06-15 | 2026-06-15 |
| 3 | domain | `t90141296286.p.clickup-attachments.com` | ClickUp attachment subdomain hosting the stage 2 BAT dropper | 2026-06-15 | 2026-06-15 |
| 4 | url | `https://t90141296286.p.clickup-attachments.com/t90141296286/fb39c3a9-3161-40ad-847b-0683e0409d6f/Financial_report.bat` | Stage 2 BAT dropper download URL | 2026-06-15 | 2026-06-15 |
| 5 | url | `https://pixeldrain.com/api/file/3v92oJiL` | Final installer payload download URL | 2026-06-15 | 2026-06-15 |
| 6 | domain | `ecajovna.sk` | Domain used to send campaign emails | 2026-06-01 | 2026-06-01 |
| 7 | domain | `ilyff.com` | Reply-to domain used to receive victim responses | 2026-06-01 | 2026-06-01 |
| 8 | domain | `j-gmails.com` | Reply-to domain used to receive victim responses | 2026-06-01 | 2026-06-01 |
| 9 | domain | `x2mails.com` | Reply-to domain used to receive victim responses | 2026-06-01 | 2026-06-01 |
| 10 | domain | `mail@ilyff.com` | Reply-to address | 2026-06-01 | 2026-06-01 |
| 11 | domain | `me@j-gmails.com` | Reply-to address | 2026-06-01 | 2026-06-01 |
| 12 | domain | `me@x2mails.com` | Reply-to address | 2026-06-01 | 2026-06-01 |
| 13 | domain | `compliance-protectionoutlook.de` | Domain hosting malicious campaign content | 2026-04-14 | 2026-04-16 |
| 14 | domain | `acceptable-use-policy-calendly.de` | Domain hosting malicious campaign content | 2026-04-14 | 2026-04-16 |
| 15 | domain | `cocinternal.com` | Domain hosting sender email address | 2026-04-14 | 2026-04-16 |
| 16 | domain | `gadellinet.com` | Domain hosting sender email address | 2026-04-14 | 2026-04-16 |
| 17 | domain | `harteprn.com` | Domain hosting sender email address | 2026-04-14 | 2026-04-16 |
| 18 | domain | `nationaladmin@gadellinet.com` | Email address used to send campaign emails | 2026-04-14 | 2026-04-16 |
| 19 | domain | `nationalintegrity@harteprn.com` | Email address used to send campaign emails | 2026-04-14 | 2026-04-16 |
| 20 | domain | `m365premiumcommunications@cocinternal.com` | Email address used to send campaign emails | 2026-04-14 | 2026-04-16 |
| 21 | domain | `documentviewer@na.businesshellosign.de` | Email address used to send campaign emails | 2026-04-14 | 2026-04-16 |
| 22 | hash | `5DB1ECBBB2C90C51D81BDA138D4300B90EA5EB2885CCE1BD921D692214AECBC6` | File hash of campaign PDF attachment | 2026-04-14 | 2026-04-16 |
| 23 | hash | `B5A3346082AC566B4494E6175F1CD9873B64ABE6C902DB49BD4E8088876C9EAD` | File hash of campaign PDF attachment | 2026-04-14 | 2026-04-16 |
| 24 | hash | `11420D6D693BF8B19195E6B98FEDD03B9BCBC770B6988BC64CB788BFABE1A49D` | File hash of campaign PDF attachment | 2026-04-14 | 2026-04-16 |
| 25 | domain | `na.businesshellosign.de` |  | 2026-07-23T08:00:00 |  |
