# From package to postinstall payload: Inside the Mastra npm supply chain compromise by Sapphire Sleet

**Source:** <https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/>
**Published:** 2026-06-17
**IOC count:** 17

> Collected for legitimate threat-intelligence purposes: building an IOC database and firewall blocking rules from publicly available Microsoft Security research blog posts.

## Indicators of Compromise

| # | Type | Value | Description | First Seen | Last Seen |
|---|------|-------|-------------|------------|-----------|
| 1 | ip | `23.254.164.92` | Primary C2 server | Primary C2 server | Primary C2 server |
| 2 | ip | `23.254.164.123` | Secondary C2 address (from deobfuscated strings) | Secondary C2 address (from deobfuscated strings) | Secondary C2 address (from deobfuscated strings) |
| 3 | url | `https[:]//23.254.164.92:8000/update/49890878` | Payload download endpoint | Payload download endpoint | Payload download endpoint |
| 4 | domain | `teams.onweblive.org` | Post Compromise PowerShell backdoor delivery domain | Post Compromise PowerShell backdoor delivery domain | Post Compromise PowerShell backdoor delivery domain |
| 5 | url | `https[:]//teams.onweblive.org/api/update/8555575039/4` | Post Compromise PowerShell backdoor download endpoint | Post Compromise PowerShell backdoor download endpoint | Post Compromise PowerShell backdoor download endpoint |
| 6 | domain | `maskasd.com` | Post Compromise C2 beacon domain | Post Compromise C2 beacon domain | Post Compromise C2 beacon domain |
| 7 | url | `https[:]//maskasd.com/8555575039` | Post Compromise C2 beacon endpoint | Post Compromise C2 beacon endpoint | Post Compromise C2 beacon endpoint |
| 8 | hash | `B122A9873BEDF145AE2A7FD024B5F309007DBB025149F4DC4AC3F7E4F32A36A4` | setup.cjs (malicious postinstall dropper) | setup.cjs (malicious postinstall dropper) | setup.cjs (malicious postinstall dropper) |
| 9 | hash | `AE70DD4F6BC0D1C8C2848E4E6B51934626C4818DCB5AF99D080DDBD7DC337185` | easy-day-js-1.11.22.tgz (weaponized tarball) | easy-day-js-1.11.22.tgz (weaponized tarball) | easy-day-js-1.11.22.tgz (weaponized tarball) |
| 10 | hash | `4A8860240E4231C3A74C81949BE655A28E096A7D72F38FBE84E5B37636B98417` | easy-day-js-1.11.21.tgz (clean bait tarball) | easy-day-js-1.11.21.tgz (clean bait tarball) | easy-day-js-1.11.21.tgz (clean bait tarball) |
| 11 | hash | `B73DE25C053C3225A077738A1FCBD9CA6966D7B3CD6F5494A30F0AA0EAE55C7E` | mastra-1.13.1.tgz (compromised CLI tarball) | mastra-1.13.1.tgz (compromised CLI tarball) | mastra-1.13.1.tgz (compromised CLI tarball) |
| 12 | hash | `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf` | protocol.cjs | protocol.cjs | protocol.cjs |
| 13 | hash | `50eae63d3e24be9ca8803f4b5a0408aef97ee3fab7af018d8c2dde7c359edd65` | Downloader and backdoor PowerShell script | Downloader and backdoor PowerShell script | Downloader and backdoor PowerShell script |
| 14 | hash | `1d1bf5e8c1539d2f05b1429235b8f4990f87036774be95157b315a7803dd5526` | Second stage Powershell Script | Second stage Powershell Script | Second stage Powershell Script |
| 15 | url | `$TMPDIR/.pkg_history` | Contains the install path of the compromised package | Contains the install path of the compromised package | Contains the install path of the compromised package |
| 16 | url | `$TMPDIR/.pkg_logs` | Contains XOR 0x80 encoded string “easy-day-js” | Contains XOR 0x80 encoded string “easy-day-js” | Contains XOR 0x80 encoded string “easy-day-js” |
| 17 | url | `<homedir>/<random_hex>.js` | Downloaded second-stage payload | Downloaded second-stage payload | Downloaded second-stage payload |
