# ChainDrop supply chain compromise: Anatomy of a self-propagating worm

**Source:** <https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/>
**Published:** 2026-08-04
**IOC count:** 7

> Collected for legitimate threat-intelligence purposes: building an IOC database and firewall blocking rules from publicly available Microsoft Security research blog posts.

## Indicators of Compromise

| # | Type | Value | Description | First Seen | Last Seen |
|---|------|-------|-------------|------------|-----------|
| 1 | hash | `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` | setup.mjs(npm tarball preinstall loader) | setup.mjs(npm tarball preinstall loader) | setup.mjs(npm tarball preinstall loader) |
| 2 | hash | `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` | setup.mjs(.claudeand.vscoderepository loader) | setup.mjs(.claudeand.vscoderepository loader) | setup.mjs(.claudeand.vscoderepository loader) |
| 3 | hash | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | Math_*.js | Math_*.js | Math_*.js |
| 4 | domain | `npm-cache.com` | C2 domain | C2 domain | C2 domain |
| 5 | domain | `pypi-get.com` | C2 domain | C2 domain | C2 domain |
| 6 | domain | `js-mirror.com` | C2 domain | C2 domain | C2 domain |
| 7 | url | `hxxps[:]//npm-cache.com:443/router` | C2 URL | C2 URL | C2 URL |
