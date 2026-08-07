# Unpacking the AsyncAPI npm supply chain compromise and import-time payload delivery

**Source:** <https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/>
**Published:** 2026-07-15
**IOC count:** 18

> Collected for legitimate threat-intelligence purposes: building an IOC database and firewall blocking rules from publicly available Microsoft Security research blog posts.

## Indicators of Compromise

| # | Type | Value | Description | First Seen | Last Seen |
|---|------|-------|-------------|------------|-----------|
| 1 | domain | `npm-oidc-no-reply@github.com` | npm-oidc-no-reply@github.com | npm-oidc-no-reply@github.com | npm-oidc-no-reply@github.com |
| 2 | url | `https://ipfs.io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf` | https://ipfs.io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf | https://ipfs.io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf | https://ipfs.io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf |
| 3 | hash | `b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a` | b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a | b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a | b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a |
| 4 | hash | `b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292` | b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292 | b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292 | b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292 |
| 5 | hash | `8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c` | 8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c | 8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c | 8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c |
| 6 | hash | `6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71` | 6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71 | 6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71 | 6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71 |
| 7 | hash | `24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168` | 24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168 | 24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168 | 24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168 |
| 8 | url | `~/.local/share/NodeJS/sync.js` | ~/.local/share/NodeJS/sync.js | ~/.local/share/NodeJS/sync.js | ~/.local/share/NodeJS/sync.js |
| 9 | url | `~/Library/Application Support/NodeJS/sync.js` | ~/Library/Application Support/NodeJS/sync.js | ~/Library/Application Support/NodeJS/sync.js | ~/Library/Application Support/NodeJS/sync.js |
| 10 | url | `~/.config/NodeJS/sync.js` | ~/.config/NodeJS/sync.js | ~/.config/NodeJS/sync.js | ~/.config/NodeJS/sync.js |
| 11 | url | `~/.config/.miasma/run/node.lock` | ~/.config/.miasma/run/node.lock | ~/.config/.miasma/run/node.lock | ~/.config/.miasma/run/node.lock |
| 12 | url | `/api/v1/beacon,/api/v1/file-result,/api/v1/file-content/<cid>` | /api/v1/beacon,/api/v1/file-result,/api/v1/file-content/<cid> | /api/v1/beacon,/api/v1/file-result,/api/v1/file-content/<cid> | /api/v1/beacon,/api/v1/file-result,/api/v1/file-content/<cid> |
| 13 | ip | `85.137.53.71` |  | 2026-07-15T18:36:21 |  |
| 14 | hash | `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7` |  | 2026-07-15T18:36:21 |  |
| 15 | hash | `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b` |  | 2026-07-15T18:36:21 |  |
| 16 | hash | `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4` |  | 2026-07-15T18:36:21 |  |
| 17 | hash | `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab` |  | 2026-07-15T18:36:21 |  |
| 18 | hash | `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1` |  | 2026-07-15T18:36:21 |  |
