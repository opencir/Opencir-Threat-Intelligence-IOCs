# Photo ZIP campaign targeting hospitality industry delivers Node.js implant for persistent access

**Source:** <https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/>
**Published:** 2026-06-25
**IOC count:** 106

> Collected for legitimate threat-intelligence purposes: building an IOC database and firewall blocking rules from publicly available Microsoft Security research blog posts.

## Indicators of Compromise

| # | Type | Value | Description | First Seen | Last Seen |
|---|------|-------|-------------|------------|-----------|
| 1 | ip | `178[.]16[.]54[.]27` | Primary — Active in both waves, ports 56001/56002 | Primary — Active in both waves, ports 56001/56002 | Primary — Active in both waves, ports 56001/56002 |
| 2 | ip | `95[.]217[.]97[.]121` | Persistent beacon (Wave 1) | Persistent beacon (Wave 1) | Persistent beacon (Wave 1) |
| 3 | ip | `193[.]202[.]84[.]32` | Secondary (Wave 1) | Secondary (Wave 1) | Secondary (Wave 1) |
| 4 | ip | `178[.]16[.]55[.]179` | Additional (Wave 1) | Additional (Wave 1) | Additional (Wave 1) |
| 5 | ip | `172[.]67[.]161[.]215` | phishing TonRAT C2 (Cloudflare shared CDN ) | phishing TonRAT C2 (Cloudflare shared CDN ) | phishing TonRAT C2 (Cloudflare shared CDN ) |
| 6 | domain | `prejointl[.]info` | C2 domain | C2 domain | C2 domain |
| 7 | domain | `safedocphoto[.]info` | C2 domain | C2 domain | C2 domain |
| 8 | domain | `recallnine[.]info` | C2 domain | C2 domain | C2 domain |
| 9 | domain | `kentjerk[.]info` | C2 domain | C2 domain | C2 domain |
| 10 | domain | `photodoc-secure[.]info` | C2 domain | C2 domain | C2 domain |
| 11 | domain | `kelopins[.]info` | C2 domain | C2 domain | C2 domain |
| 12 | domain | `docstore-safe[.]info` | C2 domain | C2 domain | C2 domain |
| 13 | domain | `photosafe-hub[.]info` | C2 domain | C2 domain | C2 domain |
| 14 | domain | `dashgamein[.]info` | C2 domain | C2 domain | C2 domain |
| 15 | domain | `image-vlt[.]info` | C2 domain | C2 domain | C2 domain |
| 16 | domain | `safedoc-storage[.]info` | C2 domain | C2 domain | C2 domain |
| 17 | domain | `safe-picvault[.]info` | C2 domain | C2 domain | C2 domain |
| 18 | domain | `photo-dekor[.]xyz` | C2 domain | C2 domain | C2 domain |
| 19 | domain | `reservebookphot[.]pro` | C2 domain | C2 domain | C2 domain |
| 20 | domain | `kellystreets[.]info` | C2 domain | C2 domain | C2 domain |
| 21 | domain | `widjssij728dj[.]com` | C2 domain | C2 domain | C2 domain |
| 22 | domain | `docshub-01[.]info` | C2 domain | C2 domain | C2 domain |
| 23 | domain | `photobookadm[.]pro` | C2 domain | C2 domain | C2 domain |
| 24 | domain | `safedoc-vault[.]info` | C2 domain | C2 domain | C2 domain |
| 25 | domain | `keypmenu[.]info` | C2 domain | C2 domain | C2 domain |
| 26 | domain | `photo-box[.]info` | C2 domain | C2 domain | C2 domain |
| 27 | domain | `expedla-getphoto[.]cloud` | C2 domain | C2 domain | C2 domain |
| 28 | domain | `vertualstreak[.]info` | C2 domain | C2 domain | C2 domain |
| 29 | domain | `montagelips[.]info` | C2 domain | C2 domain | C2 domain |
| 30 | domain | `racestrech[.]info` | C2 domain | C2 domain | C2 domain |
| 31 | domain | `derbyoni[.]info` | C2 domain | C2 domain | C2 domain |
| 32 | domain | `ministrew[.]info` | C2 domain | C2 domain | C2 domain |
| 33 | domain | `visaphoto-secure[.]info` | C2 domain | C2 domain | C2 domain |
| 34 | domain | `docshub-secure[.]com` | C2 domain | C2 domain | C2 domain |
| 35 | domain | `visaimage-storage[.]icu` | C2 domain | C2 domain | C2 domain |
| 36 | domain | `lookinlip[.]info` | C2 domain | C2 domain | C2 domain |
| 37 | domain | `safephoto-vault[.]info` | C2 domain | C2 domain | C2 domain |
| 38 | domain | `kiptownim[.]info` | C2 domain | C2 domain | C2 domain |
| 39 | domain | `finallyrain[.]info` | C2 domain | C2 domain | C2 domain |
| 40 | domain | `photobook-reserv[.]pro` | C2 domain | C2 domain | C2 domain |
| 41 | domain | `bookreservphoto[.]pro` | C2 domain | C2 domain | C2 domain |
| 42 | domain | `imagestore-hub[.]info` | C2 domain | C2 domain | C2 domain |
| 43 | domain | `visaimages[.]info` | C2 domain | C2 domain | C2 domain |
| 44 | domain | `visaphoto-vault[.]info` | C2 domain | C2 domain | C2 domain |
| 45 | domain | `visa-vault[.]info` | C2 domain | C2 domain | C2 domain |
| 46 | domain | `visa-safedocs[.]info` | C2 domain | C2 domain | C2 domain |
| 47 | domain | `joincroud[.]info` | C2 domain | C2 domain | C2 domain |
| 48 | domain | `kinghoruswe[.]info` | C2 domain | C2 domain | C2 domain |
| 49 | domain | `snapkeep[.]info` | C2 domain | C2 domain | C2 domain |
| 50 | domain | `deeprace[.]info` | C2 domain | C2 domain | C2 domain |
| 51 | domain | `lestresot[.]info` | C2 domain | C2 domain | C2 domain |
| 52 | domain | `recepyman[.]info` | C2 domain | C2 domain | C2 domain |
| 53 | domain | `recstrace[.]info` | C2 domain | C2 domain | C2 domain |
| 54 | domain | `heliosup[.]info` | C2 domain | C2 domain | C2 domain |
| 55 | domain | `fairyspells[.]info` | C2 domain | C2 domain | C2 domain |
| 56 | domain | `hakeiwjs727wj[.]com` | C2 domain | C2 domain | C2 domain |
| 57 | domain | `haobbao[.]com` | C2 domain | C2 domain | C2 domain |
| 58 | domain | `dancamp[.]info` | C2 domain | C2 domain | C2 domain |
| 59 | domain | `sec-safe-dc[.]info` | C2 domain — Active in both waves | C2 domain — Active in both waves | C2 domain — Active in both waves |
| 60 | domain | `secure-imagehub[.]info` | C2 domain | C2 domain | C2 domain |
| 61 | domain | `doc-imagehub[.]info` | C2 domain | C2 domain | C2 domain |
| 62 | domain | `imagevault-safe[.]info` | C2 domain | C2 domain | C2 domain |
| 63 | domain | `photo-hub-io[.]info` | C2 domain | C2 domain | C2 domain |
| 64 | domain | `safevault-hub[.]info` | C2 domain | C2 domain | C2 domain |
| 65 | domain | `tripadvisor-photo-view[.]com` | C2 domain | C2 domain | C2 domain |
| 66 | domain | `photo-7216302[.]sbs` | C2 domain | C2 domain | C2 domain |
| 67 | domain | `photo-26254[.]cfd` | Phishing landing page | Phishing landing page | Phishing landing page |
| 68 | domain | `photo-132454[.]cfd` | Phishing landing page | Phishing landing page | Phishing landing page |
| 69 | domain | `photo-8632454[.]cfd` | Phishing landing page | Phishing landing page | Phishing landing page |
| 70 | domain | `photo-21473[.]xyz` | C2 domain | C2 domain | C2 domain |
| 71 | domain | `photo-7216102[.]click` | C2 domain | C2 domain | C2 domain |
| 72 | domain | `zloapobikahy23[.]bond` | C2 domain | C2 domain | C2 domain |
| 73 | domain | `higoksbupwou[.]com` | C2 domain | C2 domain | C2 domain |
| 74 | domain | `aluminiostramuntana[.]com` | C2 domain | C2 domain | C2 domain |
| 75 | domain | `photo-26653[.]cfd` | Phishing landing page | Phishing landing page | Phishing landing page |
| 76 | domain | `photo-26654[.]cfd` | Phishing landing page | Phishing landing page | Phishing landing page |
| 77 | domain | `photo-26656[.]cfd` | Phishing landing page | Phishing landing page | Phishing landing page |
| 78 | domain | `photo-27857[.]cfd` | Phishing landing page | Phishing landing page | Phishing landing page |
| 79 | hash | `83e970feb3f10692c164f6889f7a026f135c2433e5bf8e662a6e63a3b81267b7` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 80 | hash | `06a2888c1f07119873ccb051221bd8717281494b33585f4242556e6e5e227969` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 81 | hash | `04ec44f2618460f5c77c5e56014a512cc03a123c9c5b6b6b1273e2a1681ac2e1` | PE payload (xmnrwv9l.exe) — Same hash in both waves | PE payload (xmnrwv9l.exe) — Same hash in both waves | PE payload (xmnrwv9l.exe) — Same hash in both waves |
| 82 | hash | `1c693bcdaf1da636eb21c274b21cc2f6c52c62ddd514700783eee83fe13acb0a` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 83 | hash | `2e5fd01b7949a45937b853eabcf4b03195614cf84338dcaaa97240d1c5301ddc` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 84 | hash | `3f66634f103b80412d1d670b91befab2a74425d2ea76d904c4a7ffae2ae94b44` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 85 | hash | `63565f15a99769bbcd527a4d53e5cc259d80e1254463ef9c878c2074685558ae` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 86 | hash | `49cc0e0c3ec060fb354cacee244d4f297aaefb6db66e67a21262d6c4d2eae1bd` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 87 | hash | `6580de3b74fd635a1d7a887b8f6e5b0c9ac9e90d6e20466ad41489203119cca9` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 88 | hash | `da4b72764ae929050353f3da759c839e2a061a8b9a8dd3c3b2e909d4a8a3291c` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 89 | hash | `f629311734b7c6e6579f8e1d0e1e3f3bf72c9ac6c301b631ba4df7f393c41b14` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 90 | hash | `98825c0c7764f45c891275b2f038ea559e84b340df30b41c2cc77b8d4215c6c8` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 91 | hash | `bd6805782df15e53581096b99bd6bbb81f4d4a5e2d2b30954df63175a4075be9` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 92 | hash | `89934cb1494cf0327f0ab82fe644c74caf687814379cad116bd7adaca74c1028` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 93 | hash | `1f8daffec5945a13a1e9231f4a76655d4c7ef4560d0c64ca3abfe48f38297cbd` | Campaign payload (Wave 1) | Campaign payload (Wave 1) | Campaign payload (Wave 1) |
| 94 | hash | `9f10e3b6e5745784f26d18c38ce01fba054b19749c17260978ac11472564aee2` | IMG-386443483.png.lnk(Wave 2) | IMG-386443483.png.lnk(Wave 2) | IMG-386443483.png.lnk(Wave 2) |
| 95 | hash | `97448688b292bfec6d83b153588076fe59b111c35ac4e42a916238df16a71e2f` | PHOTO-215746435.png.lnk(Wave 2) | PHOTO-215746435.png.lnk(Wave 2) | PHOTO-215746435.png.lnk(Wave 2) |
| 96 | hash | `c5baa0c16b0074a1e94b48aa0177e9bfc23746aca8a5b42848a6685da85658b5` | qFWe908J.ps1(419 KB, Wave 2) | qFWe908J.ps1(419 KB, Wave 2) | qFWe908J.ps1(419 KB, Wave 2) |
| 97 | hash | `b7f46b192cd83a1d2487cb048cca645f6e8855b9673d500d50bbdb04eebc6bea` | bjygtujc.dll(3,072 bytes, compiled .NET, Wave 2) | bjygtujc.dll(3,072 bytes, compiled .NET, Wave 2) | bjygtujc.dll(3,072 bytes, compiled .NET, Wave 2) |
| 98 | hash | `d14ba95cdce1ef7dc9ad3ac74949ca5db38b27378ee30f30a23cf26f9e875a11` | node.exe(v24.13.0-win-x64, 89.9 MB) | node.exe(v24.13.0-win-x64, 89.9 MB) | node.exe(v24.13.0-win-x64, 89.9 MB) |
| 99 | url | `https[://]share[.]google/TOKEN` |  | 2026-06-25 |  |
| 100 | ip | `208[.]95[.]112[.]1` |  | 2026-06-25 |  |
| 101 | domain | `em1618[.]calendly[.]com` |  | 2026-06-25 |  |
| 102 | domain | `calendly[.]com` |  | 2026-06-25 |  |
| 103 | domain | `nodejs[.]org` |  | 2026-06-25 |  |
| 104 | domain | `ip-api[.]com` |  | 2026-06-25 |  |
| 105 | hash | `25908558764390958596189327204542` |  | 2026-06-25 |  |
| 106 | hash | `17082531775760189576112827972435` |  | 2026-06-25 |  |
