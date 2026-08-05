# Inside Astaroth's New Spambot Component — IOCs

Source: public blog analysis
Original repo entry: https://www.crowdstrike.com/en-us/blog/inside-astaroths-new-spambot-component/
Purpose: Legitimate threat-intel collection for building IOC databases and firewall blocking rules.

## Summary
This document lists Indicators of Compromise (IOCs) observed for the Astaroth and Vareg spambot components. All network indicators are intentionally left obfuscated (e.g., `[.]` and `[:]`) as requested. SHA256 values are exact as provided in the source.

---

## IOCs (obfuscated only)

| Malware / Component | Indicator type | Value (obfuscated) | Notes |
|---|---:|---|---|
| Astaroth — encrypted spambot | SHA256 | `c7c62303ee1a37fd7a6e2db9c590ba75c647bc4d22d7dca50cfa8879222ac9e1` | Encrypted binary SHA256 |
| Astaroth — encrypted spambot configuration | SHA256 | `ec43a17685e3a555c2eb5f0a2802e9e45d5a2a5d49a0803155acbd74d9ecdbd7` | Encrypted configuration SHA256 |
| Astaroth — decrypted spambot | SHA256 | `d89105c4d567a95f674ed6eac538e32e288b658a4222a3d52e284a77782af4d5` | Decrypted binary SHA256 (source-provided) |
| Astaroth — installer component C2 | Domain | `stretar7[.]contabilfacil[.]sbs` | Obfuscated domain as in source |
| Astaroth — installer component C2 | Domain | `graconxonjal[.]empresaeficiente[.]sbs` | Obfuscated domain as in source |
| Astaroth — installer component C2 | Domain | `plansonval[.]impostosrapido[.]top` | Obfuscated domain as in source |
| Vareg — Python variant | SHA256 | `6168d63fad22a4e5e45547ca6116ef68bb5173e17e25fd1714f7cc1e4f7b41e1` | Python-version sample SHA256 |
| Vareg — PowerShell variant | SHA256 | `a1aa786e02fb9a37a71e0f76b052ab284ba877f2aaa2fb28f05d60487389976a` | PowerShell-version sample SHA256 |
| Vareg — Python C2 | URL | `https[:]//varegjopeaks[.]com/api/` | Obfuscated URL as in source |
| Vareg — PowerShell C2 | URL | `https[:]//docsmoonstudioclayworks[.]onlin` | Obfuscated and appears truncated in source; do not de-obfuscate |

---

