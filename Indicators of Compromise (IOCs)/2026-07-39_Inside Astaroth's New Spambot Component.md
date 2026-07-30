# Inside Astaroth's New Spambot Component — IOCs

Source: public blog analysis
Purpose: Legitimate threat-intel collection for building IOC databases and firewall blocking rules.

## Summary
This document lists Indicators of Compromise (IOCs) observed for the Astaroth and Vareg spambot components. SHA256 values refer to samples and configuration files; network indicators list known C2 domains/URLs. Some original entries were obfuscated (e.g., `[.]` and `[:]`) to avoid accidental linking — both obfuscated and de-obfuscated forms are shown below. Note: one C2 entry appears truncated in the source — verify the original blog entry if you need the exact host.

---

## IOCs

| Malware / Component | Indicator type | Value (obfuscated) | Value (de-obfuscated / notes) |
|---|---:|---|---|
| Astaroth — encrypted spambot | SHA256 | `c7c62303ee1a37fd7a6e2db9c590ba75c647bc4d22d7dca50cfa8879222ac9e1` | SHA256 of encrypted binary |
| Astaroth — encrypted spambot configuration | SHA256 | `ec43a17685e3a555c2eb5f0a2802e9e45d5a2a5d49a0803155acbd74d9ecdbd7` | SHA256 of encrypted config |
| Astaroth — decrypted spambot | SHA256 | `d89105c4d567a95f674ed6eac538e32e288b658a4222a3d52e284a77782af4d5` | SHA256 of decrypted binary |
| Astaroth — installer component C2 | Domain | `stretar7[.]contabilfacil[.]sbs` | stretar7.contabilfacil.sbs |
| Astaroth — installer component C2 | Domain | `graconxonjal[.]empresaeficiente[.]sbs` | graconxonjal.empresaeficiente.sbs |
| Astaroth — installer component C2 | Domain | `plansonval[.]impostosrapido[.]top` | plansonval.impostosrapido.top |
| Vareg — Python variant | SHA256 | `6168d63fad22a4e5e45547ca6116ef68bb5173e17e25fd1714f7cc1e4f7b41e1` | Python-edition sample SHA256 |
| Vareg — PowerShell variant | SHA256 | `a1aa786e02fb9a37a71e0f76b052ab284ba877f2aaa2fb28f05d60487389976a` | PowerShell-edition sample SHA256 |
| Vareg — Python C2 | URL | `https[:]//varegjopeaks[.]com/api/` | https://varegjopeaks.com/api/ |
| Vareg — PowerShell C2 | URL (truncated in source) | `https[:]//docsmoonstudioclayworks[.]onlin` | Appears truncated — likely `docsmoonstudioclayworks.online` (VERIFY against source) |

---

## Notes & handling recommendations
- The original file used obfuscation (`[.]`, `[:]`) to avoid accidental crawling/linking; keep obfuscation in public reports and remove it when ingesting into internal tooling that requires canonical hostnames.
- The `docsmoonstudioclayworks[.]onlin` entry looks truncated. Check the original blog or sample data to confirm the TLD (likely `.online`). Do not block based on truncated hosts alone.
- When adding these to blocklists or detection rules:
  - Use full-domain matches where possible (avoid wildcarding entire registries unless validated).
  - Add SHA256s to sample repositories and configure AV/EDR tooling to match exactly.
  - Timestamp and source the IOCs in your database (source blog URL and collection date).

## Source / provenance
- Original repo entry: https://github.com/opencir/Opencir-Threat-Intelligence-IOCs/blob/main/Indicators%20of%20Compromise%20(IOCs)/2026-07-39_Inside%20Astaroth's%20New%20Spambot%20Component.md
