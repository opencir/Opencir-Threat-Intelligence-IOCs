# IOCs Collection Skill (Microsoft Security Research)

## Scope
Use this skill for IOC ingestion and publishing workflows related to:
- `copilot/fix-defanging-issue`
- `copilot/microsoft-security-blog`
- PR reference: https://github.com/opencir/Opencir-Threat-Intelligence-IOCs/pull/4

## Goal
Produce deterministic, safe-to-publish IOC outputs and avoid publishing empty/low-value article records.

## Core Rules

### 1) Defang at publish/write time
Apply defanging only when serializing output (Markdown/JSON), not during extraction matching.

- Domain: `example.com` → `example[.]com`
- IP: `192.168.1.1` → `192[.]168[.]1[.]1`
- URL: `https://host.tld/path` → `https[://]host[.]tld/path`
- Email: preserve local-part, defang domain only  
  `user.name@example.com` → `user.name@example[.]com`

### 2) Normalize mixed inputs
If input is already defanged or partially defanged, normalize and re-serialize so output format stays consistent.

### 3) Keep safe exceptions
Do **not** transform:
- Hashes
- CVEs

### 4) Zero-IOC pruning
If an article resolves to zero retained IOCs:
- skip per-article Markdown generation
- remove previously generated stale zero-IOC files during regeneration
- exclude from index/README listing

### 5) Regeneration consistency
When scraper logic changes:
- regenerate feed JSON
- regenerate per-article Markdown
- regenerate index/README
Ensure repository artifacts match runtime scraper behavior.

## Validation Checklist (before publish)
- [ ] All published domains/IPs/URLs/emails are defanged consistently.
- [ ] No extraction-time logic depends on defanged values.
- [ ] Hashes and CVEs remain unchanged.
- [ ] No zero-IOC article files remain in output directory.
- [ ] README/index excludes zero-IOC entries.
- [ ] Feed and Markdown outputs match the same run.

## Operational Notes for Scheduled Tasks
- Run scraper first, then rebuild feed and markdown outputs in one workflow.
- Treat output normalization as deterministic and idempotent.
- Fail task if output contains refanged URL/domain/IP values in publish artifacts.
