---
name: codex-phishing-site-analysis
description: Safe, reproducible phishing and scam site analysis. Use when the user asks to analyze a suspicious URL/domain, create or update a phishing-site report, collect WHOIS/DNS/HTTP/VirusTotal/urlscan/Certificate Transparency/URLhaus/PhishTank/Wayback/Playwright evidence, investigate cloaking or JavaScript behavior, hunt staged dynamic endpoints (Case1/2/3.php, step1/2/3 chains), detect IDN homograph or APK/smishing 2nd-stage payloads, capture PII/payment-flow screens without submitting real data, cluster related scam infrastructure, or generate the standard HTML/PDF report under report/[domain].
---

# Phishing Site Analysis

Use this skill to produce evidence-backed phishing/scam-site analysis reports while keeping live-site interaction safe, reproducible, and clearly caveated. The skill is fully independent — it does not depend on any other analysis pipeline.

## Operating Rules

- Treat live targets as hostile. Use a fresh browser context/profile, no personal cookies, no real credentials, no real PII, no real payment data, and stop before submitting forms.
- Prefer passive collection first: URL normalization, DNS, WHOIS, HTTP headers, CT, VT, urlscan, URLhaus, PhishTank, Wayback, static HTML/JS download. Use Playwright only when the report needs live screenshots or flow observation.
- Save all artifacts under `report/[report_slug]/`; do not commit `report/` or `.playwright-mcp/` outputs.
- Preserve evidence: record source URL, collection time, tool/command, User-Agent, HTTP status/redirects when practical, and sha256 hashes for local artifacts.
- Use confidence levels for attribution and clustering. Do not state "same operator" from one shared SaaS/CDN signal alone.
- Keep full URLs untruncated in the report. Long URLs go in `<pre>` blocks.
- Main body screenshots should be cropped evidence; full-page screenshots belong in Appendix A.
- Build the final PDF from `report.html` only after `check_report.py` passes; verify the final renamed PDF, not `_tmp_report.pdf`.

## Workflow

1. Normalize the target with `scripts/normalize_target.py`. Use its `domain`, `url`, and `report_slug` output to set `DOMAIN`, `URL`, and `D`.
2. Read [references/workflow.md](references/workflow.md) for the step-by-step command workflow.
3. For external-intel collection (VT, urlscan, CT, URLhaus, PhishTank, OTX, Safe Browsing, ThreatFox, Wayback), read [references/data-collection.md](references/data-collection.md).
4. For cloaking detection (UA, Referer, Geo, token-gate, time-gate, headless), read [references/cloaking-checklist.md](references/cloaking-checklist.md).
5. For JS behavior analysis (static, anti-analysis, fingerprinting, APK/smishing 2nd-stage payloads), read [references/js-checklist.md](references/js-checklist.md).
5a. **For dynamic endpoint hunting** (staged data-capture chains like `Case1.php` → `Case2.php` → `Case3.php`, hidden series paths, form-submission simulation with safe dummy data), read [references/dynamic-endpoints.md](references/dynamic-endpoints.md). **Always run this step when the page's visible buttons are all `javascript:void(null);` or `href="#"` — the real phishing endpoints often live at unreferenced URLs.**
6. For IDN/homograph analysis on the target domain, run `scripts/idn_homograph.py`.
7. For report authoring, copy [references/report-template.html](references/report-template.html) to `$D/report.html` and use [references/chapter-skeletons.md](references/chapter-skeletons.md) as chapter scaffolding (chapters 1–15 + Appendix A all included).
8. For screenshot crops, copy [references/crop_screenshots_template.py](references/crop_screenshots_template.py) into `$D/` and adjust coordinates.
9. Before PDF build, run `scripts/check_report.py "$D/report.html"` to verify chapter completeness, no remaining placeholders, and all `<img>` files exist.
10. Generate `evidence_manifest.json` with `scripts/evidence_manifest.py` after collecting artifacts and again before final delivery.
11. Build and verify the PDF using [references/pdf-build.md](references/pdf-build.md).

## Standard Output

Create this structure:

```text
report/[report_slug]/
├── report.html
├── [report_slug]_YYMMDD_HHMMSS.pdf
├── evidence_manifest.json
├── mobile.html / desktop.html / detail.html
├── *.js
├── screenshot-*.png
├── crop-*.png
├── network-*.txt
├── cloak/                  # ua_*, ref_*, lang_*, noquery/withquery
├── crop_screenshots.py
└── scan_*.py
```

The report should normally include chapters 1–15 + Appendix A:

1. Fraud pattern excerpts
2. Executive summary
3. Shared infrastructure and related domains, with confidence labels
4. Attacker activity timeline (incl. MITRE ATT&CK mapping)
5. Operator identification signals, caveated
6. Site/system identifiers
7. Ads/tracking pixels
8. PII/payment collection analysis
9. JavaScript behavior analysis
10. Content disguise patterns (IDN, social-proof fakes, Korean naturalness)
11. Estimated attack scenario
12. Infrastructure IOC
13. Risk assessment (weighted scoring)
14. Recommended actions
15. Artifact list
- Appendix A. Full-page screenshots

## Safety And Evidence Checklist

Before live interaction:

- Use mobile and desktop User-Agents intentionally; document which one produced each artifact.
- Disable or avoid browser state that may expose the analyst: saved accounts, password manager, clipboard grants, notifications, camera/mic/location, downloads when not needed.
- Use dummy values only if a field cannot be reached otherwise; clear or mask them before screenshots.
- Do not click final payment/submit/confirm buttons. If a network request would send PII/payment data, stop at form observation.
- For APK or other downloaded payloads, compute sha256 and submit to VT — never install on the analyst device.

Before final answer:

- `scripts/check_report.py` exits 0 (all chapters present, no placeholders, all images resolved).
- `evidence_manifest.json` exists and covers the important files.
- Final PDF path follows `[report_slug]_YYMMDD_HHMMSS.pdf`.
- `pypdf` can read the final PDF and extract Korean text.
- Attribution claims have evidence and confidence levels.
- The answer tells the user where the report and PDF are, plus any steps that could not be completed.

## References

- [references/workflow.md](references/workflow.md) — main analysis workflow and commands
- [references/data-collection.md](references/data-collection.md) — VT/urlscan/CT/URLhaus/PhishTank/OTX/Safe Browsing/ThreatFox/Wayback snippets
- [references/cloaking-checklist.md](references/cloaking-checklist.md) — UA/Referer/Geo/token/time/headless cloaking matrix
- [references/js-checklist.md](references/js-checklist.md) — static and dynamic JS behavior checklist + APK/smishing 2nd-stage detection
- [references/dynamic-endpoints.md](references/dynamic-endpoints.md) — staged endpoint hunting (Case1/2/3, step1/2/3, hidden series paths, form-submission simulation, GET-vs-POST reflection diff)
- [references/chapter-skeletons.md](references/chapter-skeletons.md) — HTML chapter scaffolding (1–15 + Appendix A)
- [references/report-template.html](references/report-template.html) — report starting template
- [references/crop_screenshots_template.py](references/crop_screenshots_template.py) — PIL crop helper
- [references/pdf-build.md](references/pdf-build.md) — Chromium PDF build and validation
- [references/trusted-hosts.txt](references/trusted-hosts.txt) — whitelist for IOC triage (extend as analyses accumulate)

## Scripts

- `scripts/normalize_target.py` — URL/domain/slug normalizer (idna + safe filenames)
- `scripts/idn_homograph.py` — Unicode-block breakdown for the target domain, with HTML output for chapter 10.2
- `scripts/check_report.py` — pre-PDF completeness check
- `scripts/evidence_manifest.py` — sha256 manifest with tool versions
