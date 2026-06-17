# Phishing Investigation Report Lab

> Manual SOC investigation project — analyzing real-world phishing emails in an isolated VM. Evidence-backed reports, IOC extraction, threat-intelligence enrichment, SIEM hunting queries, containment recommendations.

**Author:** KBugra

## What I Investigated

- **Case 1:** Historical PayPal Phishing (2005) — raw IP credential harvesting, SpamAssassin 22.4, DNSBL enrichment ✅
- **Case 2:** Modern Microsoft Phishing (2023) — SPF/DKIM/DMARC, domain typosquatting, tracking params ✅
- **Case 3:** OneDrive Attachment Smuggling (2023) — HTML attachment, compromised account, SPF/DMARC pass ≠ safe ✅

## Skills Demonstrated

| Category | Skills |
|----------|--------|
| **Email Header Analysis** | SPF, DKIM, DMARC interpretation, Received chain tracing, Message-ID forgery detection |
| **Threat Intelligence** | VirusTotal, URLScan.io, AbuseIPDB, WHOIS/RDAP, SpamAssassin rule analysis |
| **IOC Extraction** | Domain, URL, IP, hash, email, subject, Message-ID — confidence-leveled table |
| **Incident Response** | Containment recommendations, mail gateway rules, SIEM hunting queries (Splunk, KQL, Lucene) |
| **Reporting** | Evidence-backed SOC investigation reports with timeline, verdict decision trees, Mermaid diagrams |
| **Tool Development** | Python email triage helper — header parser, IOC extractor (no automated verdict) |
| **Lab Safety** | VM isolation, defanging, public-data-only, no live infrastructure interaction |

## Evidence Produced

### Case 1: PayPal Credential Harvesting (2005)

- **📄 Report:** [CASE1_FINAL.md](reports/phishing_investigation_report_CASE1_FINAL.md) — 10-section SOC report
- **📊 IOCs:** [iocs.csv](iocs/iocs.csv) — 11 indicators with confidence levels
- **📸 Screenshots:** 10 annotated screenshots (raw headers, parser output, VT, URLScan, WHOIS, AbuseIPDB)
- **🔧 Tool:** [email_triage_helper.py](tools/email_triage_helper.py) — Python header/IOC parser

**➡️ [View Case 1 Report](reports/phishing_investigation_report_CASE1_FINAL.md)**

### Case 2: Microsoft Unusual Sign-In (2023)

- **📄 Report:** [CASE2_FINAL.md](reports/phishing_investigation_report_CASE2_FINAL.md)
- **📊 IOCs:** [iocs_case2.csv](iocs/iocs_case2.csv) — 11 indicators including SPF/DKIM/DMARC results
- **📸 Screenshots:** 9 annotated screenshots (raw headers, parser, VT domain+IP, WHOIS, AbuseIPDB)

| Indicator | Finding |
|-----------|---------|
| Typosquatting | conect.best (missing 'n') — 9/91 VT flagged |
| Auth headers | SPF softfail, DKIM none, DMARC none |
| Tracking param | ?val=jose@monkey.org in URL |
| Self-to-self | From and To same address |
| Verdict | **Phishing — Credential Harvesting** |

**➡️ [View Case 2 Report](reports/phishing_investigation_report_CASE2_FINAL.md)**

### Case 3: OneDrive Attachment Smuggling (2023)

- **📄 Report:** [CASE3_FINAL.md](reports/phishing_investigation_report_CASE3_FINAL.md)
- **📊 IOCs:** [iocs_case3.csv](iocs/iocs_case3.csv) — 11 indicators including attachment hash
- **📸 Screenshots:** [screenshots/](screenshots/) — header parser, attachment extraction

| Indicator | Finding |
|-----------|---------|
| Attack vector | HTML attachment smuggling (.shtml) — NO links in body |
| SPF/DMARC | PASS — compromised legitimate server, not exculpatory |
| Attachment hash | 450893cb... — fake Microsoft login page |
| Sender | Compromised asiainsurance.com.pk (Pakistan insurance co) |
| Verdict | **Phishing — Credential Harvesting via HTML Attachment** |

**➡️ [View Case 3 Report](reports/phishing_investigation_report_CASE3_FINAL.md)**

### Key Findings Snapshot

| Indicator | Finding |
|-----------|---------|
| Display/href mismatch | paypal.com → 217.219.163.3:280/login.html |
| Message-ID domain | 8nm.f9alj (not paypal.com) |
| SpamAssassin score | 22.4 / 5.0 threshold — 17 rules triggered |
| Relay IP | 12.219.13.159 — Spamhaus XBL + SORBS DUL + DSBL listed |
| Verdict | **Phishing — Credential Harvesting** (10 evidence chain) |

## Safety Model

- 🔒 All phishing samples processed inside **isolated VirtualBox VM** (Kali Linux)
- ⛓️ All URLs defanged in public documentation (hxxp://, [.])
- 📁 **No .eml sample files** included in this repository
- 📋 All recipient addresses from public research corpora (Nazario Corpus, CC-BY-4.0)
- 🛡️ Analysis is **defensive/lab-only** — no attack tools, no live malware

## Repository Structure

```
phishing/
├── reports/          # Investigation reports (Markdown)
├── iocs/             # IOC tables (CSV)
├── screenshots/      # Evidence screenshots
├── tools/            # Python email triage helper
├── docs/             # Dataset attribution, methodology
├── samples/          # Acquisition guide only (no .eml files)
├── references/       # Tool links, research sources
├── README.md
├── LICENSE           # MIT + CC-BY-4.0 attribution
└── SECURITY.md       # Safety notice
```

## Reproduce in Your Lab

1. Set up isolated VM (VirtualBox + Kali/REMnux) — see [VM_SETUP_GUIDE.md](VM_SETUP_GUIDE.md)
2. Acquire Nazario Phishing Corpus sample — see [samples/SAMPLE_ACQUISITION_GUIDE.md](samples/SAMPLE_ACQUISITION_GUIDE.md)
3. Run triage helper: `python tools/email_triage_helper.py sample.eml`
4. Follow manual analysis workbook: [MANUAL_WORKBOOK.md](MANUAL_WORKBOOK.md)
5. Fill investigation report template and IOC CSV

## License

- **Code & Documentation:** MIT License
- **Phishing Sample Data (Nazario Corpus):** CC-BY-4.0 — José Nazario
- See [LICENSE](LICENSE) and [docs/DATASET_ATTRIBUTION.md](docs/DATASET_ATTRIBUTION.md)
