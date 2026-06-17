# Dataset Attribution

## Nazario Phishing Corpus

All phishing email samples analyzed in this project originate from the
**Nazario Phishing Corpus**, curated by José Nazario.

- **Source URL:** https://monkey.org/~jose/phishing/
- **License:** Creative Commons Attribution 4.0 International (CC-BY-4.0)
- **Citation:** José Nazario, "Phishing Corpus", https://monkey.org/~jose/phishing/

### Usage Notes (from corpus README)

- The corpus is representative, not exhaustive (based on Nazario's personal inbox)
- Hand-classified — may contain classification errors
- Earlier mailboxes were anonymized (destination IPs and domain names)
- The corpus should not contain malicious executable attachments
- **Always process samples in an isolated VM environment**

### Files Used

| File | Size | Case Study |
|------|------|------------|
| `20051114.mbox` | 3.9 MB | Case 1 — Historical PayPal Phishing (2005) |
| `phishing-2023.mbox` | 7.4 MB | Case 2 — Microsoft Unusual Sign-In (2023) |
| `phishing-2023.mbox` | 7.4 MB | Case 3 — OneDrive Attachment Smuggling (2023) |

No original .mbox or .eml files are included in this repository.

### Additional Tools & References

- VirusTotal — https://www.virustotal.com/
- URLScan.io — https://urlscan.io/
- AbuseIPDB — https://www.abuseipdb.com/
- Google Admin Toolbox Messageheader — https://toolbox.googleapps.com/apps/messageheader/
- MXToolbox — https://mxtoolbox.com/
