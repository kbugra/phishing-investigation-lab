# Security Notice

## Purpose

This repository is a **defensive security education and portfolio project**.
It contains:
- Investigation reports analyzing phishing emails
- IOC (Indicator of Compromise) tables
- Screenshots of reputation service results
- A Python email triage helper tool (analysis aid, not an attack tool)
- Documentation and analyst checklists

## What This Repository Does NOT Contain

- No live phishing links (all URLs are defanged: hxxp://, [.])
- No .eml sample files (samples are only processed inside an isolated VM)
- No malware, exploits, or attack tools
- No real victim PII — all recipient addresses are from public research corpora
- (Sender email addresses from the Nazario corpus have been redacted in public documentation.)

## Safe Usage

- **Never** open .eml files from unknown sources on your host machine
- **Always** analyze phishing samples inside an isolated virtual machine
- **Never** click links in phishing emails — use defanged versions for documentation
- This project is for **educational and portfolio demonstration purposes only**

## Reporting

If you believe any content in this repository poses a security risk, please
open an issue or contact the repository owner.
