# Kaynak Notları — Phishing Investigation

Analiz sırasında kullanacağın araçlar, referanslar ve faydalı linkler.

---

## Örnek Phishing Email Kaynakları

| Kaynak | URL | Not |
|--------|-----|-----|
| Nazario Phishing Corpus | https://monkey.org/~jose/phishing/ | Orijinal kaynak, CC-BY-4.0 lisanslı |
| Nazario Corpus (Academic Torrents) | https://academictorrents.com/details/a77cda9a9d89a60dbdfbe581adf6e2df9197995a | 4555 .eml, torrent ile |
| Hugging Face SOC Dataset | https://huggingface.co/datasets/ | "phishing-email-soc-agent" ara |

---

## Header Analiz Araçları

| Araç | URL | Ne için? |
|------|-----|----------|
| Google Admin Toolbox Message Header Analyzer | https://toolbox.googleapps.com/apps/messageheader/ | Header'ı yapıştır, otomatik analiz et |
| MXToolbox Header Analyzer | https://mxtoolbox.com/EmailHeaders.aspx | Header analizi + blacklist kontrolü |
| MXToolbox Email Health | https://mxtoolbox.com/diagnostic.aspx | SPF/DKIM/DMARC kayıt kontrolü |

---

## Reputation / Threat Intelligence

| Servis | URL | Ne için? |
|--------|-----|----------|
| VirusTotal | https://www.virustotal.com/ | Domain, URL, IP, hash sorgulama |
| URLScan.io | https://urlscan.io/ | URL tarama, screenshot, redirect chain |
| URLhaus | https://urlhaus.abuse.ch/ | Malware URL veritabanı |
| AbuseIPDB | https://www.abuseipdb.com/ | IP reputation |
| ThreatFox | https://threatfox.abuse.ch/ | IOC veritabanı |
| AlienVault OTX | https://otx.alienvault.com/ | Threat intelligence pulses |
| Cisco Talos | https://talosintelligence.com/ | Reputation lookup |

---

## WHOIS / Domain

| Araç | URL | Ne için? |
|------|-----|----------|
| DomainTools WHOIS | https://whois.domaintools.com/ | Domain kayıt bilgisi, yaş, registrar |
| ICANN WHOIS/RDAP | https://lookup.icann.org/ | Resmi WHOIS/RDAP sorgulama |
| whois (komut satırı) | `whois domain.com` | Terminalden hızlı sorgu |

---

## Sandbox

| Sandbox | URL | Ne için? |
|---------|-----|----------|
| Any.Run | https://any.run/ | Interaktif malware sandbox |
| Hybrid Analysis | https://www.hybrid-analysis.com/ | Falcon sandbox, ücretsiz |
| Joe Sandbox | https://www.joesandbox.com/ | Community edition var |
| Triage | https://tria.ge/ | Hızlı sandbox analizi |

---

## URL/Redirect Analizi

| Araç | URL | Ne için? |
|------|-----|----------|
| URLScan.io | https://urlscan.io/ | En kapsamlı URL analizi |
| CheckPhish | https://checkphish.ai/ | Phishing URL tespiti |
| URL2PNG | https://www.url2png.com/ | URL screenshot (phishing kit tespiti) |
| WhereGoes | https://wheregoes.com/ | Redirect chain takibi |

---

## Email Spoofing Kontrolü

| Araç | URL | Ne için? |
|------|-----|----------|
| DMARC Analyzer | https://www.dmarcanalyzer.com/ | DMARC kayıt kontrolü |
| DKIM Validator | https://dkimvalidator.com/ | DKIM imza doğrulama |
| SPF Record Checker | https://mxtoolbox.com/spf.aspx | SPF kayıt kontrolü |
| Email Spoofing Test | https://emailspooftest.com/ | Domain spoof edilebilir mi? |

---

## Mermaid Diyagram

| Kaynak | URL | Ne için? |
|--------|-----|----------|
| Mermaid Live Editor | https://mermaid.live/ | Diyagramları test et |
| Mermaid Docs | https://mermaid.js.org/ | Syntax referansı |

---

## Framework / Referans

| Kaynak | URL | Ne için? |
|--------|-----|----------|
| MITRE ATT&CK — Phishing | https://attack.mitre.org/techniques/T1566/ | Phishing tekniği (T1566) |
| MITRE ATT&CK — Spearphishing | https://attack.mitre.org/techniques/T1566/001/ | Spearphishing alt tekniği |
| SANS Phishing Poster | https://www.sans.org/security-resources/posters/ | Phishing analizi görsel rehberi |
| CISA Phishing Guidance | https://www.cisa.gov/ | Resmi rehberler |
| APWG (Anti-Phishing Working Group) | https://apwg.org/ | Phishing trendleri, raporlar |

---

## Nazario Corpus Lisans

```
CC-BY-4.0 — Creative Commons Attribution 4.0 International

Kullanım şartları:
- Atıf zorunlu: "José Nazario, Phishing Corpus"
- Ticari kullanım serbest
- Değiştirilmiş versiyonlar paylaşılabilir
- Ama: corpus temsilidir, elle sınıflandırılmıştır, hata içerebilir
- Eski inbox'lar anonimleştirilmiştir
- Zararlı executable attachment İÇERMEMESİ beklenir
- Yine de VM/lab ortamında işleyin
```

---

## Defanging Reference

| Orijinal | Defanged | Amaç |
|----------|----------|------|
| `http://` | `hxxp://` | Tıklanabilir olmasın |
| `https://` | `hxxps://` | Tıklanabilir olmasın |
| `example.com` | `example[.]com` | Domain resolve edilmesin |
| `user@domain.com` | `user@domain[.]com` | Email adresi tıklanabilir olmasın |
| `192.168.1.1` | `192[.]168[.]1[.]1` | IP tıklanabilir olmasın |
| `ftp://` | `fxp://` | FTP linki |
