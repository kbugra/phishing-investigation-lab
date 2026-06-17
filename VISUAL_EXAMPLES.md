# Görsel Örnekler — Raporuna Ekleyebileceğin Mermaid Diyagramları

Bu dosyadaki diyagramları `reports/phishing_investigation_report_CASE1_FINAL.md` raporuna kopyalayıp kendi bulgularınla doldur.

---

## 1. Mail Akış Diyagramı (Email Route)

```mermaid
flowchart LR
    A["Spoofed Sender<br/>phishing@evil[.]com"] --> B["Compromised Relay<br/>185.199.x.x"]
    B --> C["Target Mail Server<br/>mx.target.com"]
    C --> D["Victim Inbox"]
    D --> E["User Clicks Link"]
    E --> F["Credential Harvest Page<br/>paypa1-alert[.]com/login"]
    F --> G["Attacker Collects Credentials"]
    H["WHOIS: Domain 2 days old"]
    I["VT: 8/90 detections"]
    H -.-> F
    I -.-> F
```

---

## 2. Link Mismatch — Görünen vs Gerçek

```mermaid
flowchart TD
    subgraph Email_Body["Email Body"]
        A["Görünen Link:<br/>🔗 https://www.paypal.com/verify"]
    end
    
    subgraph HTML_Source["HTML Source"]
        B["Gerçek href:<br/>hxxps://paypa1-alert[.]com/login"]
    end
    
    subgraph URLScan["URLScan.io Analysis"]
        C["Redirect 1: bit[.]ly/xxxxx"]
        D["Redirect 2: paypa1-alert[.]com/login"]
        E["Final: Login form<br/>Username + Password fields"]
    end
    
    A -->|"Hover reveals"| B
    B --> C --> D --> E
    
    style A fill:#90EE90,stroke:#333
    style B fill:#FFB6C1,stroke:#333
    style E fill:#FF6B6B,stroke:#333
```

---

## 3. Verdict Karar Ağacı

```mermaid
flowchart TD
    START["📧 Email Received"] --> Q1{"Brand Impersonation?"}
    Q1 -->|"Yes"| Q2{"Credential Harvest URL?"}
    Q1 -->|"No"| Q5{"Malicious Attachment?"}
    
    Q2 -->|"Yes"| Q3{"SPF/DKIM/DMARC<br/>Fail?"}
    Q2 -->|"No"| Q4{"Other Red Flags?"}
    
    Q3 -->|"Yes"| V1["✅ VERDICT:<br/>PHISHING<br/>Credential Harvesting"]
    Q3 -->|"No"| Q6{"Domain Suspicious?<br/>(typosquat, new, VT flagged)"}
    
    Q6 -->|"Yes"| V1
    Q6 -->|"No"| V3["⚠️ VERDICT:<br/>SUSPICIOUS<br/>More Analysis Needed"]
    
    Q4 -->|"Yes"| V3
    Q4 -->|"No"| V4["❌ VERDICT:<br/>LIKELY FALSE POSITIVE"]
    
    Q5 -->|"Yes"| V2["✅ VERDICT:<br/>PHISHING<br/>Malicious Attachment"]
    Q5 -->|"No"| Q4

    V1:::phishing
    V2:::phishing
    V3:::suspicious
    V4:::clean

    classDef phishing fill:#FF6B6B,stroke:#333,color:#fff
    classDef suspicious fill:#FFD93D,stroke:#333
    classDef clean fill:#6BCB77,stroke:#333,color:#fff
```

---

## 4. Timeline (Zaman Çizelgesi)

```mermaid
timeline
    title Phishing Incident Timeline
    T+0m : Email sent from spoofed sender
         : Passes through compromised relay
    T+2m : Email delivered to victim inbox
    T+15m : User opens email
    T+16m : User clicks link
    T+16m : Redirect chain (bit.ly → phishing domain)
    T+17m : Credential harvest page loads
    T+18m : User enters credentials
    T+19m : Credentials sent to attacker server
    T+4h : Incident reported to SOC
    T+4h30m : Investigation initiated
    T+5h : IOC extraction complete
    T+5h30m : VT/URLScan/WHOIS enrichment complete
    T+6h : Report finalized, containment applied
```

---

## 5. IOC Relationship Map

```mermaid
flowchart TD
    EMAIL["📧 Phishing Email<br/>Subject: Your Account<br/>Has Been Limited"] --> FROM["From: paypal@service[.]com<br/>🟡 Medium — Spoofed"]
    EMAIL --> LINK["Body Link:<br/>paypa1-alert[.]com/login<br/>🔴 High — Credential Harvest"]
    EMAIL --> HEADER["Header:<br/>SPF fail, DKIM none<br/>🔴 High — Auth Failure"]
    
    LINK --> DOMAIN["Domain:<br/>paypa1-alert[.]com<br/>🔴 High — 2 days old"]
    LINK --> URLSCAN["URLScan:<br/>Login form detected<br/>🔴 High — Phishing Kit"]
    
    DOMAIN --> WHOIS["WHOIS:<br/>Registered 2 days ago<br/>Privacy Protected<br/>🔴 High — Fresh domain"]
    DOMAIN --> VT["VirusTotal:<br/>8/90 detections<br/>🔴 High — Flagged"]
    
    HEADER --> IP["Received IP:<br/>185.199.x.x<br/>🟡 Medium — Needs check"]
    IP --> ABUSEIP["AbuseIPDB:<br/>Score 78%<br/>🔴 High — Reported"]
    
    style EMAIL fill:#4A90D9,stroke:#333,color:#fff
    style LINK fill:#FF6B6B,stroke:#333,color:#fff
    style DOMAIN fill:#FF6B6B,stroke:#333,color:#fff
    style HEADER fill:#FF6B6B,stroke:#333,color:#fff
    style FROM fill:#FFD93D,stroke:#333
    style IP fill:#FFD93D,stroke:#333
```

---

## 6. Saldırı Zinciri (Attack Chain)

```mermaid
flowchart LR
    subgraph Recon["1. Reconnaissance"]
        R1["Target email<br/>harvesting"]
    end
    
    subgraph Weaponize["2. Weaponization"]
        W1["Phishing kit<br/>+ PayPal clone"]
        W2["Domain registration<br/>paypa1-alert.com"]
    end
    
    subgraph Delivery["3. Delivery"]
        D1["Spoofed email<br/>via compromised relay"]
    end
    
    subgraph Exploit["4. Exploitation"]
        E1["Social engineering<br/>urgency + fear"]
    end
    
    subgraph Action["5. Action"]
        A1["Credential theft<br/>via fake login page"]
        A2["Credentials sold<br/>or reused"]
    end
    
    Recon --> Weaponize --> Delivery --> Exploit --> Action
```

---

## Nasıl Kullanılır?

1. Bu diyagramlardan senin vakana uygun olanı seç
2. `[ ]` içindeki placeholder'ları kendi bulgularınla değiştir
3. Raporunun ilgili bölümüne kopyala
4. GitHub/GitLab'da `.md` olarak görüntülendiğinde Mermaid otomatik render edilir

**Mermaid live editor:** https://mermaid.live/ — diyagramları burada test edebilirsin.
