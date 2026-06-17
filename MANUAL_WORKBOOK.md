# Manual Workbook — Phishing Analizi Yorumlama Rehberi

Bu dosya sana "ne gördüm?" sorusundan "bu ne anlama geliyor?" sorusuna geçişi öğretir.

---

## 1. Email Header Analizi

### 1.1 From vs Return-Path vs Reply-To

| Alan | Ne işe yarar? | Phishing göstergesi |
|------|---------------|---------------------|
| **From** | Kullanıcının gördüğü gönderen adresi | Sahte olabilir, spoof edilmesi en kolay alan |
| **Return-Path** | Bounce/NDR mesajlarının gideceği adres | From'dan farklıysa şüpheli |
| **Reply-To** | Cevapla butonuna basınca gidecek adres | From'dan tamamen farklı bir domain'e yönlendiriyorsa phishing |

**Yorum:** From `paypal@service.com` ama Return-Path `bounce@xyz123.ru` ise → tutarsızlık var, phishing olabilir. Reply-To saldırganın kontrolündeki bir adrese yönlendiriyorsa → kesin phishing.

### 1.2 Received Zinciri

Received header'ları **aşağıdan yukarıya** okunur. En alttaki ilk hop, en üstteki son duraktır.

```
Received: from mail.target.com (target.com [10.0.0.1])
    by mx.target.com ...                          ← son durak (hedef mail sunucusu)
Received: from relay.attacker.com (attacker.com [185.x.x.x])
    by mail.target.com ...                        ← ara hop
Received: from spam-bot.net (spam-bot.net [45.x.x.x])
    by relay.attacker.com ...                     ← ilk hop (orijin)
```

**Yorum:**
- İlk hop bilinmeyen/şüpheli IP/domain ise → phishing göstergesi
- Geçtiği sunucular arasında tutarsız domainler varsa → şüpheli
- Received zincirinde `(authenticated sender: ...)` veya `ESMTP` bilgileri varsa faydalı
- IP ile domain reverse DNS uyuşmuyorsa → spoofed olabilir

### 1.3 SPF (Sender Policy Framework)

```
spf=pass   → Gönderen IP, domain'in SPF kaydındaki IP'lerden biri → meşru olabilir
spf=fail   → Gönderen IP, domain'in SPF kaydında YOK → spoofing
spf=softfail → Kesin değil ama şüpheli (~all ile biten SPF)
spf=neutral → SPF kaydı yok veya ?all ile bitiyor
spf=none   → Domain'in SPF kaydı hiç yok
```

**Yorum:** `spf=fail` tek başına phishing kanıtı DEĞİLDİR (meşru forwarding de fail üretir). Ama `spf=fail` + `dkim=none` + `dmarc=fail` birleşimi güçlü göstergedir.

### 1.4 DKIM (DomainKeys Identified Mail)

```
dkim=pass  → İmza geçerli, domain doğrulanmış
dkim=fail  → İmza geçersiz, body veya header değiştirilmiş olabilir
dkim=none  → DKIM imzası yok
```

**Yorum:** DKIM fail, mail'in transit sırasında değiştirildiğini veya sahte olduğunu gösterebilir.

### 1.5 DMARC (Domain-based Message Authentication)

```
dmarc=pass → SPF ve/veya DKIM geçti, From domain ile uyumlu
dmarc=fail → Hem SPF hem DKIM başarısız → yüksek ihtimal phishing
dmarc=none → DMARC politikası yok
```

**Yorum:** `dmarc=fail` en güçlü phishing göstergelerinden biridir. Ama `dmarc=pass` olması meşru olduğu anlamına GELMEZ (saldırgan kendi domain'inden gönderip SPF/DKIM'i geçebilir — bu durumda domain benzerliğine bakılır: paypa1.com vs paypal.com).

### 1.6 Message-ID

```
Message-ID: <abc123@legit-server.com>   → tutarlı
Message-ID: <abc123@phish-kit.cn>       → From tamamen farklı domain → phishing
```

**Yorum:** Message-ID'nin domain kısmı, mail'i üreten altyapıyı gösterir. From'daki domainle alakasız bir domain varsa → phishing.

---

## 2. İçerik ve Sosyal Mühendislik Analizi

### 2.1 Taktik Sınıflandırması

| Taktik | Gösterge | Örnek |
|--------|----------|-------|
| **Urgency** | Zaman baskısı | "24 saat içinde hesabınız kapatılacak" |
| **Fear** | Tehdit | "Şüpheli giriş tespit edildi" |
| **Authority** | Otorite taklidi | "PayPal Güvenlik Departmanı" |
| **Scarcity** | Kısıtlı fırsat | "Sınırlı süreli güvenlik güncellemesi" |
| **Familiarity** | Tanıdık marka | Logo, renk şeması, footer taklidi |
| **Impersonality** | Kişisel olmayan hitap | "Dear Customer" (adını bilmiyor) |

### 2.2 Link Analizi

| Durum | Yorum |
|-------|-------|
| Görünen URL ≠ href | Kesin phishing (HTML'de `<a href="...">` farklıysa) |
| Domain benzerliği | paypa1.com, paypal-secure.com, paypal.com.tk → typosquatting |
| URL shortener | Gerçek hedefi gizlemek için kullanılır → şüpheli |
| HTTP (HTTPS değil) | Meşru finans kurumları HTTPS kullanır |
| IP tabanlı URL | `http://192.168.1.1/login` → gizlenmeye çalışılan altyapı |
| @ işareti içeren URL | `http://paypal.com@phish.cn` → tarayıcı phish.cn'e gider |

### 2.3 Ek Dosya Tehlikeleri

| Dosya Tipi | Risk |
|------------|------|
| `.exe`, `.scr`, `.bat`, `.ps1` | Doğrudan zararlı executable |
| `.docm`, `.xlsm`, `.pptm` | Makro içerebilir |
| `.doc`, `.xls` (eski format) | Makro/OLE objesi içerebilir |
| `.zip`, `.rar`, `.7z` | İçinde zararlı olabilir, şifreliyse kesin şüpheli |
| `.iso`, `.img` | Disk imajı, içerik gizlenebilir |
| `.html`, `.htm` | Tarayıcıda açılınca phishing sayfası olabilir |
| `.pdf` | JavaScript veya gömülü link içerebilir |

---

## 3. IOC Yorumlama ve Confidence

### 3.1 Confidence Seviyeleri

| Seviye | Anlamı | Örnek |
|--------|--------|-------|
| **High** | Bu IOC tek başına phishing'i kanıtlar nitelikte | `paypa1-alert[.]com` adresindeki credential harvest sayfası |
| **Medium** | Şüpheli, diğer IOC'lerle birlikte değerlendirilmeli | Spoofed gönderen IP'si |
| **Low** | Zayıf gösterge, false positive olabilir | Subject satırındaki "urgent" kelimesi |

### 3.2 IOC Tipi Rehberi

| IOC Type | Ne zaman High confidence? |
|----------|--------------------------|
| **Domain** | Brand impersonation (paypa1.com), yeni kaydedilmiş, VT'de flagged |
| **URL** | Credential harvest formu, phishing kit izleri (wp-admin, /login, /verify) |
| **IP** | AbuseIPDB'de yüksek skor, VT'de multiple detections, bilinen C2 |
| **Hash** | VT'de 10+ detection, bilinen malware ailesi |
| **Email** | Spoofed, Reply-To farklı domain, disposable email |
| **Subject** | Tek başına düşük, pattern matching için faydalı |
| **Message-ID** | From domain'le alakasız domain |

---

## 4. Reputation Servis Sonuçlarını Yorumlama

### 4.1 VirusTotal

| Sonuç | Yorum |
|-------|-------|
| 0 detections | Temiz olabilir VEYA yeni/tespit edilmemiş (0-day phishing kit) |
| 1-5 detections | Şüpheli, false positive olabilir |
| 5-15 detections | Büyük ihtimal zararlı |
| 15+ detections | Neredeyse kesin zararlı |
| "Phishing", "Malware" etiketleri | Güvenilir vendor'lardan geliyorsa yüksek güven |

**Önemli:** VT 0 detection = güvenli DEĞİLDİR. Phishing kit'leri sık değişir.

### 4.2 URLScan.io

| Gösterge | Yorum |
|----------|-------|
| Redirect chain (2+ hop) | Gizlenmeye çalışılan altyapı |
| Sayfa başlığı "PayPal Login" ama domain farklı | Brand impersonation |
| Sayfa içinde `type="password"` input varsa | Credential harvesting |
| HTTPS sertifika uyarısı | Self-signed veya domain uyuşmazlığı |
| Benzer domain/ip'lerde aynı hash | Aynı phishing kit başka domain'lerde |

### 4.3 WHOIS / Domain Yaşı

| Domain Yaşı | Yorum |
|-------------|-------|
| < 1 hafta | Yüksek ihtimal phishing (hızlı register, hızlı kullanım) |
| < 1 ay | Şüpheli |
| < 1 yıl | Bağlama bağlı |
| 1+ yıl | Daha az şüpheli ama compromised site olabilir |
| Privacy Protection | Normal (birçok meşru site de kullanır) |

### 4.4 AbuseIPDB

| Skor | Yorum |
|------|-------|
| 0-20% | Düşük risk |
| 20-60% | Orta risk, kontrol et |
| 60-100% | Yüksek risk, muhtemelen zararlı |

---

## 5. Verdict Yazma

### 5.1 Verdict Türleri

| Verdict | Ne zaman? |
|---------|-----------|
| **Phishing** | Brand impersonation + credential harvest + SPF/DKIM fail + VT detection |
| **Credential Harvesting** | Login formu var, amacı credential çalmak |
| **Malicious Attachment** | Ek dosya zararlı, VT detection var, sandbox'ta zararlı davranış |
| **Spear Phishing** | Hedefli saldırı, kişiselleştirilmiş içerik |
| **Suspicious but Unconfirmed** | Şüpheli ama kesin kanıt yok, daha fazla analiz gerek |
| **False Positive** | Meşru mail, yanlış alarm |
| **Spam** | Zararlı değil ama istenmeyen |

### 5.2 Verdict Yazma Şablonu

```
Verdict: [Tür]

Bu email [X] nedenden dolayı phishing olarak değerlendirilmiştir:

1. [En güçlü kanıt]
2. [İkinci kanıt]
3. [Üçüncü kanıt]
...

Risk Seviyesi: [Critical / High / Medium / Low]
Etkilenen Kullanıcı: [Varsa]
```

### 5.3 Kanıt Zinciri

İyi bir verdict "evet bu phishing" demez. Şöyle der:

> Bu email phishing'tir çünkü:
> 1. From adresi `paypal@service.com` gerçek PayPal domain'i değil
> 2. SPF fail + DMARC fail — gönderen domain doğrulanamadı
> 3. Mail gövdesinde `paypal.com` yazıyor ama href `paypa1-alert[.]com/login` adresine gidiyor
> 4. URLScan.io screenshot, hedef sayfanın PayPal login klonu olduğunu gösteriyor
> 5. Domain `paypa1-alert[.]com` 2 gün önce kaydedilmiş (WHOIS)
> 6. VirusTotal'da 8/90 vendor phishing olarak işaretlemiş

---

## 6. Containment Önerileri

### 6.1 Blocklist

```
Domain: paypa1-alert[.]com
URL: hxxps://paypa1-alert[.]com/login
IP: 185.199.110[.]153
Sender: phishing@paypa1-alert[.]com
Subject: "Important: Your Account Has Been Limited"
```

### 6.2 Mail Gateway Kuralı

```
# Proofpoint / Mimecast / Exchange benzeri:
if (sender.domain == "paypa1-alert.com") → Block
if (subject contains "Your Account Has Been Limited") → Quarantine
if (body contains "paypa1-alert.com") → Block
```

### 6.3 Kullanıcı Aksiyonları

- [ ] Linke tıklayan kullanıcının parolasını resetle
- [ ] MFA/Authenticator'ı kontrol et, gerekirse yeniden kaydet
- [ ] Kullanıcıya phishing awareness eğitimi ver
- [ ] Kullanıcının son 30 günlük login aktivitesini kontrol et

### 6.4 SIEM / SOC Query

```
# Splunk:
index=email sourcetype=smtp subject="*Your Account Has Been Limited*"
index=email sourcetype=smtp sender="*@paypa1-alert.com"

# Sentinel / KQL:
EmailEvents
| where Subject contains "Your Account Has Been Limited"
| where SenderFromDomain == "paypa1-alert.com"

# Elastic / Lucene:
subject:"Your Account Has Been Limited" OR sender:"paypa1-alert.com"
```
