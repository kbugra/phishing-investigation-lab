# Örnek Phishing Email Edinme Rehberi

## Ana Kaynak: Nazario Phishing Corpus

**URL:** https://monkey.org/~jose/phishing/

**Lisans:** CC-BY-4.0 (atıf gerekli, ticari kullanım serbest)

**README:** https://monkey.org/~jose/phishing/README.txt

### Önerilen Dosya

```
20051114.mbox  (3.9 MB)
```

Doğrudan indirme linki:
```
https://monkey.org/~jose/phishing/20051114.mbox
```

### Önerilen Email'ler

20051114.mbox içinden:

| Index | Subject | Neden? |
|-------|---------|--------|
| ~203 | PayPal temalı | Marka taklidi, hesap doğrulama baskısı, header tutarsızlığı — yeni başlayan için ideal |
| ~55  | KeyBank temalı | Orta seviye, finansal kimlik avı |

## ⚠️ İndirme Talimatı

**BU DOSYAYI HOST MAKİNEYE İNDİRMEYİN.**

1. VirtualBox/REMnux VM'i başlatın
2. VM içinde terminal açın:
   ```bash
   wget https://monkey.org/~jose/phishing/20051114.mbox
   ```
3. mbox'tan tek .eml ayırmak için Python script:

```python
import mailbox

mbox = mailbox.mbox('20051114.mbox')
for i, msg in enumerate(mbox):
    subject = msg['subject'] or '(no subject)'
    print(f"[{i}] {subject}")

# PayPal temalı olanı bul ve kaydet
# Örnek: i=202 (0-indexed ise 203. email)
target = mbox[202]  # index'i bulduğunuza göre ayarlayın
with open('paypal_phishing_sample.eml', 'w') as f:
    f.write(target.as_string())
```

## Alternatif Kaynaklar

### Academic Torrents
- https://academictorrents.com/details/a77cda9a9d89a60dbdfbe581adf6e2df9197995a
- Torrent ile tüm corpus'u indirir, içinde 4555 .eml dosyası var

### GitHub
- `Nazario Phishing Corpus` veya `20051114.mbox` diye arayın
- ML phishing detection repolarında sıkça referans verilir

### Kendi Spam Klasörün
- Kendi email'inin spam klasöründe phishing örneği bulabilirsin
- Hassas verileri (alıcı adresi, token, link parametreleri) redakte et
- Canlı linklere tıklama

## Defanging Rehberi

Analiz sırasında linkleri güvenli hale getirmek için:

| Orijinal | Defanged |
|----------|----------|
| `http://` | `hxxp://` |
| `https://` | `hxxps://` |
| `example.com` | `example[.]com` |
| `user@domain.com` | `user@domain[.]com` |
| `192.168.1.1` | `192[.]168[.]1[.]1` |

**Not:** Defanging sadece raporda gösterim içindir. Analiz yaparken gerçek IOC'leri CSV'ye yazın.
