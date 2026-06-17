# VM Kurulum Rehberi

Phishing sample'ları güvenle işlemek için VirtualBox + REMnux kurulumu.

## Neden VM?

- Phishing .eml dosyaları AV tarafından yakalanır
- Yanlışlıkla link tıklama riskine karşı izolasyon
- Snapshot ile temiz duruma dönme kolaylığı
- Gerçek SOC lab ortamını simüle eder

## Adım 1: VirtualBox Kur

1. https://www.virtualbox.org/wiki/Downloads adresinden indir
2. Windows için VirtualBox installer'ı çalıştır
3. Default ayarlarla kur

## Adım 2: REMnux İndir

**REMnux:** Malware analizi için hazır Linux dağıtımı. Email analiz araçları hazır gelir.

1. https://remnux.org/ adresine git
2. OVA dosyasını indir (yaklaşık 4-5 GB)
3. VirtualBox'ta: File → Import Appliance → REMnux OVA'yı seç

**Alternatif: Ubuntu**
Eğer REMnux fazla gelirse düz Ubuntu da yeterli:
- https://ubuntu.com/download/desktop
- 4 GB RAM, 2 CPU, 25 GB disk yeterli

## Adım 3: VM Ayarları

VM kapalıyken Settings:

| Ayar | Değer | Neden? |
|------|-------|--------|
| Shared Clipboard | **Disabled** | Host-VM arası veri sızıntısını önle |
| Drag and Drop | **Disabled** | Yanlışlıkla dosya sürüklemeyi engelle |
| Network | **NAT** | İnternete çıkabilir ama hosttan izole |
| Shared Folders | **Başlangıçta kapalı** | Sonradan read-only eklenebilir |

## Adım 4: Snapshot Al

VM temiz kurulumdan sonra:

1. VirtualBox ana ekran → VM seçiliyken → Snapshots
2. Take → "Temiz Kurulum" diye adlandır
3. Her analiz öncesi bu snapshot'a dönebilirsin

## Adım 5: VM İçine Gerekli Araçları Kur

```bash
# REMnux'ta çoğu araç hazır gelir. Ubuntu'da:
sudo apt update && sudo apt upgrade -y

# Email analiz araçları
sudo apt install -y thunderbird mpack python3-pip

# Python email parser için
pip3 install mailbox

# Tarayıcı (genelde hazır gelir)
# Firefox veya Chromium
```

## Adım 6: Analiz İçin Dosya Aktarımı

**Yöntem 1 — Read-only Shared Folder (güvenli):**
1. VM ayarları → Shared Folders → Add
2. Folder: Host'taki `G:\yeni indir\Projeler\phishing` klasörü
3. Read-only işaretle, Auto-mount aç
4. VM içinde `/media/sf_phishing/` yolunda görünür

**Yöntem 2 — USB aktarım (daha güvenli):**
1. Screenshot'ları USB'ye kopyala
2. VM'den USB'ye bağlan, hosta taşı

**Yöntem 3 — Sadece rapor çıktılarını hosta kopyala:**
- VM içinde analizi yap
- Rapor .md, IOC .csv, screenshot'ları oluştur
- Bunları güvenli şekilde hosta aktar
- .eml dosyasını asla hosta taşıma

## Hızlı Başlangıç

```bash
# VM içinde:
wget https://monkey.org/~jose/phishing/20051114.mbox

python3 << 'EOF'
import mailbox
mbox = mailbox.mbox('20051114.mbox')
for i, msg in enumerate(mbox):
    subject = msg['subject'] or '(no subject)'
    print(f"[{i}] {subject}")
EOF
```

PayPal temalı email'i bul, .eml olarak kaydet, analize başla.
