# Kriptoloji Ödevi – Server/Client GUI (Python)

Bu proje, **Python ve Tkinter** kullanılarak yazılmış bir **TCP Server–Client uygulamasıdır**.  
Metin ve dosya gönderimi yapılabilir; resimler GUI üzerinde gösterilir. Ayrıca AES ve XOR algoritmaları ile **şifreleme/deşifreleme** desteği vardır.

---

## Özellikler

- **TCP Sunucu / Client**
  - Server: 127.0.0.1:5000 adresinde dinler
  - Client: Server’a bağlanabilir
- **Metin Gönderme ve Alma**
  - Server GUI’de log ekranında görüntülenir
  - Client GUI’de şifrelenmiş veya düz metin gönderilebilir
- **Dosya Alma ve Gösterme**
  - Resimler GUI üzerinde gösterilir
  - Diğer dosyalar geçici klasöre kaydedilir ve açılır
- **Şifreleme/Deşifreleme**
  - AES-CBC (Base64 encode ile)
  - XOR (basit öğretici)
- **Canlı Log Ekranı**
  - Server ve client logları ayrı textbox’larda canlı gösterilir
- **Threading**
  - Sunucu arka planda çalışır, GUI kilitlenmez

---

## Gereksinimler

- Python 3.9+
- Gerekli paketler:

```bash
pip install pillow pycryptodome
```
