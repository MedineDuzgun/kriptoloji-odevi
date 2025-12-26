Mesaj Güvenliği Uygulaması

Bu proje, TCP tabanlı istemci–sunucu mimarisi üzerinde çalışan, klasik, simetrik, asimetrik ve ECC tabanlı şifreleme algoritmalarını içeren bir mesaj güvenliği uygulamasıdır.

Kullanılan Şifreleme Yöntemleri
Klasik Şifreleme

Caesar, Vigenere, Substitution, Playfair, RailFence, Columnar, Polybius, Hill, Vernam, Affine, Pigpen

Simetrik Şifreleme

AES, DES, 3DES

Manual AES, Manual DES (anahtar girişi kullanıcı tarafından yapılmaz. Sistem rastgele bir simetrik anahtar üretir ve mesaj bu anahtar ile şifrelenir. Anahtar değişimi kullanılmaz)

Asimetrik Şifreleme

RSA-MSG (RSA ile mesaj şifreleme)

RSA (simetrik anahtar şifreleme)

ECC Şifreleme

ECDH ile anahtar değişimi

AES / DES / 3DES ile mesaj şifreleme

Çalışma Mantığı
Klasik Şifreleme

Kullanıcı tarafından girilen anahtar ile mesaj şifrelenir.

Anahtar değişimi yoktur.

Manual AES / DES

Sistem rastgele bir simetrik anahtar üretir ve mesaj bu anahtar ile şifrelenir.

Anahtar değişimi kullanılmaz.

Simetrik Şifreleme (AES / DES / 3DES) + Anahtar Dağıtımı (RSA / ECC)

Simetrik anahtar KDF ile üretilir (kullanıcı şifresinden türetilir veya rastgele oluşturulur).

Anahtar dağıtımı:

RSA KEX: Simetrik anahtar RSA public key ile şifrelenir.

ECC KEX: Client ve server public key değişimi yapılır, ortak anahtar üretilir, simetrik anahtar bu ortak anahtar ile AES şifrelemesi kullanılarak şifrelenir.

Sunucu, private key veya ECC ortak anahtar ile simetrik anahtarı çözer.

Mesaj, AES / DES / 3DES ile şifrelenir.

Kullanıcı, şifrelenmiş simetrik anahtarı log ekranında görebilir.

RSA-MSG

Mesaj doğrudan RSA public key ile şifrelenir.

Anahtar dağıtımı veya KEX kullanılmaz.

Mesaj sunucu tarafında RSA private key ile çözümlenir.

Proje Yapısı
/proje_kok/
├─ client.py
├─ server.py
├─ ciphers/
│  ├─ __init__.py
│  ├─ rsa_cipher.py
│  ├─ ecc_cipher.py
│  ├─ aes_cipher.py
│  ├─ des_cipher.py
│  └─ ...
├─ README.md

Gereksinimler

Python 3.9+

pycryptodome

tkinter

pip install pycryptodome

Geliştirici

Medine Düzgün
Yazılım Mühendisliği – Kriptoloji Projesi