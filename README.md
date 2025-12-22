Bu proje, TCP tabanlı istemci–sunucu mimarisi üzerinde çalışan, klasik, simetrik, asimetrik ve ECC tabanlı şifreleme algoritmalarını içeren bir mesaj güvenliği uygulamasıdır.

Kullanılan Şifreleme Yöntemleri

Klasik:
Caesar, Vigenere, Substitution, Playfair, RailFence, Columnar, Polybius, Hill, Vernam, Affine, Pigpen

Simetrik:
AES, DES, Manual AES, Manual DES

Asimetrik:
RSA (mesaj şifreleme), RSA (simetrik anahtar şifreleme)

ECC:
ECDH ile anahtar değişimi, AES ile mesaj şifreleme

Çalışma Mantığı

AES/DES kullanıldığında simetrik anahtar KDF ile üretilir

Simetrik anahtar RSA public key ile şifrelenerek sunucuya gönderilir

Sunucu RSA private key ile anahtarı çözer ve mesajı deşifre eder

ECC yönteminde client ve server public key değişimi yapar

Ortak anahtar üretilir ve mesaj AES ile şifrelenir

Proje Yapısı
client.py
server.py
ciphers/
README.md

Gereksinimler

Python 3.9+

pycryptodome

tkinter

pip install pycryptodome

Geliştirici

Medine Düzgün
Yazılım Mühendisliği – Kriptoloji Projesi