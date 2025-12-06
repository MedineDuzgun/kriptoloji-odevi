
from Crypto.Cipher import AES
import base64

SHIFT = 3  # Caesar için örnek

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    # AES şifreleme (örnek)
    cipher = AES.new(key, AES.MODE_ECB)
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len])*pad_len
    return cipher.encrypt(data)

def aes_decrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

def caesar_encrypt(text: str) -> str:
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + SHIFT) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text: str) -> str:
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - SHIFT) % 26 + base)
        else:
            result += char
    return result

# Şifreleme yöntemlerini sözlükle tut
methods = {
    "AES": (aes_encrypt, aes_decrypt),
    "Caesar": (caesar_encrypt, caesar_decrypt)
}
