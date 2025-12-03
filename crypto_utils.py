# crypto_utils.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16
KEY = b"1234567890123456"  # 16 byte = 128-bit key

def encrypt(data: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, BLOCK_SIZE))
    return cipher.iv + ct_bytes  # IV başa ekleniyor

def decrypt(data: bytes) -> bytes:
    iv = data[:BLOCK_SIZE]
    ct = data[BLOCK_SIZE:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), BLOCK_SIZE)
