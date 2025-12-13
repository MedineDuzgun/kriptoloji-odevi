# ciphers/des_manual.py

def pad8(data):
    pad_len = 8 - len(data) % 8
    return data + bytes([pad_len]) * pad_len

def unpad8(data):
    pad_len = data[-1]
    return data[:-pad_len]

def feistel_round(left, right, subkey):
    new_right = bytes([r ^ k for r, k in zip(right, subkey)])
    new_left = right
    return new_left, new_right

class DESManual:
    @staticmethod
    def _make_key(key):
        key = key.ljust(8, "0")[:8].encode()
        return key

    @staticmethod
    def encrypt(text, key):
        key = DESManual._make_key(key)
        data = pad8(text.encode())

        encrypted = b""
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            left, right = block[:4], block[4:]

            # 4 tur Feistel
            for _ in range(4):
                left, right = feistel_round(left, right, key[:4])

            encrypted += left + right

        return encrypted.hex()

    @staticmethod
    def decrypt(text, key):
        key = DESManual._make_key(key)
        data = bytes.fromhex(text)

        decrypted = b""
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            left, right = block[:4], block[4:]

            # Aynı işlemler (sade Feistel)
            for _ in range(4):
                left, right = feistel_round(left, right, key[:4])

            decrypted += left + right

        try:
            return unpad8(decrypted).decode()
        except:
            return "[MANUAL DES DECRYPT ERROR]"
