
def pad8(data: bytes) -> bytes:
    pad_len = 8 - len(data) % 8
    return data + bytes([pad_len] * pad_len)

def unpad8(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

class DESManual:
    @staticmethod
    def _expand_key(key: str) -> bytes:
        return key.ljust(8, "0")[:8].encode()

    @staticmethod
    def _process_block(block: bytes, key: bytes) -> bytes:
        state = block
        for _ in range(3):
            state = bytes([b ^ k for b, k in zip(state, key)])
        return state

    @staticmethod
    def encrypt(text: str, key: str) -> str:
        key_bytes = DESManual._expand_key(key)
        data = pad8(text.encode())
        encrypted = b""
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            encrypted += DESManual._process_block(block, key_bytes)
        return encrypted.hex()

    @staticmethod
    def decrypt(hex_text: str, key: str) -> str:
        key_bytes = DESManual._expand_key(key)
        data = bytes.fromhex(hex_text)
        decrypted = b""
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            decrypted += DESManual._process_block(block, key_bytes)
        return unpad8(decrypted).decode()
