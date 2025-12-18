from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256


def derive_key(password: str, salt: bytes, key_len: int):
    return PBKDF2(
        password,
        salt,
        dkLen=key_len,
        count=100_000,
        hmac_hash_module=SHA256
    )
