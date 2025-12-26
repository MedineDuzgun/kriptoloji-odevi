from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Cipher import DES, DES3


class ECCCipher:
    def __init__(self):
        self.key_pair = ECC.generate(curve='P-256')
        self.private_key = self.key_pair
        self.public_key = self.key_pair.public_key()

    def export_public_key(self):
        return self.public_key.export_key(format='PEM')

    @staticmethod
    def load_public_key(pem):
        return ECC.import_key(pem)

    def derive_shared_key(self, other_public_key):
        shared_secret = self.private_key.d * other_public_key.pointQ
        shared_bytes = int(shared_secret.x).to_bytes(32, 'big')
        return SHA256.new(shared_bytes).digest()
