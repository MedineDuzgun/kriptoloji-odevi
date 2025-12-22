from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes


class ECCCipher:
    private_key = None
    public_key = None

    @staticmethod
    def generate_keys():
        ECCCipher.private_key = ECC.generate(curve='P-256')
        ECCCipher.public_key = ECCCipher.private_key.public_key()

    @staticmethod
    def export_public_key():
        return ECCCipher.public_key.export_key(format='PEM')

    @staticmethod
    def load_public_key(pem):
        return ECC.import_key(pem)

    @staticmethod
    def derive_shared_key(peer_public_key):
        shared_point = peer_public_key.pointQ * ECCCipher.private_key.d
        shared_secret = int(shared_point.x).to_bytes(32, 'big')

        return HKDF(
            master=shared_secret,
            key_len=32,
            salt=b'handshake',
            hashmod=SHA256
        )
