from .caesar import CaesarCipher
from .vigenere import VigenereCipher
from .substitution import SubstitutionCipher
from .playfair import PlayfairCipher
from .railfence import RailFenceCipher
from .columnar import ColumnarCipher
from .polybius import PolybiusCipher
from .hill import HillCipher
from .vernam import VernamCipher
from .affine import AffineCipher
from .pigpen import PigpenCipher
from .des_cipher import DESCipher
from .aes_cipher import AESCipher

METHODS = {
    "Caesar": CaesarCipher,
    "Vigenere": VigenereCipher,
    "Substitution": SubstitutionCipher,
    "Playfair": PlayfairCipher,
    "RailFence": RailFenceCipher,
    "Columnar": ColumnarCipher,
    "Polybius": PolybiusCipher,
    "Hill": HillCipher,
    "Vernam": VernamCipher,
    "Affine": AffineCipher,
    "Pigpen": PigpenCipher,
    "DES": DESCipher,
    "AES": AESCipher
}
