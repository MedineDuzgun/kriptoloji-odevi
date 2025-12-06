import string
import numpy as np
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

LETTERS = string.ascii_uppercase


# ============================================
# 1. CAESAR
# ============================================
class CaesarCipher:
    @staticmethod
    def encrypt(text, key):
        key = int(key)
        return ''.join(LETTERS[(LETTERS.index(c) + key) % 26] if c in LETTERS else c for c in text.upper())

    @staticmethod
    def decrypt(text, key):
        key = int(key)
        return ''.join(LETTERS[(LETTERS.index(c) - key) % 26] if c in LETTERS else c for c in text.upper())


# ============================================
# 2. VIGENERE
# ============================================
class VigenereCipher:
    @staticmethod
    def encrypt(text, key):
        text = text.upper()
        key = key.upper()
        res, k = "", 0
        for c in text:
            if c in LETTERS:
                res += LETTERS[(LETTERS.index(c) + LETTERS.index(key[k % len(key)])) % 26]
                k += 1
            else:
                res += c
        return res

    @staticmethod
    def decrypt(text, key):
        text = text.upper()
        key = key.upper()
        res, k = "", 0
        for c in text:
            if c in LETTERS:
                res += LETTERS[(LETTERS.index(c) - LETTERS.index(key[k % len(key)])) % 26]
                k += 1
            else:
                res += c
        return res


# ============================================
# 3. SUBSTITUTION
# ============================================
class SubstitutionCipher:
    @staticmethod
    def encrypt(text, key):
        key = key.upper()
        table = {LETTERS[i]: key[i] for i in range(26)}
        return ''.join(table.get(c, c) for c in text.upper())

    @staticmethod
    def decrypt(text, key):
        key = key.upper()
        table = {key[i]: LETTERS[i] for i in range(26)}
        return ''.join(table.get(c, c) for c in text.upper())


# ============================================
# 4. PLAYFAIR
# ============================================
class PlayfairCipher:
    @staticmethod
    def generate_table(key):
        key = key.upper().replace("J", "I")
        table = ""
        for c in key:
            if c not in table and c in LETTERS:
                table += c
        for c in LETTERS.replace("J", ""):
            if c not in table:
                table += c
        return [list(table[i:i+5]) for i in range(0, 25, 5)]

    @staticmethod
    def find(table, c):
        for r in range(5):
            for s in range(5):
                if table[r][s] == c:
                    return r, s

    @staticmethod
    def encrypt(text, key):
        table = PlayfairCipher.generate_table(key)
        text = text.upper().replace("J", "I").replace(" ", "")
        pairs = []
        i = 0
        while i < len(text):
            a = text[i]
            b = text[i+1] if i+1 < len(text) else "X"
            if a == b:
                b = "X"
                i += 1
            else:
                i += 2
            pairs.append((a, b))

        result = ""
        for a, b in pairs:
            r1, c1 = PlayfairCipher.find(table, a)
            r2, c2 = PlayfairCipher.find(table, b)
            if r1 == r2:  # aynı satır
                result += table[r1][(c1 + 1) % 5] + table[r2][(c2 + 1) % 5]
            elif c1 == c2:  # aynı sütun
                result += table[(r1 + 1) % 5][c1] + table[(r2 + 1) % 5][c2]
            else:  # dikdörtgen
                result += table[r1][c2] + table[r2][c1]
        return result

    @staticmethod
    def decrypt(text, key):
        table = PlayfairCipher.generate_table(key)
        text = text.upper()
        result = ""
        for i in range(0, len(text), 2):
            a, b = text[i], text[i+1]
            r1, c1 = PlayfairCipher.find(table, a)
            r2, c2 = PlayfairCipher.find(table, b)
            if r1 == r2:
                result += table[r1][(c1 - 1) % 5] + table[r2][(c2 - 1) % 5]
            elif c1 == c2:
                result += table[(r1 - 1) % 5][c1] + table[(r2 - 1) % 5][c2]
            else:
                result += table[r1][c2] + table[r2][c1]
        return result


# ============================================
# 5. RAIL FENCE
# ============================================
class RailFenceCipher:
    @staticmethod
    def encrypt(text, key):
        key = int(key)
        rails = [''] * key
        idx, step = 0, 1
        for c in text:
            rails[idx] += c
            if idx == 0: step = 1
            elif idx == key - 1: step = -1
            idx += step
        return ''.join(rails)

    @staticmethod
    def decrypt(text, key):
        key = int(key)
        pattern = [[] for _ in range(key)]
        idx, step = 0, 1
        for i in range(len(text)):
            pattern[idx].append(i)
            if idx == 0: step = 1
            elif idx == key - 1: step = -1
            idx += step

        result = [''] * len(text)
        p = 0
        for rail in pattern:
            for pos in rail:
                result[pos] = text[p]
                p += 1

        return ''.join(result)


# ============================================
# 6. COLUMNAR TRANSPOSITION
# ============================================
class ColumnarCipher:
    @staticmethod
    def encrypt(text, key):
        key = key.upper()
        cols = len(key)
        sorted_key = sorted(key)
        matrix = [''] * cols
        for i, c in enumerate(text):
            matrix[i % cols] += c

        ciphertext = ""
        for k in sorted_key:
            ciphertext += matrix[key.index(k)]
        return ciphertext

    @staticmethod
    def decrypt(text, key):
        key = key.upper()
        cols = len(key)
        sorted_key = sorted(key)
        col_len = len(text) // cols
        extra = len(text) % cols

        lengths = [col_len + (i < extra) for i in range(cols)]
        cols_data = {}
        idx = 0
        for i, k in enumerate(sorted_key):
            size = lengths[i]
            cols_data[k] = text[idx:idx+size]
            idx += size

        matrix = [cols_data[k] for k in key]

        result = ""
        for i in range(max(lengths)):
            for col in matrix:
                if i < len(col):
                    result += col[i]
        return result


# ============================================
# 7. POLYBIUS
# ============================================
class PolybiusCipher:
    table = [
        "ABCDE",
        "FGHIK",
        "LMNOP",
        "QRSTU",
        "VWXYZ"
    ]

    @staticmethod
    def encrypt(text, key=None):
        text = text.upper().replace("J", "I")
        result = ""
        for c in text:
            for i in range(5):
                if c in PolybiusCipher.table[i]:
                    j = PolybiusCipher.table[i].index(c)
                    result += str(i+1) + str(j+1)
        return result

    @staticmethod
    def decrypt(text, key=None):
        result = ""
        for i in range(0, len(text), 2):
            r = int(text[i]) - 1
            c = int(text[i+1]) - 1
            result += PolybiusCipher.table[r][c]
        return result


# ============================================
# 8. HILL
# ============================================
class HillCipher:
    @staticmethod
    def encrypt(text, key):
        text = text.upper().replace(" ", "")
        n = int(len(key) ** 0.5)
        matrix = np.array([int(x) % 26 for x in key], dtype=int).reshape(n, n)

        while len(text) % n != 0:
            text += "X"

        result = ""
        for i in range(0, len(text), n):
            block = np.array([LETTERS.index(c) for c in text[i:i+n]])
            enc = matrix.dot(block) % 26
            result += ''.join(LETTERS[e] for e in enc)
        return result

    @staticmethod
    def decrypt(text, key):
        n = int(len(key) ** 0.5)
        matrix = np.array([int(x) for x in key]).reshape(n, n)
        det = int(round(np.linalg.det(matrix)))
        inv_det = pow(det, -1, 26)
        adj = np.round(det * np.linalg.inv(matrix)).astype(int) % 26
        inv_matrix = (inv_det * adj) % 26

        result = ""
        for i in range(0, len(text), n):
            block = np.array([LETTERS.index(c) for c in text[i:i+n]])
            dec = inv_matrix.dot(block) % 26
            result += ''.join(LETTERS[d] for d in dec)
        return result


# ============================================
# 9. VERNAM (XOR)
# ============================================
class VernamCipher:
    @staticmethod
    def encrypt(text, key):
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(text, key))

    @staticmethod
    def decrypt(text, key):
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(text, key))


# ============================================
# 10. AFFINE
# ============================================
class AffineCipher:
    @staticmethod
    def encrypt(text, key):
        a, b = map(int, key.split(","))
        return ''.join(
            LETTERS[(a * LETTERS.index(c) + b) % 26] if c in LETTERS else c
            for c in text.upper()
        )

    @staticmethod
    def decrypt(text, key):
        a, b = map(int, key.split(","))
        a_inv = pow(a, -1, 26)
        return ''.join(
            LETTERS[(a_inv * (LETTERS.index(c) - b)) % 26] if c in LETTERS else c
            for c in text.upper()
        )


# ============================================
# 11. PIGPEN (BASİT ŞEMA)
# ============================================
PIGPEN_MAP = {
    "A": "🞀", "B": "🞁", "C": "🞂", "D": "🞃",
    "E": "🞄", "F": "🞅", "G": "🞆", "H": "🞇",
    "I": "🞈", "J": "🞉", "K": "🞊", "L": "🞋",
    "M": "🞌", "N": "🞍", "O": "🞎", "P": "🞏",
    "Q": "🞐", "R": "🞑", "S": "🞒", "T": "🞓",
    "U": "🞔", "V": "🞕", "W": "🞖", "X": "🞗",
    "Y": "🞘", "Z": "🞙"
}
REV_PIGPEN = {v: k for k, v in PIGPEN_MAP.items()}

class PigpenCipher:
    @staticmethod
    def encrypt(text, key=None):
        return ''.join(PIGPEN_MAP.get(c, c) for c in text.upper())

    @staticmethod
    def decrypt(text, key=None):
        result = ""
        buf = ""
        for c in text:
            buf += c
            if buf in REV_PIGPEN:
                result += REV_PIGPEN[buf]
                buf = ""
        return result


# ============================================
# 12. DES
# ============================================
class DESCipher:
    @staticmethod
    def encrypt(text, key):
        key = key.ljust(8, "0")[:8].encode()
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.encrypt(pad(text.encode(), 8)).hex()

    @staticmethod
    def decrypt(text, key):
        key = key.ljust(8, "0")[:8].encode()
        cipher = DES.new(key, DES.MODE_ECB)
        data = bytes.fromhex(text)
        return unpad(cipher.decrypt(data), 8).decode()


# ============================================
# 13. AES
# ============================================
class AESCipher:
    @staticmethod
    def encrypt(text, key):
        key = key.ljust(16, "0")[:16].encode()
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(text.encode(), 16)).hex()

    @staticmethod
    def decrypt(text, key):
        key = key.ljust(16, "0")[:16].encode()
        cipher = AES.new(key, AES.MODE_ECB)
        data = bytes.fromhex(text)
        return unpad(cipher.decrypt(data), 16).decode()


# ============================================
# YÖNTEMLER SÖZLÜĞÜ
# ============================================
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
