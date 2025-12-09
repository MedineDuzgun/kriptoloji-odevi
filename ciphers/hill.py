import numpy as np
import string
LETTERS = string.ascii_uppercase

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
