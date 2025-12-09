import string
LETTERS = string.ascii_uppercase

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
