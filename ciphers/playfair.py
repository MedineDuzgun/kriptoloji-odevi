import string
LETTERS = string.ascii_uppercase

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
            if r1 == r2:
                result += table[r1][(c1 + 1) % 5] + table[r2][(c2 + 1) % 5]
            elif c1 == c2:
                result += table[(r1 + 1) % 5][c1] + table[(r2 + 1) % 5][c2]
            else:
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
