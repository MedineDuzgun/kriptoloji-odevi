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
