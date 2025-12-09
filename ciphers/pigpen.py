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
