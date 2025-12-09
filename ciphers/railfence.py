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
