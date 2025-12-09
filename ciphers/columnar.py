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
