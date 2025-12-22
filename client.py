import socket
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from ciphers import METHODS
from ciphers.rsa_cipher import RSACipher
from ciphers.kdf import derive_key
from ciphers.ecc_cipher import ECCCipher
import os


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("İstemci - Mesaj Şifreleme")
        ECCCipher.generate_keys()

        tk.Label(root, text="Sunucu Host").grid(row=0, column=0, sticky="w")
        self.host_entry = tk.Entry(root)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.grid(row=0, column=1, sticky="we")

        tk.Label(root, text="Port").grid(row=1, column=0, sticky="w")
        self.port_entry = tk.Entry(root)
        self.port_entry.insert(0, "5000")
        self.port_entry.grid(row=1, column=1, sticky="we")

        tk.Label(root, text="Şifreleme Yöntemi").grid(
            row=2, column=0, sticky="w")
        self.method_combo = ttk.Combobox(root, values=list(METHODS.keys()))
        self.method_combo.current(0)
        self.method_combo.grid(row=2, column=1, sticky="we")

        tk.Label(root, text="Anahtar").grid(row=3, column=0, sticky="w")
        self.key_entry = tk.Entry(root)
        self.key_entry.insert(0, "3")
        self.key_entry.grid(row=3, column=1, sticky="we")

        tk.Label(root, text="Gönderilecek Mesaj").grid(
            row=4, column=0, sticky="w")
        self.text_entry = scrolledtext.ScrolledText(root, height=8)
        self.text_entry.grid(
            row=5,
            columnspan=2,
            sticky="nsew",
            padx=5,
            pady=5
        )

        tk.Button(root, text="Şifrele & Gönder", command=self.send_message)\
            .grid(row=6, columnspan=2, pady=5)

        tk.Label(root, text="Log").grid(row=7, column=0, sticky="w")
        self.log = scrolledtext.ScrolledText(root, height=8)
        self.log.grid(
            row=8,
            columnspan=2,
            sticky="nsew",
            padx=5,
            pady=5
        )

        root.columnconfigure(0, weight=1)
        root.columnconfigure(1, weight=1)

        root.rowconfigure(5, weight=1)
        root.rowconfigure(8, weight=1)

    def send_message(self):
        host = self.host_entry.get()
        port = int(self.port_entry.get())
        text = self.text_entry.get("1.0", tk.END).strip()
        password = self.key_entry.get()
        method = self.method_combo.get()

        if not text:
            return

        if method == "ECC":
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))

                client_pub = ECCCipher.export_public_key()
                if not client_pub:
                    raise ValueError("Client public key üretilemedi")

                sock.sendall(json.dumps({
                    "method": "ECC",
                    "client_pub": client_pub
                }).encode("utf-8"))

                data = sock.recv(16384)
                if not data:
                    raise ValueError("Server public key alınamadı")

                server_packet = json.loads(data.decode("utf-8"))

                if "server_pub" not in server_packet:
                    raise ValueError("Server public key eksik")

                server_pub_key = ECCCipher.load_public_key(
                    server_packet["server_pub"])

                shared_key = ECCCipher.derive_shared_key(server_pub_key)
                if not shared_key:
                    raise ValueError("Shared key üretilemedi")

                encrypted = METHODS["AES"].encrypt(text, shared_key)
                if not encrypted:
                    raise ValueError("AES şifreleme başarısız")

                sock.sendall(json.dumps({
                    "ciphertext": encrypted.hex()
                }).encode("utf-8"))

                sock.close()
                self.log.insert(tk.END, "[ECC] Gönderildi\n")
                return

            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                messagebox.showerror("ECC Hatası", str(e))
                return

        CipherClass = METHODS[method]

        if method == "RSA-MSG":
            encrypted = CipherClass.encrypt(text)
            packet = {
                "method": method,
                "type": "hex",
                "ciphertext": encrypted.hex()
            }

        elif method in ["AES", "DES", "3DES", "ManualAES", "ManualDES"]:
            if method in ["DES", "ManualDES"]:
                key_len = 8
            elif method == "3DES":
                key_len = 24
            else:
                key_len = 16

            salt = os.urandom(16)

            real_key = derive_key(
                password.encode("utf-8"),
                salt,
                key_len
            )

            encrypted = CipherClass.encrypt(text, real_key)

            encrypted_key = RSACipher.encrypt(real_key).hex()
            packet = {
                "method": method,
                "encrypted_key": encrypted_key,
                "salt": salt.hex(),
                "type": "hex",
                "ciphertext": encrypted.hex()
            }

        else:
            encrypted = CipherClass.encrypt(text, password)
            packet = {
                "method": method,
                "key": password,
                "type": "text",
                "ciphertext": encrypted
            }

        sock = socket.socket()
        sock.connect((host, port))
        sock.sendall(json.dumps(packet).encode())
        sock.close()

        self.log.insert(tk.END, f"[{method}] Gönderildi\n")


if __name__ == "__main__":
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()
