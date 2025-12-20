import socket
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from ciphers import METHODS
from ciphers.rsa_cipher import RSACipher
from ciphers.kdf import derive_key
import os


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("İstemci - Mesaj Şifreleme")

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
        password = self.key_entry.get().strip()
        method_name = self.method_combo.get()

        if not text:
            messagebox.showerror("Hata", "Gönderilecek metin boş olamaz.")
            return

        CipherClass = METHODS[method_name]

        if method_name == "RSA-MSG":
            try:
                encrypted = CipherClass.encrypt(text)
            except Exception as e:
                messagebox.showerror("RSA Hatası", str(e))
                return

            packet = {
                "method": method_name,
                "type": "hex",
                "ciphertext": encrypted.hex()
            }

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                sock.sendall(json.dumps(packet).encode("utf-8"))
                sock.close()

                self.log.insert(
                    tk.END,
                    "[RSA] Mesaj RSA ile şifrelendi ve gönderildi\n"
                )
                return
            except Exception as e:
                messagebox.showerror("Bağlantı Hatası", str(e))
                return

        if method_name in ["AES", "DES", "3DES", "ManualAES", "ManualDES"]:

            password_bytes = password.encode("utf-8")
            salt = os.urandom(16)

            if method_name in ["DES", "ManualDES"]:
                key_len = 8
            elif method_name == "3DES":
                key_len = 24
            else:
                key_len = 16  # AES

            real_key = derive_key(password_bytes, salt, key_len)

            try:
                encrypted = CipherClass.encrypt(text, real_key)
            except Exception as e:
                messagebox.showerror("Şifreleme Hatası", str(e))
                return

            encrypted_key = RSACipher.encrypt(real_key).hex()

            packet = {
                "method": method_name,
                "encrypted_key": encrypted_key,
                "salt": salt.hex(),
                "type": "hex",
                "ciphertext": encrypted.hex()
            }

            log_text = encrypted.hex()

        else:
            try:
                encrypted = CipherClass.encrypt(text, password)
            except Exception as e:
                messagebox.showerror("Şifreleme Hatası", str(e))
                return

            packet = {
                "method": method_name,
                "key": password,
                "type": "text",
                "ciphertext": encrypted
            }

            log_text = encrypted

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.sendall(json.dumps(packet).encode("utf-8"))
            sock.close()

            self.log.insert(
                tk.END, f"[+] Gönderildi [{method_name}]: {log_text}\n"
            )

        except Exception as e:
            messagebox.showerror("Bağlantı Hatası", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()
