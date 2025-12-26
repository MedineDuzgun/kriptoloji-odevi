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

        self.ecc = ECCCipher()

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
        self.method_combo = ttk.Combobox(
            root, values=list(METHODS.keys()), state="readonly")
        self.method_combo.current(0)
        self.method_combo.grid(row=2, column=1, sticky="we")
        self.method_combo.bind("<<ComboboxSelected>>", self.on_method_change)

        tk.Label(root, text="Anahtar Dağıtımı").grid(
            row=3, column=0, sticky="w")
        self.kex_combo = ttk.Combobox(
            root, values=["RSA", "ECC"], state="readonly")
        self.kex_combo.current(0)
        self.kex_combo.grid(row=3, column=1, sticky="we")

        tk.Label(root, text="Anahtar").grid(row=4, column=0, sticky="w")
        self.key_entry = tk.Entry(root)
        self.key_entry.insert(0, "3")
        self.key_entry.grid(row=4, column=1, sticky="we")

        tk.Label(root, text="Gönderilecek Mesaj").grid(
            row=5, column=0, sticky="w")
        self.text_entry = scrolledtext.ScrolledText(root, height=8)
        self.text_entry.grid(row=6, columnspan=2,
                             sticky="nsew", padx=5, pady=5)

        tk.Button(root, text="Şifrele & Gönder", command=self.send_message).grid(
            row=7, columnspan=2, pady=5)

        tk.Label(root, text="Log").grid(row=8, column=0, sticky="w")
        self.log = scrolledtext.ScrolledText(root, height=8)
        self.log.grid(row=9, columnspan=2, sticky="nsew", padx=5, pady=5)

        root.columnconfigure(0, weight=1)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(6, weight=1)
        root.rowconfigure(9, weight=1)

    def send_message(self):
        host = self.host_entry.get()
        port = int(self.port_entry.get())
        text = self.text_entry.get("1.0", tk.END).strip()
        password = self.key_entry.get()
        method = self.method_combo.get()
        kex = self.kex_combo.get()

        if not text:
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))

            
            if method in ["AES", "DES", "3DES"] and kex == "ECC":
                if method == "DES":
                    key_len = 8
                elif method == "3DES":
                    key_len = 24
                else:
                    key_len = 16

                self.ecc = ECCCipher()
                client_pub = self.ecc.export_public_key()

               
                sock.sendall(json.dumps({
                    "method": method,
                    "kex": "ECC",
                    "client_pub": client_pub
                }).encode())

              
                data = sock.recv(16384)
                server_pub = ECCCipher.load_public_key(
                    json.loads(data.decode())["server_pub"]
                )

                shared_key = self.ecc.derive_shared_key(server_pub)

              
                real_key = os.urandom(key_len)

               
                encrypted_key = METHODS["AES"].encrypt(
                    real_key.hex(), shared_key)
                encrypted_msg = METHODS[method].encrypt(text, real_key)

              
                self.log.insert(
                    tk.END,
                    f"[ECC] Encrypted Symmetric Key (HEX):\n{encrypted_key.hex()}\n"
                )

                packet = {
                    "method": method,
                    "kex": "ECC",
                    "encrypted_key": encrypted_key.hex(),
                    "type": "hex",
                    "ciphertext": encrypted_msg.hex()
                }

                sock.sendall(json.dumps(packet).encode())
                self.log.insert(tk.END, f"[{method}] Gönderildi (ECC KEX)\n")
                return

          
            if method in ["AES", "DES", "3DES"] and kex == "RSA":
                if method == "DES":
                    key_len = 8
                elif method == "3DES":
                    key_len = 24
                else:
                    key_len = 16

                salt = os.urandom(16)
                real_key = derive_key(password.encode(), salt, key_len)

              
                encrypted_key = RSACipher.encrypt(real_key)
                encrypted_msg = METHODS[method].encrypt(text, real_key)

                self.log.insert(
                    tk.END,
                    f"[RSA] Encrypted Symmetric Key (HEX):\n{encrypted_key.hex()}\n"
                )

                packet = {
                    "method": method,
                    "kex": "RSA",
                    "encrypted_key": encrypted_key.hex(),
                    "salt": salt.hex(),
                    "type": "hex",
                    "ciphertext": encrypted_msg.hex()
                }

                sock.sendall(json.dumps(packet).encode())
                self.log.insert(tk.END, f"[{method}] Gönderildi (RSA KEX)\n")
                return

            
            CipherClass = METHODS[method]
            encrypted = CipherClass.encrypt(text, password)

            if isinstance(encrypted, bytes):
                encrypted_str = encrypted.hex()
                packet_type = "hex"

            else:
                encrypted_str = encrypted
                packet_type = "text"

            packet = {
                "method": method,
                "key": password,
                "type": "text",
                "ciphertext": encrypted
            }
            sock.sendall(json.dumps(packet).encode())
            self.log.insert(tk.END, f"[{method}] Gönderildi\n")

        except Exception as e:
            messagebox.showerror("Hata", str(e))
        finally:
            sock.close()

    def on_method_change(self, event=None):
        method = self.method_combo.get()
        klasik = ["Caesar", "Vigenere", "Affine", "RSA-MSG"]
        manuel_sifrelemeler = ["AES (Manual)", "DES (Manual)"]

        if method in klasik:
            
            self.key_entry.config(state="normal")
            self.kex_combo.config(state="disabled")
        elif method in manuel_sifrelemeler:
           
            self.key_entry.delete(0, "end")
            self.key_entry.config(state="disabled")
            self.kex_combo.config(state="disabled")
        else:
            
            self.key_entry.delete(0, "end")
            self.key_entry.config(state="disabled")
            self.kex_combo.config(state="readonly")

    def on_kex_change(self, event=None):
        method = self.method_combo.get()
        kex = self.kex_combo.get()

        
        if method in ["AES", "DES", "3DES"] and kex in ["ECC", "RSA"]:
            self.key_entry.delete(0, "end")
            self.key_entry.config(state="disabled")
        else:
            
            if method in ["Caesar", "Vigenere", "Affine", "RSA-MSG"]:
                self.key_entry.config(state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()
