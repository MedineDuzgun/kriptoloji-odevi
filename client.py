# client.py
import socket
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from ciphers import METHODS  # AES, DES, Caesar hepsi burada dict içinde olacak


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

        tk.Label(root, text="Şifreleme Yöntemi").grid(row=2, column=0, sticky="w")
        self.method_combo = ttk.Combobox(root, values=list(METHODS.keys()))
        self.method_combo.current(0)
        self.method_combo.grid(row=2, column=1, sticky="we")

        tk.Label(root, text="Anahtar").grid(row=3, column=0, sticky="w")
        self.key_entry = tk.Entry(root)
        self.key_entry.insert(0, "3")
        self.key_entry.grid(row=3, column=1, sticky="we")

        tk.Label(root, text="Gönderilecek Mesaj").grid(row=4, column=0, sticky="w")
        self.text_entry = scrolledtext.ScrolledText(root, width=50, height=5)
        self.text_entry.grid(row=5, columnspan=2, sticky="we")

        tk.Button(root, text="Şifrele & Gönder", command=self.send_message)\
            .grid(row=6, columnspan=2, pady=5)

        tk.Label(root, text="Log").grid(row=7, column=0, sticky="w")
        self.log = scrolledtext.ScrolledText(root, width=50, height=5)
        self.log.grid(row=8, columnspan=2, sticky="we")

        for i in range(2):
            root.columnconfigure(i, weight=1)

    # ------------------------------------------------------------------
    # ŞİFRELE → JSON PAKETİ OLUŞTUR → SERVER'A GÖNDER
    # ------------------------------------------------------------------
    def send_message(self):
     host = self.host_entry.get()
     port = int(self.port_entry.get())

     text = self.text_entry.get("1.0", tk.END).strip()
     key = self.key_entry.get().strip()
     method_name = self.method_combo.get()

     if not text:
        messagebox.showerror("Hata", "Gönderilecek metin boş olamaz.")
        return

     CipherClass = METHODS[method_name]

     try:
        encrypted = CipherClass.encrypt(text, key)
     except Exception as e:
        messagebox.showerror("Şifreleme Hatası", f"Şifreleme işleminde hata:\n{e}")
        return

    # -------------------------------------------------
    # AYRIM BURADA (KRİTİK KISIM)
    # -------------------------------------------------

    # AES / DES / 3DES → binary → HEX gönder
     if method_name in ["AES", "DES", "3DES", "ManualAES", "ManualDES"]:
        if isinstance(encrypted, str):
            encrypted = encrypted.encode()

        packet = {
            "method": method_name,
            "key": key,
            "type": "hex",
            "ciphertext": encrypted.hex()
        }

        log_text = encrypted.hex()

    # KLASİK ŞİFRELER → TEXT gönder
     else:
        packet = {
            "method": method_name,
            "key": key,
            "type": "text",
            "ciphertext": encrypted
        }

        log_text = encrypted

    # -------------------------------------------------
    # SOCKET GÖNDERİM
    # -------------------------------------------------
     try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sock.sendall(json.dumps(packet).encode("utf-8"))
        sock.close()

        self.log.insert(tk.END, f"[+] Gönderildi [{method_name}]: {log_text}\n")

     except Exception as e:
        messagebox.showerror("Bağlantı Hatası", f"Sunucuya bağlanılamadı:\n{e}")



if __name__ == "__main__":
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()
