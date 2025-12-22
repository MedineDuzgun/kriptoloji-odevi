import socket
import threading
import json
import tkinter as tk
import tkinter.scrolledtext as st
from tkinter import messagebox
from ciphers import METHODS
from ciphers.rsa_cipher import RSACipher
from ciphers.kdf import derive_key
from ciphers.ecc_cipher import ECCCipher
import os


class ServerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Sunucu - Mesaj Deşifreleme")
        master.minsize(700, 550)

        ECCCipher.generate_keys()
        RSACipher.generate_keys()

        tk.Label(master, text="Host").grid(row=0, column=0, sticky='w', padx=5)
        self.host_e = tk.Entry(master)
        self.host_e.insert(0, "127.0.0.1")
        self.host_e.grid(row=0, column=1, sticky='we', padx=5)

        tk.Label(master, text="Port").grid(row=1, column=0, sticky='w', padx=5)
        self.port_e = tk.Entry(master)
        self.port_e.insert(0, "5000")
        self.port_e.grid(row=1, column=1, sticky='we', padx=5)

        tk.Label(master, text="Deşifreleme Yöntemi").grid(
            row=2, column=0, sticky='w', padx=5)
        self.method_var = tk.StringVar(master, value="Caesar")
        methods = list(METHODS.keys())
        self.method_menu = tk.OptionMenu(master, self.method_var, *methods)
        self.method_menu.grid(row=2, column=1, sticky='we', padx=5)

        tk.Label(master, text="Anahtar").grid(
            row=3, column=0, sticky='w', padx=5)
        self.key_e = tk.Entry(master)
        self.key_e.grid(row=3, column=1, sticky='we', padx=5)

        tk.Label(master, text="Gelen Şifreli Mesaj").grid(
            row=4, column=0, sticky='w', padx=5)
        self.raw_txt = st.ScrolledText(master, height=8)
        self.raw_txt.grid(row=5, column=0, columnspan=2,
                          sticky="nsew", padx=5, pady=5)

        tk.Label(master, text="Deşifrelenmiş Mesaj").grid(
            row=6, column=0, sticky='w', padx=5)
        self.dec_txt = st.ScrolledText(master, height=8)
        self.dec_txt.grid(row=7, column=0, columnspan=2,
                          sticky="nsew", padx=5, pady=5)

        tk.Button(master, text="Sunucuyu Başlat", command=self.start_server)\
            .grid(row=8, column=0, pady=5)
        tk.Button(master, text="Sunucuyu Durdur", command=self.stop_server)\
            .grid(row=8, column=1, pady=5)

        tk.Label(master, text="Log").grid(row=9, column=0, sticky='w', padx=5)
        self.log = st.ScrolledText(master, height=8)
        self.log.grid(row=10, column=0, columnspan=2,
                      sticky="nsew", padx=5, pady=5)

        master.columnconfigure(0, weight=1)
        master.columnconfigure(1, weight=1)

        master.rowconfigure(5, weight=1)
        master.rowconfigure(7, weight=1)
        master.rowconfigure(10, weight=1)

        self.server_socket = None
        self.running = False

    def clear(self):
        self.raw_txt.delete('1.0', 'end')
        self.dec_txt.delete('1.0', 'end')
        self.log.delete('1.0', 'end')

    def start_server(self):
        if self.running:
            return

        host = self.host_e.get().strip()
        port = int(self.port_e.get().strip())

        self.running = True

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server_socket.bind((host, port))
            self.server_socket.listen(5)
        except Exception as e:
            messagebox.showerror("Hata", f"Port dinlenemedi: {e}")
            return

        self.log.insert('end', f"[SERVER] Listening on {host}:{port}\n")

        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop_server(self):
        self.running = False
        try:
            if self.server_socket:
                self.server_socket.close()
            self.log.insert('end', "[SERVER] Stopped\n")
        except Exception as e:
            self.log.insert('end', f"[STOP ERROR] {e}\n")

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                self.log.insert('end', f"[CLIENT CONNECTED] {addr}\n")
                threading.Thread(target=self._handle_client,
                                 args=(conn,), daemon=True).start()
            except:
                break

    def _handle_client(self, conn):
        try:
            data = conn.recv(16384)
            if not data:
                return

            msg = json.loads(data.decode("utf-8"))
            method = msg.get("method")

            if method == "ECC":
                client_pub = ECCCipher.load_public_key(msg["client_pub"])

                conn.sendall(json.dumps({
                    "server_pub": ECCCipher.export_public_key()
                }).encode("utf-8"))

                data = conn.recv(16384)
                if not data:
                    return

                cipher_packet = json.loads(data.decode("utf-8"))
                ciphertext = bytes.fromhex(cipher_packet["ciphertext"])

                shared_key = ECCCipher.derive_shared_key(client_pub)
                decrypted = METHODS["AES"].decrypt(ciphertext, shared_key)

                if isinstance(decrypted, bytes):
                    decrypted = decrypted.decode("utf-8")

                self.raw_txt.insert("end", cipher_packet["ciphertext"] + "\n")
                self.dec_txt.insert("end", decrypted + "\n")
                self.log.insert("end", "[ECC] Mesaj çözüldü\n")
                return

            encrypted_key_hex = msg.get("encrypted_key")
            real_key = None

            if encrypted_key_hex:
                self.log.insert(
                    "end",
                    f"[RSA] Şifrelenmiş Anahtar:\n{encrypted_key_hex}\n"
                )
                real_key = RSACipher.decrypt(bytes.fromhex(encrypted_key_hex))

            cipher_data = msg.get("ciphertext")
            cipher_type = msg.get("type")

            ciphertext = cipher_data
            if cipher_type == "hex":
                ciphertext = bytes.fromhex(cipher_data)

            cipher_obj = METHODS[method]

            if method == "RSA-MSG":
                decrypted = cipher_obj.decrypt(ciphertext)
            elif method in ["AES", "DES", "3DES", "ManualAES", "ManualDES"]:
                decrypted = cipher_obj.decrypt(ciphertext, real_key)
            else:
                decrypted = cipher_obj.decrypt(ciphertext, msg.get("key"))

            if isinstance(decrypted, bytes):
                decrypted = decrypted.decode("utf-8")

            self.raw_txt.insert("end", str(cipher_data) + "\n")
            self.dec_txt.insert("end", decrypted + "\n")
            self.log.insert("end", "[OK] Mesaj çözüldü\n")

        except Exception as e:
            self.log.insert("end", f"[HATA] {str(e)}\n")

        finally:
            conn.close()


if __name__ == '__main__':
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()
