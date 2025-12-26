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

        RSACipher.generate_keys()

        tk.Label(master, text="Host").grid(row=0, column=0, sticky='w', padx=5)
        self.host_e = tk.Entry(master)
        self.host_e.insert(0, "127.0.0.1")
        self.host_e.grid(row=0, column=1, sticky='we', padx=5)

        tk.Label(master, text="Port").grid(row=1, column=0, sticky='w', padx=5)
        self.port_e = tk.Entry(master)
        self.port_e.insert(0, "5000")
        self.port_e.grid(row=1, column=1, sticky='we', padx=5)

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

            msg = json.loads(data.decode())
            method = msg.get("method")
            kex = msg.get("kex")

           
            if kex == "ECC":
                client_pub = ECCCipher.load_public_key(msg["client_pub"])
                self.ecc = ECCCipher()

                
                conn.sendall(json.dumps({
                    "server_pub": self.ecc.export_public_key()
                }).encode())

                
                data2 = conn.recv(16384)
                packet = json.loads(data2.decode())
                encrypted_key = bytes.fromhex(packet["encrypted_key"])
                ciphertext = bytes.fromhex(packet["ciphertext"])

                shared_key = self.ecc.derive_shared_key(client_pub)
                real_key_hex = METHODS["AES"].decrypt(
                    encrypted_key, shared_key)
                real_key = bytes.fromhex(real_key_hex)

                decrypted = METHODS[method].decrypt(ciphertext, real_key)
                if isinstance(decrypted, bytes):
                    decrypted = decrypted.decode()

                
                self.log.insert(
                    "end",
                    f"[ECC] Encrypted Symmetric Key (HEX):\n{packet['encrypted_key']}\n"
                )
                self.raw_txt.insert("end", packet["ciphertext"] + "\n")
                self.dec_txt.insert("end", decrypted + "\n")
                self.log.insert("end", "[ECC] Mesaj çözüldü\n")
                return

         
            if kex == "RSA":
                encrypted_key = bytes.fromhex(msg["encrypted_key"])
                real_key = RSACipher.decrypt(encrypted_key)

                self.log.insert(
                    "end",
                    f"[RSA] Encrypted Symmetric Key (HEX):\n{msg['encrypted_key']}\n"
                )

                ciphertext = bytes.fromhex(msg["ciphertext"])
                decrypted = METHODS[method].decrypt(ciphertext, real_key)
                if isinstance(decrypted, bytes):
                    decrypted = decrypted.decode()

                self.raw_txt.insert("end", msg["ciphertext"] + "\n")
                self.dec_txt.insert("end", decrypted + "\n")
                self.log.insert("end", "[RSA] Mesaj çözüldü\n")
                return

           
            cipher_data = msg.get("ciphertext")
            if msg.get("type") == "hex":
                cipher_data = bytes.fromhex(cipher_data)

            decrypted = METHODS[method].decrypt(cipher_data, msg.get("key"))
            if isinstance(decrypted, bytes):
                decrypted = decrypted.decode()

            self.raw_txt.insert("end", str(msg["ciphertext"]) + "\n")
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
