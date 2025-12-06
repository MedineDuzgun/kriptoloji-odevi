import socket, threading, json, struct, os, sys, mimetypes
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from PIL import Image, ImageTk
from io import BytesIO
import tempfile, subprocess
from crypto_methods import methods  # crypto_methods.py içindeki methods sözlüğü

HOST = "127.0.0.1"
PORT = 5000
AES_KEY = b"16bytekey1234567"  # crypto_methods AES fonksiyonunla uyumlu key

def open_with_os(path):
    if sys.platform.startswith("win"):
        os.startfile(path)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])

class ServerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Server (Sunucu)")
        root.geometry("780x560")

        # Üst kısım
        top = tk.Frame(root)
        top.pack(fill="x", padx=8, pady=6)
        self.status = tk.Label(top, text=f"Durum: Beklemede — {HOST}:{PORT}")
        self.status.pack(side="left")

        # Şifreleme seçimi (server hangi yöntemle gönderecek)
        tk.Label(top, text="Server gönderim yöntemi:").pack(side="left", padx=6)
        self.method_var = tk.StringVar(value="AES")
        tk.OptionMenu(top, self.method_var, *methods.keys()).pack(side="left")

        # Orta log kısmı (ticker gibi otomatik scroll)
        mid = tk.Frame(root)
        mid.pack(fill="both", expand=True, padx=8, pady=6)
        self.log = scrolledtext.ScrolledText(mid, height=16, state="disabled", wrap="none")
        self.log.pack(fill="both", expand=True)

        # Resim göstermek için
        self.image_label = tk.Label(root)
        self.image_label.pack(pady=8)

        # Alt kısım: mesaj gönderme (manuel)
        bottom = tk.Frame(root)
        bottom.pack(fill="x", padx=8, pady=6)
        tk.Label(bottom, text="İstemciye mesaj:").pack(anchor="w")
        self.entry = tk.Entry(bottom)
        self.entry.pack(side="left", fill="x", expand=True)
        tk.Button(bottom, text="Gönder (şifreli olarak gönderir)", command=self.send_text).pack(side="left", padx=6)
        tk.Button(bottom, text="Dosya Gönder", command=self.send_file).pack(side="left", padx=6)

        self.sock = None
        self.conn = None
        self.addr = None
        self.client_thread = None
        threading.Thread(target=self.start_server, daemon=True).start()

    def log_write(self, s):
        self.log.configure(state="normal")
        self.log.insert("end", s + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def start_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((HOST, PORT))
            self.sock.listen(1)
            self.update_status(f"Dinlemede: {HOST}:{PORT} (istemci bekleniyor)")
            self.conn, self.addr = self.sock.accept()
            self.update_status(f"Bağlandı: {self.addr}")
            self.log_write(f"[+] İstemci bağlandı: {self.addr}")

            self.client_thread = threading.Thread(target=self.handle_client, daemon=True)
            self.client_thread.start()
        except Exception as e:
            self.update_status(f"Hata: {e}")
            messagebox.showerror("Sunucu Hatası", str(e))

    def update_status(self, s):
        def _():
            self.status.config(text=f"Durum: {s}")
        self.root.after(0, _)

    def recvall(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # helper: server'ın client'a şifrelenmiş veri göndermesi
    def send_encrypted_to_client(self, plaintext: str, method_name: str):
        encrypt_func = methods[method_name][0]
        if method_name == "AES":
            body_enc = encrypt_func(plaintext.encode("utf-8"), AES_KEY)
        else:
            body_enc = encrypt_func(plaintext).encode("utf-8")

        # header içine hangi methodla gönderildiğini koy
        header = json.dumps({
            "type": "text",
            "size": len(body_enc),
            "method": method_name
        }).encode("utf-8")
        packet = struct.pack(">I", len(header)) + header + body_enc
        try:
            self.conn.sendall(packet)
            # GUI'de şifreli veriyi hex olarak göster
            self.log_write(f"[ŞİFRELİ GÖNDERİLEN → {method_name}] {body_enc.hex()}")
        except Exception as e:
            self.log_write(f"[HATA] Gönderilemedi: {e}")

    # helper: server'ın client'a şifrelenmiş dosya göndermesi
    def send_encrypted_file_to_client(self, file_bytes: bytes, filename: str, mimetype: str, method_name: str):
        encrypt_func = methods[method_name][0]
        if method_name == "AES":
            data_enc = encrypt_func(file_bytes, AES_KEY)
        else:
            data_enc = encrypt_func(file_bytes.decode("utf-8")).encode("utf-8")

        header = json.dumps({
            "type": "file",
            "filename": filename,
            "mimetype": mimetype,
            "size": len(data_enc),
            "method": method_name
        }).encode("utf-8")
        packet = struct.pack(">I", len(header)) + header + data_enc
        try:
            self.conn.sendall(packet)
            self.log_write(f"[ŞİFRELİ DOSYA GÖNDERİLDİ → {method_name}] {filename} ({len(data_enc)} bayt)")
        except Exception as e:
            self.log_write(f"[HATA] Dosya gönderilemedi: {e}")

    def handle_client(self):
        try:
            while True:
                header_len_raw = self.recvall(4)
                if not header_len_raw:
                    self.log_write("[-] Bağlantı kapandı.")
                    break
                header_len = struct.unpack(">I", header_len_raw)[0]
                header_json = self.recvall(header_len).decode("utf-8")
                header = json.loads(header_json)

                typ = header.get("type")
                # client'ın gönderdiği method (gönderirken hangi yöntemi kullandı)
                client_method = header.get("method", "AES")
                decrypt_func = methods[client_method][1]

                if typ == "text":
                    size = header.get("size", 0)
                    data_enc = self.recvall(size)
                    # GUI'de gelen şifreli veriyi göster (hex)
                    self.log_write(f"[GELEN ŞİFRELİ → {client_method}] {data_enc.hex()}")

                    # önce geleni de-crypt et (sunucu olarak orijinal metni görmek isteyebilirsin)
                    if client_method == "AES":
                        try:
                            original = decrypt_func(data_enc, AES_KEY).decode("utf-8")
                        except Exception as e:
                            original = f"<AES_DECRYPT_ERROR: {e}>"
                    else:
                        try:
                            original = decrypt_func(data_enc.decode("utf-8"))
                        except Exception as e:
                            original = f"<CAESAR_DECRYPT_ERROR: {e}>"

                    if client_method == "AES":
                       self.log_write(f"[GELEN ŞİFRELİ → {client_method}] {data_enc.hex()}")
                    else:
                    # Caesar için okunabilir göster
                        try:
                            self.log_write(f"[GELEN ŞİFRELİ → {client_method}] {data_enc.decode('utf-8')}")
                        except Exception:
                     # decode hata verirse fallback hex
                         self.log_write(f"[GELEN ŞİFRELİ → {client_method}] {data_enc.hex()}")


                    # --- CRITICAL: server seçimine göre şifrele ve client'a gönder ---
                    server_method = self.method_var.get()
                    # Burada server, istemciden gelen orijinali kendi seçimine göre şifreleyip gönderecek
                    self.send_encrypted_to_client(original, server_method)

                elif typ == "file":
                    size = header["size"]
                    filename = header.get("filename", "dosya")
                    mimetype = header.get("mimetype", "application/octet-stream")
                    data_enc = self.recvall(size)

                    # GUI'de gelen şifreli dosya bilgisini göster (kısa)
                    self.log_write(f"[GELEN ŞİFRELİ DOSYA → {client_method}] {filename} ({len(data_enc)} bayt)")

                    # decrypt gelen dosya
                    if client_method == "AES":
                        try:
                            data = decrypt_func(data_enc, AES_KEY)
                        except Exception as e:
                            self.log_write(f"[HATA] Dosya decrypt hatası: {e}")
                            data = None
                    else:
                        try:
                            data = decrypt_func(data_enc.decode("utf-8")).encode("utf-8")
                        except Exception as e:
                            self.log_write(f"[HATA] Dosya decrypt hatası: {e}")
                            data = None

                    if data is not None:
                        if mimetype.startswith("image/"):
                            img = Image.open(BytesIO(data))
                            img.thumbnail((640, 360))
                            tk_img = ImageTk.PhotoImage(img)
                            def _show(): 
                                self.image_label.configure(image=tk_img)
                                self.image_label.image = tk_img
                            self.root.after(0, _show)
                            self.log_write(f"[DOSYA] Resim alındı: {filename} ({len(data)} bayt)")
                        else:
                            ext = os.path.splitext(filename)[1] or ""
                            tmpdir = tempfile.gettempdir()
                            save_path = os.path.join(tmpdir, f"server_recv{ext}")
                            with open(save_path, "wb") as f:
                                f.write(data)
                            self.log_write(f"[DOSYA] Kaydedildi: {save_path} ({mimetype})")
                            open_with_os(save_path)

                        # dosya alındıktan sonra server, isteğe bağlı olarak client'a şifreli ACK gönderebilir
                        ack_text = f"Dosya '{filename}' alındı ({len(data)} bayt)"
                        server_method = self.method_var.get()
                        self.send_encrypted_to_client(ack_text, server_method)

                else:
                    self.log_write(f"[!] Bilinmeyen tür: {typ}")

        except Exception as e:
            self.log_write(f"[HATA] {e}")
        finally:
            if self.conn:
                try: self.conn.close()
                except: pass

    # Manuel gönderme (server GUI'den)
    def send_text(self):
        if not self.conn:
            messagebox.showwarning("Uyarı", "İstemci bağlı değil.")
            return
        msg = self.entry.get().strip()
        if not msg:
            return

        server_method = self.method_var.get()
        self.send_encrypted_to_client(msg, server_method)
        self.log_write(f"[SUNUCU] (gönderildi original) {msg}")
        self.entry.delete(0, "end")

    def send_file(self):
        if not self.conn:
            messagebox.showwarning("Uyarı", "İstemci bağlı değil.")
            return
        path = filedialog.askopenfilename(title="Dosya seç (resim/ses/video)")
        if not path:
            return

        with open(path, "rb") as f:
            data = f.read()

        filename = os.path.basename(path)
        mimetype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        server_method = self.method_var.get()
        self.send_encrypted_file_to_client(data, filename, mimetype, server_method)
        self.log_write(f"[SUNUCU] Dosya gönderildi (original): {filename} ({len(data)} bayt)")

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()
