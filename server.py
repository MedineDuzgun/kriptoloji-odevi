# server.py
# Simple server GUI: listens on host:port, accepts one client, receives JSON messages containing:
# { "method": "Caesar", "key": "...", "cipher": "..." }
# It will decrypt and show result in GUI.
import socket, threading, json, tkinter as tk, tkinter.scrolledtext as st
from ciphers import METHODS
from tkinter import messagebox

class ServerGUI:
    def __init__(self, master):
        self.master = master; master.title("Sunucu - Mesaj Deşifreleme")
        # Layout (simple)
        tk.Label(master, text="Host").grid(row=0,column=0,sticky='w')
        self.host_e = tk.Entry(master); self.host_e.grid(row=0,column=1,sticky='we'); self.host_e.insert(0,"127.0.0.1")
        tk.Label(master, text="Port").grid(row=1,column=0,sticky='w')
        self.port_e = tk.Entry(master); self.port_e.grid(row=1,column=1,sticky='we'); self.port_e.insert(0,"5000")
        tk.Label(master, text="Deşifreleme Yöntemi").grid(row=2,column=0,sticky='w')
        self.method_var = tk.StringVar(master)
        self.method_var.set("Caesar")
        methods = list(METHODS.keys())
        self.method_menu = tk.OptionMenu(master, self.method_var, *methods)
        self.method_menu.grid(row=2,column=1,sticky='we')
        tk.Label(master, text="Anahtar").grid(row=3,column=0,sticky='w')
        self.key_e = tk.Entry(master); self.key_e.grid(row=3,column=1,sticky='we')
        tk.Label(master, text="Gelen Şifreli (Ham)").grid(row=4,column=0,sticky='w')
        self.raw_txt = st.ScrolledText(master, height=6); self.raw_txt.grid(row=4,column=1,sticky='we')
        tk.Label(master, text="Deşifrelenmiş").grid(row=5,column=0,sticky='w')
        self.dec_txt = st.ScrolledText(master, height=6); self.dec_txt.grid(row=5,column=1,sticky='we')
        tk.Button(master, text="Sunucuyu Başlat", command=self.start_server).grid(row=6,column=0)
        tk.Button(master, text="Sunucuyu Durdur", command=self.stop_server).grid(row=6,column=1)
        tk.Button(master, text="Temizle", command=self.clear).grid(row=6,column=2)
        tk.Label(master, text="Log").grid(row=7,column=0,sticky='w')
        self.log = st.ScrolledText(master, height=6); self.log.grid(row=7,column=1,sticky='we')
        master.grid_columnconfigure(1, weight=1)
        self.server_socket = None
        self.running = False
        self.client_thread = None

    def clear(self):
        self.raw_txt.delete('1.0','end'); self.dec_txt.delete('1.0','end'); self.log.delete('1.0','end')

    def start_server(self):
        if self.running: return
        host = self.host_e.get().strip() or '127.0.0.1'
        port = int(self.port_e.get().strip() or 5000)
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host,port))
        self.server_socket.listen(1)
        self.log.insert('end', f"Listening on {host}:{port}\n")
        self.client_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.client_thread.start()

    def stop_server(self):
        self.running = False
        try:
            if self.server_socket: self.server_socket.close()
            self.log.insert('end', "Server stopped\n")
        except Exception as e:
            self.log.insert('end', f"Error stopping: {e}\n")

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                self.log.insert('end', f"Connected: {addr}\n")
                threading.Thread(target=self._handle_client, args=(conn,addr), daemon=True).start()
            except Exception as e:
                if self.running:
                    self.log.insert('end', f"Accept error: {e}\n")
                break

    def _handle_client(self, conn, addr):
        with conn:
            data = b''
            while True:
                chunk = conn.recv(4096)
                if not chunk: break
                data += chunk
            try:
                msg = json.loads(data.decode('utf-8'))
                method = msg.get('method'); key = msg.get('key',''); cipher = msg.get('cipher','')
                self.raw_txt.insert('end', cipher + "\n")
                try:
                    cls = METHODS.get(method)
                    dec = cls.decrypt(cipher, key)
                except Exception as e:
                    dec = f"Error during decrypt: {e}"
                self.dec_txt.insert('end', dec + "\n")
                self.log.insert('end', f"Processed message from {addr}\n")
            except Exception as e:
                self.log.insert('end', f"Invalid message: {e}\n")

if __name__ == '__main__':
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()
