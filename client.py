import asyncio
import time
import base64

from lib.security.cryption import generate_keypair, encrypt
from lib.security.signing import load_or_generate_keypair, sign, build_registration_message
from lib.network.proxy import get_proxied_session, ProxyUnavailableError

import threading
import os
import uuid
from typing import AsyncGenerator
import customtkinter as ctk
import tkinter.messagebox
from tkinter import filedialog
import qrcode
from PIL import ImageTk
import fastapi
import dotenv

dotenv.load_dotenv()

from lib.utils import find_free_port

TRACKER_URL = os.environ.get('TRACKER_URL', 'https://p2pfiles.provolance.com/fileshare')
_KEY_PATH = os.path.join('.', 'peer_keys', 'signing_private.der')

app = fastapi.FastAPI()


class FileShareApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("P2P File Share via QR Code")
        self.geometry("600x700")

        self.filepath = None
        self.qr_code_image = None
        self.port = int(os.environ.get("ACCESS_PORT", find_free_port()))
        self.shared_files = {}
        self.url = None
        self.server_stop_event = threading.Event()

        self._signing_private_key, self._signing_public_key = load_or_generate_keypair(_KEY_PATH)

        self.server_thread = threading.Thread(target=self.start_http_file_server, daemon=True)
        self.server_thread.start()
        print("File server is running...")

        self.create_widgets()

    def create_widgets(self):
        self.main_frame = ctk.CTkScrollableFrame(self, width=600, height=700)
        self.main_frame.pack(fill="both", expand=True)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.title_label = ctk.CTkLabel(
            self.main_frame,
            text="P2P File Share via QR Code",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.title_label.grid(row=0, column=0, pady=(20, 10))

        self.select_file_button = ctk.CTkButton(
            self.main_frame, text="Select File", command=self.select_file
        )
        self.select_file_button.grid(row=1, column=0, pady=10, padx=20, sticky="ew")

        self.file_label = ctk.CTkLabel(self.main_frame, text="No file selected")
        self.file_label.grid(row=2, column=0, pady=10)

        self.share_button = ctk.CTkButton(
            self.main_frame, text="Start Sharing", command=self.start_sharing, state="disabled"
        )
        self.share_button.grid(row=3, column=0, pady=10, padx=20, sticky="ew")

        self.qr_label = ctk.CTkLabel(self.main_frame, text="")
        self.qr_label.grid(row=4, column=0, pady=20)

        self.copy_url_button = ctk.CTkButton(
            self.main_frame, text="Copy URL", command=self.copy_url, state="disabled"
        )
        self.copy_url_button.grid(row=5, column=0, pady=10, padx=20, sticky="ew")

        self.save_qr_button = ctk.CTkButton(
            self.main_frame, text="Save QR Code", command=self.save_qr_code, state="disabled"
        )
        self.save_qr_button.grid(row=6, column=0, pady=10, padx=20, sticky="ew")

        self.shared_files_label = ctk.CTkLabel(
            self.main_frame,
            text="Files Being Shared:",
            font=ctk.CTkFont(weight="bold")
        )
        self.shared_files_label.grid(row=7, column=0, pady=(20, 5), padx=20, sticky="w")

        self.shared_files_frame = ctk.CTkFrame(self.main_frame)
        self.shared_files_frame.grid(row=8, column=0, padx=20, pady=10, sticky="nsew")
        self.shared_files_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(8, weight=1)

        self.update_shared_files_list()

    def select_file(self):
        self.filepath = filedialog.askopenfilename()
        if self.filepath:
            self.file_label.configure(text=os.path.basename(self.filepath))
            self.share_button.configure(state="normal")
            self.copy_url_button.configure(state="disabled")
            self.save_qr_button.configure(state="disabled")
            self.qr_code_image = None
            self.qr_label.configure(image=self.qr_code_image)

    @staticmethod
    def generate_file_id() -> str:
        fid = ""
        for _ in range(10):
            fid += str(uuid.uuid4()).replace("-", "")
        return fid

    def start_sharing(self):
        file_id = self.generate_file_id()
        created, encrypting_key = self.register_file(file_id)

        if not created:
            tkinter.messagebox.showerror("Error", "Failed to share file")
            return

        self.shared_files[file_id] = {
            'path': self.filepath,
            'encrypting_key': encrypting_key,
        }

        print(f"Sharing file with ID: {file_id}")
        self.url = f"{TRACKER_URL}/{file_id}"
        self.generate_qr_code(self.url)
        self.copy_url_button.configure(state="normal")
        self.save_qr_button.configure(state="normal")
        self.update_shared_files_list()

    def register_file(self, file_id: str) -> tuple[bool, bytes]:
        filename = os.path.basename(self.filepath)
        size = os.path.getsize(self.filepath)
        timestamp = int(time.time())

        message = build_registration_message(file_id, self.port, filename, size, timestamp)
        signature = sign(self._signing_private_key, message)

        data = {
            'port': self.port,
            'filename': filename,
            'size': size,
            'peer_public_key': base64.b64encode(self._signing_public_key).decode(),
            'signature': base64.b64encode(signature).decode(),
            'timestamp': timestamp,
        }

        print(f"Registering file of size {size} bytes")

        try:
            session = get_proxied_session()
            response = session.post(f"{TRACKER_URL}/{file_id}", json=data)
        except ProxyUnavailableError as exc:
            print(f"Registration failed — no proxy: {exc}")
            return False, b""
        except Exception as exc:
            print(f"Registration request failed: {exc}")
            return False, b""

        if response.status_code == 200:
            print(f"Registered file {file_id} with tracker.")
            return True, base64.b64decode(response.json()["encrypting_key"])
        else:
            print(f"Failed to register file (HTTP {response.status_code})")
            return False, b""

    def start_http_file_server(self):
        from fastapi.responses import JSONResponse, Response
        import uvicorn

        @app.get("/{file_id}/exists")
        async def file_exists(file_id: str):
            if not file_id.isalnum():
                return {"exists": False}
            return {"exists": file_id in self.shared_files}

        @app.get("/{file_id}")
        async def serve_file(file_id: str):
            if not file_id.isalnum():
                return Response(status_code=404)

            entry = self.shared_files.get(file_id)
            if not entry:
                return JSONResponse(status_code=404, content={"detail": "File not found"})

            file_path = entry.get("path", "")
            encrypting_key = entry.get("encrypting_key", b"")

            if not (file_path and os.path.exists(file_path)):
                return JSONResponse(status_code=404, content={"detail": "File not found"})

            async def generate() -> AsyncGenerator[bytes, None]:
                with open(file_path, 'rb') as fh:
                    while True:
                        chunk = fh.read(4096)
                        if not chunk:
                            break
                        if self.server_stop_event.is_set() or file_id not in self.shared_files:
                            print("Server stopped or file unshared — aborting transfer")
                            break
                        yield encrypt(encrypting_key, chunk)

            return fastapi.responses.StreamingResponse(generate(), media_type='application/octet-stream')

        def run_server():
            uvicorn.run(app, host='0.0.0.0', port=self.port, log_level="info")

        threading.Thread(target=run_server, daemon=True).start()

    def generate_qr_code(self, url: str):
        qr = qrcode.QRCode(version=1, box_size=6, border=4)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white').resize((300, 300))
        self.qr_code_image = ImageTk.PhotoImage(img)
        self.qr_label.configure(image=self.qr_code_image)

    def copy_url(self):
        if self.url:
            self.clipboard_clear()
            self.clipboard_append(self.url)
            tkinter.messagebox.showinfo(title="URL Copied", message="The URL has been copied to the clipboard.")

    def save_qr_code(self):
        if self.qr_code_image:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
            )
            if file_path:
                qr = qrcode.QRCode(version=1, box_size=6, border=4)
                qr.add_data(self.url)
                qr.make(fit=True)
                qr.make_image(fill_color='black', back_color='white').save(file_path)
                tkinter.messagebox.showinfo(title="QR Code Saved", message="The QR Code has been saved successfully.")

    def update_shared_files_list(self):
        for widget in self.shared_files_frame.winfo_children():
            widget.destroy()

        for idx, (file_id, entry) in enumerate(self.shared_files.items()):
            file_name = os.path.basename(entry.get("path", ""))
            ctk.CTkLabel(self.shared_files_frame, text=file_name, anchor="w").grid(
                row=idx, column=0, sticky="ew", pady=5
            )
            ctk.CTkButton(
                self.shared_files_frame,
                text="Copy URL",
                command=lambda url=f"{TRACKER_URL}/{file_id}": self.copy_specific_url(url),
                width=80,
            ).grid(row=idx, column=1, padx=5)
            ctk.CTkButton(
                self.shared_files_frame,
                text="Save QR",
                command=lambda url=f"{TRACKER_URL}/{file_id}", fn=file_name: self.save_specific_qr_code(url, fn),
                width=80,
            ).grid(row=idx, column=2, padx=5)
            ctk.CTkButton(
                self.shared_files_frame,
                text="Stop Sharing",
                command=lambda fid=file_id: self.stop_sharing(fid),
                width=100,
            ).grid(row=idx, column=3, padx=5)

    def copy_specific_url(self, url: str):
        self.clipboard_clear()
        self.clipboard_append(url)
        tkinter.messagebox.showinfo(title="URL Copied", message="The URL has been copied to the clipboard.")

    def save_specific_qr_code(self, url: str, suggested_name: str = ""):
        qr = qrcode.QRCode(version=1, box_size=6, border=4)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')
        file_path = filedialog.asksaveasfilename(
            initialfile=f"{suggested_name}-p2p_QRcode",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        if file_path:
            img.save(file_path)
            tkinter.messagebox.showinfo(title="QR Code Saved", message="The QR Code has been saved successfully.")

    def stop_sharing(self, file_id: str):
        if file_id in self.shared_files:
            del self.shared_files[file_id]
            print(f"Stopped sharing file with ID: {file_id}")
            self.update_shared_files_list()

    def on_closing(self):
        for file_id in list(self.shared_files.keys()):
            del self.shared_files[file_id]
        self.server_stop_event.set()
        self.destroy()


def main():
    import time as _time
    tkapp = FileShareApp()
    tkapp.protocol("WM_DELETE_WINDOW", tkapp.on_closing)
    while not tkapp.server_stop_event.is_set():
        tkapp.update()
        _time.sleep(0.1)


if __name__ == '__main__':
    main()
