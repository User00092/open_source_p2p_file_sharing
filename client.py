from lib.security.cryption import generate_keypair, encrypt

import requests
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

from lib.utils import find_free_port

import base64
# p2pfiles.provolance.com
TRACKER_URL = 'http://localhost:8080/fileshare'

app = fastapi.FastAPI()


class FileShareApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("P2P File Share via QR Code")
        self.geometry("600x700")

        # Initialize variables
        self.filepath = None
        self.qr_code_image = None
        self.port = 51321 or find_free_port()  # You can change the port if needed
        self.shared_files = {}  # Store shared files with their IDs
        self.url = None

        # Create an event to control server shutdown
        self.server_stop_event = threading.Event()

        # Start the HTTP file server in a separate thread
        self.server_thread = threading.Thread(target=self.start_http_file_server, daemon=True)
        self.server_thread.start()
        print("File server is running...")

        self.create_widgets()

    def create_widgets(self):
        # Create main scrollable frame
        self.main_frame = ctk.CTkScrollableFrame(self, width=600, height=700)
        self.main_frame.pack(fill="both", expand=True)

        # Configure grid layout
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Title label
        self.title_label = ctk.CTkLabel(
            self.main_frame,
            text="P2P File Share via QR Code",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.title_label.grid(row=0, column=0, pady=(20, 10))

        # File selection button
        self.select_file_button = ctk.CTkButton(
            self.main_frame, text="Select File", command=self.select_file
        )
        self.select_file_button.grid(row=1, column=0, pady=10, padx=20, sticky="ew")

        # Label to show selected file
        self.file_label = ctk.CTkLabel(self.main_frame, text="No file selected")
        self.file_label.grid(row=2, column=0, pady=10)

        # Start sharing button
        self.share_button = ctk.CTkButton(
            self.main_frame, text="Start Sharing", command=self.start_sharing, state="disabled"
        )
        self.share_button.grid(row=3, column=0, pady=10, padx=20, sticky="ew")

        # QR Code display
        self.qr_label = ctk.CTkLabel(self.main_frame, text="")
        self.qr_label.grid(row=4, column=0, pady=20)

        # Copy URL button
        self.copy_url_button = ctk.CTkButton(
            self.main_frame, text="Copy URL", command=self.copy_url, state="disabled"
        )
        self.copy_url_button.grid(row=5, column=0, pady=10, padx=20, sticky="ew")

        # Save QR Code button
        self.save_qr_button = ctk.CTkButton(
            self.main_frame, text="Save QR Code", command=self.save_qr_code, state="disabled"
        )
        self.save_qr_button.grid(row=6, column=0, pady=10, padx=20, sticky="ew")

        # Shared files label
        self.shared_files_label = ctk.CTkLabel(
            self.main_frame,
            text="Files Being Shared:",
            font=ctk.CTkFont(weight="bold")
        )
        self.shared_files_label.grid(row=7, column=0, pady=(20, 5), padx=20, sticky="w")

        # Shared files list
        self.shared_files_frame = ctk.CTkFrame(self.main_frame)
        self.shared_files_frame.grid(row=8, column=0, padx=20, pady=10, sticky="nsew")
        self.shared_files_frame.grid_columnconfigure(0, weight=1)

        self.main_frame.grid_rowconfigure(8, weight=1)

        # Update the shared files list
        self.update_shared_files_list()

    def select_file(self):
        self.filepath = filedialog.askopenfilename()
        if self.filepath:
            self.file_label.configure(text=os.path.basename(self.filepath))
            self.share_button.configure(state="normal")

            self.copy_url_button.configure(state="disabled")
            self.save_qr_button.configure(state="disabled")

            self.qr_code_image = None

            # Display QR code in GUI
            self.qr_label.configure(image=self.qr_code_image)

    @staticmethod
    def generate_file_id():
        fid = ""
        for _ in range(10):
            fid += str(uuid.uuid4()).replace("-", "")

        return fid

    def start_sharing(self):
        file_id = self.generate_file_id()

        created, encrypting_key = self.register_file(file_id)

        if not created:
            tkinter.messagebox.showerror("Failed to share file")
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

    def register_file(self, file_id) -> [bool, str]:
        # Register with the tracker server
        data = {
            'port': self.port,
            'filename': os.path.basename(self.filepath),
            'size': os.path.getsize(self.filepath),
        }

        print(f"Registering file of size {data['size']} bytes")
        response = requests.post(f"{TRACKER_URL}/{file_id}", json=data)
        response_json = response.json()
        if response.status_code == 200:
            print(f"Registered file {file_id} with tracker.")
            return True, base64.b64decode(response_json["encrypting_key"])
        else:
            print(f"Failed to register file: {response.text}")
            return False, ""

    def start_http_file_server(self):
        import os
        import threading
        from fastapi.responses import FileResponse, JSONResponse, Response
        import uvicorn

        @app.get("/{file_id}/exists")
        async def file_exists(file_id: str):
            if not file_id.isalnum():
                return {"exists": False}

            file_path = self.shared_files.get(file_id, None)
            return {"exists": file_path is not None}

        @app.get("/{file_id}")
        async def serve_file(file_id: str):
            if not file_id.isalnum():
                return Response(status_code=404)

            file_path = self.shared_files.get(file_id, {}).get("path", "")
            encrypting_key = self.shared_files.get(file_id, {}).get("encrypting_key", "")
            if file_path != "" and os.path.exists(file_path):
                async def generate() -> AsyncGenerator[bytes, None]:
                    with open(file_path, 'rb') as file:
                        while True:
                            chunk = file.read(4096)
                            if not chunk:
                                break

                            encrypted_chunk = encrypt(encrypting_key, chunk)
                            yield encrypted_chunk

                return fastapi.responses.StreamingResponse(generate(), media_type='application/octet-stream', headers={
                    'Content-Disposition': f'attachment; filename="{os.path.basename(file_path)}"',
                    # 'Content-Length': str(os.path.getsize(file_path))
                })
            else:
                return JSONResponse(status_code=404, content={"detail": "File not found"})

        def run_server():
            uvicorn.run(
                app,
                host='0.0.0.0',
                port=self.port,
                log_level="info"
            )

        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()

    def generate_qr_code(self, url):
        qr = qrcode.QRCode(
            version=1,
            box_size=6,
            border=4
        )
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')

        # Convert image to PhotoImage
        img = img.resize((300, 300))
        self.qr_code_image = ImageTk.PhotoImage(img)

        # Display QR code in GUI
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
                # Re-generate the QR code to save
                qr = qrcode.QRCode(
                    version=1,
                    box_size=6,
                    border=4
                )
                qr.add_data(self.url)
                qr.make(fit=True)
                img = qr.make_image(fill_color='black', back_color='white')
                img.save(file_path)
                tkinter.messagebox.showinfo(title="QR Code Saved", message="The QR Code has been saved successfully.")

    def update_shared_files_list(self):
        # Clear previous widgets in the frame
        for widget in self.shared_files_frame.winfo_children():
            widget.destroy()

        for idx, (file_id, file_path) in enumerate(self.shared_files.items()):
            file_path = self.shared_files.get(file_id, {}).get("path", "")
            file_name = os.path.basename(file_path)
            file_label = ctk.CTkLabel(self.shared_files_frame, text=f"{file_name}", anchor="w")
            file_label.grid(row=idx, column=0, sticky="ew", pady=5)
            copy_button = ctk.CTkButton(
                self.shared_files_frame,
                text="Copy URL",
                command=lambda url=f"{TRACKER_URL}/{file_id}": self.copy_specific_url(url),
                width=80
            )
            copy_button.grid(row=idx, column=1, padx=5)
            save_qr_button = ctk.CTkButton(
                self.shared_files_frame,
                text="Save QR",
                command=lambda url=f"{TRACKER_URL}/{file_id}",
                               file_name=f"{os.path.basename(file_path)}": self.save_specific_qr_code(url, file_name),
                width=80
            )
            save_qr_button.grid(row=idx, column=2, padx=5)
            stop_button = ctk.CTkButton(
                self.shared_files_frame,
                text="Stop Sharing",
                command=lambda fid=file_id: self.stop_sharing(fid),
                width=100
            )
            stop_button.grid(row=idx, column=3, padx=5)

    def copy_specific_url(self, url):
        self.clipboard_clear()
        self.clipboard_append(url)
        tkinter.messagebox.showinfo(title="URL Copied", message="The URL has been copied to the clipboard.")

    def save_specific_qr_code(self, url, suggested_name=""):
        qr = qrcode.QRCode(
            version=1,
            box_size=6,
            border=4
        )
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

    def stop_sharing(self, file_id):
        # Unregister the file and remove it from the shared files
        if file_id in self.shared_files:
            del self.shared_files[file_id]
            print(f"Stopped sharing file with ID: {file_id}")
            self.update_shared_files_list()

    def on_closing(self):
        # Unregister all shared files upon closing
        for file_id in list(self.shared_files.keys()):
            del self.shared_files[file_id]
        # Stop the server
        self.server_stop_event.set()
        self.destroy()


def main():
    import time
    tkapp = FileShareApp()

    tkapp.protocol("WM_DELETE_WINDOW", tkapp.on_closing)

    while not tkapp.server_stop_event.is_set():
        tkapp.update()
        time.sleep(0.1)


if __name__ == '__main__':
    main()
