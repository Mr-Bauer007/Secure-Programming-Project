# Import necessary modules
import tkinter as tk  # GUI framework
from tkinter import filedialog, messagebox, ttk  # For file selection dialogs, message popups, and styled widgets
import requests  # For making HTTP requests to the server
import json  # For parsing and formatting JSON
import os  # For interacting with the file system

# API key used for authenticating with the server
API_KEY = "my-super-secret-api-key"

# URL of the server (must be HTTPS to trigger SSL verification)
SERVER_URL = "https://localhost:5000"

# Path to the CA certificate used to verify the server's SSL certificate
VERIFY_SSL = False

# GUI Application class
class SecureClientApp:
    def __init__(self, master):
        # Set the main window
        self.master = master
        master.title("Secure File Encryption/Decryption Tool")
        master.geometry("600x400")  # Set window size

        self.file_path = None  # Path of the selected file

        # Create tabbed layout using ttk Notebook
        self.tab_control = ttk.Notebook(master)
        self.encrypt_tab = ttk.Frame(self.tab_control)
        self.decrypt_tab = ttk.Frame(self.tab_control)

        # Add tabs for encryption and decryption
        self.tab_control.add(self.encrypt_tab, text='Encrypt File')
        self.tab_control.add(self.decrypt_tab, text='Decrypt File')
        self.tab_control.pack(expand=1, fill='both')

        # Build the UI for each tab
        self.build_encrypt_tab()
        self.build_decrypt_tab()

    def build_encrypt_tab(self):
        # UI for encryption tab
        ttk.Label(self.encrypt_tab, text="Select File to Encrypt:").pack(pady=10)
        self.enc_file_label = ttk.Label(self.encrypt_tab, text="No file selected")
        self.enc_file_label.pack()

        # Browse button for file selection
        ttk.Button(self.encrypt_tab, text="Browse", command=self.select_file_to_encrypt).pack(pady=5)

        # Password input
        ttk.Label(self.encrypt_tab, text="Password:").pack(pady=10)
        self.enc_password_entry = ttk.Entry(self.encrypt_tab, show="*")
        self.enc_password_entry.pack()

        # Encrypt button
        ttk.Button(self.encrypt_tab, text="Encrypt", command=self.encrypt_file).pack(pady=20)

    def build_decrypt_tab(self):
        # UI for decryption tab
        ttk.Label(self.decrypt_tab, text="Select Encrypted File:").pack(pady=10)
        self.dec_file_label = ttk.Label(self.decrypt_tab, text="No file selected")
        self.dec_file_label.pack()

        # Browse button for encrypted file
        ttk.Button(self.decrypt_tab, text="Browse", command=self.select_file_to_decrypt).pack(pady=5)

        # Password input
        ttk.Label(self.decrypt_tab, text="Password:").pack(pady=10)
        self.dec_password_entry = ttk.Entry(self.decrypt_tab, show="*")
        self.dec_password_entry.pack()

        # Decrypt button
        ttk.Button(self.decrypt_tab, text="Decrypt", command=self.decrypt_file).pack(pady=20)

    def select_file_to_encrypt(self):
        # Open file dialog to choose file to encrypt
        path = filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.enc_file_label.config(text=os.path.basename(path))  # Show filename in label

    def select_file_to_decrypt(self):
        # Open file dialog to choose encrypted file
        path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
        if path:
            self.file_path = path
            self.dec_file_label.config(text=os.path.basename(path))  # Show filename in label

    def encrypt_file(self):
        # Validate inputs
        if not self.file_path or not self.enc_password_entry.get():
            messagebox.showerror("Error", "File and password are required")
            return

        # Prepare and send the POST request to the encryption endpoint
        with open(self.file_path, 'rb') as f:
            files = {'file': f}
            data = {'password': self.enc_password_entry.get()}
            headers = {'x-api-key': API_KEY}

            try:
                response = requests.post(
                    f"{SERVER_URL}/encrypt",  # Endpoint for encryption
                    files=files,
                    data=data,
                    headers=headers,
                    verify=VERIFY_SSL,# 🔐 SSL certificate verification using custom CA
                    timeout=10  
                )
                response.raise_for_status()  # Raise exception for HTTP errors
                download_url = response.json().get("download_url")
                messagebox.showinfo("Success", f"File encrypted.\nDownload from: {download_url}")
            except requests.exceptions.SSLError:
                messagebox.showerror("SSL Error", "SSL verification failed. Check certificate or connection.")
            except requests.exceptions.ConnectionError:
                messagebox.showerror("Connection Error", "Cannot connect to the server. Is it running?")
            except Exception as e:
                messagebox.showerror("Encryption Failed", str(e))

    def decrypt_file(self):
        # Validate inputs
        if not self.file_path or not self.dec_password_entry.get():
            messagebox.showerror("Error", "File and password are required")
            return

        # Prepare and send the POST request to the decryption endpoint
        with open(self.file_path, 'rb') as f:
            files = {'file': f}
            data = {'password': self.dec_password_entry.get()}
            headers = {'x-api-key': API_KEY}

            try:
                response = requests.post(
                    f"{SERVER_URL}/decrypt-file",  # Endpoint for decryption
                    files=files,
                    data=data,
                    headers=headers,
                    verify=VERIFY_SSL,  # 🔐 SSL verification using the CA cert
                    timeout=10
                )
                if response.status_code == 400:
                    messagebox.showwarning("Decryption Failed", "Wrong password or file is corrupted.")
                else:
                    response.raise_for_status()
                    download_url = response.json().get("download_url")
                    messagebox.showinfo("Success", f"File decrypted.\nDownload from: {download_url}")
            except requests.exceptions.SSLError:
                messagebox.showerror("SSL Error", "SSL verification failed. Check certificate or connection.")
            except requests.exceptions.ConnectionError:
                messagebox.showerror("Connection Error", "Cannot connect to the server. Is it running?")
            except Exception as e:
                messagebox.showerror("Decryption Failed", str(e))

# Launch the GUI application
if __name__ == '__main__':
    root = tk.Tk()
    app = SecureClientApp(root)
    root.mainloop()
