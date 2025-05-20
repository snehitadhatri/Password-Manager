import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import os
from cryptography.fernet import Fernet
import base64
import hashlib

DATA_FILE = "passwords.json"
KEY_FILE = "key.key"

class PasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")
        self.master.geometry("400x300")

        self.key = None
        self.fernet = None
        self.data = {}

        self.create_widgets()
        self.load_key()
        self.load_data()

    def create_widgets(self):
        self.label = tk.Label(self.master, text="Password Manager", font=("Arial", 16))
        self.label.pack(pady=10)

        self.login_button = tk.Button(self.master, text="Enter Master Password", command=self.login)
        self.login_button.pack(pady=5)

        self.add_button = tk.Button(self.master, text="Add Credential", command=self.add_credential, state=tk.DISABLED)
        self.add_button.pack(pady=5)

        self.get_button = tk.Button(self.master, text="Get Credential", command=self.get_credential, state=tk.DISABLED)
        self.get_button.pack(pady=5)

        self.delete_button = tk.Button(self.master, text="Delete Credential", command=self.delete_credential, state=tk.DISABLED)
        self.delete_button.pack(pady=5)

        self.exit_button = tk.Button(self.master, text="Exit", command=self.master.quit)
        self.exit_button.pack(pady=5)

    def load_key(self):
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "rb") as f:
                self.key = f.read()
        else:
            # No key file, create a dummy key for now (will be replaced after master password set)
            self.key = None

    def save_key(self):
        with open(KEY_FILE, "wb") as f:
            f.write(self.key)

    def derive_key(self, password: str) -> bytes:
        # Derive a key from the master password using SHA-256 and base64 encoding
        hash = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(hash)

    def load_data(self):
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "rb") as f:
                    encrypted_data = f.read()
                if self.fernet:
                    decrypted = self.fernet.decrypt(encrypted_data)
                    self.data = json.loads(decrypted.decode())
                else:
                    self.data = {}
            except Exception:
                self.data = {}
        else:
            self.data = {}

    def save_data(self):
        if self.fernet:
            encrypted = self.fernet.encrypt(json.dumps(self.data).encode())
            with open(DATA_FILE, "wb") as f:
                f.write(encrypted)

    def login(self):
        password = simpledialog.askstring("Master Password", "Enter master password:", show="*")
        if not password:
            messagebox.showwarning("Warning", "Master password is required.")
            return

        key = self.derive_key(password)
        self.fernet = Fernet(key)

        # If key file does not exist, save this key as the master key
        if not os.path.exists(KEY_FILE):
            self.key = key
            self.save_key()
            self.load_data()
            self.enable_buttons()
            messagebox.showinfo("Success", "Master password set and logged in.")
            return

        # If key file exists, verify key matches
        with open(KEY_FILE, "rb") as f:
            saved_key = f.read()
        if key == saved_key:
            self.key = key
            self.load_data()
            self.enable_buttons()
            messagebox.showinfo("Success", "Logged in successfully.")
        else:
            messagebox.showerror("Error", "Incorrect master password.")
            self.fernet = None

    def enable_buttons(self):
        self.add_button.config(state=tk.NORMAL)
        self.get_button.config(state=tk.NORMAL)
        self.delete_button.config(state=tk.NORMAL)
        self.login_button.config(state=tk.DISABLED)

    def add_credential(self):
        website = simpledialog.askstring("Add Credential", "Enter website:")
        if not website:
            return
        username = simpledialog.askstring("Add Credential", "Enter username:")
        if not username:
            return
        password = simpledialog.askstring("Add Credential", "Enter password:", show="*")
        if not password:
            return

        self.data[website] = {"username": username, "password": password}
        self.save_data()
        messagebox.showinfo("Success", f"Credential for {website} added.")

    def get_credential(self):
        website = simpledialog.askstring("Get Credential", "Enter website:")
        if not website:
            return
        cred = self.data.get(website)
        if cred:
            messagebox.showinfo("Credential", f"Website: {website}\nUsername: {cred['username']}\nPassword: {cred['password']}")
        else:
            messagebox.showerror("Error", "Credential not found.")

    def delete_credential(self):
        website = simpledialog.askstring("Delete Credential", "Enter website:")
        if not website:
            return
        if website in self.data:
            del self.data[website]
            self.save_data()
            messagebox.showinfo("Success", f"Credential for {website} deleted.")
        else:
            messagebox.showerror("Error", "Credential not found.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
