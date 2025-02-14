import tkinter as tk
from tkinter import filedialog, messagebox
import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HEADER = b"SGFS"
HEADER_LENGTH = len(HEADER)
SALT_LENGTH = 16
NONCE_LENGTH = 12
ALLOWED_EXTENSIONS = {
    '.txt', '.docx', '.pdf', '.docm', '.dotx', '.doc', '.wbk',
    '.xlsx', '.xlsm', '.sltm', '.xls', '.xlm', '.xlsb', '.xla',
    '.xlam', '.xll', '.pptx', '.pptm', '.potx', '.potm', '.ppsx',
    '.ppsm', '.eml', '.odp', '.ods', '.odt', '.enc', '.rtf', '.xml'
}


class ClatsGuardApp:
    def __init__(self, master):
        """Initialize the application UI and state."""
        self.master = master
        self.master.title("ClatsGuard File Encrypter v1.00 (AES-256-GCM w/ PBKDF2-HMAC)")
        self.derived_salt = None  # Will store the salt when deriving a key

        self.passphrase_var = tk.StringVar()
        self.generated_key_var = tk.StringVar()
        self.encryption_key_var = tk.StringVar()
        self.selected_file_var = tk.StringVar()

        self.build_ui()

    def build_ui(self):
        main_frame = tk.Frame(self.master)
        main_frame.pack(padx=10, pady=10)

        ascii_art = (
            " ██████╗██╗      █████╗ ████████╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ \n"
            "██╔════╝██║     ██╔══██╗╚══██╔══╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗\n"
            "██║     ██║     ███████║   ██║   ███████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║\n"
            "██║     ██║     ██╔══██║   ██║   ╚════██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║\n"
            "╚██████╗███████╗██║  ██║   ██║   ███████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝\n"
            " ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ \n\n"
            "███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗███████╗██████╗        \n"
            "██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗       \n"
            "█████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   █████╗  ██████╔╝       \n"
            "██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██╔══╝  ██╔══██╗       \n"
            "███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║   ███████╗██║  ██║       \n"
            "╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚══════╝╚═╝  ╚═╝       "
        )
        ascii_label = tk.Label(main_frame, text=ascii_art, fg="red", font=("Courier", 10), justify="left")
        ascii_label.pack()

        branding_frame = tk.Frame(main_frame)
        branding_frame.pack(fill="x", pady=(5, 0))
        tk.Label(branding_frame, text="C L A T S G U A R D        F I L E        E N C R Y P T E R",
                 fg="blue", font=("Arial", 12, "bold")).pack(side="left", anchor="w")
        tk.Label(branding_frame, text="Version 1.01", fg="red", font=("Arial", 12, "bold")).pack(side="right", anchor="e")
        tk.Label(main_frame, text="By Joshua M Clatney - Ethical Pentesting Enthusiast", font=("Arial", 10)).pack(
            anchor="w", pady=(0, 10))

        key_frame = tk.Frame(main_frame)
        key_frame.pack(fill="x", pady=(5, 10))
        tk.Label(key_frame, text="Seed Value:").grid(row=0, column=0, sticky="e", pady=(5, 0))
        self.passphrase_entry = tk.Entry(key_frame, textvariable=self.passphrase_var, width=70, show="*")
        self.passphrase_entry.grid(row=0, column=1, padx=5, pady=(5, 0))
        tk.Button(key_frame, text="Derive Key", command=self.on_derive_key).grid(row=0, column=2, padx=5, pady=(5, 0))

        tk.Label(key_frame, text="Generated Key:").grid(row=1, column=0, sticky="e")
        self.gen_key_entry = tk.Entry(key_frame, textvariable=self.generated_key_var, state="readonly", width=70)
        self.gen_key_entry.grid(row=1, column=1, padx=5)
        tk.Button(key_frame, text="Copy", command=self.copy_to_clipboard).grid(row=1, column=2, padx=5)

        tk.Label(key_frame, text="Enter Key:").grid(row=2, column=0, sticky="e", pady=(5, 0))
        self.encryption_key_entry = tk.Entry(key_frame, textvariable=self.encryption_key_var, width=70)
        self.encryption_key_entry.grid(row=2, column=1, padx=5, pady=(5, 0))
        tk.Button(key_frame, text="Paste", command=self.paste_from_clipboard).grid(row=2, column=2, padx=5, pady=(5, 0))

        file_frame = tk.Frame(main_frame)
        file_frame.pack(fill="x", pady=(5, 10))
        tk.Label(file_frame, text="Selected File:").grid(row=0, column=0, sticky="e")
        self.file_path_entry = tk.Entry(file_frame, textvariable=self.selected_file_var, width=70, state="readonly")
        self.file_path_entry.grid(row=0, column=1, padx=5)
        tk.Button(file_frame, text="Browse", command=self.on_select_file).grid(row=0, column=2, padx=5)

        tk.Button(main_frame, text="Encrypt File", command=self.on_encrypt_file,
                  bg="green", fg="white", font=("Arial", 12, "bold")).pack(pady=10)
        tk.Button(main_frame, text="Decrypt File", command=self.on_decrypt_file,
                  bg="blue", fg="white", font=("Arial", 12, "bold")).pack(pady=10)

    def copy_to_clipboard(self):
        self.master.clipboard_clear()
        self.master.clipboard_append(self.generated_key_var.get())
        messagebox.showinfo("Copied", "Encryption key copied to clipboard.")

    def paste_from_clipboard(self):
        try:
            key = self.master.clipboard_get()
            self.encryption_key_entry.delete(0, tk.END)
            self.encryption_key_entry.insert(0, key)
        except tk.TclError:
            messagebox.showerror("Error", "Clipboard is empty or inaccessible.")

    def on_derive_key(self):
        passphrase = self.passphrase_var.get().strip()
        if not passphrase:
            messagebox.showerror("Error", "Please enter a passphrase for key derivation.")
            return

        password_bytes = passphrase.encode('utf-8')
        if len(password_bytes) < 4:
            password_bytes = password_bytes.ljust(4, b'\0')
        salt = secrets.token_bytes(SALT_LENGTH)

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=300000,
            )
            key_bytes = kdf.derive(password_bytes)
        except Exception as e:
            messagebox.showerror("Error", f"Key derivation failed: {e}")
            return

        self.derived_salt = salt
        key_hex = key_bytes.hex()
        self.generated_key_var.set(key_hex)
        messagebox.showinfo("Salt", f"Key derived using PBKDF2-HMAC.\nSalt (hex): {salt.hex()}\n"
                                    f"This salt is now embedded in the encrypted file and is not required for decryption.")

    def on_select_file(self):
        file_path = filedialog.askopenfilename(
            title="Select file to encrypt or decrypt",
            filetypes=[("Allowed Files",
                        "*.txt *.docx *.pdf *.docm *.dotx *.doc *.wbk "
                        "*.xlsx *.xlsm *.sltm *.xls *.xlm *.xlsb *.xla "
                        "*.xlam *.xll *.pptx *.pptm *.potx *.potm *.ppsx "
                        "*.ppsm *.eml *.odp *.ods *.odt *.rtf *.enc *.xml")]
        )
        if file_path:
            self.selected_file_var.set(file_path)

    def get_key(self):

        key_str = self.encryption_key_var.get().strip()
        if key_str:
            try:
                key_bytes = bytes.fromhex(key_str)
                if len(key_bytes) != 32:
                    raise ValueError
                return key_bytes
            except ValueError:
                messagebox.showerror("Error", "Invalid key. It must be a 64-character hex string representing 32 bytes.")
                return None
        elif self.generated_key_var.get().strip():
            try:
                return bytes.fromhex(self.generated_key_var.get().strip())
            except ValueError:
                messagebox.showerror("Error", "Invalid generated key. Please derive a new key.")
                return None
        else:
            messagebox.showerror("Error", "No key provided. Please derive one from a passphrase or paste one.")
            return None

    def encrypt_file(self, file_path, key_bytes):

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            raise IOError(f"Failed to read file: {e}")

        nonce = os.urandom(NONCE_LENGTH)
        aesgcm = AESGCM(key_bytes)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        out_file = file_path + ".enc"
        try:
            with open(out_file, 'wb') as f:
                if self.derived_salt is not None:

                    f.write(HEADER + self.derived_salt + nonce + ciphertext)
                else:

                    f.write(nonce + ciphertext)
        except Exception as e:
            raise IOError(f"Failed to write encrypted file: {e}")
        return out_file

    def decrypt_file(self, file_path, key_bytes=None, passphrase=None):

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            raise IOError(f"Failed to read file: {e}")

        if data.startswith(HEADER):

            salt = data[HEADER_LENGTH:HEADER_LENGTH + SALT_LENGTH]
            nonce = data[HEADER_LENGTH + SALT_LENGTH:HEADER_LENGTH + SALT_LENGTH + NONCE_LENGTH]
            ciphertext = data[HEADER_LENGTH + SALT_LENGTH + NONCE_LENGTH:]
            if passphrase is None:
                raise ValueError("Passphrase required for decryption of salted file.")
            password_bytes = passphrase.encode('utf-8')
            if len(password_bytes) < 4:
                password_bytes = password_bytes.ljust(4, b'\0')
            try:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=300000,
                )
                key_bytes = kdf.derive(password_bytes)
            except Exception as e:
                raise ValueError(f"Key derivation failed: {e}")
        else:

            nonce = data[:NONCE_LENGTH]
            ciphertext = data[NONCE_LENGTH:]

        try:
            aesgcm = AESGCM(key_bytes)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

        if file_path.endswith(".enc"):
            out_file = file_path[:-4]
        else:
            out_file = file_path + ".dec"

        try:
            with open(out_file, 'wb') as f:
                f.write(plaintext)
        except Exception as e:
            raise IOError(f"Failed to write decrypted file: {e}")
        return out_file

    def on_encrypt_file(self):
        file_path = self.selected_file_var.get()
        if not file_path:
            messagebox.showerror("Error", "No file selected.")
            return

        ext = os.path.splitext(file_path)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            messagebox.showerror("Error", f"File type {ext} is not allowed.")
            return

        key_bytes = self.get_key()
        if key_bytes is None:
            return

        try:
            out_file = self.encrypt_file(file_path, key_bytes)
            messagebox.showinfo("Success", f"File encrypted successfully:\n{out_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def on_decrypt_file(self):
        file_path = self.selected_file_var.get()
        if not file_path:
            messagebox.showerror("Error", "No file selected.")
            return

        try:
            with open(file_path, 'rb') as f:
                header = f.read(HEADER_LENGTH)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")
            return

        if header == HEADER:
            passphrase = self.passphrase_var.get().strip()
            if not passphrase:
                messagebox.showerror("Error", "Passphrase required for decryption of salted file.")
                return
            try:
                out_file = self.decrypt_file(file_path, passphrase=passphrase)
                messagebox.showinfo("Success", f"File decrypted successfully:\n{out_file}")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
        else:
            key_bytes = self.get_key()
            if key_bytes is None:
                return
            try:
                out_file = self.decrypt_file(file_path, key_bytes=key_bytes)
                messagebox.showinfo("Success", f"File decrypted successfully:\n{out_file}")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")


if __name__ == '__main__':
    root = tk.Tk()
    app = ClatsGuardApp(root)
    root.mainloop()
