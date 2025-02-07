import tkinter as tk
from tkinter import filedialog, messagebox
import os
import secrets

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:
    print("Error: The cryptography package is not installed. Please install it using 'pip install cryptography'.")
    raise e

ALLOWED_EXTENSIONS = {
    '.txt', '.docx', '.pdf', '.docm', '.dotx', '.doc', '.wbk',
    '.xlsx', '.xlsm', '.sltm', '.xls', '.xlm', '.xlsb', '.xla',
    '.xlam', '.xll', '.pptx', '.pptm', '.potx', '.potm', '.ppsx',
    '.ppsm', '.eml', '.odp', '.ods', '.odt', '.rtf'
}

derived_salt = None

def generate_key():
    return secrets.token_bytes(32)

def encrypt_file(file_path, key_bytes):
    with open(file_path, 'rb') as f:
        data = f.read()

    nonce = os.urandom(12)
    aesgcm = AESGCM(key_bytes)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    out_file = file_path + ".enc"
    with open(out_file, 'wb') as f:

        if derived_salt is not None:
            f.write(b"SGFS" + derived_salt + nonce + ciphertext)
        else:
            f.write(nonce + ciphertext)
    return out_file

def decrypt_file(file_path, key_bytes, passphrase_provided=None):
    with open(file_path, 'rb') as f:
        data = f.read()

    if data.startswith(b"SGFS"):

        salt = data[4:20]       # 16 bytes salt
        nonce = data[20:32]     # 12 bytes nonce
        ciphertext = data[32:]
        if passphrase_provided is None:
            raise ValueError("Passphrase required for decryption of salted file.")
        password_bytes = passphrase_provided.encode('utf-8')
        if len(password_bytes) < 4:
            password_bytes = password_bytes.ljust(4, b'\0')
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
        except ImportError as e:
            raise ImportError("PBKDF2HMAC or hashes module is not available. Please update your cryptography package.") from e
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=300000,
        )

        key_bytes = kdf.derive(password_bytes)
        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    else:

        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    if file_path.endswith(".enc"):
        out_file = file_path[:-4]
    else:
        out_file = file_path + ".dec"
    with open(out_file, 'wb') as f:
        f.write(plaintext)
    return out_file

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(generated_key_var.get())
    messagebox.showinfo("Copied", "Encryption key copied to clipboard.")

def paste_from_clipboard():
    try:
        key = root.clipboard_get()
        encryption_key_entry.delete(0, tk.END)
        encryption_key_entry.insert(0, key)
    except tk.TclError:
        messagebox.showerror("Error", "Clipboard is empty or inaccessible.")

def on_derive_key():
    global derived_salt
    passphrase = passphrase_var.get().strip()
    if not passphrase:
        messagebox.showerror("Error", "Please enter a passphrase for key derivation.")
        return

    password_bytes = passphrase.encode('utf-8')

    if len(password_bytes) < 4:
        password_bytes = password_bytes.ljust(4, b'\0')
    salt = secrets.token_bytes(16)

    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
    except ImportError as e:
        messagebox.showerror("Error", "PBKDF2HMAC or hashes module is not available. Please update your cryptography package.")
        return

    try:

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=300000,
        )
        key_bytes = kdf.derive(password_bytes)
    except Exception as e:
        messagebox.showerror("Error", f"Key derivation failed: {str(e)}")
        return

    derived_salt = salt
    key_hex = key_bytes.hex()
    generated_key_var.set(key_hex)
    messagebox.showinfo("Salt", f"Key derived using PBKDF2-HMAC.\nSalt (hex): {salt.hex()}\nThis salt is now embedded in the encrypted file and is not required for decryption.")

def on_select_file():
    file_path = filedialog.askopenfilename(
        title="Select file to encrypt or decrypt",
        filetypes=[("Allowed Files",
                    "*.txt;*.docx;*.pdf;*.docm;*.dotx;*.doc;*.wbk;"
                    "*.xlsx;*.xlsm;*.sltm;*.xls;*.xlm;*.xlsb;*.xla;"
                    "*.xlam;*.xll;*.pptx;*.pptm;*.potx;*.potm;*.ppsx;"
                    "*.ppsm;*.eml;*.odp;*.ods;*.odt;*.rtf;*.enc")]
    )
    if file_path:
        selected_file_var.set(file_path)

def on_encrypt_file():
    file_path = selected_file_var.get()
    if not file_path:
        messagebox.showerror("Error", "No file selected.")
        return

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        messagebox.showerror("Error", f"File type {ext} is not allowed.")
        return

    key_str = encryption_key_var.get().strip()
    if key_str:
        try:
            key_bytes = bytes.fromhex(key_str)
            if len(key_bytes) != 32:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Invalid encryption key. It must be a 64-character hex string representing 32 bytes.")
            return
    elif generated_key_var.get().strip():
        try:
            key_bytes = bytes.fromhex(generated_key_var.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid generated key. Please derive a new key.")
            return
    else:
        messagebox.showerror("Error", "No encryption key provided. Please derive one from a passphrase or paste one.")
        return

    try:
        out_file = encrypt_file(file_path, key_bytes)
        messagebox.showinfo("Success", f"File encrypted successfully:\n{out_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

def on_decrypt_file():
    file_path = selected_file_var.get()
    if not file_path:
        messagebox.showerror("Error", "No file selected.")
        return

    with open(file_path, 'rb') as f:
        header = f.read(4)
    if header == b"SGFS":
        passphrase = passphrase_var.get().strip()
        if not passphrase:
            messagebox.showerror("Error", "Passphrase required for decryption of salted file.")
            return
        try:
            out_file = decrypt_file(file_path, None, passphrase)
            messagebox.showinfo("Success", f"File decrypted successfully:\n{out_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    else:
        key_str = encryption_key_var.get().strip()
        if key_str:
            try:
                key_bytes = bytes.fromhex(key_str)
                if len(key_bytes) != 32:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error", "Invalid decryption key. It must be a 64-character hex string representing 32 bytes.")
                return
        elif generated_key_var.get().strip():
            try:
                key_bytes = bytes.fromhex(generated_key_var.get().strip())
            except ValueError:
                messagebox.showerror("Error", "Invalid generated key. Please derive a new key.")
                return
        else:
            messagebox.showerror("Error", "No decryption key provided. Please derive one from a passphrase or paste one.")
            return
        try:
            out_file = decrypt_file(file_path, key_bytes)
            messagebox.showinfo("Success", f"File decrypted successfully:\n{out_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

root = tk.Tk()
root.title("ClatsGuard File Encrypter v1.00 (AES-256-GCM w/ PBKDF2-HMAC)")

main_frame = tk.Frame(root)
main_frame.pack(padx=10, pady=10)

ascii_art = """ ██████╗██╗      █████╗ ████████╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██╔════╝██║     ██╔══██╗╚══██╔══╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║     ██║     ███████║   ██║   ███████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║     ██║     ██╔══██║   ██║   ╚════██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
╚██████╗███████╗██║  ██║   ██║   ███████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
                                                                                   

███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗███████╗██████╗        
██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗       
█████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   █████╗  ██████╔╝       
██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██╔══╝  ██╔══██╗       
███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║   ███████╗██║  ██║       
╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚══════╝╚═╝  ╚═╝       """
ascii_label = tk.Label(main_frame, text=ascii_art, fg="red", font=("Courier", 10), justify="left")
ascii_label.pack()

branding_frame = tk.Frame(main_frame)
branding_frame.pack(fill="x", pady=(5, 0))
clatsguard_label = tk.Label(branding_frame, text="C L A T S G U A R D        F I L E        E N C R Y P T O R",
                            fg="blue", font=("Arial", 12, "bold"))
clatsguard_label.pack(side="left", anchor="w")
version_label = tk.Label(branding_frame, text="Version 1.00", fg="red", font=("Arial", 12, "bold"))
version_label.pack(side="right", anchor="e")

author_label = tk.Label(main_frame, text="By Joshua M Clatney - Ethical Pentesting Enthusiast", font=("Arial", 10))
author_label.pack(anchor="w", pady=(0, 10))

key_frame = tk.Frame(main_frame)
key_frame.pack(fill="x", pady=(5, 10))

passphrase_var = tk.StringVar()
tk.Label(key_frame, text="Seed Value:").grid(row=0, column=0, sticky="e", pady=(5, 0))
passphrase_entry = tk.Entry(key_frame, textvariable=passphrase_var, width=70, show="*")
passphrase_entry.grid(row=0, column=1, padx=5, pady=(5, 0))
tk.Button(key_frame, text="Derive Key", command=on_derive_key).grid(row=0, column=2, padx=5, pady=(5, 0))

generated_key_var = tk.StringVar()
tk.Label(key_frame, text="Generated Key:").grid(row=1, column=0, sticky="e")
gen_key_entry = tk.Entry(key_frame, textvariable=generated_key_var, state="readonly", width=70)
gen_key_entry.grid(row=1, column=1, padx=5)
tk.Button(key_frame, text="Copy", command=copy_to_clipboard).grid(row=1, column=2, padx=5)

encryption_key_var = tk.StringVar()
tk.Label(key_frame, text="Enter Key:").grid(row=2, column=0, sticky="e", pady=(5, 0))
encryption_key_entry = tk.Entry(key_frame, textvariable=encryption_key_var, width=70)
encryption_key_entry.grid(row=2, column=1, padx=5, pady=(5, 0))
tk.Button(key_frame, text="Paste", command=paste_from_clipboard).grid(row=2, column=2, padx=5, pady=(5, 0))

file_frame = tk.Frame(main_frame)
file_frame.pack(fill="x", pady=(5, 10))

selected_file_var = tk.StringVar()
tk.Label(file_frame, text="Selected File:").grid(row=0, column=0, sticky="e")
file_path_entry = tk.Entry(file_frame, textvariable=selected_file_var, width=70, state="readonly")
file_path_entry.grid(row=0, column=1, padx=5)
tk.Button(file_frame, text="Browse", command=on_select_file).grid(row=0, column=2, padx=5)

tk.Button(main_frame, text="Encrypt File", command=on_encrypt_file,
          bg="green", fg="white", font=("Arial", 12, "bold")).pack(pady=10)

tk.Button(main_frame, text="Decrypt File", command=on_decrypt_file,
          bg="blue", fg="white", font=("Arial", 12, "bold")).pack(pady=10)

if __name__ == '__main__':
    root.mainloop()