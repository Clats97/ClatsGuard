# ClatsGuard File Encrypter (AES-256-GCM with PBKDF2-HMAC)

**Version:** 1.01
**Author:** Joshua M Clatney aka (Clats97)- Ethical Pentesting Enthusiast 

![Screenshot 2025-02-07 131933](https://github.com/user-attachments/assets/8c8a90c0-aab4-4f7c-86df-bf6c6310953b)

**Overview**
ClatsGuard File Encryptor is a Python-based GUI application for securely encrypting and decrypting files. It uses AES-256-GCM for authenticated encryption, and PBKDF2-HMAC for key derivation from a user-provided passphrase.

**Key Features**

- **AES-256-GCM**: Ensures data confidentiality and integrity with authenticated encryption.
- **PBKDF2-HMAC Key Derivation**: Strengthens passphrase-based keys with salt and multiple iterations.
- **Hex Key Support**: Allows use of raw 256-bit hex keys if you already have them.
- **Hex Key Generation**: Generates secure 256-bit keys if neccessary.
- **GUI with Tkinter**: User-friendly interface for easy file selection and encryption/decryption.
- **Supported File Types**: `.txt`, `.docx`, `.pdf`, `.xls`, `.pptx`, `.rtf`, and more (see code for full list).

**Requirements**

- **Python 3.6+** (Tested with Python 3.12.1)
- **cryptography** library (`pip install cryptography`)
- **tkinter** (usually included with most Python installations on Windows/macOS; on Linux, install via your package manager)

**Installation**

1. Clone or download this repository.
2. Install the required Python libraries:
   pip install cryptography

**Key Management**

•	Passphrase-Derived Keys: You can generate a key from any passphrase. It is recommended to use a strong passphrase for better security

•	Hex Keys: If you already have a 256-bit hex key, you can directly paste it into the key field.

**Encryption Workflow**

1.	Click Browse to select the file.
2.	Optionally enter a passphrase in the "Seed Value" field and click Derive Key to generate a new key.
or
Paste an existing 256-bit hex key into the "Enter Key" field.
3.	Click Encrypt File.
4.	The tool generates an .enc file which contains the encrypted data, and if applicable, the salt header.

**Decryption Workflow**

1.	Click Browse to select the .enc file.
2.	Enter the passphrase used to generate the key.
3.	Click Decrypt File.
4.	The tool creates a new file with the original content.

**Advanced Configuration**

•	Iteration Count: Currently set to 300,000 iterations for PBKDF2-HMAC. For specialized requirements, modify this value in the source code. Higher iterations add more security, but slow down the key derivation process.

•	Allowed File Extensions: Expand or reduce the set of allowed file types by editing the ALLOWED_EXTENSIONS set in the source code.

**Troubleshooting**

•	Invalid Key Error: Ensure you are using the correct passphrase or hex key. The tool expects a 64-character hex string for a direct key, corresponding to 256-bits.

•	Missing cryptography: Run pip install cryptography. On some systems, you might need to install additional dev libraries or upgrade pip/setuptools.

**Author**

Joshua M Clatney (Clats97)

Ethical Pentesting Enthusiast

Copyright 2025 Joshua M Clatney (Clats97)

**DISCLAIMER: This project comes with no warranty, express or implied. The author is not responsible for abuse, misuse, or vulnerabilities. Please use responsibly and ethically in accordance with relevant laws, regulations, legislation and best practices.**
