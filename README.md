# MyVault 🔐  
A secure password manager written in Python.  

MyVault provides a safe way to generate, store, and manage your passwords. It uses **encryption, hashing, and two-factor authentication (2FA)** to keep your credentials secure.  

---

## Features ✨
- 🔒 Vault encrypted with Fernet (symmetric encryption)  
- 🔑 Master password protection  
- 📱 Two-Factor Authentication (2FA) via Google Authenticator  
- 🛡️ Password hashing and key derivation  
- 🎲 Secure random password generator (min 12 chars)  
- 📋 Optional clipboard copy (auto-clears after 60s)  
- ⏳ Idle timeout for added security  
- 📂 Add, remove, and search password entries  

---

## Project Structure 🗂️
src/
├── README.md
├── requirements.txt
└── src/
    ├── main.py
    ├── vault/
    │   ├── __init__.py
    │   ├── vault.py
    │   └── password_info.py
    ├── utils/
    │   ├── __init__.py
    │   └── password_generator.py
    └── Authentication/
        ├── __init__.py
        ├── MFA.py
        └── hashing.py

## Install Dependencies

pip install -r requirements.txt


## Security Highlights 🔒

Encrypted vault ensures data confidentiality

HMAC prevents vault tampering

Strong random passwords with no repeats

Clipboard clears after 60 seconds

Auto log-out after inactivity