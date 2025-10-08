# Password Vault (CLI)

A simple command-line Password Vault built in Python.
All account data is encrypted using Fernet symmetric encryption with a key derived from your **master password** (PBKDF2-HMAC-SHA256 + salt).

## Features
- Master-password protected vault
- AES-based encryption via Fernet
- You'll have options to: Add, retrieve, list, and delete account passwords
- Encrypted JSON file storage
- Automatic salt generation

## How to run
1. Install dependencies:
  ```bash
pip install cryptography
```
2. Run the script
```
python vault.py
```
3. Create a master password on first time run, this will unlock your vault.

## Future Improvements
- Edit existing accounts
- GUI version



