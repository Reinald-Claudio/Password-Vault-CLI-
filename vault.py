import os
import json
import base64
import json
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken


def load_create_salt():
    salt_path = "vault.salt"
    if os.path.exists(salt_path):
        with open(salt_path, "rb") as f:
            salt = f.read()
    else:
        salt = os.urandom(16)
        with open(salt_path, "wb") as f:
            f.write(salt)
    return salt

def derive_key(salt, iterations=100000):
    # print("password sanity test")
    master_password = input("Enter master password: ")
    password_bytes = master_password.encode("utf-8") # Essential: converting human
    # string into sequence of bytes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes)) # converting to base64,
    # because fernet only accepts base64
    return key

def load_vault(f, vault_path):
    if not os.path.exists(vault_path):
        return {}

    with open(vault_path, "rb") as file:
        encrypted_bytes = file.read()                   # reading the bytes
        decrypted_bytes = f.decrypt(encrypted_bytes)    # decrypting the encrypted bytes
        json_str = decrypted_bytes.decode("utf-8")      # Converting the bytes to a string
        data = json.loads(json_str)                     # Converting the string to a dictionary
        return data

def save_vault(f, vault_path, data):
    json_str = json.dumps(data)                         # Converting data to string
    json_bytes = json_str.encode("utf-8")               # Encoding the string to bytes for fernet to read

    encrypted = f.encrypt(json_bytes)                   # Encrypting the JSON bytes

    # Saving the encrypted bytes to vault.json
    with open(vault_path, "wb") as file:
        file.write(encrypted)

# Load / create salt
salt = load_create_salt()

# Prompt for master password, and derive encryption key for fernet
key = derive_key(salt)
f = Fernet(key)

# Vault Path
vault_path = "vault.json"

# Load existing vault, exit if invalid master password
try:
    data = load_vault(f, vault_path="vault.json")
except InvalidToken:
    print("Invalid master password or vault is corrupted.")
    exit()

while True:
    print("\n========= Menu options =========")
    print("[1] Add new account + password")
    print("[2] Retrieve account password?")
    print("[3] List all account names (no passwords)")
    print("[4] Delete an account")
    print("[5] Quit")
    choice = input("Select an option. (Choose 1-4): ")

    if choice == "1":
        # Prompt to add new account
        account = input("Enter account name: ")
        password = input("Enter password for this account: ")

        # Add to the vault, then save
        data[account] = password
        save_vault(f, vault_path, data)
        print("Data added, account secured.")

    elif choice == "2":
        r_account = input("Enter account name: ")
        retrieved = data.get(r_account)

        # if key account name is found, print value.
        if retrieved is not None:
            input("Account found. Press Enter to reveal password..")
            print(f"Password for '{r_account}': {retrieved}")
        else:
            print(f"No password found for account '{r_account}'")

    elif choice == "3":
        if not data:
            print("No accounts stored yet.")
        else:
            print("Stored accounts:")
            for key in data.keys():
                print(f"- {key}")

    elif choice == "4":
        d_account = input("Enter account name to delete: ")

        if d_account in data:
            del data[d_account]
            save_vault(f, vault_path, data)
            print(f"Account '{d_account}' deleted.")
        else:
            print(f"{d_account} account not found.")

    elif choice == "5":
        break
    else:
        print("Bruh.. Invalid choice.")







