import os
import json
import hashlib
import time
import base64
import shutil
import sys
from getpass4 import getpass
from dotenv import load_dotenv
from threading import Timer
from cryptography.fernet import Fernet

load_dotenv()

# Constants for user and vault management
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VAULTS_DIR = os.path.join(BASE_DIR, "..", "Vaults")
FILE_IN = os.path.join(BASE_DIR, "..", "file in")
FILE_OUT = os.path.join(BASE_DIR, "..", "file out")
USER_DATA_FILE = os.path.join(BASE_DIR, "users.json")
ENC_USER_DATA_FILE = os.path.join(BASE_DIR, "users.json.enc")
VAULT_METADATA_FILE = os.path.join(BASE_DIR, "vault_metadata.json")
ENC_VAULT_METADATA_FILE = os.path.join(BASE_DIR, "vault_metadata.json.enc")
SESSION_TIMEOUT = 300  # 5 minutes
SYSTEM_SECRET_KEY = os.getenv('SYSTEM_SECRET_KEY')
SYSTEM_SALT = os.getenv('SYSTEM_SALT')

# Initialize storage files if they do not exist
if not os.path.exists(VAULTS_DIR):
    os.makedirs(VAULTS_DIR)
if not os.path.exists(FILE_IN):
    os.makedirs(FILE_IN)
if not os.path.exists(FILE_OUT):
    os.makedirs(FILE_OUT)

# Session Management
session = {
    "authenticated_user": None,
    "session_expiry": None
}
session_timer = None

def reset_session_timer():
    global session_timer
    if session_timer:
        session_timer.cancel()
    session["session_expiry"] = time.time() + SESSION_TIMEOUT
    session_timer = Timer(SESSION_TIMEOUT, logout_user)
    session_timer.start()

def is_session_active():
    if session["authenticated_user"] and time.time() < session["session_expiry"]:
        reset_session_timer()
        return True
    logout_user()  # Logout if the session expired
    return False

def logout_user():
    global session_timer
    if session_timer:
        session_timer.cancel()
    session["authenticated_user"] = None
    session["session_expiry"] = None
    print("\nSession expired. Please authenticate again.")
    main_menu()

# Encryption/Decryption Functions
def generate_key(password, salt=None):

    if salt is None:
        salt = os.urandom(16)
    raw_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(raw_key), salt

# In use
def encrypt_file(vault_key, filepath, encrypted_path):
    fernet = Fernet(vault_key)
    with open(filepath, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(encrypted_path, 'wb') as enc_file:
        enc_file.write(encrypted_data)
    return encrypted_path

# In use
def decrypt_file(vault_key, encrypted_filepath, filename, destination_path):
    fernet = Fernet(vault_key)
    with open(encrypted_filepath, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    decrypted_path = os.path.join(f"{destination_path}", f"{filename}")
    with open(decrypted_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    return decrypted_path

# In use
def encrypt_userdata_file(password):
    if not os.path.exists(USER_DATA_FILE):
        return
    data_salt = bytes.fromhex(SYSTEM_SALT)
    data_key = password
    jsonKey, _ = generate_key(data_key, data_salt)
    fernet = Fernet(jsonKey)
    with open(USER_DATA_FILE, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    encrypted_path = ENC_USER_DATA_FILE
    with open(encrypted_path, 'wb') as enc_file:
        enc_file.write(encrypted_data)
    if os.path.exists(USER_DATA_FILE):
        os.remove(USER_DATA_FILE)
    else:
        print("user file not found!")
        return
    return encrypted_path

# In use
def encrypt_vaultdata_file(password):
    if not os.path.exists(VAULT_METADATA_FILE):
        return
    data_salt = bytes.fromhex(SYSTEM_SALT)
    data_key = password
    jsonKey, _ =generate_key(data_key, data_salt)
    fernet = Fernet(jsonKey)
    with open(VAULT_METADATA_FILE, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    encrypted_path = ENC_VAULT_METADATA_FILE
    with open(encrypted_path, 'wb') as enc_file:
        enc_file.write(encrypted_data)
    if os.path.exists(VAULT_METADATA_FILE):
        os.remove(VAULT_METADATA_FILE)
    else:
        print("vault_metadata.json file not found!")
        return
    return encrypted_path

# In use
def decrypt_userdata_file(password):
    decrypt_path = USER_DATA_FILE
    data_salt = bytes.fromhex(SYSTEM_SALT)
    data_key = password
    jsonKey, _ =generate_key(data_key, data_salt)
    fernet = Fernet(jsonKey)
    with open(ENC_USER_DATA_FILE, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(decrypt_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    return decrypt_path

# In use
def decrypt_vaultdata_file(password):
    decrypt_path = VAULT_METADATA_FILE
    data_salt = bytes.fromhex(SYSTEM_SALT)
    data_key = password
    jsonKey, _ =generate_key(data_key, data_salt)
    fernet = Fernet(jsonKey)
    with open(ENC_VAULT_METADATA_FILE, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(decrypt_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    return decrypt_path

# In use
def calculate_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# User Management
def create_user(username, password):
    with open(USER_DATA_FILE, 'r') as f:
        users = json.load(f)
    if username in users:
        print("User already exists!")
        return    
    key, salt =generate_key(password)
    users[username] = {"password_hash": key.hex(), "salt": salt.hex()}
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(users, f)
    print(f"User '{username}' registered successfully!")

def authenticate_user(username, password):
    with open(USER_DATA_FILE, 'r') as f:
        users = json.load(f)
    if username not in users:
        print("User does not exist!")
        return False
    salt = bytes.fromhex(users[username]["salt"])
    stored_password_hash = bytes.fromhex(users[username]["password_hash"])
    password_hash, _ = generate_key(password, salt)
    if stored_password_hash == password_hash:
        print("Authentication successful!")
        session["authenticated_user"] = username
        reset_session_timer()
        return True
    print("Incorrect password!")
    return False

# Delete user
def delete_user():

    if os.path.exists(VAULTS_DIR):
        vaults = os.listdir(VAULTS_DIR)
        for vault in vaults:
            vault_path = os.path.join(VAULTS_DIR, vault)
            shutil.rmtree(vault_path)
    if os.path.exists(USER_DATA_FILE):
        os.remove(USER_DATA_FILE)
    if os.path.exists(VAULT_METADATA_FILE):
        os.remove(VAULT_METADATA_FILE)
    
    if not os.path.exists(USER_DATA_FILE) and not os.path.exists(VAULT_METADATA_FILE) and not os.listdir(VAULTS_DIR):
        print("User deleted successfuly!")
        print("Good Bye!")
        first_menu()
    else:
        print("Something went wrong. Please be sure to close all files and try again.")
        return

# Vault Management
def create_vault(vault_name, password): 
    if not is_session_active():
        return
    username = session["authenticated_user"]
    reset_session_timer()

    if not os.path.exists(VAULT_METADATA_FILE):
        with open(VAULT_METADATA_FILE, 'w') as f:
            json.dump({}, f)
    key, salt = generate_key(password)
    enc_vault_name = hashlib.sha256(key + vault_name.encode('utf-8')).hexdigest()
    vault_path = os.path.join(VAULTS_DIR, enc_vault_name)
    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    if vault_name in vaults:
        print("Vault already exists!")
        return
    vaults[vault_name] = {"owner": username, "key": key.hex(), "salt": salt.hex(), "files": []}
    with open(VAULT_METADATA_FILE, 'w') as f:
        json.dump(vaults, f)
    if not os.path.exists(vault_path): 
        os.makedirs(vault_path)
        print(f"Vaul '{vault_name}' created at {vault_path}")
    else:
        print(f"Vault '{vault_name}' already exists.")

# Open the vault
def authenticate_vault(vault_name, vault_password):
    if not is_session_active():
        return None
    username = session["authenticated_user"]
    reset_session_timer()

    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    if vault_name not in vaults or vaults[vault_name]["owner"] != username:
        print("Access denied!")
        return None
    stored_salt = bytes.fromhex(vaults[vault_name]["salt"])
    stored_key = bytes.fromhex(vaults[vault_name]["key"])
    key, salt = generate_key(vault_password, stored_salt)
    if stored_key == key and salt.hex() == vaults[vault_name]["salt"]:
        print("Vault authentication successful!")
        return key
    print("Incorrect password!")
    return None

# List all vaults that user has
def list_vaults(username):
    if not is_session_active():
        return None
    username = session["authenticated_user"]
    reset_session_timer()
    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    user_vaults = [vault_name for vault_name, metadata in vaults.items() if metadata["owner"] == username]
    if user_vaults:
        print(f"Vaults owned by {username}:")
        for vault_name in user_vaults:
            print(f"  - {vault_name}")
    else:
        print(f"No vaults found for user {username}.")

# Delete a vault
def delete_vault(username, vault_name, vault_key):
    if not is_session_active(username):
        return None
    username = session["authenticated_user"]
    reset_session_timer()

    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    metadata = vaults.items()
    if vault_name not in vaults and metadata["owner"] != username:
        print("Vault not found!")
        return
    
    enc_vault_name = hashlib.sha256(vault_key + vault_name.encode('utf-8')).hexdigest()
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)

    if os.path.exists(vault_folder):
        shutil.rmtree(vault_folder)
    else:
        print("Vault folder not found!")
        return
    
    del vaults[vault_name]

    with open(VAULT_METADATA_FILE, 'w') as f:
        json.dump(vaults, f)
    print(f"Vault '{vault_name}' removed!")

# Add file to vault
def add_file_to_vault(vault_name, vault_key, filepath, username):
    if not is_session_active():
        return
    reset_session_timer()

    if not os.path.exists(filepath):
        print("File not found!")
        return
    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    metadata = vaults.items()
    if vault_name not in vaults and metadata["owner"] != username:
        print("Vault not found!")
        return
    enc_vault_name = hashlib.sha256(vault_key + vault_name.encode('utf-8')).hexdigest()
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)
    file_name = f"{os.path.basename(filepath)}"
    enc_file_name = hashlib.sha256(vault_key + file_name.encode('utf-8')).hexdigest()
    encrypted_path = os.path.join(vault_folder, f"{enc_file_name}.enc")

    encrypt_file(vault_key, filepath, encrypted_path)
    file_hash = calculate_file_hash(filepath)
    enc_file_hash = calculate_file_hash(encrypted_path)

    # Add metadata
    file_metadata = {
        "name": os.path.basename(filepath),
        "size": os.path.getsize(filepath),
        "hash": file_hash,
        "enc_hash": enc_file_hash,
        "date_added": time.strftime('%Y-%m-%d %H:%M:%S')
    }
    vaults[vault_name]["files"].append(file_metadata)
    with open(VAULT_METADATA_FILE, 'w') as f:
        json.dump(vaults, f)
    print(f"File '{os.path.basename(filepath)}' added to vault {vault_name}!")

# List files in vault
def list_files_in_vault(vault_name, username):
    if not is_session_active():
        return
    reset_session_timer()

    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    metadata = vaults.items()
    if vault_name not in vaults and metadata["owner"] != username:
        print("Vault not found!")
        return
    print(f"Files in vault '{vault_name}':")
    for file in vaults[vault_name]["files"]:
        print(f"  - {file['name']} (Size: {file['size']} bytes, Added: {file['date_added']})")

# Remove file from vault
def remove_file_from_vault(vault_name, file_name, username, vault_key):
    if not is_session_active():
        return
    reset_session_timer()

    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    metadata = vaults.items()
    if vault_name not in vaults and metadata["owner"] != username:
        print("Vault not found!")
        return

    file_metadata = next((file for file in vaults[vault_name]["files"] if file["name"] == file_name), None)
    if not file_metadata:
        print("File not found in vault!")
        return

    enc_vault_name = hashlib.sha256(vault_key + vault_name.encode('utf-8')).hexdigest()
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)
    enc_file_name = hashlib.sha256(vault_key + file_name.encode('utf-8')).hexdigest()
    encrypted_path = os.path.join(vault_folder, f"{enc_file_name}.enc")
    
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)
    else:
        print("Encrypted file not found!")
        return

    # Remove metadata
    vaults[vault_name]["files"].remove(file_metadata)
    with open(VAULT_METADATA_FILE, 'w') as f:
        json.dump(vaults, f)
    print(f"File '{file_name}' removed from vault!")

# Extract file from vault
def extract_file_from_vault(vault_name, vault_key, file_name, destination_path):
    if not is_session_active():
        return
    reset_session_timer()

    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    if vault_name not in vaults:
        print("Vault not found!")
        return

    file_name = file_name.strip()
    enc_file_name = hashlib.sha256(vault_key + file_name.encode()).hexdigest()
    enc_vault_name = hashlib.sha256(vault_key + vault_name.encode()).hexdigest()
    file_metadata = next((file for file in vaults[vault_name]["files"] if file["name"].lower() == file_name.lower()), None)
    if not file_metadata:
        print("File not found in vault!")
        return
    
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)
    encrypted_path = os.path.join(vault_folder, f"{enc_file_name}.enc")
    if not os.path.exists(encrypted_path):
        print("Encrypted file not found!")
        return
    enc_file_hash = calculate_file_hash(encrypted_path)
    stored_enc_file_hash = next((file["enc_hash"] for file in vaults[vault_name]["files"] if file["name"] == file_name), None)
    if enc_file_hash != stored_enc_file_hash:
        print("Encrypted file corrupted!")
        return
    decrypt_file(vault_key, encrypted_path, file_name, destination_path)
    decrypted_path = os.path.join(destination_path, f"{file_name}")
    file_hash = calculate_file_hash(decrypted_path)
    stored_file_hash = next((file["hash"] for file in vaults[vault_name]["files"] if file["name"] == file_name), None)
    if file_hash != stored_file_hash:
        print("Decrypted file corrupted!")
        return
    print(f"File '{file_metadata['name']}' extracted to '{destination_path}'")

# First menu loop
def first_menu():
    while True:
        print("\nSirius Vault")
        print("\n1. Create User")
        print("0. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            username = input("Username: ")
            user_password = getpass("Password: ")
            with open(USER_DATA_FILE, 'w') as f:
                json.dump({}, f)
            create_user(username, user_password)
            encrypt_userdata_file(user_password)
            main_menu()
        elif choice == "0":
            print("Exiting the Sirius Vault.")
            sys.exit()
        else:
            print("\nInvalid choice, please try again.")

# Main menu loop
def main_menu():
    while True:
        print("\nSirius Vault")
        print("\n1. Log in")
        print("0. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            username = input("Enter username: ")
            user_password = getpass("Enter password: ")
            decrypt_userdata_file(user_password)
            if authenticate_user(username, user_password):
                encrypt_userdata_file(user_password)
                authenticate_menu(username, user_password)
            else:
                encrypt_userdata_file()
        elif choice == "0":
            print("Exiting the Sirius Vault.")
            sys.exit()
        else:
            print("Invalid choice, please try again.")

# Authenticate menu loop
def authenticate_menu(username, user_password):
    while True:
        print(f"\nWelcome back {username}!")
        print("\n1. Create Vault")
        print("2. Authenticate Vault")
        print("3. List my vaults")
        print("4. Delete a vault")
        print("5. Delete user (This will delete all user data)")
        print("6. Logout")
        print("0. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            vault_name = input("Enter vault name: ")
            vault_password = getpass("Enter vault password: ")
            if os.path.exists(ENC_VAULT_METADATA_FILE):
                decrypt_vaultdata_file(user_password)
            create_vault(vault_name, vault_password)
            encrypt_vaultdata_file(user_password)
        elif choice == "2":
            vault_name = input("Enter vault name: ")
            vault_password = getpass("Enter vault password: ")
            decrypt_vaultdata_file(user_password)
            vault_key = authenticate_vault(vault_name, vault_password)
            encrypt_vaultdata_file(user_password)
            if vault_key:
                print(f"Access granted to vault: {vault_name}")
                vault_menu(vault_name, vault_password, username, user_password)
        elif choice == "3":
            decrypt_vaultdata_file(user_password)
            list_vaults(username)
            encrypt_vaultdata_file(user_password)
        elif choice == "4":
            decrypt_vaultdata_file(user_password)
            list_vaults(username)
            encrypt_vaultdata_file(user_password)
            vault_name = input("Enter vault name you want to delete: ")
            vault_password = getpass("Enter vault password: ")
            decrypt_vaultdata_file(user_password)
            vault_key = authenticate_vault(vault_name, vault_password)
            encrypt_vaultdata_file(user_password)
            if vault_key:
                decrypt_vaultdata_file(user_password)
                delete_vault(username, vault_name, vault_key)
                encrypt_vaultdata_file(user_password)
            else:
                print("Wrong password!")
        elif choice == "5":
            print("Warning you are about to delete all vaults, files and user data!")
            consent_confirm = input("Do you wish to continue?(Y/N)")
            if consent_confirm.lower() == "y" or consent_confirm.lower() == "yes":
                username = input("Enter username: ")
                user_password = getpass("Enter password: ")
                if authenticate_user(username, user_password):
                    decrypt_userdata_file(user_password)
                    decrypt_vaultdata_file(user_password)
                    delete_user()
                else:
                    print("Wrong username or password")
        elif choice == "6":
            logout_user()
        elif choice == "0":
            print("Exiting the Sirius Vault.")
            sys.exit()
        else:
            print("Invalid choice, please try again.")

# Vault menu loop
def vault_menu(vault_name, vault_password, username, user_password):
    while True:
        print(f"\nYou are in Vault {vault_name}")
        print("\n1. Add File to Vault")
        print("2. List Files in Vault")
        print("3. Remove File from Vault")
        print("4. Extract File from Vault")
        print("5. Back")
        print("0. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            decrypt_vaultdata_file(user_password)
            vault_key = authenticate_vault(vault_name, vault_password)
            encrypt_vaultdata_file(user_password)
            if vault_key:
                files = os.listdir(FILE_IN)
                print("Files in input folder: ")
                for filename in files:
                    print(filename)
                file_name = input("Enter file name: ")
                file_remove = input("Do you want to remove file after adding it to vault?(Y/N)")
                filepath = os.path.join(FILE_IN, f"{file_name}")
                decrypt_vaultdata_file(user_password)
                add_file_to_vault(vault_name, vault_key, filepath, username)
                encrypt_vaultdata_file(user_password)
                if file_remove.lower() == "y" or file_remove.lower() == "yes":
                    os.remove(filepath)
            else:
                print("Wrong password!")
        elif choice == "2":
            decrypt_vaultdata_file(user_password)
            list_files_in_vault(vault_name, username)
            encrypt_vaultdata_file(user_password)
        elif choice == "3":
            file_name = input("Enter file name to remove: ")
            vault_password = getpass("Enter vault password: ")
            decrypt_vaultdata_file(user_password)
            vault_key = authenticate_vault(vault_name, vault_password)
            encrypt_vaultdata_file(user_password)
            if vault_key:
                decrypt_vaultdata_file(user_password)
                remove_file_from_vault(vault_name, file_name, username, vault_key)
                encrypt_vaultdata_file(user_password)
            else:
                print("Wrong password!")
        elif choice == "4":
            vault_password = getpass("Enter vault password: ")
            decrypt_vaultdata_file(user_password)
            vault_key = authenticate_vault(vault_name, vault_password)
            encrypt_vaultdata_file(user_password)
            if vault_key:
                decrypt_vaultdata_file(user_password)
                list_files_in_vault(vault_name, username)
                encrypt_vaultdata_file(user_password)
                file_name = input("Enter file name to extract: ")
                destination_path = FILE_OUT
                file_remove = input("Do you want to remove file from the vault after extraction?(Y/N)")
                decrypt_vaultdata_file(user_password)
                extract_file_from_vault(vault_name, vault_key, file_name, destination_path)
                encrypt_vaultdata_file(user_password)
                if file_remove.lower() == "y" or file_remove.lower() == "yes":
                    decrypt_vaultdata_file(user_password)
                    remove_file_from_vault(vault_name, file_name, username, vault_key)
                    encrypt_vaultdata_file(user_password)
            else:
                print("Wrong password!")
        elif choice == "5":
            authenticate_menu(username)
        elif choice == "0":
            print("Exiting the Sirius Vault.")
            sys.exit()
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    if os.path.exists(USER_DATA_FILE) or os.path.exists(ENC_USER_DATA_FILE):
        main_menu()
    else:
        first_menu()
