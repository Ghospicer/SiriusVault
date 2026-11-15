import os
import io
import json
import hashlib
import hmac
import argon2
import time
import base64
import shutil
import sys
import mimetypes
import secrets
import subprocess
import ctypes
import stat
import struct
from PIL import Image
from dotenv import load_dotenv
from threading import Timer
from cryptography.fernet import Fernet

# Constants for user, password and vault management
# GLOBAL PATH VARIABLES
STORAGE_ROOT = None
VAULTS_DIR = None
DATA_FOLDER = None
USER_DIR = None
RECOVERY_DIR = None
USER_ENV = None
USER_SYSTEM_SALT = None
USER_DATA_FILE = None
ENC_USER_DATA_FILE = None
VAULT_METADATA_FILE = None
ENC_VAULT_METADATA_FILE = None
PASS_METADATA_FILE = None
ENC_PASS_METADATA_FILE = None

# LOCAL PATHS
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMP_DIR = os.path.join(BASE_DIR, "..", "temp")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
SESSION_TIMEOUT = 300  # 5 minutes
CHUNK_SIZE = 64 * 1024 * 1024

# Encryption/Decryption Functions (LEGACY)
def generate_key_legacy(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    raw_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(raw_key), salt

# In use (LEGACY)
def encrypt_file_legacy(vault_key, filepath, encrypted_path):
    fernet = Fernet(vault_key)
    with open(filepath, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(encrypted_path, 'wb') as enc_file:
        enc_file.write(encrypted_data)
    return encrypted_path

# In use (LEGACY)
def decrypt_file_legacy(vault_key, encrypted_filepath, filename, destination_path):
    fernet = Fernet(vault_key)
    with open(encrypted_filepath, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    decrypted_path = os.path.join(f"{destination_path}", f"{filename}")
    with open(decrypted_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    return decrypted_path

# In use (LEGACY)
def encrypt_userdata_file_legacy(password):
    if not os.path.exists(USER_DATA_FILE):
        return None
    data_salt = bytes.fromhex(USER_SYSTEM_SALT)
    data_key = password
    try:
        jsonKey, _ = generate_key_legacy(data_key, data_salt)
        fernet = Fernet(jsonKey)
        with open(USER_DATA_FILE, 'rb') as file:
            file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)
        encrypted_path = ENC_USER_DATA_FILE
        with open(encrypted_path, 'wb') as enc_file:
            enc_file.write(encrypted_data)
        if os.path.exists(USER_DATA_FILE):
            secure_delete(USER_DATA_FILE)
        else:
            return None
    except Exception as e:
        print(f"[ERROR] User data ENC failed: {e}")
        return None
    return encrypted_path
    
# In use (LEGACY)
def encrypt_vaultdata_file_legacy(password):
    if not os.path.exists(VAULT_METADATA_FILE):
        return None
    data_salt = bytes.fromhex(USER_SYSTEM_SALT)
    data_key = password
    try:
        jsonKey, _ = generate_key_legacy(data_key, data_salt)
        fernet = Fernet(jsonKey)
        with open(VAULT_METADATA_FILE, 'rb') as file:
            file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)
        encrypted_path = ENC_VAULT_METADATA_FILE
        with open(encrypted_path, 'wb') as enc_file:
            enc_file.write(encrypted_data)
        if os.path.exists(VAULT_METADATA_FILE):
            secure_delete(VAULT_METADATA_FILE)
        else:
            return None
    except Exception as e:
        print(f"[ERROR] Vault data ENC failed: {e}")
        return None
    return encrypted_path

# In Use (LEGACY)
def encrypt_passdata_file_legacy(password):
    if not os.path.exists(PASS_METADATA_FILE):
        return None
    data_salt = bytes.fromhex(USER_SYSTEM_SALT)
    data_key = password
    try:
        jsonKey, _ = generate_key_legacy(data_key, data_salt)
        fernet = Fernet(jsonKey)
        with open(PASS_METADATA_FILE, 'rb') as file:
            file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)
        encrypted_path = ENC_PASS_METADATA_FILE
        with open(encrypted_path, 'wb') as enc_file:
            enc_file.write(encrypted_data)
        if os.path.exists(PASS_METADATA_FILE):
            secure_delete(PASS_METADATA_FILE)
        else:
            return None
    except Exception as e:
        print(f"[ERROR] PM data ENC failed: {e}")
        return None
    return encrypted_path

# In use (LEGACY)
def decrypt_userdata_file_legacy(password):
    if not os.path.exists(ENC_USER_DATA_FILE):
        return None
    decrypted_path = USER_DATA_FILE
    data_salt = bytes.fromhex(USER_SYSTEM_SALT)
    data_key = password
    try:
        jsonKey, _ = generate_key_legacy(data_key, data_salt)
        fernet = Fernet(jsonKey)
        with open(ENC_USER_DATA_FILE, 'rb') as enc_file:
            encrypted_data = enc_file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(decrypted_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)
    except Exception as e:
        print(f"[ERROR] User data DEC(Legacy) failed: {e}")
        return None
    return decrypted_path

# In use (LEGACY)
def decrypt_vaultdata_file_legacy(password):
    if not os.path.exists(ENC_VAULT_METADATA_FILE):
        return None
    decrypted_path = VAULT_METADATA_FILE
    data_salt = bytes.fromhex(USER_SYSTEM_SALT)
    data_key = password
    try:
        jsonKey, _ = generate_key_legacy(data_key, data_salt)
        fernet = Fernet(jsonKey)
        with open(ENC_VAULT_METADATA_FILE, 'rb') as enc_file:
            encrypted_data = enc_file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(decrypted_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)
    except Exception as e:
        print(f"[ERROR] Vault data DEC failed: {e}")
        return None
    return decrypted_path

# In Use (LEGACY)
def decrypt_passdata_file_legacy(password):
    if not os.path.exists(ENC_PASS_METADATA_FILE):
        return None
    decrypted_path = PASS_METADATA_FILE
    data_salt = bytes.fromhex(USER_SYSTEM_SALT)
    data_key = password
    try:
        jsonKey, _ = generate_key_legacy(data_key, data_salt)
        fernet = Fernet(jsonKey)
        with open(ENC_PASS_METADATA_FILE, 'rb') as enc_file:
            encrypted_data = enc_file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(decrypted_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)
    except Exception as e:
        print(f"[ERROR] PM data DEC failed: {e}")
        return None
    return decrypted_path

def secure_delete(filepath, passes=3):

    if not os.path.exists(filepath):
        return
    
    try:
        length = os.path.getsize(filepath)
        if length == 0:
            os.remove(filepath)
            return True
        
        with open(filepath, "ba+", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))

            f.seek(0)
            f.write(b'\x00' * length)
            os.fsync(f.fileno())

        dir_name = os.path.dirname(filepath)
        random_name = os.path.join(dir_name, secrets.token_hex(8) + ".tmp")
        os.rename(filepath, random_name)

        os.remove(random_name)
        return True
    except Exception as e:
        print(f"[WARNING] Secure delete failed for {filepath}. Falling back to normal remove. Error: {e}")
        try: os.remove(filepath)
        except: pass
        return False
