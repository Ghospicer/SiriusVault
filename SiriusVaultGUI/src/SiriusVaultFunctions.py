import os
import io
import json
import hashlib
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

# Session Management
session = {
    "authenticated_user": None,
    "session_expiry": None,
    "session_timeout_index": 1
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

def update_user_timeout_setting(username, password, new_index):
    
    load_user_context(username)
    if not os.path.exists(ENC_USER_DATA_FILE):
        print("User data file not encrypted.")
        return False
    try:
        decrypt_userdata_file(password)
        with open(USER_DATA_FILE, 'r') as f:
            user_data = json.load(f)
        user_data["session_timeout_index"] = new_index
        with open(USER_DATA_FILE, 'w') as f:
            json.dump(user_data, f)
        reset_session_timer()
        encrypt_userdata_file(password)
        return True
    except Exception as e:
        encrypt_userdata_file(password)
        print(f"Session timeout setting not saved: {e}")
        return False

def clean_memory():
    global USER_DIR, VAULTS_DIR, RECOVERY_DIR
    global USER_DATA_FILE, VAULT_METADATA_FILE, PASS_METADATA_FILE
    global ENC_USER_DATA_FILE, ENC_VAULT_METADATA_FILE, ENC_PASS_METADATA_FILE
    global USER_ENV, USER_SYSTEM_SALT

    USER_DIR = None
    VAULTS_DIR = None
    RECOVERY_DIR = None
    USER_DATA_FILE = None
    VAULT_METADATA_FILE = None
    PASS_METADATA_FILE = None
    ENC_USER_DATA_FILE= None
    ENC_VAULT_METADATA_FILE = None
    ENC_PASS_METADATA_FILE = None
    USER_ENV = None
    USER_SYSTEM_SALT = None

    if 'SYSTEM_SALT' in os.environ:
        del os.environ['SYSTEM_SALT']
    
    print("[INFO] Global variables wiped from memory.")

def logout_user():
    global session_timer
    if session_timer:
        session_timer.cancel()
    session["authenticated_user"] = None
    session["session_expiry"] = None
    clean_memory()
    print("\nSession ended. Please authenticate again.")
    return True

def exit_program():
    global session_timer
    if session_timer:
        session_timer.cancel()
    print("Exiting Sirius Vault.")
    sys.exit()

# .env
def set_file_readonly(USER_ENV):
    try: os.chmod(USER_ENV, stat.S_IREAD)
    except: pass

def remove_readonly(USER_ENV):
    try: os.chmod(USER_ENV, stat.S_IWRITE)
    except: pass

def handle_remove_readonly(func, path, exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)

def create_user_system_salt():
    
    new_salt = secrets.token_hex(16)
    if os.path.exists(USER_ENV): remove_readonly(USER_ENV)
    try:
        with open(USER_ENV, "w") as f:
            f.write(f"SYSTEM_SALT={new_salt}")
        set_file_readonly(USER_ENV)
        print("User Salt created!")
    except Exception as e:
        print(f"User salt creation error: {e}")

def initialize_user_system_salt():
    load_dotenv(USER_ENV, override=True)
    raw_env = os.getenv('SYSTEM_SALT')
    salt_from_env = raw_env if raw_env and raw_env.strip() else None
    final_salt = None
    if salt_from_env:
        final_salt = salt_from_env
        return final_salt
    else:
        print("[WARNING] System cannot find the SALT.")

# CONFIG FUNC (TEST)
def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None
    
# Save config
def save_config(storage_path):
    config_data = {
        "last_storage_root": os.path.abspath(storage_path),
        "last_access_date": time.strftime('%Y-%m-%d %H:%M:%S')
    }
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_data, f, indent=4)
    except IOError as e:
        print(f"[ERROR] Configurations cannot saved: {e}")

# INIT FUNC
def initialize_storage(target_path=None, default=True):

    global STORAGE_ROOT, VAULTS_DIR, DATA_FOLDER

    if default:
        STORAGE_ROOT = os.path.join(BASE_DIR, "..")
        DATA_FOLDER = os.path.join(STORAGE_ROOT, "SiriusData")
    else:
        if target_path is None:
            print("ERROR: You need to declare a path for setup.")
            return False
        
        raw_path = os.path.abspath(target_path)
        STORAGE_ROOT = os.path.join(raw_path, "SiriusVault")
        DATA_FOLDER = os.path.join(STORAGE_ROOT, "SiriusData")
        if not os.path.exists(STORAGE_ROOT):
            try:
                os.makedirs(STORAGE_ROOT)
            except OSError as e:
                print(f"ERROR: Storage root can not created or not reachable: {e}")
                return False

    if not os.path.exists(DATA_FOLDER):
        try:
            os.makedirs(DATA_FOLDER)
        except OSError as e:
            print(f"[ERROR] Data directory can not created or not reachable: {e}")
            return False
    save_config(STORAGE_ROOT)
    return True

def load_user_context(username):
    
    global USER_DIR, VAULTS_DIR, RECOVERY_DIR, USER_ENV, USER_DATA_FILE, ENC_USER_DATA_FILE, VAULT_METADATA_FILE, ENC_VAULT_METADATA_FILE, PASS_METADATA_FILE, ENC_PASS_METADATA_FILE

    user_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()
    backup_name = username + "backup"
    backup_hash = hashlib.sha256(backup_name.encode('utf-8')).hexdigest()
    USER_DIR = os.path.join(DATA_FOLDER, user_hash)

    VAULTS_DIR = os.path.join(USER_DIR, "Vaults")

    RECOVERY_DIR = os.path.join(USER_DIR, f"{backup_hash}")
    USER_ENV = os.path.join(USER_DIR, ".env")
    USER_DATA_FILE = os.path.join(USER_DIR, "user.json")
    ENC_USER_DATA_FILE = os.path.join(USER_DIR, "user.json.enc")
    VAULT_METADATA_FILE = os.path.join(USER_DIR, "vault_metadata.json")
    ENC_VAULT_METADATA_FILE = os.path.join(USER_DIR, "vault_metadata.json.enc")
    PASS_METADATA_FILE = os.path.join(USER_DIR, "pass_metadata.json")
    ENC_PASS_METADATA_FILE = os.path.join(USER_DIR, "pass_metadata.json.enc")

    return USER_DIR

def move_user_data(username, new_path):
    global DATA_FOLDER, USER_DIR
    user_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()
    current_user_dir = USER_DIR

    target_storage_root = os.path.join(os.path.abspath(new_path), "SiriusVault")
    target_data_folder = os.path.join(target_storage_root, "SiriusData")
    target_user_dir = os.path.join(target_data_folder, user_hash)

    if os.path.exists(target_user_dir):
        return "EXISTS"
    
    try:
        if not os.path.exists(target_data_folder):
            os.makedirs(target_data_folder)
        
        shutil.copytree(current_user_dir, target_user_dir)

        if os.path.exists(target_user_dir):
            shutil.rmtree(current_user_dir, onerror=handle_remove_readonly)
            return "SUCCESS"
        else:
            return "ERROR"
    except Exception as e:
        print(f"[ERROR] User data move failed: {e}")
        return "ERROR"

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
            os.remove(USER_DATA_FILE)
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
            os.remove(VAULT_METADATA_FILE)
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
            os.remove(PASS_METADATA_FILE)
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
        print(f"[ERROR] User data DEC failed: {e}")
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

# Eencryption/Decryption Functions
def generate_key(password, salt=None):
    if salt == None:
        salt = os.urandom(16)

    try:
        raw_key = argon2.low_level.hash_secret_raw(
            secret = password.encode('utf-8'),
            salt = salt,
            time_cost = 3, 
            memory_cost = 102400,
            parallelism = 2,
            hash_len = 64,
            type = argon2.low_level.Type.ID 
        )
        encryption_key = base64.urlsafe_b64encode(raw_key[:32])
        auth_hash = base64.urlsafe_b64encode(raw_key[32:])
        return encryption_key, auth_hash, salt
    except Exception as e:
        print(f"[ERROR] Argon2 key generation failed: {e}")
        return None, None, None

# In use
def encrypt_file(enc_key_b64, filepath, encrypted_path):
    raw_key = base64.urlsafe_b64decode(enc_key_b64)
    aesgcm = AESGCM(raw_key)

    with open(filepath, 'rb') as f_in, open(encrypted_path, 'wb') as f_out:
        chunk_index = 0
        
        while True:
            chunk = f_in.read(CHUNK_SIZE)

            if not chunk:
                break

            nonce = os.urandom(12)
            aad = struct.pack('<Q', chunk_index)
            encrypted_chunk = aesgcm.encrypt(nonce, chunk, aad)
            f_out.write(struct.pack('<I', len(encrypted_chunk)))
            f_out.write(nonce)
            f_out.write(encrypted_chunk)
            chunk_index += 1
    return encrypted_path

# In use
def decrypt_file(enc_key_b64, encrypted_filepath, filename, destination_path):
    raw_key = base64.urlsafe_b64decode(enc_key_b64)
    aesgcm = AESGCM(raw_key)
    decrypted_path = os.path.join(destination_path, f"{filename}")

    with open(encrypted_filepath, 'rb') as f_in, open(decrypted_path, 'wb') as f_out:
        chunk_index = 0

        while True:
            length_bytes = f_in.read(4)

            if not length_bytes:
                break

            chunk_length = struct.unpack('<I', length_bytes)[0]
            nonce = f_in.read(12)
            encrypted_chunk = f_in.read(chunk_length)
            aad = struct.pack('<Q', chunk_index)
            decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, aad)
            f_out.write(decrypted_chunk)
            chunk_index += 1
        
    return decrypted_path

# In use
def encrypt_userdata_file(enc_key):
    if not os.path.exists(USER_DATA_FILE):
        return None
    try:
        encrypt_file(enc_key, USER_DATA_FILE, ENC_USER_DATA_FILE)
        os.remove(USER_DATA_FILE)
        return ENC_USER_DATA_FILE
    except Exception as e:
        print(f"[ERROR] User data ENC failed: {e}")
        return None
    
# In use
def encrypt_vaultdata_file(enc_key):
    if not os.path.exists(VAULT_METADATA_FILE):
        return None
    try:
        encrypt_file(enc_key, VAULT_METADATA_FILE, ENC_VAULT_METADATA_FILE)
        os.remove(VAULT_METADATA_FILE)
        return ENC_VAULT_METADATA_FILE
    except Exception as e:
        print(f"[ERROR] Vault data ENC failed: {e}")
        return None
    
# In use
def encrypt_passdata_file(enc_key):
    if not os.path.exists(PASS_METADATA_FILE):
        return None
    try:
        encrypt_file(enc_key, PASS_METADATA_FILE, ENC_PASS_METADATA_FILE)
        os.remove(PASS_METADATA_FILE)
        return ENC_PASS_METADATA_FILE
    except Exception as e:
        print(f"[ERROR] PM data ENC failed: {e}")
        return None

# In use
def decrypt_userdata_file(enc_key):
    if not os.path.exists(ENC_USER_DATA_FILE):
        return None
    try:
        filename = os.path.basename(USER_DATA_FILE)
        dest_dir = os.path.dirname(USER_DATA_FILE)
        decrypt_file(enc_key, ENC_USER_DATA_FILE, filename, dest_dir)
        return USER_DATA_FILE
    except Exception as e:
        print(f"[ERROR] User data DEC failed: {e}")
        return None
    
# In use
def decrypt_vaultdata_file(enc_key):
    if not os.path.exists(ENC_VAULT_METADATA_FILE):
        return None
    try:
        filename = os.path.basename(VAULT_METADATA_FILE)
        dest_dir = os.path.dirname(VAULT_METADATA_FILE)
        decrypt_file(enc_key, ENC_VAULT_METADATA_FILE, filename, dest_dir)
        return VAULT_METADATA_FILE
    except Exception as e:
        print(f"[ERROR] Vault data DEC failed: {e}")

# In use
def decrypt_passdata_file(enc_key):
    if not os.path.exists(ENC_PASS_METADATA_FILE):
        return None
    try:
        filename = os.path.basename(PASS_METADATA_FILE)
        dest_dir = os.path.dirname(PASS_METADATA_FILE)
        decrypt_file(enc_key, ENC_PASS_METADATA_FILE, filename, dest_dir)
        return PASS_METADATA_FILE
    except Exception as e:
        print(f"[ERROR] PM data DEC failed: {e}")
        return None

# Recovery (Testing)
def generate_recovery_codes(count=6):
    codes = []
    for _ in range(count):
        part1 = secrets.token_hex(2).upper()
        part2 = secrets.token_hex(2).upper()
        part3 = secrets.token_hex(2).upper()
        codes.append(f"{part1}-{part2}-{part3}")
    return codes

def setup_recovery_codes(username, user_password):
    
    load_user_context(username)
    if os.path.exists(RECOVERY_DIR):
        shutil.rmtree(RECOVERY_DIR)
    os.makedirs(RECOVERY_DIR)
    codes = generate_recovery_codes()

    for i, code in enumerate(codes):
        try:
            rec_enc_key, _, _ = generate_key(code, salt=code.encode())
            raw_key = base64.urlsafe_b64decode(rec_enc_key)
            aesgcm = AESGCM(raw_key)
            nonce = os.urandom(16)
            encrypted_pass = aesgcm.encrypt(nonce, user_password.encode('utf-8'), None)
            dat_name = f"recovery_{i}"
            dat_hash = hashlib.sha256(dat_name.encode()).hexdigest()
            file_path = os.path.join(RECOVERY_DIR, f"{dat_hash}.dat")

            with open(file_path, 'wb') as f:
                f.write(nonce + encrypted_pass)
        except Exception as e:
            print(f"[ERROR] Could not create recovery slot {i}: {e}")
            return None
    return codes

def recover_account_with_code(username, recovery_code):
    load_user_context(username)

    if not os.path.exists(RECOVERY_DIR):
        return None
    
    recovery_code = recovery_code.strip().upper()

    # Argon2
    try:
        rec_enc_key, _, _ = generate_key(recovery_code, salt=recovery_code.encode())
        raw_key = base64.urlsafe_b64decode(rec_enc_key)
        aesgcm = AESGCM(raw_key)
    except Exception as e:
        print(f"[WARNING] Argon recovery generation failed: {e}")
        aesgcm = None

    # Legacy
    try:
        legacy_key, _ = generate_key_legacy(recovery_code, salt=recovery_code.encode())
        fernet = Fernet(legacy_key)
    except Exception as e:
        print(f"[WARNING] Fernet recovery generation failed: {e}")
        fernet = None
    
    for filename in os.listdir(RECOVERY_DIR):
        file_path = os.path.join(RECOVERY_DIR, filename)

        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            if aesgcm:
                try:
                    nonce = encrypted_data[:12]
                    ciphertext = encrypted_data[12:]
                    decryprted_pass = aesgcm.decrypt(nonce, ciphertext, None)
                    return decryprted_pass.decode('utf-8')
                except Exception:
                    pass
            if fernet:
                try:
                 decryprted_pass = fernet.decrypt(encrypted_data)
                 return decryprted_pass.decode('utf-8')
                except Exception:
                    pass
        except Exception:
            continue
    return None

# Multimedia Manager (Terminal version. Not for GUI)
def multimedia_manager(vault_name, vault_key, file_name):
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)
    enc_vault_name = hashlib.sha256(vault_key + vault_name.encode('utf-8')).hexdigest()
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)
    enc_file_name = hashlib.sha256(vault_key + file_name.encode('utf-8')).hexdigest()
    encrypted_path = os.path.join(vault_folder, f"{enc_file_name}.enc")
    fernet = Fernet(vault_key)
    with open(encrypted_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    file_type, _ = mimetypes.guess_type(file_name)
    if file_type:
        if file_type.startswith("image/"):
            img_buffer = io.BytesIO(decrypted_data)
            img_buffer.seek(0)
            image = Image.open(img_buffer)
            img_form = image.format
            if not img_form:
                print("Unknown Image format.")
            else:
                image.show()
        elif file_type.startswith("video/"):
            print("Under Cons.")
        elif file_type.startswith("application/") or file_type.startswith("text/"):
            print("Under Cons.")
        elif file_type.startswith("audio/"):
            print("Under Cons.")
        else:
            print("Unknown file type.")
    else:
        print("Unknown file type.")
    return

# In use
def calculate_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# External Vault Functions
def format_drive_windows(drive_path):
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False

    if not is_admin:
        print("\n[ERROR] To format the external storage drive, you must run this program as administrator!")
        return False
    
    drive_letter = os.path.splitdrive(drive_path)[0]

    if not drive_letter:
        print("Invalid driver path.")
        return False
    
    if drive_letter.upper() == "C:":
        print("\n[ERROR] Drive C: cannot be formatted with this program for security reasons!")
        return False
    
    print(f"\nATTENTION")
    print(f"You are about to delete everything in drive {drive_letter} and name it 'SIRIUS_VAULT'.")
    print("This operation is not reversible.")

    confirm_code = f"FORMAT {drive_letter.upper()}"
    user_input = input(f"If you are accepting this please enter exactly this line -> '{confirm_code}':")
    if user_input != confirm_code:
        print("Confirmation error. Canceling process.")
        return False

    print("\nFormatting process beginning... Please do not remove external drive.")
    print("This process may take a while depending on the drive size.")

    try:
        cmd = f'format {drive_letter} /FS:exFAT /V:SIRIUS_VAULT /Q /Y'
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        print(f"\n[SUCCESS] {drive_letter} drive cleaned and named 'SIRIUS_VAULT'.")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Formatting failed.")
        print("Possible causes: The disk may be in use or write-protected.")
        return False

# User Management
def create_user(username, password):

    global USER_SYSTEM_SALT
    load_user_context(username)

    if os.path.exists(USER_DIR):
        print("User already existing.")
        return False
    else:
        os.makedirs(USER_DIR)
    if not os.path.exists(VAULTS_DIR):
        os.makedirs(VAULTS_DIR)
    create_user_system_salt()
    USER_SYSTEM_SALT = initialize_user_system_salt()

    enc_key, _, _ = generate_key(password, USER_SYSTEM_SALT)
    _, auth_hash, salt = generate_key(password)
    user_data = {"username": username,
                "password_hash": auth_hash.decode('utf-8'),
                "salt": salt.hex(),
                "session_timeout_index": 1}
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(user_data, f)
    encrypt_userdata_file(enc_key)
    print(f"User '{username}' registered successfully!")
    print("You can login now.")
    return True

def authenticate_user(username, password):

    global USER_SYSTEM_SALT
    load_user_context(username)
    USER_SYSTEM_SALT = initialize_user_system_salt()

    if not os.path.exists(ENC_USER_DATA_FILE):
        print("User not registered.")
        return False
    
    if not USER_SYSTEM_SALT:
        print(f"[ERROR] No user system salt.")
        return False
    
    enc_key, _, _ = generate_key(password, USER_SYSTEM_SALT)

    try:
        if decrypt_userdata_file(enc_key):
            with open(USER_DATA_FILE, 'r') as f:
                user_data = json.load(f)
            stored_salt = bytes.fromhex(user_data.get("salt"))
            _, auth_hash, _ = generate_key(password, stored_salt)
            stored_password_hash = user_data.get("password_hash")
            
            if stored_password_hash == auth_hash.decode('utf-8'):
                print("User Authentication successful!")
                session["authenticated_user"] = username
                session["session_timeout_index"] = user_data.get("session_timeout_index", 1)
                reset_session_timer()
                encrypt_userdata_file(enc_key)
                return True
            else:
                encrypt_userdata_file(enc_key)
                return False
        # Legacy
        if decrypt_userdata_file_legacy(password):
            print("[INFO] Legacy account detected. Initiating migration...")
            if migrate_user_to_pqc(username, password):
                session["authenticated_user"] = username
                with open(USER_DATA_FILE, 'r') as f:
                    user_data = json.load(f)
                session["session_timeout_index"] = user_data.get("session_timeout_index", 1)
                reset_session_timer()
                encrypt_userdata_file(enc_key)
                return True
            else:
                encrypt_userdata_file_legacy(password)
                return False
        return False
    except Exception as e:
        try: 
            encrypt_userdata_file_legacy(password)
            encrypt_userdata_file(enc_key)
        except: pass
        print(f"[ERROR] User authentication failed: {e}")
        return False
    
# Migrate user
def migrate_user_to_pqc(username, password):
    try:
        USER_SYSTEM_SALT = initialize_user_system_salt()
        new_enc_key, _, _ = generate_key(password, USER_SYSTEM_SALT)
        _, new_auth_hash, new_salt = generate_key(password)

        with open(USER_DATA_FILE, 'r') as f:
            user_data = json.load(f)

        user_data["password_hash"] = new_auth_hash.decode('utf-8')
        user_data["salt"] = new_salt.hex()

        with open(USER_DATA_FILE, 'w') as f:
            json.dump(user_data, f)

        if os.path.exists(ENC_VAULT_METADATA_FILE):
            decrypt_vaultdata_file_legacy(password)
        if os.path.exists(VAULT_METADATA_FILE):
            encrypt_vaultdata_file(new_enc_key)

        new_codes = setup_recovery_codes(username, password)
        session["migrated_recovery_codes"] = new_codes

        print(f"[INFO] User '{username}' successfully migrated to AES-GCM.")
        return True
    except Exception as e:
        print(f"[ERROR] Migration failed for '{username}': {e}")
        return False

# Delete user
def delete_user(username, user_password):
    load_user_context(username)
    if authenticate_user(username, user_password):
        if os.path.exists(USER_DIR):
            try:
                shutil.rmtree(USER_DIR)
                if not os.path.exists(USER_DIR):
                    print("User and all associated vaults deleted successfully!")
                    print("Good Bye!")
                    session["authenticated_user"] = None
                else:
                    print("Something went wrong. Please be sure to close all files and try again.")
                    return
            except Exception as e:
                print(f"[ERROR] Cannot delete user: {e}")
        else:
            print("User not found.")

# Vault Management
def create_vault(vault_name, password, user_password): 
    if not is_session_active():
        return
    username = session["authenticated_user"]
    reset_session_timer()

    global USER_SYSTEM_SALT
    if not USER_SYSTEM_SALT:
        USER_SYSTEM_SALT = initialize_user_system_salt()

    master_enc_key, _, _ = generate_key(user_password, USER_SYSTEM_SALT)

    decrypt_vaultdata_file(master_enc_key)

    if not os.path.exists(VAULT_METADATA_FILE):
        with open(VAULT_METADATA_FILE, 'w') as f:
            json.dump({}, f)
    try:
        with open(VAULT_METADATA_FILE, 'r') as f:
            vaults = json.load(f)

        if vault_name in vaults:
            return "SAME_NAME"
    
        enc_key, auth_hash, salt = generate_key(password)
        enc_vault_name = hashlib.sha256(enc_key + vault_name.encode('utf-8')).hexdigest()
        vault_path = os.path.join(VAULTS_DIR, enc_vault_name)
        vaults[vault_name] = {"owner": username, "auth_hash": auth_hash.decode('utf-8'), "salt": salt.hex(), "files": []}
    
        with open(VAULT_METADATA_FILE, 'w') as f:
            json.dump(vaults, f)
    
        if not os.path.exists(vault_path): 
            os.makedirs(vault_path)
            return "SUCCESS"
        else:
            return "SAME_NAME"
    finally:
        encrypt_vaultdata_file(master_enc_key)

# Open the vault
def authenticate_vault(vault_name, vault_password, user_password):
    if not is_session_active():
        return None
    username = session["authenticated_user"]
    reset_session_timer()

    global USER_SYSTEM_SALT
    if not USER_SYSTEM_SALT:
        USER_SYSTEM_SALT = initialize_user_system_salt()

    master_enc_key, _, _ = generate_key(user_password, USER_SYSTEM_SALT)

    if not decrypt_vaultdata_file(master_enc_key):
        if not decrypt_vaultdata_file_legacy(user_password):
            print("[ERROR] Wrong credentials!")
            return None
        
    try:

        with open(VAULT_METADATA_FILE, 'r') as f:
            vaults = json.load(f)

        if vault_name not in vaults or vaults[vault_name]["owner"] != username:
            return None
    
        v_data = vaults[vault_name]
        if "auth_hash" in v_data:
            stored_salt = bytes.fromhex(v_data["salt"])
            vault_enc_key, auth_hash, _ = generate_key(vault_password, stored_salt)
            if v_data["auth_hash"] == auth_hash.decode('utf-8'):
                return vault_enc_key
            return None
        elif "key" in v_data:
            stored_salt = bytes.fromhex(v_data["salt"])
            stored_key = bytes.fromhex(vaults[vault_name]["key"])
            legacy_key, _ = generate_key_legacy(vault_password, stored_salt)
            if stored_key == legacy_key:
                print(f"[INFO] Legacy Vault '{vault_name}' detected. Upgrading to PQC...")
                if migrate_vault_files_to_pqc(vault_name, vault_password, legacy_key, vaults):
                    return authenticate_vault(vault_name, vault_password)
            return None
    finally:
        encrypt_vaultdata_file(master_enc_key)
    return None

# Migrate
def migrate_vault_files_to_pqc(vault_name, vault_password, legacy_key, vaults):
    try:
        new_salt = os.urandom(16)
        new_enc_key, new_auth_hash, _ = generate_key(vault_password, new_salt)

        old_enc_vault_name = hashlib.sha256(legacy_key + vault_name.encode('utf-8')).hexdigest()
        new_enc_vault_name = hashlib.sha256(new_enc_key + vault_name.encode('utf-8')).hexdigest()

        old_vault_folder = os.path.join(VAULTS_DIR, old_enc_vault_name)
        new_vault_folder = os.path.join(VAULTS_DIR, new_enc_vault_name)

        if not os.path.exists(new_vault_folder):
            os.makedirs(new_vault_folder)

        if not os.path.exists(TEMP_DIR):
            os.makedirs(TEMP_DIR)
        
        print(f"[INFO] Migrating files for vault '{vault_name}'...")

        for file_meta in vaults[vault_name]["files"]:
            f_name = file_meta["name"]

            old_enc_file_name = hashlib.sha256(legacy_key + f_name.encode('utf-8')).hexdigest() + ".enc"
            new_enc_file_name = hashlib.sha256(new_enc_key + f_name.encode('utf-8')).hexdigest() + ".enc"

            old_path = os.path.join(old_vault_folder, old_enc_file_name)
            new_path = os.path.join(new_vault_folder, new_enc_file_name)
            temp_path = os.path.join(TEMP_DIR, f_name)

            decrypt_file_legacy(legacy_key, old_path, f_name, TEMP_DIR)
            encrypt_file(new_enc_key, temp_path, new_path)

            os.remove(temp_path)

            file_meta["enc_hash"] = calculate_file_hash(new_path)
        
        if os.path.exists(old_vault_folder):
            shutil.rmtree(old_vault_folder)

        vaults[vault_name]["salt"] = new_salt.hex()
        vaults[vault_name]["auth_hash"] = new_auth_hash.decode('utf-8')
        del vaults[vault_name]["key"]

        with open(VAULT_METADATA_FILE, 'w')as f:
            json.dump(vaults, f)
        
        print(f"[SUCCESS] Vault '{vault_name}' successfully migrated to PQC.")
        return True
    except Exception as e:
        print(f"[ERROR] Vault migration failed for '{vault_name}': {e}")
        return False

# List all vaults that user has
def list_vaults_GUI(username):
    if not is_session_active():
        return None
    username = session["authenticated_user"]
    reset_session_timer()
    if os.path.exists(VAULT_METADATA_FILE):
        with open(VAULT_METADATA_FILE, 'r') as f:
            vaults = json.load(f)
        user_vaults = [vault_name for vault_name, metadata in vaults.items() if metadata["owner"] == username]
        if user_vaults:
            return user_vaults

# Delete a vault
def delete_vault(username, vault_name, vault_key):
    if not is_session_active():
        return None
    username = session["authenticated_user"]
    reset_session_timer()

    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    metadata = vaults.items()
    if vault_name not in vaults and metadata["owner"] != username:
        #print("Vault not found!")
        return
    
    enc_vault_name = hashlib.sha256(vault_key + vault_name.encode('utf-8')).hexdigest()
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)

    if os.path.exists(vault_folder):
        shutil.rmtree(vault_folder)
    else:
        #print("Vault folder not found!")
        return
    
    del vaults[vault_name]

    with open(VAULT_METADATA_FILE, 'w') as f:
        json.dump(vaults, f)
    #print(f"Vault '{vault_name}' removed!")

# Add file to vault
def add_file_to_vault(vault_name, vault_key, filepath, username):
    if not is_session_active():
        return
    reset_session_timer()

    if not os.path.exists(filepath):
        #print("File not found!")
        return
    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    metadata = vaults.items()
    if vault_name not in vaults and metadata["owner"] != username:
        #print("Vault not found!")
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
    #print(f"File '{os.path.basename(filepath)}' added to vault {vault_name}!")

def add_folder_recursive(vault_name, vault_key, folder_path, username):
    
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                add_file_to_vault(vault_name, vault_key, file_path, username)
                print(f"[INFO] Processed: {file}")
            except Exception as e:
                print(f"[ERROR] Could not process {file}: {e}")

# List files in vault
def list_files_in_vault_GUI(vault_name, username):
    if not is_session_active():
        return
    reset_session_timer()

    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    metadata = vaults.items()
    if vault_name not in vaults and metadata["owner"] != username:
        #print("Vault not found!")
        return
    files = vaults[vault_name]["files"]
    return files

# Remove file from vault
def remove_file_from_vault(vault_name, file_name, username, vault_key):
    if not is_session_active():
        return
    reset_session_timer()

    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    metadata = vaults.items()
    if vault_name not in vaults and metadata["owner"] != username:
        #print("Vault not found!")
        return

    file_metadata = next((file for file in vaults[vault_name]["files"] if file["name"] == file_name), None)
    if not file_metadata:
        #print("File not found in vault!")
        return

    enc_vault_name = hashlib.sha256(vault_key + vault_name.encode('utf-8')).hexdigest()
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)
    enc_file_name = hashlib.sha256(vault_key + file_name.encode('utf-8')).hexdigest()
    encrypted_path = os.path.join(vault_folder, f"{enc_file_name}.enc")
    
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)
    else:
        #print("Encrypted file not found!")
        return

    # Remove metadata
    vaults[vault_name]["files"].remove(file_metadata)
    with open(VAULT_METADATA_FILE, 'w') as f:
        json.dump(vaults, f)
    #print(f"File '{file_name}' removed from vault!")

# Extract file from vault
def extract_file_from_vault(vault_name, vault_key, file_name, destination_path):
    if not is_session_active():
        return
    reset_session_timer()

    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    if vault_name not in vaults:
        #print("Vault not found!")
        return

    file_name = file_name.strip()
    enc_file_name = hashlib.sha256(vault_key + file_name.encode()).hexdigest()
    enc_vault_name = hashlib.sha256(vault_key + vault_name.encode()).hexdigest()
    file_metadata = next((file for file in vaults[vault_name]["files"] if file["name"].lower() == file_name.lower()), None)
    if not file_metadata:
        #print("File not found in vault!")
        return
    
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)
    encrypted_path = os.path.join(vault_folder, f"{enc_file_name}.enc")
    if not os.path.exists(encrypted_path):
        #print("Encrypted file not found!")
        return
    enc_file_hash = calculate_file_hash(encrypted_path)
    stored_enc_file_hash = next((file["enc_hash"] for file in vaults[vault_name]["files"] if file["name"] == file_name), None)
    if enc_file_hash != stored_enc_file_hash:
        #print("Encrypted file corrupted!")
        return
    decrypt_file(vault_key, encrypted_path, file_name, destination_path)
    decrypted_path = os.path.join(destination_path, f"{file_name}")
    file_hash = calculate_file_hash(decrypted_path)
    stored_file_hash = next((file["hash"] for file in vaults[vault_name]["files"] if file["name"] == file_name), None)
    if file_hash != stored_file_hash:
        #print("Decrypted file corrupted!")
        return
    #print(f"File '{file_metadata['name']}' extracted to '{destination_path}'")

# Password Manager
def create_passMngr(passMngr_pass, pass_Mngr=None):
    if not is_session_active():
        return
    reset_session_timer()
    #Create PASS_METADA_FILE
    try:
        if not os.path.exists(PASS_METADATA_FILE):
            with open(PASS_METADATA_FILE, 'w') as f:
                json.dump({}, f)
        pass_Mngr = "Sirius Password Manager"
        with open(PASS_METADATA_FILE, 'r') as f:
            pass_Mngrs = json.load(f)
        passMngr_key, passMngr_auth_hash, passMngr_salt = generate_key(passMngr_pass)
        pass_Mngrs[pass_Mngr] = {"password_hash": passMngr_auth_hash.decode('utf-8'), "salt": passMngr_salt.hex(), "services": []}
        with open(PASS_METADATA_FILE, 'w') as f:
            json.dump(pass_Mngrs, f)
        session["pm_enc_key"] = passMngr_key
        encrypt_passdata_file(passMngr_key)
        return True
    except Exception as e:
        print(f"[ERROR] Password Manager Creation failed: {e}")

# Authenticate Password Manager //Maybe add username as arg?
def authenticate_passMngr(passMngr_pass, pass_Mngr=None):
    if not is_session_active():
        return False
    reset_session_timer()
    if not os.path.exists(PASS_METADATA_FILE):
        return False
    USER_SYSTEM_SALT = initialize_user_system_salt()
    enc_key, auth_hash, _ = generate_key(passMngr_pass, USER_SYSTEM_SALT)
    try:
        if decrypt_passdata_file(enc_key):
            with open(PASS_METADATA_FILE, 'r') as f:
                pass_Mngrs = json.load(f)
            pass_Mngr = "Sirius Password Manager"
            if pass_Mngr in pass_Mngrs:
                stored_hash = pass_Mngrs[pass_Mngr].get("password_hash")
                if stored_hash == auth_hash.decode('utf-8'):
                    session["pm_enc_key"] = enc_key
                    return True
            encrypt_passdata_file(enc_key)
            return False
        # LEGACY
        if decrypt_passdata_file_legacy(passMngr_pass):
            print("[INFO] Legacy Password Manager detected. Initiating migration...")

            if migrate_pm_to_pqc(passMngr_pass):
                session["pm_enc_key"] = enc_key
                reset_session_timer()
                encrypt_passdata_file(enc_key)
                return True
            else:
                encrypt_passdata_file_legacy(passMngr_pass)
                return False
        return False
    except Exception as e:
        try: 
            encrypt_passdata_file_legacy(passMngr_pass)
            encrypt_passdata_file(enc_key)
        except: pass
        print(f"[ERROR] Password Manager Authentication failed: {e}")
        return False

# Migrate Password Manager
def migrate_pm_to_pqc(passMngr_pass):
    try:
        USER_SYSTEM_SALT = initialize_user_system_salt()
        new_enc_key, new_auth_hash, _ = generate_key(passMngr_pass, USER_SYSTEM_SALT)

        with open(PASS_METADATA_FILE, 'r') as f:
            passMngrs = json.load(f)
        pm_name = "Sirius Password Manager"
        passMngrs[pm_name]["password_hash"] = new_auth_hash.decode('utf-8')

        with open(PASS_METADATA_FILE, 'w') as f:
            json.dump(passMngrs, f)
        
        print(f"[INFO] Password Manager successfully migrated to AES-GCM.")
        return True
    except Exception as e:
        print(f"[ERROR] Password Manager migration failed: {e}")
        return False

# Add Password to Password Manager
def add_password_to_PassMngr(service_name, service_user_mail, service_pass, pass_Mngr=None):
    if not is_session_active():
        return
    reset_session_timer()
    pass_Mngr = "Sirius Password Manager"
    with open(PASS_METADATA_FILE, 'r') as f:
        pass_Mngrs = json.load(f)
    service_metadata = {
        "service_name": service_name,
        "service_user_mail": service_user_mail,
        "service_pass": service_pass
    }
    pass_Mngrs[pass_Mngr]["services"].append(service_metadata)
    with open(PASS_METADATA_FILE, 'w') as f:
        json.dump(pass_Mngrs, f)

# List Services in PassMngr
def list_services_in_passMngr(pass_Mngr=None):
    if not is_session_active():
        return
    reset_session_timer()
    pass_Mngr = "Sirius Password Manager"
    with open(PASS_METADATA_FILE, 'r') as f:
        pass_Mngrs = json.load(f)
    if pass_Mngr not in pass_Mngrs:
        print("Incorrect Password Manager or Password!")
        return
    services = pass_Mngrs[pass_Mngr]["services"]
    return services

# Audit Password Strenght
def audit_password_strenght(password):
    if not password:
        return 0, "Weak"
    
    lenght_score = len(password) * 4
    complexity_score = 0

    if any(c.isupper() for c in password): complexity_score += 15
    if any(c.islower() for c in password): complexity_score += 10
    if any(c.isdigit() for c in password): complexity_score += 15
    if any(not c.isalnum() and not c.isspace() for c in password): complexity_score += 20

    total = min(lenght_score + complexity_score, 100)
    if total > 75:
        return total, "Strong"
    elif total > 40:
        return total, "Moderate"
    else:
        return total, "Weak"

# Extract Password for service
def extract_password_service(service_name, pass_Mngr=None):
    if not is_session_active():
        return
    reset_session_timer()
    pass_Mngr = "Sirius Password Manager"
    with open(PASS_METADATA_FILE, 'r') as f:
        pass_Mngrs = json.load(f)
    service_metadata = next((services for services in pass_Mngrs[pass_Mngr]["services"] if services["service_name"].lower() == service_name.lower()), None)
    if not service_metadata:
        print("Service not found! Check the list and try again.")
        return
    service_pass = next((services["service_pass"] for services in pass_Mngrs[pass_Mngr]["services"] if services["service_name"] == service_name), None)
    # print(f"Password for service: {service_name}")
    # print(f"{service_pass}")
    return service_pass


# Remove Password for service
def remove_password_service(service_name, pass_Mngr=None):
    if not is_session_active():
        return
    reset_session_timer()
    pass_Mngr = "Sirius Password Manager"
    with open(PASS_METADATA_FILE, 'r') as f:
        pass_Mngrs = json.load(f)
    service_metadata = next((services for services in pass_Mngrs[pass_Mngr]["services"] if services["service_name"] == service_name), None)
    if not service_metadata:
        return False
    pass_Mngrs[pass_Mngr]["services"].remove(service_metadata)
    with open(PASS_METADATA_FILE, 'w') as f:
        json.dump(pass_Mngrs, f)
    return True

# Delete Password Manager
def delete_passMngr(username, user_password):
    load_user_context(username)
    if authenticate_user(username, user_password):
        if os.path.exists(PASS_METADATA_FILE):
            os.remove(PASS_METADATA_FILE)
        if os.path.exists(ENC_PASS_METADATA_FILE):
            os.remove(ENC_PASS_METADATA_FILE)

        if not os.path.exists(PASS_METADATA_FILE) and not os.path.exists(ENC_PASS_METADATA_FILE):
            print("Password Manager deleted successfuly!")
            return True
        else:
            print("Something went wrong. Please be sure to close all files and try again.")
            return False
    else:
        print("User authentication failed.")
        return False
