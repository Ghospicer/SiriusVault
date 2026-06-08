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
import string
import subprocess
import ctypes
import stat
import struct
from PIL import Image
from dotenv import load_dotenv
from threading import Timer
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import LegacyFunctions as legacy
except ImportError:
    print("Legacy functions not found!")

APP_VERSION = "1.0.0"

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
    if not session.get("authenticated_user"):
        return
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

def is_system_locked():

    target_os = sys.platform

    if target_os == "win32":
        user32 = ctypes.windll.User32
        desktop = user32.OpenInputDesktop(0, False, 0x0100)

        if desktop:
            user32.CloseDesktop(desktop)
            return False
        else:
            return True
    elif target_os.startswith("linux"):
        try:
            gnome_cmd = ["dbus-send", "--print-reply", "--dest=org.gnome.ScreenSaver", 
                         "/org/gnome/ScreenSaver", "org.gnome.ScreenSaver.GetActive"]
            result = subprocess.run(gnome_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1)
            if "boolean true" in result.stdout:
                return True

            fd_cmd = ["dbus-send", "--print-reply", "--dest=org.freedesktop.ScreenSaver", 
                      "/org/freedesktop/ScreenSaver", "org.freedesktop.ScreenSaver.GetActive"]
            result_fd = subprocess.run(fd_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1)
            if "boolean true" in result_fd.stdout:
                return True
                
        except Exception as e:
            print(f"[DEBUG] Linux lock check failure: {e}")
        return False
    elif target_os == "darwin":
        try:
            mac_cmd = "python3 -c 'import Quartz; print(Quartz.CGSessionCopyCurrentDictionary())'"
            pass
        except Exception:
            pass
        return False
    return False

def update_user_timeout_setting(username, password, new_index):
    
    load_user_context(username)
    if not os.path.exists(ENC_USER_DATA_FILE):
        print("User data file not encrypted.")
        return False
    global USER_SYSTEM_SALT
    enc_key, _, _ = generate_key(password, USER_SYSTEM_SALT)
    try:
        decrypt_userdata_file(enc_key)
        with open(USER_DATA_FILE, 'r') as f:
            user_data = json.load(f)
        user_data["session_timeout_index"] = new_index
        with open(USER_DATA_FILE, 'w') as f:
            json.dump(user_data, f)
        reset_session_timer()
        encrypt_userdata_file(enc_key)
        return True
    except Exception as e:
        encrypt_userdata_file(enc_key)
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

def secure_delete(filepath, passes=3):

    if not os.path.exists(filepath):
        return
    
    try:
        os.chmod(filepath, stat.S_IWRITE)
    except Exception:
        pass
    
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
    
def secure_rmtree(directory_path):
    if not os.path.exists(directory_path):
        return
    
    for root, dirs, files in os.walk(directory_path, topdown=False):
        for name in files:
            file_path = os.path.join(root, name)
            secure_delete(file_path)

        for name in dirs:
            dir_path = os.path.join(root, name)
            try:
                os.rmdir(dir_path)
            except:
                pass

    try:
        os.rmdir(directory_path)
    except:
        pass

def logout_user():
    global session_timer
    if session_timer:
        session_timer.cancel()
    session["authenticated_user"] = None
    session["session_expiry"] = None
    session["pm_inner_key"] = None
    session["pm_outer_key"] = None
    clean_memory()
    print("\n[INFO] Session ended. Please authenticate again.")
    return True

def logout_passMngr():
    if "pm_outer_key" in session:
        session["pm_outer_key"] = None
    if "pm_inner_key" in session:
        session["pm_inner_key"] = None

    print("[INFO] Password Manager session keys wiped from memory.")
    return True
# Not in use
def exit_program():
    logout_user()
    print("[INFO] Exiting Sirius Vault.")
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

def initialize_vault_metadata(vault_path):
    global VAULT_METADATA_FILE
    global  ENC_VAULT_METADATA_FILE
    if vault_path:
        VAULT_METADATA_FILE = os.path.join(vault_path, "vault_metadata.json")
        ENC_VAULT_METADATA_FILE = os.path.join(vault_path, "vault_metadata.json.enc")
        return True
    else:
        print("[ERROR] Vault metadata files cannot initialized.")
        return False
        

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

# Resource Path
def get_resource_path(filename):
    return os.path.join(os.path.dirname(__file__), "resources", filename)

# Encryption/Decryption Functions
def generate_key(password, salt=None):
    if salt == None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        try:
            salt = bytes.fromhex(salt)
        except ValueError:
            salt = salt.encode('utf-8')

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
def encrypt_text(enc_key_b64, plaintext):
    raw_key = base64.urlsafe_b64decode(enc_key_b64)
    aesgcm = AESGCM(raw_key)
    nonce = os.urandom(12)
    try:
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return base64.b64encode(nonce + ciphertext).decode('utf-8')
    except Exception as e:
        print(f"[ERROR] Ciphertext cannot encrypted: {e}")
        return None

# In use
def decrypt_text(enc_key_b64, encrypted_b64_string):
    raw_key = base64.urlsafe_b64decode(enc_key_b64)
    aesgcm = AESGCM(raw_key)
    data = base64.b64decode(encrypted_b64_string)
    nonce = data[:12]
    ciphertext = data[12:]
    try:
        decrypted_text = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_text.decode('utf-8')
    except Exception as e:
        print(f"[ERROR] Ciphertext cannot decrypted: {e}")
        return None

# In use
def encrypt_userdata_file(enc_key):
    if not os.path.exists(USER_DATA_FILE):
        return None
    try:
        encrypt_file(enc_key, USER_DATA_FILE, ENC_USER_DATA_FILE)
        return ENC_USER_DATA_FILE
    except Exception as e:
        print(f"[ERROR] User data ENC failed: {e}")
        return None
    finally:
        secure_delete(USER_DATA_FILE)
    
# In use
def encrypt_vaultdata_file(enc_key):
    if not os.path.exists(VAULT_METADATA_FILE):
        return None
    try:
        encrypt_file(enc_key, VAULT_METADATA_FILE, ENC_VAULT_METADATA_FILE)
        return ENC_VAULT_METADATA_FILE
    except Exception as e:
        print(f"[ERROR] Vault data ENC failed: {e}")
        return None
    finally:
        secure_delete(VAULT_METADATA_FILE)
    
# In use
def encrypt_passdata_file(enc_key):
    if not os.path.exists(PASS_METADATA_FILE):
        return None
    try:
        encrypt_file(enc_key, PASS_METADATA_FILE, ENC_PASS_METADATA_FILE)
        return ENC_PASS_METADATA_FILE
    except Exception as e:
        print(f"[ERROR] PM data ENC failed: {e}")
        return None
    finally:
        secure_delete(PASS_METADATA_FILE)

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
            nonce = os.urandom(12)
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
        legacy_key, _ = legacy.generate_key_legacy(recovery_code, salt=recovery_code.encode())
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
                    decrypted_pass = aesgcm.decrypt(nonce, ciphertext, None)
                    return decrypted_pass.decode('utf-8')
                except Exception:
                    pass
            if fernet:
                try:
                 decrypted_pass = fernet.decrypt(encrypted_data)
                 return decrypted_pass.decode('utf-8')
                except Exception:
                    pass
        except Exception:
            continue
    return None

# Multimedia Manager (Test for GUI)
def multimedia_manager(vault_name, vault_keys, file_name):
    if not is_session_active():
        return None
    reset_session_timer()

    outer_key = vault_keys["outer_key"]
    inner_key = vault_keys["inner_key"]

    enc_vault_name = hashlib.sha256(outer_key + vault_name.encode('utf-8')).hexdigest()
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)

    enc_file_name = hashlib.sha256(inner_key + file_name.encode('utf-8')).hexdigest()
    encrypted_path = os.path.join(vault_folder, f"{enc_file_name}.enc")

    if not os.path.exists(encrypted_path):
        print(f"[ERROR] Encrypted file not found: {encrypted_path}")
        return None
    
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)

    try:
        decrypted_path = decrypt_file(inner_key, encrypted_path, file_name, TEMP_DIR)
        return decrypted_path
    except Exception as e:
        print(f"[ERROR] Multimedia Manager decryption error: {e}")
        return None

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
                "session_timeout_index": 1,
                "vaults": {}}
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
                reset_lockout(username)
                session["authenticated_user"] = username
                session["session_timeout_index"] = user_data.get("session_timeout_index", 1)
                reset_session_timer()
                encrypt_userdata_file(enc_key)
                return True
            else:
                encrypt_userdata_file(enc_key)
                return False
        # Legacy
        if legacy.decrypt_userdata_file_legacy(password):
            print("[INFO] Legacy account detected. Initiating migration...")
            if migrate_user_to_pqc(username, password):
                reset_lockout(username)
                session["authenticated_user"] = username
                with open(USER_DATA_FILE, 'r') as f:
                    user_data = json.load(f)
                session["session_timeout_index"] = user_data.get("session_timeout_index", 1)
                reset_session_timer()
                encrypt_userdata_file(enc_key)
                return True
            else:
                legacy.encrypt_userdata_file_legacy(password)
                return False
        print("[ERROR] User authentication failed.")
        return False
    except Exception as e:
        try: 
            legacy.encrypt_userdata_file_legacy(password)
            encrypt_userdata_file(enc_key)
        except:
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
            legacy.decrypt_vaultdata_file_legacy(password)
        if os.path.exists(VAULT_METADATA_FILE):
            encrypt_vaultdata_file(new_enc_key)

        new_codes = setup_recovery_codes(username, password)
        session["migrated_recovery_codes"] = new_codes

        print(f"[INFO] User '{username}' successfully migrated to AES-GCM.")
        return True
    except Exception as e:
        print(f"[ERROR] Migration failed for '{username}': {e}")
        return False

# Brute Force Protection (In TEST)
def get_lockout_data(username):
    load_user_context(username)
    USER_SYSTEM_SALT = initialize_user_system_salt()
    security_file = os.path.join(USER_DIR, "security.json")

    if not os.path.exists(security_file) or not USER_SYSTEM_SALT:
        return {"attempts": 0, "lock_until": 0}
    
    try:
        with open(security_file, 'r') as f:
            data = json.load(f)

        payload = f"{data['attempts']}:{data['lock_until']}"
        expected_sig = hmac.new(USER_SYSTEM_SALT.encode(), payload.encode(), hashlib.sha256).hexdigest()

        if data.get("signature") != expected_sig:
            print("[WARNING] Security file tampered! Applying harsh penalty.")
            record_failed_attempt(username, penalty_override=86400)
            return {"attempts": 99, "lock_until": time.time() + 86400}
        
        return data
    except Exception as e:
        print(f"[ERROR] get_lockout_data error: {e}")
        return {"attempts": 0, "lock_until": 0}
    
def record_failed_attempt(username, penalty_override=None):
    load_user_context(username)

    if not USER_DIR or not os.path.exists(USER_DIR):
        print(f"[WARNING] Failed login attempt for non-existent user: {username}")
        return

    USER_SYSTEM_SALT = initialize_user_system_salt()
    if not USER_SYSTEM_SALT:
        return
    
    security_file = os.path.join(USER_DIR, "security.json")
    data = get_lockout_data(username)

    if data["attempts"] >= 99:
        return

    attempts = data["attempts"] + 1

    if penalty_override:
        lockout_duration = penalty_override
    elif attempts >= 6: lockout_duration = 3600 #1s
    elif attempts >= 5: lockout_duration = 900 #15dk
    elif attempts >= 4: lockout_duration = 300 #5dk
    elif attempts >= 3: lockout_duration = 60 #1dk
    else: lockout_duration = 0

    lock_until = int(time.time() + lockout_duration) if lockout_duration > 0 else 0

    payload = f"{attempts}:{lock_until}"
    signature = hmac.new(USER_SYSTEM_SALT.encode(), payload.encode(), hashlib.sha256).hexdigest()

    try:
        with open(security_file, 'w') as f:
            json.dump({"attempts": attempts, "lock_until": lock_until, "signature": signature}, f)
    except Exception as e:
        print(f"[ERROR] Cannot write to security.json: {e}")

def reset_lockout(username):
    load_user_context(username)
    security_file = os.path.join(USER_DIR, "security.json")
    if os.path.exists(security_file):
        os.remove(security_file)

# Delete user
def delete_user(username, user_password):
    load_user_context(username)
    if authenticate_user(username, user_password):
        if os.path.exists(USER_DIR):
            try:
                if os.path.exists(USER_ENV):
                    remove_readonly(USER_ENV)
                secure_rmtree(USER_DIR)
                if not os.path.exists(USER_DIR):
                    print("User and all associated vaults deleted successfully!")
                    print("Good Bye!")
                    logout_user()
                else:
                    print("Something went wrong. Please be sure to close all files and try again.")
                    return
            except Exception as e:
                print(f"[ERROR] Cannot delete user: {e}")
        else:
            print("User not found.")

# Vault Management
def create_vault(vault_name, vault_password, user_password): 
    if not is_session_active():
        return
    username = session["authenticated_user"]
    reset_session_timer()

    global USER_SYSTEM_SALT
    if not USER_SYSTEM_SALT:
        USER_SYSTEM_SALT = initialize_user_system_salt()

    master_enc_key, _, _ = generate_key(user_password, USER_SYSTEM_SALT)
    if not decrypt_userdata_file(master_enc_key):
        return "ERROR"
    
    try:
        with open(USER_DATA_FILE, 'r') as f:
            user_data = json.load(f)
        
        if vault_name in user_data["vaults"]: return "SAME_NAME"

        outer_salt = os.urandom(16)
        outer_key, _, _ = generate_key(vault_password, outer_salt)

        enc_vault_name = hashlib.sha256(outer_key + vault_name.encode('utf-8')).hexdigest()
        vault_path = os.path.join(VAULTS_DIR, enc_vault_name)
    
        if os.path.exists(vault_path):
            return "SAME_NAME"
        os.makedirs(vault_path)

        inner_key, auth_hash, inner_salt = generate_key(vault_password)

        vault_meta = {"owner": username,
                      "inner_salt": inner_salt.hex(),
                      "auth_hash": auth_hash.decode('utf-8'),
                      "files": [] }
        
        initialize_vault_metadata(vault_path) 
        with open(VAULT_METADATA_FILE, 'w') as f:
            json.dump(vault_meta, f)

        try:
            encrypt_vaultdata_file(outer_key)
        except Exception as e:
            print(f"[ERROR] Create vault error: {e}")
        finally:
            secure_delete(VAULT_METADATA_FILE)

        user_data["vaults"][vault_name] = {"outer_salt": outer_salt.hex()}
        with open(USER_DATA_FILE, 'w') as f:
            json.dump(user_data, f)
        return "SUCCESS"
    finally:
        encrypt_userdata_file(master_enc_key)

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

    if not os.path.exists(USER_DATA_FILE):
        decrypt_userdata_file(master_enc_key)

    try:
        with open(USER_DATA_FILE, 'r') as f:
            user_data = json.load(f)

        if vault_name not in user_data["vaults"]:
            return None
        
        outer_salt = bytes.fromhex(user_data["vaults"][vault_name]["outer_salt"])
        outer_key, _, _ = generate_key(vault_password, outer_salt)

        enc_vault_name = hashlib.sha256(outer_key + vault_name.encode('utf-8')).hexdigest()
        vault_path = os.path.join(VAULTS_DIR, enc_vault_name)

        if initialize_vault_metadata(vault_path):
            if not os.path.exists(ENC_VAULT_METADATA_FILE):
                return None
        
        try:
            decrypt_vaultdata_file(outer_key)
        except:
            return
        
        with open(VAULT_METADATA_FILE, 'r') as f:
            vault_meta = json.load(f)

        inner_salt = bytes.fromhex(vault_meta["inner_salt"])
        inner_key, auth_hash, _ = generate_key(vault_password, inner_salt)

        if vault_meta["auth_hash"] == auth_hash.decode('utf-8'):
            try:
                encrypt_vaultdata_file(outer_key)
            except Exception as e:
                print(f"[ERROR] Vault authentication error: {e}")
            finally:
                secure_delete(VAULT_METADATA_FILE)
            return {"outer_key":outer_key, "inner_key": inner_key}
        secure_delete(VAULT_METADATA_FILE)
        return None
    finally:
        encrypt_userdata_file(master_enc_key)

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

            legacy.decrypt_file_legacy(legacy_key, old_path, f_name, TEMP_DIR)
            encrypt_file(new_enc_key, temp_path, new_path)

            secure_delete(temp_path)

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
def list_vaults_GUI(username, user_password):
    if not is_session_active():
        return None
    reset_session_timer()

    global USER_SYSTEM_SALT
    master_enc_key, _, _ = generate_key(user_password, USER_SYSTEM_SALT)
    decrypt_userdata_file(master_enc_key)
    try:
        with open(USER_DATA_FILE, 'r') as f:
            user_data = json.load(f)
        return list(user_data.get("vaults", {}).keys())
    finally:
        encrypt_userdata_file(master_enc_key)

# Delete a vault
def delete_vault(username, vault_name, vault_keys, user_password):
    if not is_session_active():
        return None
    reset_session_timer()

    global USER_SYSTEM_SALT
    master_enc_key, _, _ = generate_key(user_password, USER_SYSTEM_SALT)

    decrypt_userdata_file(master_enc_key)
    try:
        with open(USER_DATA_FILE, 'r') as f:
            user_data = json.load(f)
        if vault_name in user_data.get("vaults", {}):
            del user_data["vaults"][vault_name]
            with open(USER_DATA_FILE, 'w') as f:
                json.dump(user_data, f)

        outer_key = vault_keys["outer_key"]
        enc_vault_name = hashlib.sha256(outer_key + vault_name.encode('utf-8')).hexdigest()
        vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)
        
        if os.path.exists(vault_folder):
            secure_rmtree(vault_folder)
    finally:
        encrypt_userdata_file(master_enc_key)

# Add file to vault
def add_file_to_vault(vault_name, vault_keys, filepath, username, delete_original=False):
    if not is_session_active():
        return
    reset_session_timer()

    if not os.path.exists(filepath):
        print("[ERROR] File not found!")
        return
    
    outer_key = vault_keys["outer_key"]
    inner_key = vault_keys["inner_key"]

    enc_vault_name = hashlib.sha256(outer_key + vault_name.encode('utf-8')).hexdigest()
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)

    file_name = os.path.basename(filepath)
    enc_file_name = hashlib.sha256(inner_key + file_name.encode('utf-8')).hexdigest()
    encrypted_path = os.path.join(vault_folder, f"{enc_file_name}.enc")

    try:
        encrypt_file(inner_key, filepath, encrypted_path)
    except Exception as e:
        print(f"[ERROR] Encryption failed for {file_name}: {e}")
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        return False

    file_hash = calculate_file_hash(filepath)
    enc_file_hash = calculate_file_hash(encrypted_path)

    if initialize_vault_metadata(vault_folder):
        if not os.path.exists(ENC_VAULT_METADATA_FILE):
            return None
        
    if not decrypt_vaultdata_file(outer_key):
        print("[ERROR] Vault metadata could not be decrypted.")
        return None
    
    with open(VAULT_METADATA_FILE, 'r') as f:
        vault_meta = json.load(f)

    file_metadata = {
        "name": file_name,
        "size": os.path.getsize(filepath),
        "hash": file_hash,
        "enc_hash": enc_file_hash,
        "date_added": time.strftime('%Y-%m-%d %H:%M:%S')
    }
    vault_meta["files"].append(file_metadata)

    with open(VAULT_METADATA_FILE, 'w') as f:
        json.dump(vault_meta, f)

    if encrypt_vaultdata_file(outer_key) is None:
        print("[CRITICAL] Metadata encryption failed! Aborting secure delete to prevent data loss.")
        return False

    if delete_original:
        try:
            secure_delete(filepath)
        except Exception as e:
            print(f"[WARNING] Could not delete original file: {e}")
    
    return True

def add_folder_recursive(vault_name, vault_keys, folder_path, username, delete_original=False):
    
    for root, _, files in os.walk(folder_path, topdown=False):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                success = add_file_to_vault(vault_name, vault_keys, file_path, username, delete_original)
                if success:
                    print(f"[INFO] Processed: {file}")
                else:
                    print(f"[ERROR] Failed to proccess {file}")
            except Exception as e:
                print(f"[ERROR] Could not process {file}: {e}")
        if delete_original:
            try: 
                os.rmdir(root)
            except:
                pass
    if delete_original:
        try:
            os.rmdir(folder_path)
        except:
            pass

# List files in vault
def list_files_in_vault_GUI(vault_name, username, vault_keys):
    if not is_session_active():
        return
    reset_session_timer()

    outer_key = vault_keys["outer_key"]
    enc_vault_name = hashlib.sha256(outer_key + vault_name.encode('utf-8')).hexdigest()
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)

    if initialize_vault_metadata(vault_folder):
        if not os.path.exists(ENC_VAULT_METADATA_FILE):
            print(f"[ERROR] Initiliaze Vault Metadata failed.")
            return []

    if not os.path.exists(ENC_VAULT_METADATA_FILE):
        return []
    
    try:
        decrypt_vaultdata_file(outer_key)
    except Exception as e:
        print(f"[ERROR] File list error: {e}")
        return

    with open(VAULT_METADATA_FILE, 'r') as f:
        vault_meta = json.load(f)

    files = vault_meta.get("files", [])

    encrypt_vaultdata_file(outer_key)
    return files

# Remove file from vault
def remove_file_from_vault(vault_name, file_name, username, vault_keys):
    if not is_session_active():
        return
    reset_session_timer()

    outer_key = vault_keys["outer_key"]
    inner_key = vault_keys["inner_key"]

    enc_vault_name = hashlib.sha256(outer_key + vault_name.encode('utf-8')).hexdigest()
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)

    if initialize_vault_metadata(vault_folder):
        if not os.path.exists(ENC_VAULT_METADATA_FILE):
            print("[ERROR] Initialize Vault Metadata failed.")
            return
    try:
        decrypt_vaultdata_file(outer_key)
    except Exception as e:
        print(f"[ERROR] Remove file error: {e}")
        return 

    with open(VAULT_METADATA_FILE, 'r') as f:
        vault_meta = json.load(f)

    file_metadata = next((file for file in vault_meta["files"] if file["name"] == file_name), None)
    if not file_metadata: 
        secure_delete(VAULT_METADATA_FILE)
        return
    
    enc_file_name = hashlib.sha256(inner_key + file_name.encode('utf-8')).hexdigest()
    encrypted_path = os.path.join(vault_folder, f"{enc_file_name}.enc")
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)

    vault_meta["files"].remove(file_metadata)
    with open(VAULT_METADATA_FILE, 'w') as f:
        json.dump(vault_meta, f)

    encrypt_vaultdata_file(outer_key)

# Extract file from vault
def extract_file_from_vault(vault_name, vault_keys, file_name, destination_path):
    if not is_session_active():
        raise Exception("[ERROR] Session is not active!")
    reset_session_timer()

    outer_key = vault_keys["outer_key"]
    inner_key = vault_keys["inner_key"]

    enc_vault_name = hashlib.sha256(outer_key + vault_name.encode('utf-8')).hexdigest()
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)

    if initialize_vault_metadata(vault_folder):
        if not os.path.exists(ENC_VAULT_METADATA_FILE):
            return

    try:
        decrypt_vaultdata_file(outer_key)
    except Exception as e:
        print(f"[ERROR] Extract file error: {e}")
        return

    with open(VAULT_METADATA_FILE, 'r') as f:
        vault_meta = json.load(f)

    encrypt_vaultdata_file(outer_key)

    file_metadata = next((file for file in vault_meta["files"] if file["name"].lower() == file_name.lower()), None)
    if not file_metadata:
        raise Exception(f"[ERROR] File cannot find in the metadata: {file_name}")
    
    enc_file_name = hashlib.sha256(inner_key + file_name.encode('utf-8')).hexdigest()
    encrypted_path = os.path.join(vault_folder, f"{enc_file_name}.enc")

    if not os.path.exists(encrypted_path):
        raise Exception(f"[ERROR] Encrypted file is not on the disk! Searched Path: {encrypted_path}")
    
    enc_file_hash = calculate_file_hash(encrypted_path)
    stored_enc_file_hash = next((file["enc_hash"] for file in vault_meta["files"] if file["name"] == file_name), None)
    if enc_file_hash != stored_enc_file_hash:
        #print("Encrypted file corrupted!")
        raise Exception(f"[ERROR] Encrypted File Corrupted! Expected Hash: {stored_enc_file_hash}, File Hash: {enc_file_hash}")

    try:
        decrypt_file(inner_key, encrypted_path, file_name, destination_path)
    except Exception as e:
        print(f"[ERROR] Extract file error: {e}")
        return
    decrypted_path = os.path.join(destination_path, f"{file_name}")
    file_hash = calculate_file_hash(decrypted_path)
    stored_file_hash = next((file["hash"] for file in vault_meta["files"] if file["name"] == file_name), None)
    if file_hash != stored_file_hash:
        #print("Decrypted file corrupted!")
        raise Exception(f"[ERROR] Decrypted File Corrupted! Expected Hash: {stored_file_hash}, File Hash: {file_hash}")

# Password Manager
def create_passMngr(passMngr_pass, pass_Mngr=None):
    if not is_session_active():
        return
    reset_session_timer()
    global USER_SYSTEM_SALT
    #Create PASS_METADA_FILE
    try:
        if not os.path.exists(PASS_METADATA_FILE):
            with open(PASS_METADATA_FILE, 'w') as f:
                json.dump({}, f)
        pass_Mngr = "Sirius Password Manager"
        with open(PASS_METADATA_FILE, 'r') as f:
            pass_Mngrs = json.load(f)
        USER_SYSTEM_SALT = initialize_user_system_salt()
        outer_salt = USER_SYSTEM_SALT
        pm_outer_key, _, _ = generate_key(passMngr_pass, outer_salt)
        pm_inner_key, passMngr_auth_hash, inner_salt = generate_key(passMngr_pass)
        pass_Mngrs[pass_Mngr] = {"auth_hash": passMngr_auth_hash.decode('utf-8'),
                                 "inner_salt": inner_salt.hex(),
                                 "services": []}
        with open(PASS_METADATA_FILE, 'w') as f:
            json.dump(pass_Mngrs, f)
        session["pm_outer_key"] = pm_outer_key
        session["pm_inner_key"] = pm_inner_key
        encrypt_passdata_file(pm_outer_key)
        return True
    except Exception as e:
        print(f"[ERROR] Password Manager Creation failed: {e}")

# Authenticate Password Manager //Maybe add username as arg?
def authenticate_passMngr(passMngr_pass, pass_Mngr=None):
    if not is_session_active():
        return False
    reset_session_timer()
    global USER_SYSTEM_SALT
    if not os.path.exists(ENC_PASS_METADATA_FILE):
        print("Password Manager for User not created.")
        return False
    USER_SYSTEM_SALT = initialize_user_system_salt()
    outer_key, _, _ = generate_key(passMngr_pass, USER_SYSTEM_SALT)
    try:
        if decrypt_passdata_file(outer_key):
            with open(PASS_METADATA_FILE, 'r') as f:
                pass_Mngrs = json.load(f)
            pass_Mngr = "Sirius Password Manager"
            if pass_Mngr in pass_Mngrs:
                stored_salt = bytes.fromhex(pass_Mngrs[pass_Mngr].get("inner_salt"))
                inner_key, auth_hash, _ = generate_key(passMngr_pass, stored_salt)
                stored_hash = pass_Mngrs[pass_Mngr].get("auth_hash")
                if stored_hash == auth_hash.decode('utf-8'):
                    encrypt_passdata_file(outer_key)
                    session["pm_outer_key"] = outer_key
                    session["pm_inner_key"] = inner_key
                    return True
            encrypt_passdata_file(outer_key)
            return False
        # LEGACY
        if legacy.decrypt_passdata_file_legacy(passMngr_pass):
            print("[INFO] Legacy Password Manager detected. Initiating migration...")

            if migrate_pm_to_pqc(passMngr_pass):
                session["pm_outer_key"] = outer_key
                session["pm_inner_key"] = inner_key
                reset_session_timer()
                encrypt_passdata_file(outer_key)
                return True
            else:
                legacy.encrypt_passdata_file_legacy(passMngr_pass)
                return False
        return False
    except Exception as e:
        try: 
            legacy.encrypt_passdata_file_legacy(passMngr_pass)
            encrypt_passdata_file(outer_key)
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

    pm_outer_key = session.get("pm_outer_key")
    pm_inner_key = session.get("pm_inner_key")

    if not pm_outer_key or not decrypt_passdata_file(pm_outer_key):
        return None
    try:
        pass_Mngr = "Sirius Password Manager"
        with open(PASS_METADATA_FILE, 'r') as f:
            pass_Mngrs = json.load(f)
        encrypted_service_pass = encrypt_text(pm_inner_key, service_pass)
        service_metadata = {
            "service_name": service_name,
            "service_user_mail": service_user_mail,
            "service_pass": encrypted_service_pass
        }
        pass_Mngrs[pass_Mngr]["services"].append(service_metadata)
        with open(PASS_METADATA_FILE, 'w') as f:
            json.dump(pass_Mngrs, f)
    finally:
        encrypt_passdata_file(pm_outer_key)

# List Services in PassMngr
def list_services_in_passMngr(pass_Mngr=None):
    if not is_session_active():
        return
    reset_session_timer()

    pm_outer_key = session.get("pm_outer_key")
    
    if not pm_outer_key or not decrypt_passdata_file(pm_outer_key):
        return None
    try:
        pass_Mngr = "Sirius Password Manager"
        with open(PASS_METADATA_FILE, 'r') as f:
            pass_Mngrs = json.load(f)
        if pass_Mngr not in pass_Mngrs:
            print("Incorrect Password Manager or Password!")
            return
        services = pass_Mngrs[pass_Mngr]["services"]
        return services
    finally:
        encrypt_passdata_file(pm_outer_key)

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
    
# Generate Password
def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_specials=True, use_advanced_specials=False, min_upper=1, min_lower=1, min_digits=1, min_specials=1):
    
    pool = ""
    password_chars = []
    safe_specials = "!@#$%^&*"
    advanced_specials = "()_+-=[]{}|;:,.<>?"

    active_specials = safe_specials
    if use_advanced_specials:
        active_specials += advanced_specials

    if use_upper:
        pool += string.ascii_uppercase
        password_chars.extend(secrets.choice(string.ascii_uppercase) for _ in range(min_upper))
    if use_lower:
        pool += string.ascii_lowercase
        password_chars.extend(secrets.choice(string.ascii_uppercase) for _ in range(min_lower))
    if use_digits:
        pool += string.digits
        password_chars.extend(secrets.choice(string.digits) for _ in range(min_digits))
    if use_specials:
        pool += active_specials
        password_chars.extend(secrets.choice(active_specials) for _ in range(min_specials))

    if not pool or len(password_chars) > length:
        return None
    
    password_chars.extend(secrets.choice(pool) for _ in range(length - len(password_chars)))

    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)

# Generate Passphrase
def generate_passphrase(word_count=4, separator="-", capitalize=False, include_numbers=False):

    wordlist_file = get_resource_path("wordlist.txt")
    wordlist = []

    if os.path.exists(wordlist_file):
        try:
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        wordlist.append(parts[1])
        except Exception as e:
            print(f"[ERROR] Could not read wordlist file: {e}")

    if not wordlist:
        print("[WARNING] Using fallback wordlist!")
        wordlist = [
            "apple", "brave", "crane", "dance", "eagle", "flame", "grape", "heart", "image", "juice",
            "knife", "lemon", "magic", "night", "ocean", "piano", "queen", "river", "snake", "train",
            "uncle", "voice", "water", "xenon", "yacht", "zebra", "alarm", "bread", "cloud", "dream",
            "earth", "force", "ghost", "house", "iron", "jelly", "karma", "light", "mouse", "nurse",
            "onion", "peace", "quote", "radio", "stone", "tiger", "union", "video", "wheat", "xerox",
            "youth", "zesty", "arrow", "beach", "cabin", "delta", "enemy", "frost", "giant", "honey",
            "index", "judge", "knock", "laser", "metal", "ninja", "orbit", "pilot", "quest", "robot",
            "sugar", "toast", "ultra", "virus", "watch", "xray", "yield", "zonal", "asset", "blend",
            "chase", "draft", "elite", "focal", "globe", "habit", "issue", "joint", "kneel", "logic"
        ]

    words = [secrets.choice(wordlist) for _ in range(word_count)]

    if capitalize:
        words = [w.capitalize() for w in words]

    if include_numbers:
        target_index = secrets.randbelow(word_count)
        random_digit = str(secrets.randbelow(10))
        words[target_index] += random_digit

    return separator.join(words)

# Extract Password for service
def extract_password_service(service_name, pass_Mngr=None):
    if not is_session_active():
        return
    reset_session_timer()

    pm_outer_key = session.get("pm_outer_key")
    pm_inner_key = session.get("pm_inner_key")

    if not pm_outer_key or not decrypt_passdata_file(pm_outer_key):
        return None
    try:
        pass_Mngr = "Sirius Password Manager"
        with open(PASS_METADATA_FILE, 'r') as f:
            pass_Mngrs = json.load(f)
        service_metadata = next((services for services in pass_Mngrs[pass_Mngr]["services"] if services["service_name"].lower() == service_name.lower()), None)
        if not service_metadata:
            print("Service not found! Check the list and try again.")
            return None
        decrypted_pass = decrypt_text(pm_inner_key, service_metadata["service_pass"])
        return decrypted_pass
    finally:
        encrypt_passdata_file(pm_outer_key)

# Remove Password for service
def remove_password_service(service_name, pass_Mngr=None):
    if not is_session_active():
        return
    reset_session_timer()

    pm_outer_key = session.get("pm_outer_key")

    if not pm_outer_key or not decrypt_passdata_file(pm_outer_key):
        return None
    try:
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
    finally:
        encrypt_passdata_file(pm_outer_key)

# Delete Password Manager
def delete_passMngr(username, user_password):
    load_user_context(username)
    if authenticate_user(username, user_password):
        if os.path.exists(PASS_METADATA_FILE):
            secure_delete(PASS_METADATA_FILE)
        if os.path.exists(ENC_PASS_METADATA_FILE):
            secure_delete(ENC_PASS_METADATA_FILE)

        if not os.path.exists(PASS_METADATA_FILE) and not os.path.exists(ENC_PASS_METADATA_FILE):
            print("Password Manager deleted successfuly!")
            return True
        else:
            print("Something went wrong. Please be sure to close all files and try again.")
            return False
    else:
        print("User authentication failed.")
        return False
