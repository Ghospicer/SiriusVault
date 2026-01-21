import os
import io
import json
import hashlib
import time
import base64
import shutil
import sys
import mimetypes
import cv2
import pygame
import string
import secrets
import re
import subprocess
import ctypes
import stat
import platform
from PIL import Image
from getpass4 import getpass
from dotenv import load_dotenv
from threading import Timer
from cryptography.fernet import Fernet

load_dotenv()

# Constants for user, password and vault management
# GLOBAL PATH VARIABLES
STORAGE_ROOT = None
VAULTS_DIR = None
DATA_FOLDER = None
USER_DIR = None
USER_DATA_FILE = None
ENC_USER_DATA_FILE = None
VAULT_METADATA_FILE = None
ENC_VAULT_METADATA_FILE = None
PASS_METADATA_FILE = None
ENC_PASS_METADATA_FILE = None

# LOCAL PATHS
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMP_DIR = os.path.join(BASE_DIR, "..", "temp")
FILE_IN = os.path.join(BASE_DIR, "..", "file in")
FILE_OUT = os.path.join(BASE_DIR, "..", "file out")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
SESSION_TIMEOUT = 300  # 5 minutes

# Initialize storage files if they do not exist
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
    logout_user()
    return False

def logout_user():
    global session_timer
    if session_timer:
        session_timer.cancel()
    session["authenticated_user"] = None
    session["session_expiry"] = None
    print("\nSession expired. Please authenticate again.")

def exit_program():
    global session_timer
    if session_timer:
        session_timer.cancel()
    print("Exiting Sirius Vault.")
    sys.exit()

# .env
def set_file_readonly(filepath):
    try:
        os.chmod(filepath, stat.S_IREAD)
    except Exception as e:
        print(f"[WARNING] {filepath} can not locked: {e}")

def remove_readonly(filepath):
    try:
        os.chmod(filepath, stat.S_IWRITE)
    except Exception as e:
        pass

def initialize_system_salt():
    env_path = os.path.join(BASE_DIR, ".env")

    raw_env = os.getenv('SYSTEM_SALT')
    salt_from_env = raw_env if raw_env and raw_env.strip() else None
    salt_from_config = None
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config_data = json.load(f)
                salt_from_config = config_data.get("system_salt_backup")
        except:
            pass
    
    final_salt = None

    if salt_from_env:
        final_salt = salt_from_env
        if salt_from_config != salt_from_env:
            if salt_from_config:
                print(f"[WARNING] Salts not match. Using SALT from .env ({salt_from_env[:4]}...).")
            try:
                config_data = {}
                if os.path.exists(CONFIG_FILE):
                    with open(CONFIG_FILE, 'r') as f:
                        try: config_data = json.load(f)
                        except: config_data = {}
                
                config_data["system_salt_backup"] = final_salt
                with open(CONFIG_FILE, 'w') as f:
                    json.dump(config_data, f, indent=4)
            except Exception as e:
                print(f"[ERROR] Config backup failed: {e}")
        set_file_readonly(env_path)
    elif not salt_from_env and salt_from_config:
        print("[WARNING] Missing .env file! Loading backup from config file...")
        final_salt = salt_from_config
        
        try:
            if os.path.exists(env_path): remove_readonly(env_path)
            
            with open(env_path, "w") as f:
                f.write(f"SYSTEM_SALT={final_salt}")
            
            os.environ['SYSTEM_SALT'] = final_salt
            set_file_readonly(env_path)
        except Exception as e:
            print(f"[ERROR] .env file cannot recovered: {e}")
            sys.exit(1)
    else:
        print("[WARNING] System cannot find the SALT. Creating a new one...")
        new_salt = secrets.token_hex(16)
        final_salt = new_salt
        
        if os.path.exists(env_path): remove_readonly(env_path)
        with open(env_path, "w") as f:
            f.write(f"SYSTEM_SALT={new_salt}")
        set_file_readonly(env_path)
        
        try:
            config_data = {}
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    try: config_data = json.load(f)
                    except: config_data = {}
            config_data["system_salt_backup"] = new_salt
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config_data, f, indent=4)
        except:
            pass

    return final_salt

SYSTEM_SALT = initialize_system_salt()

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
    
    global USER_DIR, VAULTS_DIR, USER_DATA_FILE, ENC_USER_DATA_FILE, VAULT_METADATA_FILE, ENC_VAULT_METADATA_FILE, PASS_METADATA_FILE, ENC_PASS_METADATA_FILE

    user_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()

    USER_DIR = os.path.join(DATA_FOLDER, user_hash)

    VAULTS_DIR = os.path.join(USER_DIR, "Vaults")

    USER_DATA_FILE = os.path.join(USER_DIR, "user.json")
    ENC_USER_DATA_FILE = os.path.join(USER_DIR, "user.json.enc")
    VAULT_METADATA_FILE = os.path.join(USER_DIR, "vault_metadata.json")
    ENC_VAULT_METADATA_FILE = os.path.join(USER_DIR, "vault_metadata.json.enc")
    PASS_METADATA_FILE = os.path.join(USER_DIR, "pass_metadata.json")
    ENC_PASS_METADATA_FILE = os.path.join(USER_DIR, "pass_metadata.json.enc")

    return USER_DIR

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
    jsonKey, _ = generate_key(data_key, data_salt)
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

# In Use
def encrypt_passdata_file(password):
    if not os.path.exists(PASS_METADATA_FILE):
        return
    data_salt = bytes.fromhex(SYSTEM_SALT)
    data_key = password
    jsonKey, _ = generate_key(data_key, data_salt)
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
        print("pass_metadata.json file not found!")
        return
    return encrypted_path

# In use
def decrypt_userdata_file(password):
    if not os.path.exists(ENC_USER_DATA_FILE):
        return
    decrypted_path = USER_DATA_FILE
    data_salt = bytes.fromhex(SYSTEM_SALT)
    data_key = password
    jsonKey, _ = generate_key(data_key, data_salt)
    fernet = Fernet(jsonKey)
    with open(ENC_USER_DATA_FILE, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(decrypted_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    return decrypted_path

# In use
def decrypt_vaultdata_file(password):
    if not os.path.exists(ENC_VAULT_METADATA_FILE):
        return
    decrypted_path = VAULT_METADATA_FILE
    data_salt = bytes.fromhex(SYSTEM_SALT)
    data_key = password
    jsonKey, _ = generate_key(data_key, data_salt)
    fernet = Fernet(jsonKey)
    with open(ENC_VAULT_METADATA_FILE, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(decrypted_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    return decrypted_path

# In Use
def decrypt_passdata_file(password):
    if not os.path.exists(ENC_PASS_METADATA_FILE):
        return
    decrypted_path = PASS_METADATA_FILE
    data_salt = bytes.fromhex(SYSTEM_SALT)
    data_key = password
    jsonKey, _ = generate_key(data_key, data_salt)
    fernet = Fernet(jsonKey)
    with open(ENC_PASS_METADATA_FILE, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(decrypted_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    return decrypted_path


# Multimedia Manager (Out of Order)
def multimedia_manager(vault_name, vault_key, file_name):
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)
    enc_vault_name = hashlib.sha256(vault_key + vault_name.encode('utf-8')).hexdigest()
    vault_folder = os.path.join(VAULTS_DIR, enc_vault_name)
    enc_file_name = hashlib.sha256(vault_key + file_name.encode('utf-8')).hexdigest()
    encrypted_path = os.path.join(vault_folder, f"{enc_file_name}.enc")
    if not os.path.exists(encrypted_path):
        print("File can not found.")
        return
    fernet = Fernet(vault_key)
    with open(encrypted_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        print(f"Decryption Error: {e}")
        return
    
    file_type, _ = mimetypes.guess_type(file_name)
    if not file_type:
        print("File not recognized.")
        return

    if file_type.startswith("image/"):
        try:
            img_buffer = io.BytesIO(decrypted_data)
            image = Image.open(img_buffer)
            image.show()
        except Exception as e:
            print(f"Image Error: {e}")
    elif file_type.startswith("audio/"):
        try:
            pygame.mixer.init()
            sound_buffer = io.BytesIO(decrypted_data)
            pygame.mixer.music.load(sound_buffer)
            print("Playing audio. Press Enter to stop.")
            pygame.mixer.music.play()
            input()
            pygame.mixer.music.stop()
            pygame.mixer.quit()
        except Exception as e:
            print(f"Audio Error: {e}")
    elif file_type.startswith("text/") or file_type.endswith(".py", ".json", ".md", ".txt"):
        try:
            text_content = decrypted_data.decode('utf-8')
            print("\n--- File Content ---")
            print(text_content)
            print("----------------------")
            input("Press Enter to return.")
        except UnicodeDecodeError as e:
            print(f"Txt Decode Error: {e}")
    elif file_type.startswith("video/"):
        print("Decrypting video to temp file.")
        file_ext = os.path.splitext(file_name)[1]
        temp_filename = f"temp_video_{int(time.time())}{file_ext}"
        temp_file_path = os.path.join(TEMP_DIR, temp_filename)
        try:
            with open(temp_file_path, 'wb') as f:
                f.write(decrypted_data)
            cap = cv2.VideoCapture(temp_file_path)
            if not cap.isOpened():
                print("Video Codec Problem")
            else:
                print("Playing the video. Press 'q' for exit.")
                while cap.isOpened():
                    ret, frame = cap.read()
                    if not ret:
                        break
                    cv2.imshow('SiriusVault Player', frame)
                cap.release()
                cv2.destroyAllWindows()
        except Exception as e:
            print(f"Video Error: {e}")
        
        finally:
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                    print("Temp file deleted successfully!")
                except PermissionError:
                    print(f"Temp file cant be deleted because of {PermissionError}")
    else:
        print("Unknown file type. (For now.)")
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

    load_user_context(username)

    if os.path.exists(USER_DIR):
        print("User already existing.")
        return False
    else:
        os.makedirs(USER_DIR)
    if not os.path.exists(VAULTS_DIR):
        os.makedirs(VAULTS_DIR)
    
    key, salt =generate_key(password)
    user_data = {"username": username, "password_hash": key.hex(), "salt": salt.hex()}
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(user_data, f)
    encrypt_userdata_file(password)
    print(f"User '{username}' registered successfully!")
    print("You can login now.")
    return True

def authenticate_user(username, password):

    load_user_context(username)
    if not os.path.exists(ENC_USER_DATA_FILE):
        print("User not registered.")
        return False
    try:
        decrypt_userdata_file(password)
        with open(USER_DATA_FILE, 'r') as f:
            user_data = json.load(f)
        stored_salt = bytes.fromhex(user_data["salt"])
        stored_password_hash = bytes.fromhex(user_data["password_hash"])
        derived_key, _ = generate_key(password, stored_salt)
        if stored_password_hash == derived_key:
            print("User Authentication successful!")
            session["authenticated_user"] = username
            reset_session_timer()
            encrypt_userdata_file(password)
            return True
        else:
            encrypt_userdata_file(password)
            return False
    except Exception as e:
        encrypt_userdata_file(password)
        print("Incorrect Username or Password!")
        return False

# Delete user
def delete_user():
    username = session["authenticated_user"]
    if not username: return
    load_user_context(username)
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
        return True
    else:
        print(f"No vaults found for user {username}.")
        return False

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
    
    if list_vaults(username):
        print(f"Vault '{vault_name}' removed!")
    else:
        if os.path.exists(ENC_VAULT_METADATA_FILE):
            os.remove(ENC_VAULT_METADATA_FILE)
        if os.path.exists(VAULT_METADATA_FILE):
            os.remove(VAULT_METADATA_FILE)
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

def list_files_in_vault_GUI(vault_name, username):
    if not is_session_active():
        return
    reset_session_timer()

    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    metadata = vaults.items()
    if vault_name not in vaults and metadata["owner"] != username:
        print("Vault not found!")
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

# Password Manager
def create_passMngr(passMngr_pass, pass_Mngr=None):
    if not is_session_active():
        return
    reset_session_timer()
    #Create PASS_METADA_FILE
    if not os.path.exists(PASS_METADATA_FILE):
        with open(PASS_METADATA_FILE, 'w') as f:
            json.dump({}, f)
    pass_Mngr = "Sirius Password Manager"
    with open(PASS_METADATA_FILE, 'r') as f:
        pass_Mngrs = json.load(f)
    passMngr_key, passMngr_salt = generate_key(passMngr_pass)
    pass_Mngrs[pass_Mngr] = {"password_hash": passMngr_key.hex(), "salt": passMngr_salt.hex(), "services": []}
    with open(PASS_METADATA_FILE, 'w') as f:
        json.dump(pass_Mngrs, f)
    print("Password Manager Created Successfully!")

# Authenticate Password Manager
def authenticate_passMngr(passMngr_pass, pass_Mngr=None):
    if not is_session_active():
        return
    reset_session_timer()
    with open(PASS_METADATA_FILE, 'r') as f:
        pass_Mngrs = json.load(f)
    pass_Mngr = "Sirius Password Manager"
    if pass_Mngr not in pass_Mngrs:
        print("Password Manager does not exist!")
    passMngr_salt = bytes.fromhex(pass_Mngrs[pass_Mngr]["salt"])
    stored_password_hash = bytes.fromhex(pass_Mngrs[pass_Mngr]["password_hash"])
    password_hash, _ = generate_key(passMngr_pass, passMngr_salt)
    if stored_password_hash == password_hash:
        print("Password Manager Authentication successful!")
        reset_session_timer()
        return True
    print("Incorrect Password Manager or Password!")
    return False

# Add Password to Password Manager
def add_password_to_PassMngr(service_name, service_pass, pass_Mngr=None):
    if not is_session_active():
        return
    reset_session_timer()
    pass_Mngr = "Sirius Password Manager"
    with open(PASS_METADATA_FILE, 'r') as f:
        pass_Mngrs = json.load(f)
    service_metadata = {
        "service_name": service_name,
        "service_pass": service_pass
    }
    pass_Mngrs[pass_Mngr]["services"].append(service_metadata)
    with open(PASS_METADATA_FILE, 'w') as f:
        json.dump(pass_Mngrs, f)
    print(f"Password added for service: {service_name}")

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
    print(f"Services in {pass_Mngr}:")
    for services in pass_Mngrs[pass_Mngr]["services"]:
        print(f"  - {services['service_name']}")


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
    print(f"Password for service: {service_name}")
    print(f"{service_pass}")


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
        print("Service not found! Check the list and try again.")
        return
    pass_Mngrs[pass_Mngr]["services"].remove(service_metadata)
    with open(PASS_METADATA_FILE, 'w') as f:
        json.dump(pass_Mngrs, f)
    print(f"Service '{service_name}' removed from {pass_Mngr}")

# Delete Password Manager
def delete_passMngr(username, user_password):

    if os.path.exists(PASS_METADATA_FILE):
        os.remove(PASS_METADATA_FILE)
    if os.path.exists(ENC_PASS_METADATA_FILE):
        os.remove(ENC_PASS_METADATA_FILE)

    if not os.path.exists(PASS_METADATA_FILE) and not os.path.exists(ENC_PASS_METADATA_FILE):
        print("Password Manager deleted successfuly!")
        authenticate_menu(username, user_password)
    else:
        print("Something went wrong. Please be sure to close all files and try again.")
        return
    
# Password Tester
def check_password_strength(password):
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password too short. Must be at least 8 characters.")
    
    if len(password) >= 12:
        score += 1
    
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Missing upper-case letter (A-Z).")
    
    if re.search[r"[a-z]", password]:
        score += 1
    else:
        feedback.append("Missing lower-case letter (a-z).")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Missing number (0-9).")

    if re.search(r"[ !#$%&'()*+,-./:;<=>?@[\]^_`{|}~]", password):
        score += 1
    else:
        feedback.append("Missing special character (!-*).")
    
    return score, feedback

# Password Generator
def password_generator(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c in password) and any(c in string.punctuation for c in password)):
            return password

# Password Manager Audit
def audit_password_manager(passMngr_pass):
    if not is_session_active():
        return
    reset_session_timer()

    print("\n--- Password Security Audit ---")
    print("Being analyzed...\n")

    pass_Mngr = "Sirius Password Manager"

    with open(PASS_METADATA_FILE, 'r') as f:
        pass_Mngrs = json.load(f)

    services = pass_Mngrs[pass_Mngr]["services"]
    if not services:
        print("Can not find any registered Services.")
        return

    weak_passwords_found = False

    for service in services[:]:
        s_name = service["service_name"]
        s_pass = service["service_pass"]

        score, feedback = check_password_strength(s_pass)

        if score < 4:
            weak_passwords_found = True
            print(f"\n Weak password for service [{s_name}]")
            print(f"Score: {score}/5")
            print("Missing: " + ", ".join(feedback))

            change = input("Do you wish to change this password with generated stronger one? (Y/N):")
            
            if change.lower() in ["y", "yes"]:
                new_pass = password_generator()
                print(f"New password for service [{s_name}]: {new_pass}")
                confirm = input("Do you confirm? (Y/N):")

                if confirm.lower() in ["y", "yes"]:
                    service["service_pass"] = new_pass
                    print(f"{s_name} updated.")
                else:
                    print("Password change canceled.")
            else:
                print("Password not changed.")
        
    if weak_passwords_found:
        with open(PASS_METADATA_FILE, 'w') as f:
            json.dump(pass_Mngrs, f)
        print("\n Checks completed. Passwords updated. Please change your passwords on services to.")
    else:
        print("All password look strong")

# # First menu loop
# def first_menu():
#     while True:
#         print("\nSirius Vault")
#         print("\n1. Create User")
#         print("2. Connect external Vault.")
#         print("0. Exit")
#         choice = input("Choose an option: ")
#         if choice == "1":
#             print("Leave blank for default storage, or enter path.")
#             storage_path = input("Storage Path:").strip()
#             if storage_path:
#                 print("\nDo you want to format this drive?")
#                 print("This process deletes all the data on drive and name it 'SIRIUS_VAULT'.")
#                 want_format = input("Format? (Y/N):").strip().lower()
#                 if want_format in ["y", "yes"]:
#                     if format_drive_windows(storage_path):
#                         format_success = True
#                     else:
#                         print("Formatting failed.")
#                 default = False
#                 if not initialize_storage(storage_path, default):
#                     continue
#             else:
#                 default = True
#                 initialize_storage(None, default)
#             if os.path.exists(USER_DATA_FILE) or os.path.exists(ENC_USER_DATA_FILE):
#                 print("\n[ERROR] There is a user data in this location!")
#                 print("Please use '2. Connect external Vault' option.")
#                 print("Process canceled to prevent data loss.")
#                 continue
#             username = input("Username: ")
#             user_password = getpass("Password: ")
#             with open(USER_DATA_FILE, 'w') as f:
#                 json.dump({}, f)
#             create_user(username, user_password)
#             encrypt_userdata_file(user_password)
#             main_menu()
#         elif choice == "2":
#             storage_path = input("Please enter storage path: ").strip()
#             if initialize_storage(storage_path, default=False):
#                 if os.path.exists(ENC_USER_DATA_FILE):
#                     print("External storage found. Redirecting to login screen.")
#                     main_menu()
#                 else:
#                     print("There is no user data on external storage please use option Create user and enter custom storage path.")
#         elif choice == "0":
#             print("Exiting the Sirius Vault.")
#             exit_program()
#         else:
#             print("\nInvalid choice, please try again.")

# # Main menu loop
# def main_menu():
#     global STORAGE_ROOT
#     while True:
#         active_location = f"({STORAGE_ROOT})"
#         print("\nSirius Vault")
#         print(f"Target Path: {active_location}")
#         print("\n1. Log in")
#         print("2. Login with External Vault")
#         print("0. Exit")
#         choice = input("Choose an option: ")
#         if choice == "1":
#             username = input("Enter Username: ")
#             user_password = getpass("Enter Password: ")
#             try:
#                 decrypt_userdata_file(user_password)
#             except:
#                 print("Wrong credentials.")
#                 continue
#             if authenticate_user(username, user_password):
#                 encrypt_userdata_file(user_password)
#                 authenticate_menu(username, user_password)
#             else:
#                 encrypt_userdata_file(user_password)
#         elif choice == "2":
#             storage_path = input("Please enter external storage path: ").strip()
#             if initialize_storage(storage_path, default=False):
#                 if os.path.exists(ENC_USER_DATA_FILE):
#                     print(f"\n[SUCCESS] Target Vault changed.")
#                     print("You can login now.")
#                     username = input("Enter Username: ")
#                     user_password = getpass("Enter Password: ")
#                     try:
#                         decrypt_userdata_file(user_password)
#                     except:
#                         print("Wrong credentials.")
#                         continue
#                     if authenticate_user(username, user_password):
#                         encrypt_userdata_file(user_password)
#                         authenticate_menu(username, user_password)
#                     else:
#                         encrypt_userdata_file(user_password)
#                 else:
#                     print("\n[ERROR] There is no user data on given path.")
#                     print("Returning to default path...")
#                     initialize_storage(default=True)
#             else:
#                 print("Invalid path.")
#         elif choice == "0":
#             exit_program()
#         else:
#             print("Invalid choice, please try again.")

# start_screen
def start_screen():
    global STORAGE_ROOT
    while True:
        location_display = STORAGE_ROOT if STORAGE_ROOT else "Not Set"
        print("\nSIRIUS VAULT")
        print(f"Storage Location: {location_display}")
        print("1. Login")
        print("2. Register")
        print("3. Change Storage Location")
        print("0. Exit")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            username = input("Username: ")
            user_password = getpass("Password: ")
            try:
                if authenticate_user(username, user_password):
                    authenticate_menu(username, user_password)
                else:
                    print("Login failed.")
            except Exception as e:
                print(f"Error: {e}")
        elif choice == "2":
            print("\nCreate New User")
            username = input("Username: ")
            user_password = getpass("Password: ")
            create_user(username, user_password)
        elif choice == "3":
            print("\nCurrent Storage: ", STORAGE_ROOT)
            new_path = input("Enter new storage path: ").strip()
            if os.path.exists(new_path):
                initialize_storage(new_path, default=False)
                print("Storage location updated.")
            else:
                print("Invalid path.")
        elif choice == "0":
            exit_program()
        else:
            print("Invalid choice, please try again.")


# Authenticate menu loops
def authenticate_menu(username, user_password):
    while True:
        print(f"\nWelcome back {username}!")
        print("\n1. Create Vault")
        print("2. Authenticate Vault")
        if not os.path.exists(ENC_PASS_METADATA_FILE):
            print("3. Create Password Manager")
        else:
            print("3. Authenticate Password Manager")
        print("4. List my vaults")
        print("5. Delete a vault")
        print("6. Delete user (This will delete all user data)")
        print("7. Logout")
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
            if not os.path.exists(ENC_VAULT_METADATA_FILE):
                print("You should create a vault first.")
                continue
            vault_name = input("Enter vault name: ")
            vault_password = getpass("Enter vault password: ")
            decrypt_vaultdata_file(user_password)
            vault_key = authenticate_vault(vault_name, vault_password)
            encrypt_vaultdata_file(user_password)
            if vault_key:
                print(f"Access granted to vault: {vault_name}")
                vault_menu(vault_name, vault_password, username, user_password)
        elif choice == "3":
            passMngr_pass = getpass("Enter Password Manager Password: ")
            if not os.path.exists(ENC_PASS_METADATA_FILE):
                create_passMngr(passMngr_pass)
                encrypt_passdata_file(passMngr_pass)
            else:
                decrypt_passdata_file(passMngr_pass)
                if authenticate_passMngr(passMngr_pass):
                    encrypt_passdata_file(passMngr_pass)
                    passwordManager_menu(passMngr_pass, user_password)
        elif choice == "4":
            decrypt_vaultdata_file(user_password)
            list_vaults(username)
            encrypt_vaultdata_file(user_password)
        elif choice == "5":
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
                print("Wrong vault name or password!")
        elif choice == "6":
            print("Warning you are about to delete all vaults, files, passwords and user data!")
            consent_confirm = input("Do you wish to continue?(Y/N)")
            if consent_confirm.lower() in ["y", "yes"]:
                username = input("Enter username: ")
                user_password = getpass("Enter password: ")
                decrypt_userdata_file(user_password)
                if authenticate_user(username, user_password):
                    decrypt_vaultdata_file(user_password)
                    delete_user()
                    start_screen()
                else:
                    print("Wrong username or password")
        elif choice == "7":
            logout_user()
            return
        elif choice == "0":
            exit_program()
        else:
            print("Invalid choice, please try again.")

# Password Manager Menu loop
def passwordManager_menu(passMngr_pass, user_password):
    while True:
        print("\nYou are in the Sirius Password Manager")
        print("\n1. Add Password to Password Manager")
        print("2. List Services in Password Manager")
        print("3. Extract Password for Service")
        print("4. Change Password for Service")
        print("5. Remove Password for Service")
        print("6. Password Security Audit")
        print("7. Delete Password Manager")
        print("8. Back")
        print("0. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            service_name = input("Enter Service Name: ")
            service_pass = getpass("Enter Service Password: ")
            decrypt_passdata_file(passMngr_pass)
            add_password_to_PassMngr(service_name, service_pass)
            encrypt_passdata_file(passMngr_pass)
        elif choice == "2":
            decrypt_passdata_file(passMngr_pass)
            list_services_in_passMngr()
            encrypt_passdata_file(passMngr_pass)
        elif choice == "3":
            decrypt_passdata_file(passMngr_pass)
            list_services_in_passMngr()
            encrypt_passdata_file(passMngr_pass)
            service_name = input("Enter Service name: ")
            pMngr_password = getpass("Enter Password Manager Password: ")
            decrypt_passdata_file(passMngr_pass)
            if authenticate_passMngr(pMngr_password):
                extract_password_service(service_name, pMngr_password)
                encrypt_passdata_file(passMngr_pass)
            else:
                encrypt_passdata_file(passMngr_pass)
        elif choice == "4":
            decrypt_passdata_file(passMngr_pass)
            list_services_in_passMngr()
            encrypt_passdata_file(passMngr_pass)
            pMngr_password = getpass("Enter Password Manager Password: ")
            decrypt_passdata_file(passMngr_pass)
            if authenticate_passMngr(pMngr_password):
                encrypt_passdata_file(passMngr_pass)
                service_name = input("Enter Service name: ")
                new_password = input("Enter new Password for Service: ")
                decrypt_passdata_file(passMngr_pass)
                remove_password_service(service_name, pMngr_password)
                add_password_to_PassMngr(service_name, new_password)
                encrypt_passdata_file(passMngr_pass)
                print(f"Password for {service_name} changed.")
            else:
                encrypt_passdata_file(passMngr_pass)
        elif choice == "5":
            decrypt_passdata_file(passMngr_pass)
            list_services_in_passMngr()
            encrypt_passdata_file(passMngr_pass)
            service_name = input("Enter service name: ")
            pMngr_password = getpass("Enter Password Manager Password: ")
            decrypt_passdata_file(passMngr_pass)
            if authenticate_passMngr(pMngr_password):
                remove_password_service(service_name, pMngr_password)
                encrypt_passdata_file(passMngr_pass)
            else:
                encrypt_passdata_file(passMngr_pass)
        elif choice == "6":
            decrypt_passdata_file(passMngr_pass)
            audit_password_manager(passMngr_pass)
            encrypt_passdata_file(passMngr_pass)
        elif choice == "7":
            print("Warning you are about to delete all passwords in password manager!")
            consent_confirm = input("Do you wish to continue?(Y/N)")
            if consent_confirm.lower() in ["y", "yes"]:
                username = input("Enter username: ")
                user_password = getpass("Enter password: ")
                pMngr_password = getpass("Enter Password Manager Password: ")
                decrypt_userdata_file(user_password)
                if authenticate_user(username, user_password):
                    encrypt_userdata_file(user_password)
                    decrypt_passdata_file(passMngr_pass)
                    if authenticate_passMngr(pMngr_password):    
                        delete_passMngr(username, user_password)
                    else:
                        encrypt_passdata_file(passMngr_pass)
                        print("Wrong username or password.")
                else:
                    encrypt_userdata_file(user_password)
                    print("Wrong username or password.")
        elif choice == "8":
            logout_user()
        elif choice == "0":
            exit_program()
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
        print("5. View Files") #Out of Order
        print("6. Back")
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
                if file_remove.lower() in ["y", "yes"]:
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
                if file_remove.lower() in ["y", "yes"]:
                    decrypt_vaultdata_file(user_password)
                    remove_file_from_vault(vault_name, file_name, username, vault_key)
                    encrypt_vaultdata_file(user_password)
            else:
                print("Wrong password!")
        elif choice == "5":
            decrypt_vaultdata_file(user_password)
            list_files_in_vault(vault_name, username)
            encrypt_vaultdata_file(user_password)
            file_name = input("File name you want to view:")
            vault_password = getpass("Enter vault password: ")
            decrypt_vaultdata_file(user_password)
            vault_key = authenticate_vault(vault_name, vault_password)
            encrypt_vaultdata_file(user_password)
            if vault_key:
                decrypt_vaultdata_file(user_password)
                multimedia_manager(vault_name, vault_key, file_name)
                encrypt_vaultdata_file(user_password)
        elif choice == "6":
            authenticate_menu(username, user_password)
        elif choice == "0":
            exit_program()
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    config = load_config()
    loaded_from_config = False

    default_root_path = os.path.abspath(os.path.join(BASE_DIR, ".."))

    if config and "last_storage_root" in config:
        last_path = config["last_storage_root"]
    
        if os.path.exists(last_path):
            print(f"[INFO] Storage loaded from config: {last_path}")
            if os.path.normpath(last_path) == os.path.normpath(default_root_path):
                if initialize_storage(default=True):
                    loaded_from_config = True
            else:
                parent_path = os.path.dirname(last_path)
                if initialize_storage(parent_path, default=False):
                    loaded_from_config = True
        else:
            print("[INFO] There is no config file. Using defaults.")
    
    if not loaded_from_config:
        initialize_storage(default=True)

    start_screen()