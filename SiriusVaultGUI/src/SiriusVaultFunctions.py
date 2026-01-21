import os
import io
import json
import hashlib
import time
import base64
import shutil
import sys
import mimetypes
import secrets
import subprocess
import ctypes
import stat
from PIL import Image
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
    logout_user()  # Logout if the session expired
    return False

def logout_user():
    global session_timer
    if session_timer:
        session_timer.cancel()
    session["authenticated_user"] = None
    session["session_expiry"] = None
    print("\nSession expired. Please authenticate again.")
    return True

def exit_program():
    global session_timer
    if session_timer:
        session_timer.cancel()
    print("Exiting Sirius Vault.")
    sys.exit()

# .env
def set_file_readonly(filepath):
    try: os.chmod(filepath, stat.S_IREAD)
    except: pass

def remove_readonly(filepath):
    try: os.chmod(filepath, stat.S_IWRITE)
    except: pass

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

# Multimedia Manager (TESTING)
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
        return "SAME_NAME"
    vaults[vault_name] = {"owner": username, "key": key.hex(), "salt": salt.hex(), "files": []}
    with open(VAULT_METADATA_FILE, 'w') as f:
        json.dump(vaults, f)
    if not os.path.exists(vault_path): 
        os.makedirs(vault_path)
        return "SUCCESS"
    else:
        return "SAME_NAME"

# Open the vault
def authenticate_vault(vault_name, vault_password):
    if not is_session_active():
        return None
    username = session["authenticated_user"]
    reset_session_timer()

    with open(VAULT_METADATA_FILE, 'r') as f:
        vaults = json.load(f)
    if vault_name not in vaults or vaults[vault_name]["owner"] != username:
        #print("Access denied!")
        return None
    stored_salt = bytes.fromhex(vaults[vault_name]["salt"])
    stored_key = bytes.fromhex(vaults[vault_name]["key"])
    key, salt = generate_key(vault_password, stored_salt)
    if stored_key == key and salt.hex() == vaults[vault_name]["salt"]:
        #print("Vault authentication successful!")
        return key
    #print("Incorrect password!")
    return None

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
    return True


# Authenticate Password Manager
def authenticate_passMngr(passMngr_pass, pass_Mngr=None):
    if not is_session_active():
        return False
    reset_session_timer()
    if not os.path.exists(PASS_METADATA_FILE):
        return False
    with open(PASS_METADATA_FILE, 'r') as f:
        pass_Mngrs = json.load(f)
    pass_Mngr = "Sirius Password Manager"
    if pass_Mngr not in pass_Mngrs:
        return False
    passMngr_salt = bytes.fromhex(pass_Mngrs[pass_Mngr]["salt"])
    stored_password_hash = bytes.fromhex(pass_Mngrs[pass_Mngr]["password_hash"])
    password_hash, _ = generate_key(passMngr_pass, passMngr_salt)
    if stored_password_hash == password_hash:
        reset_session_timer()
        return True
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
        return False
    pass_Mngrs[pass_Mngr]["services"].remove(service_metadata)
    with open(PASS_METADATA_FILE, 'w') as f:
        json.dump(pass_Mngrs, f)
    return True

# Delete Password Manager
def delete_passMngr(username, user_password):

    if os.path.exists(PASS_METADATA_FILE):
        os.remove(PASS_METADATA_FILE)
    if os.path.exists(ENC_PASS_METADATA_FILE):
        os.remove(ENC_PASS_METADATA_FILE)

    if not os.path.exists(PASS_METADATA_FILE) and not os.path.exists(ENC_PASS_METADATA_FILE):
        print("Password Manager deleted successfuly!")
        ##authenticate_menu_1(username, user_password)
        ##Change this code with return to dashboard screen
    else:
        print("Something went wrong. Please be sure to close all files and try again.")
        return
