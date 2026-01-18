import SiriusVaultFunctions as backend
import customtkinter as ctk
import os
import sys
import json
from tkinter import messagebox

# System Settings
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

class SiriusVault(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Sirius Vault")
        self.geometry("900x600")
        self.resizable(False, False)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.container = ctk.CTkFrame(self)
        self.container.grid(row=0, column=0, sticky="nsew")
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        self.screen_classes = (RegisterScreen, LoginScreen, DashboardScreen, PasswordManagerScreen, VaultDetailScreen, CreateVaultScreen, AuthVaultScreen, DeleteVaultScreen, DeleteUserScreen)

        for F in self.screen_classes:
            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame

        if os.path.exists(backend.USER_DATA_FILE) or os.path.exists(backend.ENC_USER_DATA_FILE):
            self.show_frame("LoginScreen")
        else:
            self.show_frame("RegisterScreen")

    def show_frame(self, page_name, data=None):
        for frame in self.frames.values():
            frame.grid_forget()

        frame = self.frames[page_name]
        frame.grid(row=0, column=0, sticky="nsew")
        
        
        if hasattr(frame, "on_show"):
            self.after(20, lambda: frame.on_show(data))
    
    def get_user_password(self):
        return self.frames["LoginScreen"].entry_userpassword.get()

# Register Screen    
class RegisterScreen(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        ctk.CTkLabel(self, text="Welcome to Sirius Vault", font=("Roboto Medium", 32)).pack(pady=(60, 10))
        ctk.CTkLabel(self, text="Create New User", font=("Roboto Medium", 16)).pack(pady=(0,30))

        self.entry_username = ctk.CTkEntry(self, placeholder_text="Username", width=300)
        self.entry_username.pack(pady=10)
        self.entry_userpassword = ctk.CTkEntry(self, placeholder_text="Password", show="*", width=300)
        self.entry_userpassword.pack(pady=10)

        btn_create_user = ctk.CTkButton(self, text="Register", width=300, command=self.create_user)
        btn_create_user.pack(pady=20)
        self.btn_exit = ctk.CTkButton(self, text="Exit", width=300, fg_color="#444", hover_color="#333", command=sys.exit)
        self.btn_exit.pack(pady=5)
        
    def on_show(self, data=None):
        self.entry_username.delete(0, "end")
        self.entry_userpassword.delete(0, "end")

        # HACK:
        self.entry_username.configure(placeholder_text="Username")
        self.entry_userpassword.configure(placeholder_text="Password")

    def create_user(self):
        username = self.entry_username.get()
        user_password = self.entry_userpassword.get()

        if username and user_password:
            with open(backend.USER_DATA_FILE, 'w') as f:
                json.dump({}, f)
            backend.create_user(username, user_password)
            backend.encrypt_userdata_file(user_password)
            
            messagebox.showinfo(title="Success!", message=f"User '{username}' registered successfully!")
            self.controller.show_frame("LoginScreen")
        else:
            messagebox.showwarning(title="Warning!", message="Please fill all the field provided.")

# Login Screen    
class LoginScreen(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        lbl_title = ctk.CTkLabel(self, text="SIRIUS VAULT", font=("Roboto Medium", 32))
        lbl_title.pack(pady=(80, 20))

        self.entry_username = ctk.CTkEntry(self, placeholder_text="Username", width=300)
        self.entry_username.pack(pady=10)
        self.entry_userpassword = ctk.CTkEntry(self, placeholder_text="Password", show="*", width=300)
        self.entry_userpassword.pack(pady=10)

        btn_login = ctk.CTkButton(self, text="Login", width=300, command=self.attempt_login)
        btn_login.pack(pady=20)
        self.btn_exit = ctk.CTkButton(self, text="Exit", width=300, fg_color="#444", hover_color="#333", command=sys.exit)
        self.btn_exit.pack(pady=5)

    def on_show(self, data=None):
        self.entry_username.delete(0, "end")
        self.entry_userpassword.delete(0, "end")

        # HACK:
        self.entry_username.configure(placeholder_text="Username")
        self.entry_userpassword.configure(placeholder_text="Password")

    def attempt_login(self):
        username = self.entry_username.get()
        user_password = self.entry_userpassword.get()

        if not username or not user_password:
            messagebox.showerror(title="Error!", message="Please fill all the field provided.")
            return
        
        try:
            backend.decrypt_userdata_file(user_password)

            if backend.authenticate_user(username, user_password):
                backend.encrypt_userdata_file(user_password)
                self.controller.show_frame("DashboardScreen")
            else:
                backend.encrypt_userdata_file(user_password)
                messagebox.showerror(title="Error!", message="Wrong username or password.")
        except Exception as e:
            messagebox.showerror(title="ERROR!", message=f"File Decryption Error: {e}")

# Dashboard Screen
class DashboardScreen(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # Left Side (SideBar)
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")

        lbl_brand = ctk.CTkLabel(self.sidebar, text="Sirius Vault", font=("Roboto Medium", 20))
        lbl_brand.pack(pady=30, padx=20)

        btn_new_vault = ctk.CTkButton(self.sidebar, text="Create New Vault", command=lambda: self.controller.show_frame("CreateVaultScreen"))
        btn_new_vault.pack(pady=10, padx=20)
        self.btn_pm = ctk.CTkButton(self.sidebar, text="Password Manager", fg_color="transparent", border_width=2, command=lambda: self.controller.show_frame("PasswordManagerScreen"))
        self.btn_pm.pack(pady=10, padx=20)

        btn_delete_user = ctk.CTkButton(self.sidebar, text="Delete User", fg_color="#b32d2d", command=lambda: self.controller.show_frame("DeleteUserScreen"))
        btn_delete_user.pack(pady=10, padx=20)

        ctk.CTkButton(self.sidebar, text="Exit", fg_color="#b32d2d", hover_color="#801f1f", command=self.logout).pack(side="bottom", pady=30, padx=20)

        # Right Side (Content)
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.pack(side="right", fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(self.content, text="Vaults", font=("Roboto Medium", 24)).pack(anchor="w")
        
        self.vault_list_frame = ctk.CTkScrollableFrame(self.content, label_text="Existing Vaults")
        self.vault_list_frame.pack(fill="both", expand=True, pady=10)

    def on_show(self, data=None):
        self.refresh_vaults()

        if os.path.exists(backend.ENC_PASS_METADATA_FILE):
            self.btn_pm.configure(text="Password Manager Login")
        else:
            self.btn_pm.configure(text="Create Password Manager")

    def refresh_vaults(self):
        for widget in self.vault_list_frame.winfo_children():
            widget.destroy()

        username = backend.session.get("authenticated_user")
        user_password = self.controller.get_user_password()

        if os.path.exists(backend.VAULT_METADATA_FILE) or os.path.exists(backend.ENC_VAULT_METADATA_FILE):
            try:
                backend.decrypt_vaultdata_file(user_password)
                user_vaults = backend.list_vaults_GUI(username)
                backend.encrypt_vaultdata_file(user_password)
                for vault_name in user_vaults:
                    self.create_vault_item(vault_name)
            except Exception as e:
                messagebox.showerror(title="Error!", message=f"Vault Listing Error: {e}")
        else:
            return

    def create_vault_item(self, vault_name):
        row = ctk.CTkFrame(self.vault_list_frame)
        row.pack(fill="x", pady=5)

        lbl = ctk.CTkLabel(row, text=vault_name, font=("Roboto", 16))
        lbl.pack(side="left", padx=10)

        btn_open = ctk.CTkButton(row, text="Open Vault", width=80, command=lambda: self.controller.show_frame("AuthVaultScreen", data=vault_name))
        btn_open.pack(side="right", padx=10, pady=5)
        btn_delete_vault = ctk.CTkButton(row, text="Delete", width=60, fg_color="#c0392b", hover_color="#922b21", command=lambda: self.controller.show_frame("DeleteVaultScreen", data=vault_name))
        btn_delete_vault.pack(side="right", padx=(0, 5), pady=5)

            
    def logout(self):
        backend.logout_user()
        self.controller.show_frame("LoginScreen")

# Password Manager Screen
class PasswordManagerScreen(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        self.login_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.login_frame.pack(fill="both", expand=True)

        self.lbl_pm_title = ctk.CTkLabel(self.login_frame, text="Sirius Password Manager", font=("Roboto Medium", 24))
        self.lbl_pm_title.pack(pady=(60, 20))

        self.entry_master_pass = ctk.CTkEntry(self.login_frame, placeholder_text="Master Password", show="*", width=300)
        self.entry_master_pass.pack(pady=10)

        self.btn_pmLogin = ctk.CTkButton(self.login_frame, text="Login", width=300, command=self.handle_auth_action)
        self.btn_pmLogin.pack(pady=20)
        
        ctk.CTkButton(self.login_frame, text="Back", width=300, fg_color="#555", command=lambda: controller.show_frame("DashboardScreen")).pack(pady=5)

        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        
        self.top_bar = ctk.CTkFrame(self.content_frame, height=50)
        self.top_bar.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(self.top_bar, text="My Passwords", font=("Roboto Medium", 20)).pack(side="left", padx=20)
        ctk.CTkButton(self.top_bar, text="Back / Lock", width=100, fg_color="#555", command=self.lock_and_exit).pack(side="right", padx=10)
        ctk.CTkButton(self.top_bar, text="Delete Manager", width=120, fg_color="#c0392b", hover_color="#922b21", command=self.delete_manager).pack(side="right", padx=10)

        self.add_frame = ctk.CTkFrame(self.content_frame)
        self.add_frame.pack(fill="x", padx=10, pady=5)
        
        self.entry_service_name = ctk.CTkEntry(self.add_frame, placeholder_text="Service Name (e.g. Netflix)")
        self.entry_service_name.pack(side="left", fill="x", expand=True, padx=5, pady=10)
        
        self.entry_service_pass = ctk.CTkEntry(self.add_frame, placeholder_text="Password", show="*")
        self.entry_service_pass.pack(side="left", fill="x", expand=True, padx=5, pady=10)
        
        ctk.CTkButton(self.add_frame, text="Add", width=80, command=self.add_service).pack(side="right", padx=10)

        self.scroll_frame = ctk.CTkScrollableFrame(self.content_frame, label_text="Saved Services")
        self.scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

    def on_show(self, data=None):
        self.is_authenticated = False
        self.content_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)
        
        self.entry_master_pass.delete(0, "end")
        # HACK:
        self.entry_master_pass.configure(placeholder_text="Master Password")
        
        if os.path.exists(backend.ENC_PASS_METADATA_FILE):
            self.lbl_pm_title.configure(text="Unlock Password Manager")
            self.btn_pmLogin.configure(text="Login")
        else:
            self.lbl_pm_title.configure(text="Create Password Manager")
            self.btn_pmLogin.configure(text="Create & Encrypt")

    def handle_auth_action(self):
        master_pass = self.entry_master_pass.get()
        user_sys_pass = self.controller.get_user_password()
        
        if not master_pass:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        try:
            if os.path.exists(backend.ENC_PASS_METADATA_FILE):
                backend.decrypt_passdata_file(user_sys_pass)
                if backend.authenticate_passMngr(master_pass):
                    self.is_authenticated = True
                    self.show_content()
                else:
                    backend.encrypt_passdata_file(user_sys_pass)
                    messagebox.showerror("Error", "Incorrect Master Password.")
            
            else:
                backend.create_passMngr(master_pass)
                backend.encrypt_passdata_file(user_sys_pass)
                messagebox.showinfo("Success", "Password Manager created! Please login.")
                self.on_show()
                
        except Exception as e:
            messagebox.showerror("Error", f"Operation failed: {e}")

    def show_content(self):
        self.login_frame.pack_forget()
        self.content_frame.pack(fill="both", expand=True)
        self.refresh_list()
        
        self.entry_service_name.delete(0, "end")
        self.entry_service_pass.delete(0, "end")
        self.entry_service_name.configure(placeholder_text="Service Name (e.g. Netflix)")
        self.entry_service_pass.configure(placeholder_text="Password")

    def refresh_list(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
            
        services = backend.list_services_in_passMngr()
        for s in services:
            self.create_service_row(s)

    def create_service_row(self, service_data):
        row = ctk.CTkFrame(self.scroll_frame)
        row.pack(fill="x", pady=2)
        
        ctk.CTkLabel(row, text=service_data['service_name'], font=("Roboto", 14)).pack(side="left", padx=10)
        
        btn_copy = ctk.CTkButton(row, text="Copy Pass", width=80, fg_color="#2980b9", command=lambda p=service_data['service_pass']: self.copy_to_clipboard(p))
        btn_copy.pack(side="right", padx=5, pady=5)
        
        btn_del = ctk.CTkButton(row, text="Delete", width=60, fg_color="#c0392b", hover_color="#922b21", command=lambda n=service_data['service_name']: self.delete_service(n))
        btn_del.pack(side="right", padx=5, pady=5)

    def add_service(self):
        s_name = self.entry_service_name.get()
        s_pass = self.entry_service_pass.get()
        
        if s_name and s_pass:
            backend.add_password_to_PassMngr(s_name, s_pass)
            self.refresh_list()
            self.entry_service_name.delete(0, "end")
            self.entry_service_pass.delete(0, "end")
            # HACK:
            self.entry_service_name.configure(placeholder_text="Service Name (e.g. Netflix)")
            self.entry_service_pass.configure(placeholder_text="Password")
        else:
            messagebox.showwarning("Missing Info", "Please fill both fields.")

    def delete_service(self, s_name):
        if messagebox.askyesno("Confirm", f"Delete password for {s_name}?"):
            backend.remove_password_service(s_name)
            self.refresh_list()

    def copy_to_clipboard(self, password):
        self.clipboard_clear()
        self.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def lock_and_exit(self):
        user_sys_pass = self.controller.get_user_password()
        if os.path.exists(backend.PASS_METADATA_FILE):
             backend.encrypt_passdata_file(user_sys_pass)
        
        self.controller.show_frame("DashboardScreen")

    def delete_manager(self):
        if messagebox.askyesno("DANGER", "Are you sure? This will delete ALL saved passwords permanently!"):
             backend.delete_passMngr("dummy", "dummy") 
             
             messagebox.showinfo("Deleted", "Password Manager deleted.")
             self.controller.show_frame("DashboardScreen")

# Vault Detail Screen
class VaultDetailScreen(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.current_vault_data = None

        vault_name = ""

        self.topbar = ctk.CTkFrame(self, height=50)
        self.topbar.pack(fill="x", padx=10, pady=10)

        self.lbl_vault_name = ctk.CTkLabel(self.topbar, text=vault_name, font=("Roboto Medium", 20))
        self.lbl_vault_name.pack(side="left", padx=10)

        btn_back = ctk.CTkButton(self.topbar, text="Back", width=80, fg_color="#555", command=lambda: controller.show_frame("DashboardScreen"))
        btn_back.pack(side="right", padx=10)

        self.actions = ctk.CTkFrame(self)
        self.actions.pack(fill="x", padx=10)

        btn_add_file = ctk.CTkButton(self.actions, text="Add File to Vault", command=self.add_file)
        btn_add_file.pack(side="left", padx=5)

        self.file_list = ctk.CTkScrollableFrame(self, label_text=f"Files in vault '{vault_name}'")
        self.file_list.pack(fill="both", expand=True, padx=10, pady=10)

    def on_show(self, data):
        self.current_vault_data = data
        self.lbl_vault_name.configure(text=data['vault_name'])
        self.refresh_files()

    def refresh_files(self):
        for widget in self.file_list.winfo_children():
            widget.destroy()

        username = backend.session.get("authenticated_user")
        user_password = self.controller.get_user_password()
        vault_name = self.current_vault_data['vault_name']

        try:
            backend.decrypt_vaultdata_file(user_password)
            files = backend.list_files_in_vault_GUI(vault_name, username)
            backend.encrypt_vaultdata_file(user_password)
            for file_info in files:
                self.create_file_row(file_info)
        except Exception as e:
            messagebox.showerror(title="Error!", message=f"File Listing Error: {e}")
    
    def create_file_row(self, file_info):
        row = ctk.CTkFrame(self.file_list)
        row.pack(fill="x", pady=2)

        info_text = f"{file_info['name']} (Size: {file_info['size']} bytes, Added: {file_info['date_added']})"
        ctk.CTkLabel(row, text=info_text).pack(side="left", padx=10)

        # Extract
        ctk.CTkButton(row, text="Extract", width=60, fg_color="green", command=lambda: self.extract_file(file_info['name'])).pack(side="right", padx=5)
        # Delete
        ctk.CTkButton(row, text="Delete", width=60, fg_color="red", command=lambda: self.delete_file(file_info['name'])).pack(side="right", padx=5)

    def add_file(self):
        file_path = ctk.filedialog.askopenfilename()
        if file_path:
            username = backend.session.get("authenticated_user")
            user_password = self.controller.get_user_password()
            vault_name = self.current_vault_data['vault_name']
            vault_key = self.current_vault_data['key']

            backend.decrypt_vaultdata_file(user_password)
            backend.add_file_to_vault(vault_name, vault_key, file_path, username)
            backend.encrypt_vaultdata_file(user_password)

            self.refresh_files()
            messagebox.showinfo(title="Success!", message=f"File added to vault '{vault_name}'.")
        else:
            messagebox.showwarning(title="Warning!", message="Please provide a file path.")

    def extract_file(self, file_name):
        username = backend.session.get("authenticated_user")
        user_password = self.controller.get_user_password()
        vault_name = self.current_vault_data['vault_name']
        vault_key = self.current_vault_data['key']
        dest_path = ctk.filedialog.askdirectory(title="Extraction Path")
        if not dest_path:
            return
        file_remove = messagebox.askyesno("Do you want to remove file from the vault after extraction?(Y/N)")
        try:    
            backend.decrypt_vaultdata_file(user_password)
            backend.extract_file_from_vault(vault_name, vault_key, file_name, dest_path)
            if file_remove:
                backend.remove_file_from_vault(vault_name, file_name, username, vault_key)
            backend.encrypt_vaultdata_file(user_password)
            if file_remove:
                self.refresh_files()
                messagebox.showinfo(title="Success!", message=f"File extracted to '{dest_path}' and deleted from vault.")
            else:     
                messagebox.showinfo("Success!", f"File extracted to '{dest_path}'.")
        except Exception as e:
            backend.encrypt_vaultdata_file(user_password)
            messagebox.showerror(title="Error!", message=f"Extraction Error: {e}")
    
    def delete_file(self, filename):
        if messagebox.askyesno(title="Delete File?", message="Do you want to delete this file from vault?"):
            username = backend.session.get("authenticated_user")
            user_password = self.controller.get_user_password()
            vault_name = self.current_vault_data['vault_name']
            vault_key = self.current_vault_data['key']

            backend.decrypt_vaultdata_file(user_password)
            backend.remove_file_from_vault(vault_name, filename, username, vault_key)
            backend.encrypt_vaultdata_file(user_password)

            self.refresh_files()

# Create Vault Screen
class CreateVaultScreen(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        ctk.CTkLabel(self, text="Create New Vault", font=("Roboto Medium", 24)).pack(pady=(40, 20))
        self.entry_vault_name = ctk.CTkEntry(self, placeholder_text="Vault Name", width=300)
        self.entry_vault_name.pack(pady=10)

        self.entry_vault_pass = ctk.CTkEntry(self, placeholder_text="Vault Password", show="*", width=300)
        self.entry_vault_pass.pack(pady=10)

        btn_createV = ctk.CTkButton(self, text="Create Vault", width=300, command=self.create_vault)
        btn_createV.pack(pady=20)

        btn_cancel = ctk.CTkButton(self, text="Cancel", width=300, fg_color="#555", command=lambda: controller.show_frame("DashboardScreen"))
        btn_cancel.pack(pady=5)

    def on_show(self, data=None):
        self.entry_vault_name.delete(0, "end")
        self.entry_vault_pass.delete(0, "end")

        # HACK:
        self.entry_vault_name.configure(placeholder_text="Vault Name")
        self.entry_vault_pass.configure(placeholder_text="Vault Password")

    def create_vault(self):
        vault_name = self.entry_vault_name.get()
        vault_password = self.entry_vault_pass.get()
        if not vault_name or not vault_password:
            messagebox.showwarning(title="Warning!", message="Please fill all the field provided.")
            return
        
        try:
            user_password = self.controller.get_user_password()
            if os.path.exists(backend.ENC_VAULT_METADATA_FILE):
                backend.decrypt_vaultdata_file(user_password)
            result = backend.create_vault(vault_name, vault_password)
            if result == "SUCCESS":
                backend.encrypt_vaultdata_file(user_password)
                messagebox.showinfo(title="Success!", message=f"'{vault_name}' created successfully.")
                self.controller.show_frame("DashboardScreen")
            else:
                backend.encrypt_vaultdata_file(user_password)
                messagebox.showwarning(title="Warning!", message="Vault already exists.")
        except Exception as e:
            backend.encrypt_vaultdata_file(user_password)
            messagebox.showerror(title="Error!", message=f"Create Vault Error: {e}")

# Authenticate Vault Screen
class AuthVaultScreen(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.vault_name = None
        
        self.lbl_title = ctk.CTkLabel(self, text="Authenticate Vault", font=("Roboto Medium", 24))
        self.lbl_title.pack(pady=(60, 20))

        self.entry_vault_pass = ctk.CTkEntry(self, placeholder_text="Vault Password", show="*", width=300)
        self.entry_vault_pass.pack(pady=20)

        btn_open_vault = ctk.CTkButton(self, text="Authenticate", width=300, command=self.authenticate_vault)
        btn_open_vault.pack(pady=10)

        self.btn_cancel = ctk.CTkButton(self, text="Cancel", width=300, fg_color="#555", command=lambda: controller.show_frame("DashboardScreen"))
        self.btn_cancel.pack(pady=5)

    def on_show(self, data):
        self.vault_name = data
        self.lbl_title.configure(text=f"Authenticate Vault {data}")
        self.entry_vault_pass.delete(0, "end")
        self.btn_cancel.focus()

        # HACK:
        self.entry_vault_pass.configure(placeholder_text="Vault Password")

    def authenticate_vault(self):
        user_password = self.controller.get_user_password()
        vault_password = self.entry_vault_pass.get()
        vault_name = self.vault_name

        try:
            backend.decrypt_vaultdata_file(user_password)
            key = backend.authenticate_vault(vault_name, vault_password)
            backend.encrypt_vaultdata_file(user_password)

            if key:
                self.controller.show_frame("VaultDetailScreen", data={"vault_name": vault_name, "key": key})
            else:
                messagebox.showerror(title="Error!", message="Wrong credidentials.")
        except Exception as e:
            backend.encrypt_vaultdata_file(user_password)
            messagebox.showerror(title="Error!", message=f"Vault Authentication Error: {e}")

# Delete Vault Screen
class DeleteVaultScreen(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.vault_name = None

        self.lbl_title = ctk.CTkLabel(self, text="Delete Vault", font=("Roboto Medium", 24))
        self.lbl_title.pack(pady=(60, 20))
        self.lbl_warning = ctk.CTkLabel(self, text="You are about to delete a vault with all files in it.", font=("Roboto Medium", 16))
        self.lbl_warning.pack(pady=(0, 20))

        self.entry_vault_pass = ctk.CTkEntry(self, placeholder_text="Vault Password", show="*", width=300)
        self.entry_vault_pass.pack(pady=20)

        btn_delete_vault = ctk.CTkButton(self, text="Delete Vault", width=300, fg_color="#c0392b", hover_color="#922b21", command= self.delete_vault)
        btn_delete_vault.pack(pady=10)

        self.btn_cancel = ctk.CTkButton(self, text="Cancel", width=300, command=lambda: controller.show_frame("DashboardScreen"))
        self.btn_cancel.pack(pady=5)
    
    def on_show(self, data):
        self.vault_name = data
        self.lbl_title.configure(text=f"Delete Vault {data}")
        self.entry_vault_pass.delete(0, "end")
        self.btn_cancel.focus()

        # HACK:
        self.entry_vault_pass.configure(placeholder_text="Vault Password")
        

    def delete_vault(self):
        username = backend.session.get("authenticated_user")
        user_password = self.controller.get_user_password()
        vault_password = self.entry_vault_pass.get()
        vault_name = self.vault_name

        try:
            backend.decrypt_vaultdata_file(user_password)
            vault_key = backend.authenticate_vault(vault_name, vault_password)
            if vault_key:
                backend.delete_vault(username, vault_name, vault_key)
                backend.encrypt_vaultdata_file(user_password)
                messagebox.showinfo(title="Success!", message=f"Vault '{vault_name}' deleted successfully!")
                self.controller.show_frame("DashboardScreen")
            else:
                backend.encrypt_vaultdata_file(user_password)
                messagebox.showwarning(title="Warning!", message="Wrong credidentials!")
        except Exception as e:
            messagebox.showerror(title="Error!", message=f"Vault Deletion Error: {e}")

# Delete User Screen
class DeleteUserScreen(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        self.lbl_title = ctk.CTkLabel(self, text="Delete User", font=("Roboto Medium", 24))
        self.lbl_title.pack(pady=(60, 20))
        self.lbl_warning = ctk.CTkLabel(self, text="Do are about to delete all vaults, files, password and user data!", font=("Roboto Medium", 16))
        self.lbl_warning.pack(pady=(0, 20))

        self.entry_username = ctk.CTkEntry(self, placeholder_text="Username", width=300)
        self.entry_username.pack(pady=20)
        self.entry_user_password = ctk.CTkEntry(self, placeholder_text="User Password", show="*", width=300)
        self.entry_user_password.pack(pady=10)

        btn_delete_user = ctk.CTkButton(self, text="Delete User", width=300, fg_color="#c0392b", hover_color="#922b21", command= self.delete_user)
        btn_delete_user.pack(pady=10)

        self.btn_cancel = ctk.CTkButton(self, text="Cancel", width=300, command=lambda: controller.show_frame("DashboardScreen"))
        self.btn_cancel.pack(pady=5)
    
    def on_show(self, data=None):
        self.entry_username.delete(0, "end")
        self.entry_user_password.delete(0, "end")

        # HACK:
        self.entry_username.configure(placeholder_text="Username")
        self.entry_user_password.configure(placeholder_text="Password")

    def delete_user(self):
        username = self.entry_username.get()
        user_password = self.entry_user_password.get()
        try:
            backend.decrypt_userdata_file(user_password)
            if backend.authenticate_user(username, user_password):
                result = backend.delete_user()
                if result:
                    self.controller.show_frame("RegisterScreen")
                else:
                    backend.encrypt_userdata_file(user_password)
                    messagebox.showwarning(title="Error!", message="User files couldn't deleted!")
            else:
                backend.encrypt_userdata_file(user_password)
                messagebox.showwarning(title="Warning!", message="Wrong Credidentials!")
        except Exception as e:
            messagebox.showerror(title="Error!", message=f"Delete User Error: {e}")

if __name__ == "__main__":
    app = SiriusVault()
    app.mainloop()