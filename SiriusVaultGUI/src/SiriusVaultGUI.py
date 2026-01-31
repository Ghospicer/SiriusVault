import sys
import os
import shutil
from PyQt6 import QtWidgets, uic, QtCore, QtGui
from PyQt6.QtWidgets import QFileDialog, QMessageBox, QTableWidgetItem, QHeaderView, QWidget, QHBoxLayout, QPushButton, QApplication, QAbstractItemView, QLineEdit
from PyQt6.QtGui import QAction, QIcon, QPixmap, QPainter, QColor, QFont
from PyQt6.QtCore import Qt

# Backend
try:
    import SiriusVaultFunctions as backend
except ImportError:
    print("CRITICAL ERROR: 'SiriusVaultFunctions.py' not found!")
    sys.exit(1)

# UI
def get_ui_path(filename):
    return os.path.join(os.path.dirname(__file__), "ui", filename)

# HELPER
def create_text_icon(text, color="#a6adc8"):
    size = 32
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setPen(QColor(color))
    font = QFont("Segoe UI Symbol", 16)
    painter.setFont(font)
    painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, text)
    painter.end()
    return QIcon(pixmap)

def setup_password_toggle(line_edit):
    
    icon_visible = create_text_icon("🔓")
    icon_hidden = create_text_icon("🔒")

    action = line_edit.addAction(icon_visible, QLineEdit.ActionPosition.TrailingPosition)
    
    def toggle_visibility():
        if line_edit.echoMode() == QLineEdit.EchoMode.Password:
            line_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            action.setIcon(icon_hidden)
            line_edit.setToolTip("Hide Password")
        else:
            line_edit.setEchoMode(QLineEdit.EchoMode.Password)
            action.setIcon(icon_visible)
            line_edit.setToolTip("Show Password")

    action.setIcon(icon_visible)
    line_edit.setEchoMode(QLineEdit.EchoMode.Password)

    action.triggered.connect(toggle_visibility)

# =============================================================================
# 1. LOGIN WINDOW (Login, Register, USB Selection)
# =============================================================================
class LoginWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi(get_ui_path("login.ui"), self)
        
        self.selected_storage_path = None 
        self.temp_password_holder = None

        setup_password_toggle(self.input_user_password_log)
        setup_password_toggle(self.input_user_password_reg)
        setup_password_toggle(self.input_confirm_user_password_reg)

        # --- Button Connections ---
        self.btn_login.clicked.connect(self.handle_login)
        self.btn_register_log.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(1))
        self.btn_ext_storage_log.clicked.connect(self.select_external_storage_login)
        self.input_user_password_log.returnPressed.connect(self.handle_login)

        self.btn_register_reg.clicked.connect(self.handle_register)
        
        self.btn_register_back.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(0))
        
        self.btn_ext_storage_reg.clicked.connect(self.select_external_storage_reg)

        # Default storage paht start
        backend.initialize_storage(default=True)

    def select_external_storage_login(self):
        path = QFileDialog.getExistingDirectory(self, "Select External Drive (USB/HDD)")
        if path:
            self.selected_storage_path = path
            if backend.initialize_storage(path, default=False):
                self.update_storage_btn_ui(self.btn_ext_storage_log, path)
            else:
                QMessageBox.critical(self, "Error", "Could not initialize storage.")

    def select_external_storage_reg(self):
        path = QFileDialog.getExistingDirectory(self, "Select External Drive (USB/HDD)")
        if path:
            self.selected_storage_path = path
            if backend.initialize_storage(path, default=False):
                self.update_storage_btn_ui(self.btn_ext_storage_reg, path)
            else:
                QMessageBox.critical(self, "Error", "Could not initialize storage.")

    def update_storage_btn_ui(self, btn, path):
        short_path = path if len(path) < 20 else "..." + path[-15:]
        btn.setText(f"📂 {short_path}")
        btn.setStyleSheet("""
            QPushButton {
                background-color: #a6e3a1; color: #1e1e2e; 
                border: 1px solid #a6e3a1; font-weight: bold;
                border-radius: 8px; padding: 6px;
            }
        """)
        btn.setToolTip(f"Selected Storage: {path}")

    def handle_login(self):
        username = self.input_username_log.text().strip()
        password = self.input_user_password_log.text()

        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Please fill in all fields.")
            return
        
        if backend.authenticate_user(username, password):
            self.temp_password_holder = password 
            self.open_main_menu()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password.")

    def handle_register(self):
        user = self.input_username_reg.text().strip()
        pwd = self.input_user_password_reg.text()
        confirm = self.input_confirm_user_password_reg.text()

        if not user or not pwd:
            QMessageBox.warning(self, "Error", "Fields cannot be empty.")
            return

        if pwd != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match!")
            return

        if backend.create_user(user, pwd):
            QMessageBox.information(self, "Success", "Account created! You can now login.")
            self.stackedWidget.setCurrentIndex(0) 
        else:
            QMessageBox.warning(self, "Error", "User already exists.")

    def open_main_menu(self):
        self.main_menu = MainMenuWindow(self.temp_password_holder)
        self.main_menu.show()
        self.close()

# =============================================================================
# 2. MAIN MENU WINDOW
# =============================================================================
class MainMenuWindow(QtWidgets.QMainWindow):
    def __init__(self, user_password):
        super().__init__()
        uic.loadUi(get_ui_path("main_menu.ui"), self)
        
        self.user_password = user_password
        self.current_user = backend.session.get("authenticated_user")
        self.is_logging_out = False 

        setup_password_toggle(self.input_pm_auth_pass)
        setup_password_toggle(self.input_pm_reg_pass)
        setup_password_toggle(self.input_pm_reg_pass_confirm)
        
        # --- Sidebar ---
        self.btn_my_vaults_mm.clicked.connect(self.show_my_vaults)
        self.btn_create_vault_mm.clicked.connect(self.open_create_vault_dialog)
        self.btn_pass_manager_mm.clicked.connect(self.check_pm_status)
        self.btn_settings_mm.clicked.connect(self.show_settings)
        self.btn_logout_mm.clicked.connect(self.handle_logout)

        # --- PM Page ---
        self.btn_pm_auth.clicked.connect(self.handle_pm_login)
        self.btn_pm_reg.clicked.connect(self.handle_pm_register)
        self.btn_pm_add.clicked.connect(self.open_pm_add_dialog)
        self.btn_pm_audit.clicked.connect(self.open_pm_audit_dialog)
        self.btn_pm_gen.clicked.connect(self.open_pm_gen_dialog)
        self.btn_pm_logout.clicked.connect(self.logout_pm_only)

        # --- Settings ---
        self.btn_settings_dZ_deleteAC.clicked.connect(self.delete_account_logic)
        self.btn_settings_dZ_deleteAC_2.clicked.connect(self.delete_pm_logic)
        if hasattr(backend, 'STORAGE_ROOT'):
             self.label_cur_storage_path.setText(f"Path: {backend.STORAGE_ROOT}")

        # --- Table Config ---
        # Select Rows
        self.table_vaults.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_vaults.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table_pm_list.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_pm_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        self.table_vaults.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table_vaults.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vaults.cellDoubleClicked.connect(self.on_vault_double_click)
        
        self.table_pm_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table_pm_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_pm_list.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_pm_list.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        self.show_my_vaults()

    def show_my_vaults(self):
        self.stackedWidget.setCurrentIndex(0)
        self.load_vaults_table() 

    # --- VAULT LOGIC ---
    def load_vaults_table(self):
        self.table_vaults.setRowCount(0)
        
        # [DEC -> OP -> ENC]
        try:
            backend.decrypt_vaultdata_file(self.user_password)
            vaults = backend.list_vaults_GUI(self.current_user)
        finally:
            backend.encrypt_vaultdata_file(self.user_password)

        if vaults:
            for v_name in vaults:
                row = self.table_vaults.rowCount()
                self.table_vaults.insertRow(row)
                self.table_vaults.setItem(row, 0, QTableWidgetItem(v_name))
                
                action_widget = QWidget()
                layout = QHBoxLayout(action_widget)
                layout.setContentsMargins(0, 0, 0, 0)
                layout.setSpacing(5)

                btn_unlock = QPushButton("🔓")
                btn_unlock.setToolTip("Open Vault")
                btn_unlock.setFixedSize(30, 25)
                btn_unlock.setStyleSheet("background-color: #a6e3a1; border: none; border-radius: 4px;")
                btn_unlock.clicked.connect(lambda _, r=row: self.on_vault_double_click(r, 0))

                btn_del = QPushButton("🗑️")
                btn_del.setToolTip("Delete Vault")
                btn_del.setFixedSize(30, 25)
                btn_del.setStyleSheet("background-color: #f38ba8; border: none; border-radius: 4px;")
                btn_del.clicked.connect(lambda _, v=v_name: self.delete_vault_click(v))
                
                layout.addWidget(btn_unlock)
                layout.addWidget(btn_del)
                layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
                
                self.table_vaults.setCellWidget(row, 1, action_widget)

    def delete_vault_click(self, vault_name):
        dialog = VaultLoginDialog(vault_name, self.user_password, self)
        if dialog.exec():
            vault_key = dialog.vault_key
            confirm = QMessageBox.question(self, "Confirm Delete", f"Delete vault '{vault_name}' permanently?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if confirm == QMessageBox.StandardButton.Yes:
                try:
                    backend.decrypt_vaultdata_file(self.user_password)
                    backend.delete_vault(self.current_user, vault_name, vault_key)
                finally:
                    backend.encrypt_vaultdata_file(self.user_password)
                self.load_vaults_table()

    def open_create_vault_dialog(self):
        dialog = CreateVaultDialog(self.user_password, self)
        if dialog.exec():
            self.load_vaults_table() 

    def on_vault_double_click(self, row, column):
        vault_name = self.table_vaults.item(row, 0).text()
        login_dialog = VaultLoginDialog(vault_name, self.user_password, self)
        
        if login_dialog.exec():
            vault_key = login_dialog.vault_key
            self.vault_window = VaultMenuWindow(vault_name, vault_key, self.user_password, parent_menu=self)
            self.hide() 
            self.vault_window.show()

    # --- PASSWORD MANAGER LOGIC ---
    def check_pm_status(self):
        self.stackedWidget.setCurrentIndex(1)
        if os.path.exists(backend.PASS_METADATA_FILE) or os.path.exists(backend.ENC_PASS_METADATA_FILE):
             self.stack_pass_manager.setCurrentIndex(0) 
        else:
             self.stack_pass_manager.setCurrentIndex(1) 

    def handle_pm_login(self):
        passMngr_pass = self.input_pm_auth_pass.text()
        
        # [DEC -> OP -> ENC]
        try:
            backend.decrypt_passdata_file(passMngr_pass)
            auth_success = backend.authenticate_passMngr(passMngr_pass)
        finally:
            if os.path.exists(backend.PASS_METADATA_FILE):
                backend.encrypt_passdata_file(passMngr_pass)

        if auth_success:
            self.master_pm_password = passMngr_pass 
            self.stack_pass_manager.setCurrentIndex(2) 
            self.load_pm_table()
        else:
            QMessageBox.warning(self, "Error", "Incorrect Password.")

    def handle_pm_register(self):
        passMngr_pass = self.input_pm_reg_pass.text()
        confirm = self.input_pm_reg_pass_confirm.text()
        if passMngr_pass == confirm and passMngr_pass:
            backend.create_passMngr(passMngr_pass)
            backend.encrypt_passdata_file(passMngr_pass)
            
            self.master_pm_password = passMngr_pass
            QMessageBox.information(self, "Success", "Password Manager Created!")
            self.stack_pass_manager.setCurrentIndex(2) 
        else:
            QMessageBox.warning(self, "Error", "Passwords do not match.")

    def load_pm_table(self):
        self.table_pm_list.setRowCount(0)
        
        try:
            backend.decrypt_passdata_file(self.master_pm_password)
            services = backend.list_services_in_passMngr()
        finally:
            backend.encrypt_passdata_file(self.master_pm_password)
            
        if not services: return

        for s in services:
            row = self.table_pm_list.rowCount()
            self.table_pm_list.insertRow(row)
            
            s_name = s['service_name']
            s_pass = s['service_pass'] 

            self.table_pm_list.setItem(row, 0, QTableWidgetItem(s_name))
            self.table_pm_list.setItem(row, 1, QTableWidgetItem("-")) 
            
            strength_item = QTableWidgetItem("🟢" if len(s_pass) > 10 else "🔴")
            strength_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table_pm_list.setItem(row, 2, strength_item)

            action_widget = QWidget()
            layout = QHBoxLayout(action_widget)
            layout.setContentsMargins(2, 2, 2, 2)
            
            btn_reveal = QPushButton("👁️")
            btn_reveal.setToolTip("Reveal")
            btn_reveal.setFixedWidth(30)
            btn_reveal.setStyleSheet("background-color: #89b4fa; border: none; border-radius: 4px;")
            btn_reveal.clicked.connect(lambda _, n=s_name: self.open_pm_reveal_dialog(n))
            
            btn_copy = QPushButton("📋")
            btn_copy.setToolTip("Copy")
            btn_copy.setFixedWidth(30)
            btn_copy.setStyleSheet("background-color: #89b4fa; border: none; border-radius: 4px;")
            btn_copy.clicked.connect(lambda _, p=s_pass: QApplication.clipboard().setText(p))

            btn_delete = QPushButton("🗑️")
            btn_delete.setToolTip("Delete")
            btn_delete.setFixedWidth(30)
            btn_delete.setStyleSheet("background-color: #f38ba8; border: none; border-radius: 4px;")
            btn_delete.clicked.connect(lambda _, n=s_name: self.delete_pm_service(n))

            layout.addWidget(btn_reveal)
            layout.addWidget(btn_copy)
            layout.addWidget(btn_delete)
            self.table_pm_list.setCellWidget(row, 3, action_widget)

    def open_pm_add_dialog(self):
        if AddPasswordDialog(self.master_pm_password, self).exec():
            self.load_pm_table()

    def open_pm_reveal_dialog(self, service_name):
        dialog = AuthCheckDialog(service_name, self.master_pm_password, self)
        if dialog.exec():
            # AuthCheckDialog içinde zaten dec/enc yapıp şifreyi alıyoruz,
            # burada tekrar backend çağırmaya gerek yok, dialog sonucu gösterecek.
            pass

    def open_pm_audit_dialog(self):
        AuditPasswordDialog(self).exec()

    def open_pm_gen_dialog(self):
        GeneratePasswordDialog(self).exec()

    def delete_pm_service(self, service_name):
        reply = QMessageBox.question(self, "Delete", f"Remove '{service_name}'?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                backend.decrypt_passdata_file(self.master_pm_password)
                backend.remove_password_service(service_name)
            finally:
                backend.encrypt_passdata_file(self.master_pm_password)
            self.load_pm_table()

    def logout_pm_only(self):
        if hasattr(self, 'master_pm_password'):
            if os.path.exists(backend.PASS_METADATA_FILE):
                backend.encrypt_passdata_file(self.master_pm_password)
        self.stack_pass_manager.setCurrentIndex(0) 

    # --- SETTINGS & LOGOUT ---
    def show_settings(self):
        self.stackedWidget.setCurrentIndex(2)

    def delete_account_logic(self):
        confirm = QMessageBox.warning(self, "DANGER", "All data will be lost.\nProceed?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            try:
                backend.decrypt_userdata_file(self.user_password)
                backend.decrypt_vaultdata_file(self.user_password)
                backend.delete_user()
            except Exception as e:
                print(f"Error during deletion: {e}")
            
            self.is_logging_out = True 
            self.close()

    def delete_pm_logic(self):
        confirm = QMessageBox.question(self, "Delete PM", "Delete Password Manager?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            backend.delete_passMngr(self.current_user, "dummy") 
            QMessageBox.information(self, "Deleted", "Password Manager deleted.")
            self.check_pm_status()

    def handle_logout(self):
        self.is_logging_out = True 
        self.close() 

    def closeEvent(self, event):
        print("[INFO] Cleaning up and encrypting data...")
        if os.path.exists(backend.USER_DATA_FILE):
            backend.encrypt_userdata_file(self.user_password)
        if os.path.exists(backend.VAULT_METADATA_FILE):
            backend.encrypt_vaultdata_file(self.user_password)
        if hasattr(self, 'master_pm_password') and os.path.exists(backend.PASS_METADATA_FILE):
            backend.encrypt_passdata_file(self.master_pm_password)
        
        backend.logout_user()

        if self.is_logging_out:
            self.login_window = LoginWindow()
            self.login_window.show()
            event.accept() 
        else:
            event.accept()
            QApplication.quit() 

# =============================================================================
# 3. VAULT CONTENT WINDOW
# =============================================================================
class VaultMenuWindow(QtWidgets.QWidget):
    def __init__(self, vault_name, vault_key, user_password, parent_menu=None):
        super().__init__()
        uic.loadUi(get_ui_path("vault_menu.ui"), self)
        
        self.vault_name = vault_name
        self.vault_key = vault_key 
        self.user_password = user_password
        self.current_user = backend.session["authenticated_user"]
        self.parent_menu = parent_menu

        self.lbl_vaultmenu_vaultName.setText(self.vault_name)
        
        self.setAcceptDrops(True)
        self.table_files.setAcceptDrops(True)
        
        self.btn_vaultmenu_back.clicked.connect(self.go_back_to_main)
        self.btn_vaultmenu_add.clicked.connect(self.import_file_dialog)

        self.table_files.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.load_files()

    def go_back_to_main(self):
        if os.path.exists(backend.VAULT_METADATA_FILE):
            backend.encrypt_vaultdata_file(self.user_password)
        self.close()
        
        if self.parent_menu:
            self.parent_menu.show()
            self.parent_menu.load_vaults_table() 

    def load_files(self):
        self.table_files.setRowCount(0)
        try:
            backend.decrypt_vaultdata_file(self.user_password)
            files = backend.list_files_in_vault_GUI(self.vault_name, self.current_user)
        finally:
            backend.encrypt_vaultdata_file(self.user_password)
            
        if not files: return

        for f_meta in files:
            row = self.table_files.rowCount()
            self.table_files.insertRow(row)
            
            f_name = f_meta['name']
            f_size = f"{f_meta['size'] / 1024:.2f} KB"
            f_date = f_meta['date_added']

            self.table_files.setItem(row, 0, QTableWidgetItem(f_name))
            self.table_files.setItem(row, 1, QTableWidgetItem(os.path.splitext(f_name)[1]))
            self.table_files.setItem(row, 2, QTableWidgetItem(f_size))
            self.table_files.setItem(row, 3, QTableWidgetItem(f_date))

            action_widget = QWidget()
            layout = QHBoxLayout(action_widget)
            layout.setContentsMargins(0,0,0,0)
            
            btn_ext = QPushButton("📤")
            btn_ext.setToolTip("Extract")
            btn_ext.setFixedSize(30, 25)
            btn_ext.setStyleSheet("background-color: #89b4fa; border: none; border-radius: 4px;")
            btn_ext.clicked.connect(lambda _, n=f_name: self.extract_file(n))
            
            btn_del = QPushButton("🗑️")
            btn_del.setToolTip("Delete")
            btn_del.setFixedSize(30, 25)
            btn_del.setStyleSheet("background-color: #f38ba8; border: none; border-radius: 4px;")
            btn_del.clicked.connect(lambda _, n=f_name: self.delete_file(n))

            layout.addWidget(btn_ext)
            layout.addWidget(btn_del)
            layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table_files.setCellWidget(row, 4, action_widget)

    def import_file_dialog(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files to Encrypt")
        for f in files:
            self.process_file_import(f)
        self.load_files()

    def process_file_import(self, filepath):
        try:
            backend.decrypt_vaultdata_file(self.user_password)
            backend.add_file_to_vault(self.vault_name, self.vault_key, filepath, self.current_user)
        finally:
            backend.encrypt_vaultdata_file(self.user_password)

    def extract_file(self, file_name):
        dest_folder = QFileDialog.getExistingDirectory(self, "Select Destination")
        if dest_folder:
            try:
                backend.decrypt_vaultdata_file(self.user_password)
                backend.extract_file_from_vault(self.vault_name, self.vault_key, file_name, dest_folder)
                QMessageBox.information(self, "Success", f"File extracted to {dest_folder}")
            finally:
                backend.encrypt_vaultdata_file(self.user_password)

    def delete_file(self, file_name):
        confirm = QMessageBox.question(self, "Delete", f"Delete {file_name}?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            try:
                backend.decrypt_vaultdata_file(self.user_password)
                backend.remove_file_from_vault(self.vault_name, file_name, self.current_user, self.vault_key)
            finally:
                backend.encrypt_vaultdata_file(self.user_password)
            self.load_files()

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        for f in files:
            if os.path.isfile(f):
                self.process_file_import(f)
        self.load_files()

# =============================================================================
# 4. DIALOG CLASSES
# =============================================================================
class CreateVaultDialog(QtWidgets.QDialog):
    def __init__(self, user_password, parent=None):
        super().__init__(parent)
        uic.loadUi(get_ui_path("dialog_create_vault.ui"), self)
        self.user_password = user_password

        setup_password_toggle(self.input_dialog_vpassword)
        setup_password_toggle(self.input_dialog_vcpassword)
        
        self.btn_dialog_vCreate_create.clicked.connect(self.validate)
        self.btn_dialog_vCreate_cancel.clicked.connect(self.reject)

    def validate(self):
        name = self.input_dialog_vname.text()
        pwd = self.input_dialog_vpassword.text()
        confirm = self.input_dialog_vcpassword.text()
        
        if not name or not pwd:
            QMessageBox.warning(self, "Error", "Fields cannot be empty.")
            return
        if pwd != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return
        
        # [DEC -> OP -> ENC]
        try:
            backend.decrypt_vaultdata_file(self.user_password)
            result = backend.create_vault(name, pwd)
        finally:
            backend.encrypt_vaultdata_file(self.user_password)
            
        if result == "SUCCESS":
            QMessageBox.information(self, "Success", f"Vault '{name}' created.")
            self.accept()
        elif result == "SAME_NAME":
            QMessageBox.warning(self, "Error", "Vault name already exists.")
        else:
            QMessageBox.warning(self, "Error", "Could not create vault.")

class VaultLoginDialog(QtWidgets.QDialog):
    def __init__(self, vault_name, user_password, parent=None):
        super().__init__(parent)
        uic.loadUi(get_ui_path("dialog_vault_login.ui"), self)
        self.vault_name = vault_name
        self.user_password = user_password
        self.vault_key = None
        self.setWindowTitle(f"Unlock {vault_name}")

        setup_password_toggle(self.input_dialog_vLogin_vpassword)
        
        self.btn_dialog_vLogin_auth.clicked.connect(self.attempt_login)
        self.btn_dialog_vLogin_cancel.clicked.connect(self.reject)

    def attempt_login(self):
        pwd = self.input_dialog_vLogin_vpassword.text()
        
        # [DEC -> OP -> ENC]
        try:
            backend.decrypt_vaultdata_file(self.user_password)
            key = backend.authenticate_vault(self.vault_name, pwd)
        finally:
            backend.encrypt_vaultdata_file(self.user_password)
            
        if key:
            self.vault_key = key
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Incorrect Password.")

class AddPasswordDialog(QtWidgets.QDialog):
    def __init__(self, master_password, parent=None):
        super().__init__(parent)
        uic.loadUi(get_ui_path("dialog_pm_addP.ui"), self)
        self.master_password = master_password

        setup_password_toggle(self.input_service_pass)
        setup_password_toggle(self.input_service_confirm_pass)
        
        self.btn_dialog_addP_genRP.clicked.connect(self.generate_random)
        self.btn_dialog_addP_Add.clicked.connect(self.save)
        self.btn_dialog_addP_cancel.clicked.connect(self.reject)

    def generate_random(self):
        import secrets, string
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = ''.join(secrets.choice(chars) for _ in range(16))
        self.input_service_pass.setText(pwd)
        self.input_service_confirm_pass.setText(pwd)
        self.input_service_pass.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        self.input_service_confirm_pass.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)

    def save(self):
        s_name = self.input_service_name.text()
        s_pass = self.input_service_pass.text()
        confirm = self.input_service_confirm_pass.text()

        if s_pass != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return
        
        # [DEC -> OP -> ENC]
        try:
            backend.decrypt_passdata_file(self.master_password)
            backend.add_password_to_PassMngr(s_name, s_pass)
        finally:
            backend.encrypt_passdata_file(self.master_password)
        self.accept()

class AuthCheckDialog(QtWidgets.QDialog):
    def __init__(self, service_name, master_password, parent=None):
        super().__init__(parent)
        uic.loadUi(get_ui_path("dialog_pm_auth_check.ui"), self)
        self.lbl_service_title.setText(f"Service: {service_name}")
        self.master_password = master_password
        self.service_name = service_name

        setup_password_toggle(self.input_dialog_reqP_masterP)
        
        self.stackedWidget.setCurrentIndex(0) 
        self.btn_dialog_reqP_auth.clicked.connect(self.check_master_pass)
        self.btn_dialog_reqP_close.clicked.connect(self.accept)
        self.btn_dialog_reqP_copy.clicked.connect(self.copy_to_clip)
        self.btn_dialog_reqP_reveal.clicked.connect(self.toggle_reveal)

    def check_master_pass(self):
        mp = self.input_dialog_reqP_masterP.text()
        
        # [DEC -> OP -> ENC]
        try:
            backend.decrypt_passdata_file(self.master_password)
            auth_ok = backend.authenticate_passMngr(mp)
            if auth_ok:
                raw_pass = backend.extract_password_service(self.service_name)
        finally:
            backend.encrypt_passdata_file(self.master_password)

        if auth_ok:
            self.show_revealed_password(raw_pass)
            self.stackedWidget.setCurrentIndex(1) 
        else:
            QMessageBox.warning(self, "Error", "Incorrect Master Password.")

    def show_revealed_password(self, password):
        self.output_dialog_reqP_serviceP.setText(password)

    def toggle_reveal(self):
        if self.output_dialog_reqP_serviceP.echoMode() == QtWidgets.QLineEdit.EchoMode.Password:
            self.output_dialog_reqP_serviceP.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        else:
            self.output_dialog_reqP_serviceP.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

    def copy_to_clip(self):
        QApplication.clipboard().setText(self.output_dialog_reqP_serviceP.text())

class AuditPasswordDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(get_ui_path("dialog_pm_auditP.ui"), self)
        setup_password_toggle(self.input_dialog_check_strength)

        self.input_dialog_check_strength.textChanged.connect(self.update_meter)

    def update_meter(self):
        text = self.input_dialog_check_strength.text()
        length_score = len(text) * 4
        complexity_score = 0
        if any(c.isupper() for c in text): complexity_score += 15
        if any(c.islower() for c in text): complexity_score += 10
        if any(c.isdigit() for c in text): complexity_score += 15
        if any(c in "!@#$%^&*" for c in text): complexity_score += 20
        total = min(length_score + complexity_score, 100)
        self.bar_strength_score.setValue(total)
        color = "#f38ba8" 
        msg = "Weak"
        if total > 40: color = "#fab387"; msg = "Moderate"
        if total > 75: color = "#a6e3a1"; msg = "Strong"
        self.bar_strength_score.setStyleSheet(f"""
            QProgressBar {{ border: none; background-color: #313244; border-radius: 2px; height: 9px; text-align: center; }}
            QProgressBar::chunk {{ background-color: {color}; border-radius: 2px; }}
        """)
        self.lbl_audit_message.setText(msg)

class GeneratePasswordDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(get_ui_path("dialog_pm_genP.ui"), self)
        self.generate()
        self.btn_dialog_genP_close.clicked.connect(self.accept)
        self.btn_dialog_genP_copy.clicked.connect(lambda: QApplication.clipboard().setText(self.output_dialog_genP_generatedP.text()))
        self.btn_dialog_genP_reveal.clicked.connect(self.toggle_reveal)

    def generate(self):
        import secrets, string
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = ''.join(secrets.choice(chars) for _ in range(16))
        self.output_dialog_genP_generatedP.setText(pwd)

    def toggle_reveal(self):
        if self.output_dialog_genP_generatedP.echoMode() == QtWidgets.QLineEdit.EchoMode.Password:
            self.output_dialog_genP_generatedP.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        else:
            self.output_dialog_genP_generatedP.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
