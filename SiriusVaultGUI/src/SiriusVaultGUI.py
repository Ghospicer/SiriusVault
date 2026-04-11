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

        self.lbl_forgot_pass.linkActivated.connect(self.open_recovery_dialog)

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

    def open_recovery_dialog(self):
        dialog = RecoveryDialog(self)
        if dialog.exec():
            if dialog.recovered_password:
                self.stackedWidget.setCurrentIndex(0)

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

        score, strength_msg = backend.audit_password_strenght(pwd)
        if score <= 40:
            QMessageBox.warning(self, "Weak Password", "Your password is too weak!\nPlease use a longer password with uppercase, lowercase, numbers and symbols.")
            return
        if backend.create_user(user, pwd):
            codes = backend.setup_recovery_codes(user, pwd)
            msg_text = "Account created!"
            if codes:
                code_str = "\n".join(codes)
                msg_text += "IMPORTANT: SAVE THESE RECOVERY CODES!\n"
                msg_text += "If you lose your password, these are the ONLY way to recover your account.\n\n"
                msg_text += code_str
                QMessageBox.information(self, "Success", msg_text)
            else:
                QMessageBox.warning(self, "Warning", "Account created but recovery codes could not be generated.")        
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
        self.saved_index = backend.session.get("session_timeout_index", 1)
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
        if hasattr(backend, 'USER_DIR'):
             self.lineEdit_cur_storage_path.setPlaceholderText(backend.USER_DIR)
        self.btn_settings_sto_move.clicked.connect(self.move_storage_logic)
        self.btn_settings_sto_change.hide() # Remove this btn from ui
        self.comboBox.setCurrentIndex(self.saved_index)
        timeouts = {0: 60, 1: 300, 2: 600, 3: 1800}
        backend.SESSION_TIMEOUT = timeouts.get(self.saved_index, 300)
        self.comboBox.currentIndexChanged.connect(self.update_session_timeout)

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

        self.session_monitor = QtCore.QTimer(self)
        self.session_monitor.timeout.connect(self.verify_session)
        self.session_monitor.start(2000)

    def show_my_vaults(self):
        self.stackedWidget.setCurrentIndex(0)
        self.load_vaults_table()

    def verify_session(self):
        if backend.session.get("authenticated_user") is None:
            self.session_monitor.stop()
            for widget in QApplication.topLevelWidgets():
                if isinstance(widget, QtWidgets.QDialog):
                    widget.reject()

            self.hide()
            
            if hasattr(self, 'vault_window') and self.vault_window.isVisible():
                self.vault_window.close()
            
            QMessageBox.warning(self, "Session Expired", "Your session has expired due to inactivity.\nPlease log in again.")
            
            self.handle_logout()

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

                vault_item = QTableWidgetItem(v_name)
                vault_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                font = QFont("Yu Gothic UI Bold", 12)
                vault_item.setFont(font)
                self.table_vaults.setItem(row, 0, vault_item)

                empty_item = QTableWidgetItem()
                empty_item.setFlags(empty_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table_vaults.setItem(row, 1, empty_item)

                self.table_vaults.setRowHeight(row, 50)
                
                action_widget = QWidget()
                if row % 2 == 1:
                    action_widget.setStyleSheet("background-color: #2a2b3d;")
                else:
                    action_widget.setStyleSheet("background-color: transparent;")
                layout = QHBoxLayout(action_widget)
                layout.setContentsMargins(0, 0, 0, 0)
                layout.setSpacing(10)

                btn_unlock = QPushButton("🔓")
                btn_unlock.setToolTip("Open Vault")
                btn_unlock.setFixedSize(35, 30)
                btn_unlock.setStyleSheet("background-color: #a6e3a1; border: none; border-radius: 4px;")
                btn_unlock.clicked.connect(lambda _, r=row: self.on_vault_double_click(r, 0))

                btn_del = QPushButton("🗑️")
                btn_del.setToolTip("Delete Vault")
                btn_del.setFixedSize(35, 30)
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
        
        if backend.authenticate_passMngr(passMngr_pass):
            self.master_pm_password = passMngr_pass
            self.input_pm_auth_pass.clear()
            self.stack_pass_manager.setCurrentIndex(2)
            self.load_pm_table()
        else:
            self.input_pm_auth_pass.clear()
            QMessageBox.warning(self, "Error", "Incorrect Password.")

    def handle_pm_register(self):
        passMngr_pass = self.input_pm_reg_pass.text()
        confirm = self.input_pm_reg_pass_confirm.text()
        if passMngr_pass == confirm and passMngr_pass:
            score, strength_msg = backend.audit_password_strenght(passMngr_pass)
            if score <= 40:
                QMessageBox.warning(self, "Weak Password", "Your password is too weak!\nPlease use a longer password with uppercase, lowercase, numbers and symbols.")
                return
            if backend.create_passMngr(passMngr_pass):
                self.master_pm_password = passMngr_pass
                QMessageBox.information(self, "Success", "Password Manager Created!")
                self.input_pm_reg_pass.clear()
                self.input_pm_reg_pass_confirm.clear()
                self.stack_pass_manager.setCurrentIndex(2)
        else:
            self.input_pm_reg_pass.clear()
            self.input_pm_reg_pass_confirm.clear()
            QMessageBox.warning(self, "Error", "Passwords do not match.")

    def load_pm_table(self):
        self.table_pm_list.setRowCount(0)
        
        try:
            backend.decrypt_passdata_file(self.master_pm_password)
            services = backend.list_services_in_passMngr()
        finally:
            backend.encrypt_passdata_file(self.master_pm_password)
            
        if not services: return

        font = QFont("Yu Gothic UI Bold", 12)

        for s in services:
            row = self.table_pm_list.rowCount()
            self.table_pm_list.insertRow(row)
            
            s_name = s['service_name']
            s_user_mail = s['service_user_mail']
            s_pass = s['service_pass']

            # Service Name
            name_item = QTableWidgetItem(s_name)
            name_item.setFont(font)
            name_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table_pm_list.setItem(row, 0, name_item)

            # Service Username/email
            user_mail_item = QTableWidgetItem(s_user_mail)
            user_mail_item.setFont(font)
            user_mail_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            user_mail_item.setFlags(user_mail_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table_pm_list.setItem(row, 1, user_mail_item) 
            
            # Password Strenght
            score, strength_msg = backend.audit_password_strenght(s_pass)
            
            if strength_msg == "Strong":
                indicator = "🟢"
            elif strength_msg == "Moderate":
                indicator = "🟡"
            else:
                indicator = "🔴"
            
            strength_item = QTableWidgetItem(indicator)
            strength_item.setToolTip(f"Strength: {strength_msg}, Score: {score}")
            strength_item.setFont(font)
            strength_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            strength_item.setFlags(strength_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table_pm_list.setItem(row, 2, strength_item)

            self.table_pm_list.setRowHeight(row, 50)

            action_widget = QWidget()

            action_widget.setStyleSheet("background-color: transparent;")

            layout = QHBoxLayout(action_widget)
            layout.setContentsMargins(2, 2, 2, 2)
            layout.setSpacing(10)
            
            btn_reveal = QPushButton("👁️")
            btn_reveal.setToolTip("Reveal")
            btn_reveal.setFixedSize(35, 30)
            btn_reveal.setStyleSheet("background-color: #89b4fa; border: none; border-radius: 4px;")
            btn_reveal.clicked.connect(lambda _, n=s_name: self.open_pm_reveal_dialog(n))
            
            btn_copy = QPushButton("📋")
            btn_copy.setToolTip("Copy")
            btn_copy.setFixedSize(35, 30)
            btn_copy.setStyleSheet("background-color: #89b4fa; border: none; border-radius: 4px;")
            btn_copy.clicked.connect(lambda _, p=s_pass: QApplication.clipboard().setText(p))

            btn_delete = QPushButton("🗑️")
            btn_delete.setToolTip("Delete")
            btn_delete.setFixedSize(35, 30)
            btn_delete.setStyleSheet("background-color: #f38ba8; border: none; border-radius: 4px;")
            btn_delete.clicked.connect(lambda _, n=s_name: self.delete_pm_service(n))

            layout.addWidget(btn_reveal)
            layout.addWidget(btn_copy)
            layout.addWidget(btn_delete)
            layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table_pm_list.setCellWidget(row, 3, action_widget)

    def open_pm_add_dialog(self):
        if AddPasswordDialog(self.master_pm_password, self).exec():
            self.load_pm_table()

    def open_pm_reveal_dialog(self, service_name):
        dialog = AuthCheckDialog(service_name, self.master_pm_password, self)
        if dialog.exec():
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

    def move_storage_logic(self):
        new_path = QFileDialog.getExistingDirectory(self, "Select New Location to Move Your Data")
        if not new_path:
            return
        
        confirm = QMessageBox.warning(self, "Move Data", "Your data will be moved to the new location.\nYou will be logged out after this operation to secure your files.\nProceed?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if confirm == QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, "Processing", "Moving your data... Please wait.")
            QApplication.processEvents()

            if os.path.exists(backend.USER_DATA_FILE):
                backend.encrypt_userdata_file(self.user_password)
            if os.path.exists(backend.VAULT_METADATA_FILE):
                backend.encrypt_vaultdata_file(self.user_password)
            if hasattr(self, 'master_pm_password') and os.path.exists(backend.PASS_METADATA_FILE):
                backend.encrypt_passdata_file(self.master_pm_password)

            result = backend.move_user_data(self.current_user, new_path)

            if result == "SUCCESS":
                backend.initialize_storage(new_path, default=False)
                backend.load_user_context(self.current_user)
                self.lineEdit_cur_storage_path.setPlaceholderText(backend.USER_DIR)
                QMessageBox.information(self, "Success", "Your data has been successfully moved!\nPlease select your new storage on the login screen next time.")
            elif result == "EXISTS":
                QMessageBox.warning(self, "Error", "Your user data already exists in the target location.")
            else:
                QMessageBox.critical(self, "Error", "An error occurred while moving your data.")

    def update_session_timeout(self, index):
        timeouts = {
            0: 60,     # 1 minute
            1: 300,    # 5 minutes
            2: 600,    # 10 minutes
            3: 1800    # 30 minutes
        }
        
        new_timeout = timeouts.get(index, 300)
        
        if hasattr(backend, 'SESSION_TIMEOUT'):
            backend.SESSION_TIMEOUT = new_timeout
            backend.session["session_timeout_index"] = index
            print(f"[INFO] Session timeout changed to {new_timeout} seconds.")
            backend.reset_session_timer()

            backend.update_user_timeout_setting(self.current_user, self.user_password, index)
            print("User timeout setting saved!")

    def delete_account_logic(self):
        confirm = QMessageBox.warning(self, "DANGER", "All data will be lost.\nProceed?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            try:
                backend.decrypt_userdata_file(self.user_password)
                backend.decrypt_vaultdata_file(self.user_password)
                backend.delete_user(self.current_user, self.user_password)
            except Exception as e:
                print(f"Error during deletion: {e}")
            
            self.session_monitor.stop()
            self.is_logging_out = True 
            self.close()

    def delete_pm_logic(self):
        confirm = QMessageBox.question(self, "Delete PM", "Delete Password Manager?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            if backend.delete_passMngr(self.current_user, self.user_password):
                QMessageBox.information(self, "Deleted", "Password Manager deleted.")
                self.check_pm_status()
            else:
                QMessageBox.warning(self, "Warning!", "Password Manager not deleted.")
                self.check_pm_status()

    def handle_logout(self):
        self.session_monitor.stop()
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

        self.import_menu = QtWidgets.QMenu()
        self.import_menu.setStyleSheet("""
            QMenu {
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
            }
            QMenu::item {
                padding: 5px 20px;
            }
            QMenu::item:selected {
                background-color: #585b70;
            }
        """)

        action_file = self.import_menu.addAction("📄  Import Files...")
        action_folder = self.import_menu.addAction("📁  Import Folder...")

        action_file.triggered.connect(self.import_file_dialog)
        action_folder.triggered.connect(self.import_folder_dialog)

        self.btn_vaultmenu_add.setMenu(self.import_menu)

        self.table_files.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.load_files()

    def go_back_to_main(self):
        self.close() 

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

    def import_folder_dialog(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder to Encrypt")
        if folder_path:
            QMessageBox.information(self, "Processing", "Encrypting folder contents... This may take a moment.")
            QApplication.processEvents()
            
            try:
                backend.decrypt_vaultdata_file(self.user_password)
                count = backend.add_folder_recursive(self.vault_name, self.vault_key, folder_path, self.current_user)
                QMessageBox.information(self, "Success", f"{count} files encrypted successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))
            finally:
                backend.encrypt_vaultdata_file(self.user_password)
            
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
        urls = event.mimeData().urls()
        if not urls:
            return
        
        QMessageBox.information(self, "Processing", "Encrypting dropped items...")
        QApplication.processEvents()
        
        try:
            backend.decrypt_vaultdata_file(self.user_password)
            for u in urls:
                local_path = u.toLocalFile()
                if os.path.isdir(local_path):
                    backend.add_folder_recursive(self.vault_name, self.vault_key, local_path, self.current_user)
                elif os.path.isfile(local_path):
                    backend.add_file_to_vault(self.vault_name, self.vault_key, local_path, self.current_user)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"An error occurred during import:\n{str(e)}")
        finally:
            backend.encrypt_vaultdata_file(self.user_password)
        
        self.load_files()

    def closeEvent(self, event):
        if os.path.exists(backend.VAULT_METADATA_FILE):
            backend.encrypt_vaultdata_file(self.user_password)

        if self.parent_menu:
            self.parent_menu.show()
            self.parent_menu.load_vaults_table()
        
        event.accept()

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
        
        score, strength_msg = backend.audit_password_strenght(pwd)
        if score <= 40:
            QMessageBox.warning(self, "Weak Password", "Your password is too weak!\nPlease use a longer password with uppercase, lowercase, numbers and symbols.")
            return
        
        result = backend.create_vault(name, pwd, self.user_password)
            
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

        key = backend.authenticate_vault(self.vault_name, pwd, self.user_password)
            
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
        s_user_mail = self.input_service_user_mail.text()
        s_pass = self.input_service_pass.text()
        confirm = self.input_service_confirm_pass.text()

        if s_pass != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return
        
        # [DEC -> OP -> ENC]
        try:
            backend.decrypt_passdata_file(self.master_password)
            backend.add_password_to_PassMngr(s_name, s_user_mail, s_pass)
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
        original_text = self.btn_dialog_reqP_copy.text()
        self.btn_dialog_reqP_copy.setText("Copied!")
        QtCore.QTimer.singleShot(1000, lambda: self.btn_dialog_reqP_copy.setText(original_text))

class AuditPasswordDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(get_ui_path("dialog_pm_auditP.ui"), self)
        setup_password_toggle(self.input_dialog_check_strength)

        self.input_dialog_check_strength.textChanged.connect(self.update_meter)

    def update_meter(self):
        text = self.input_dialog_check_strength.text()
        
        total, msg = backend.audit_password_strenght(text)
        self.bar_strength_score.setValue(total)
        color = "#f38ba8" 
        if msg == "Moderate":
            color = "#fab387"
        elif msg == "Strong":
            color = "#a6e3a1"
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
        self.btn_dialog_genP_copy.clicked.connect(self.copy_to_clipboard)
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

    def copy_to_clipboard(self):
        QApplication.clipboard().setText(self.output_dialog_genP_generatedP.text())
        original_text = self.btn_dialog_genP_copy.text()
        self.btn_dialog_genP_copy.setText("Copied!")
        QtCore.QTimer.singleShot(1000, lambda: self.btn_dialog_genP_copy.setText(original_text))
        
class RecoveryDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(get_ui_path("dialog_recovery.ui"), self)
        
        self.setWindowTitle("Account Recovery")
        
        self.stackedWidget.setCurrentIndex(0)

        setup_password_toggle(self.input_rec_code)
        setup_password_toggle(self.output_recovered_pass)
        
        # Btn Page 0
        self.btn_rec_recover.clicked.connect(self.process_recovery)
        self.btn_rec_cancel.clicked.connect(self.reject)
            
        # Btn - Page 1
        self.btn_dialog_rec_copy.clicked.connect(self.copy_to_clipboard)
        self.btn_rec_to_login.clicked.connect(self.accept)
        self.btn_dialog_rec_close.clicked.connect(self.accept) 

        self.recovered_password = None 
        self.recovered_username = None

    def process_recovery(self):
        user = self.input_rec_username.text().strip()
        code = self.input_rec_code.text().strip()
        
        if not user or not code:
            QMessageBox.warning(self, "Error", "Please fill in all fields.")
            return

        QApplication.processEvents()
        
        recovered_pass = backend.recover_account_with_code(user, code)
        
        if recovered_pass:
            self.recovered_password = recovered_pass
            self.recovered_username = user
            
            self.output_recovered_pass.setText(recovered_pass)
            
            self.stackedWidget.setCurrentIndex(1)
            
        else:
            QMessageBox.critical(self, "Failed", "Invalid Username or Recovery Code.\nPlease check your inputs.")

    def copy_to_clipboard(self):
        QApplication.clipboard().setText(self.output_recovered_pass.text())
        original_text = self.btn_dialog_rec_copy.text()
        self.btn_dialog_rec_copy.setText("Copied!")
        QtCore.QTimer.singleShot(1000, lambda: self.btn_dialog_rec_copy.setText(original_text))