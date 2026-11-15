import sys
import os
import time
import shutil
import mimetypes
from PyQt6 import QtWidgets, uic, QtCore, QtGui
from PyQt6.QtWidgets import QFileDialog, QMessageBox, QTableWidgetItem, QHeaderView, QWidget, QHBoxLayout, QPushButton, QApplication, QAbstractItemView, QLineEdit
from PyQt6.QtGui import QAction, QIcon, QPixmap, QPainter, QColor, QFont
from PyQt6.QtCore import Qt, QTimer, QMimeData, QEvent, QUrl, QTranslator, QCoreApplication
from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
from PyQt6.QtMultimediaWidgets import QVideoWidget

# Globals
clipboard_timer = None
last_copied_sensitive_data = None

# Backend
try:
    import SiriusVaultFunctions as backend
except ImportError:
    print("CRITICAL ERROR: 'SiriusVaultFunctions.py' not found!")
    sys.exit(1)

# UI
#def get_ui_path(filename):
#    return os.path.join(os.path.dirname(__file__), "ui", filename)
from ui.ui_login import Ui_MainWindow as UI_LoginWindow
from ui.ui_main_menu import Ui_MainWindow as UI_MainMenu
from ui.ui_vault_menu import Ui_Form as UI_VaultMenu
from ui.ui_dialog_create_vault import Ui_Dialog as UI_CreateVaultDialog
from ui.ui_dialog_vault_login import Ui_Dialog as UI_VaultLoginDialog
from ui.ui_dialog_pm_addP import Ui_Dialog as UI_AddPasswordDialog
from ui.ui_dialog_pm_auth_check import Ui_Dialog as UI_AuthCheckDialog
from ui.ui_dialog_pm_auditP import Ui_Dialog as UI_AuditPasswordDialog
from ui.ui_dialog_pm_genP import Ui_Dialog as UI_GeneratePasswordDialog
from ui.ui_dialog_recovery import Ui_Dialog as UI_RecoveryDialog
from ui.ui_dialog_mm_preview import Ui_Dialog as UI_MultimediaPreviewDialog
from ui.ui_dialog_change_pass import Ui_Dialog as UI_ChangePasswordDialog


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

def secure_copy_to_clipboard(sensitive_text):
    global clipboard_timer, last_copied_sensitive_data

    mime_data = QMimeData()
    mime_data.setText(sensitive_text)

    dword_zero = b'\x00\x00\x00\x00'

    #Win10/11
    mime_data.setData("ExcludeClipboardContentFromMonitorUI", dword_zero)
    mime_data.setData("ExcludeClipboardContentFromMonitorProcessing", dword_zero)
    mime_data.setData("CanIncludeInClipboardHistory", dword_zero)
    mime_data.setData("CanUploadToCloudClipboard", dword_zero)

    #macOS
    mime_data.setData("org.nspasteboard.ConcealedType", dword_zero)

    QApplication.clipboard().setMimeData(mime_data)
    last_copied_sensitive_data = sensitive_text

    if clipboard_timer:
        clipboard_timer.stop()
    
    clipboard_timer = QtCore.QTimer()
    clipboard_timer.setSingleShot(True)
    clipboard_timer.timeout.connect(clear_sensitive_clipboard)
    clipboard_timer.start(30000) #30s

    print("[INFO] Sensitive data copied to clipboard with DWORD Zero.")

def clear_sensitive_clipboard():
    global last_copied_sensitive_data

    current_clipboard_text = QApplication.clipboard().text()

    if last_copied_sensitive_data and current_clipboard_text == last_copied_sensitive_data:
        QApplication.clipboard().clear()
        print("[INFO] Clipboard automatically cleared for security.")
    
    last_copied_sensitive_data = None

class JumpSlider(QtWidgets.QSlider):
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            click_x = event.position().x()
            val = self.minimum() + ((self.maximum() - self.minimum()) * click_x) / self.width()
            self.setValue(int(val))
            self.sliderMoved.emit(int(val))
            
        super().mousePressEvent(event)

# =============================================================================
# 1. LOGIN WINDOW (Login, Register, USB Selection)
# =============================================================================
class LoginWindow(QtWidgets.QMainWindow, UI_LoginWindow):
    def __init__(self):
        super().__init__()
        #uic.loadUi(get_ui_path("login.ui"), self)
        self.setupUi(self)

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

        # --- Language Change ---
        self.combo_login_language.currentIndexChanged.connect(self.change_language)
        self.combo_register_language.currentIndexChanged.connect(self.change_language) 
        saved_lang_index = backend.get_config_settings("language_index", 1)
        self.combo_login_language.setCurrentIndex(saved_lang_index)
        self.combo_register_language.setCurrentIndex(saved_lang_index)

        # Default storage paht start
        backend.initialize_storage(default=True)

    def open_recovery_dialog(self):
        dialog = RecoveryDialog(self)
        if dialog.exec():
            if dialog.recovered_password:
                self.stackedWidget.setCurrentIndex(0)

    def change_language(self, index):

        app = QCoreApplication.instance()
        if not hasattr(app, 'translator'):
            app.translator = QTranslator()

        supported_locales = ["tr_TR", "en_EN", "de_DE", "fr_FR", "es_ES"]

        if index < 0 or index > len(supported_locales):
            return

        selected_locale = supported_locales[index]

        if selected_locale == "en_EN":
            app.removeTranslator(app.translator)
        else:
            qm_path = backend.get_resource_path(f"locales/{selected_locale}.qm")
            if app.translator.load(qm_path):
                app.installTranslator(app.translator)

        backend.save_config_settings("language_index", index)
        self.combo_login_language.setCurrentIndex(index)
        self.combo_register_language.setCurrentIndex(index)
        self.retranslateUi(self)

    def select_external_storage_login(self):
        path = QFileDialog.getExistingDirectory(self, "Select External Drive (USB/HDD)")
        if path:
            self.selected_storage_path = path
            if backend.initialize_storage(path, default=False):
                self.update_storage_btn_ui(self.btn_ext_storage_log, path)
            else:
                QMessageBox.critical(self, self.tr("Error"), self.tr("Could not initialize storage."))

    def select_external_storage_reg(self):
        path = QFileDialog.getExistingDirectory(self, "Select External Drive (USB/HDD)")
        if path:
            self.selected_storage_path = path
            if backend.initialize_storage(path, default=False):
                self.update_storage_btn_ui(self.btn_ext_storage_reg, path)
            else:
                QMessageBox.critical(self, self.tr("Error"), self.tr("Could not initialize storage."))

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
            QMessageBox.warning(self, self.tr("Input Error"), self.tr("Please fill in all fields."))
            return
        
        lockout_data = backend.get_lockout_data(username)
        current_time = int(time.time())

        if lockout_data["lock_until"] > current_time:
            remaining_seconds = lockout_data["lock_until"] - current_time
            hours, remainder = divmod(remaining_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)

            error_msg = self.tr("Account locked due to multiple failed attempts.\n\n")

            if hours > 0:
                error_msg += self.tr("Try again in {0} hour(s), {1} minute(s) and {2} second(s).").format(int(hours), int(minutes), int(seconds))
            elif minutes > 0:
                error_msg += self.tr("Try again in {0} minute(s) and {1} second(s).").format(int(minutes), int(seconds))
            else:
                error_msg += self.tr("Try again in {0} second(s).").format(int(seconds))
            
            QMessageBox.critical(self, self.tr("Account Locked"), error_msg)
            return
        
        if backend.authenticate_user(username, password):
            self.temp_password_holder = password
            new_codes = backend.session.get("migrated_recovery_codes")
            if new_codes:
                code_str = "\n".join(new_codes)
                msg_text = self.tr("SECURITY INFRASTRUCTURE UPGRADED!\n\n")
                msg_text += self.tr("Your account has been successfully migrated to the new Quantum-Resistant architecture.\n")
                msg_text += self.tr("Your old recovery codes are now INVALID.\n")
                msg_text += self.tr("Please save your new recovery codes in a secure location:\n\n")
                msg_text += code_str

                QMessageBox.information(self, self.tr("System Upgrade Complete"), msg_text)
                backend.session["migrated_recovery_codes"] = None

            self.open_main_menu()
        else:
            backend.record_failed_attempt(username)
            QMessageBox.warning(self, self.tr("Login Failed"), self.tr("Invalid username or password."))

    def handle_register(self):
        user = self.input_username_reg.text().strip()
        pwd = self.input_user_password_reg.text()
        confirm = self.input_confirm_user_password_reg.text()

        if not user or not pwd:
            QMessageBox.warning(self, self.tr("Error"), self.tr("Fields cannot be empty."))
            return

        if pwd != confirm:
            QMessageBox.warning(self, self.tr("Error"), self.tr("Passwords do not match!"))
            return

        score, strength_msg = backend.audit_password_strenght(pwd)
        if score <= 40:
            QMessageBox.warning(self, self.tr("Weak Password"), self.tr("Your password is too weak!\nPlease use a longer password with uppercase, lowercase, numbers and symbols."))
            return
        if backend.create_user(user, pwd):
            codes = backend.setup_recovery_codes(user, pwd)
            msg_text = self.tr("Account created!")
            if codes:
                code_str = "\n".join(codes)
                msg_text += self.tr("\nIMPORTANT: SAVE THESE RECOVERY CODES!\n")
                msg_text += self.tr("If you lose your password, these are the ONLY way to recover your account.\n\n")
                msg_text += code_str
                QMessageBox.information(self, self.tr("Success"), msg_text)
            else:
                QMessageBox.warning(self, self.tr("Warning"), self.tr("Account created but recovery codes could not be generated."))        
            self.stackedWidget.setCurrentIndex(0)
        else:
            QMessageBox.warning(self, self.tr("Error"), self.tr("User already exists."))

    def open_main_menu(self):
        self.main_menu = MainMenuWindow(self.temp_password_holder)
        self.main_menu.show()
        self.close()

# =============================================================================
# 2. MAIN MENU WINDOW
# =============================================================================
class MainMenuWindow(QtWidgets.QMainWindow, UI_MainMenu):
    def __init__(self, user_password):
        super().__init__()
        #uic.loadUi(get_ui_path("main_menu.ui"), self)
        self.setupUi(self)

        self.user_password = user_password
        self.current_user = backend.session.get("authenticated_user")
        self.saved_TO_index = backend.session.get("session_timeout_index", 1)
        self.saved_lang_index = backend.get_config_settings("language_index", 1)
        self.saved_theme_index = backend.get_config_settings("theme_index", 0)
        self.is_logging_out = False 

        setup_password_toggle(self.input_pm_auth_pass)
        setup_password_toggle(self.input_pm_reg_pass)
        setup_password_toggle(self.input_pm_reg_pass_confirm)

        version_string = f"Sirius Vault v{backend.APP_VERSION} | Developed by Ghospicer"
        if hasattr(self, 'lbl_about'):
            self.lbl_about.setText(version_string)

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
        self.btn_settings_change_pm_pass.clicked.connect(self.open_pm_pass_change_dialog)
        self.btn_settings_change_user_pass.clicked.connect(self.open_account_pass_change_dialog)
        if hasattr(backend, 'USER_DIR'):
             self.lineEdit_cur_storage_path.setPlaceholderText(backend.USER_DIR)
        self.btn_settings_sto_move.clicked.connect(self.move_storage_logic)
        self.btn_settings_sto_change.hide() # Remove this btn from ui
        self.comboBox_timeout.setCurrentIndex(self.saved_TO_index)
        timeouts = {0: 60, 1: 300, 2: 600, 3: 1800}
        backend.SESSION_TIMEOUT = timeouts.get(self.saved_TO_index, 300)
        self.comboBox_timeout.currentIndexChanged.connect(self.update_session_timeout)
        self.comboBox_language.setCurrentIndex(self.saved_lang_index)
        self.comboBox_language.currentIndexChanged.connect(self.change_app_language)
        self.comboBox_theme.setCurrentIndex(self.saved_theme_index)
        self.comboBox_theme.currentIndexChanged.connect(self.change_app_theme)

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

    def change_app_language(self, index):

        app = QCoreApplication.instance()
        if not hasattr(app, 'translator'):
            app.translator = QTranslator()

        supported_locales = ["tr_TR", "en_EN"]

        if index < 0 or index >= len(supported_locales):
            return

        selected_locale = supported_locales[index]

        if selected_locale == "en_EN":
            app.removeTranslator(app.translator)
        else:
            qm_path = backend.get_resource_path(f"locales/{selected_locale}.qm")
            if app.translator.load(qm_path):
                app.installTranslator(app.translator)

        backend.save_config_settings("language_index", index)
        self.comboBox_language.setCurrentIndex(index)

    def show_my_vaults(self):
        self.stackedWidget.setCurrentIndex(0)
        self.load_vaults_table()

    def verify_session(self):
        if backend.is_system_locked():
            print("[SECURITY] OS Lock detected! Forcing immediate logout...")
            backend.logout_user()

        if backend.session.get("authenticated_user") is None:
            self.session_monitor.stop()
            for widget in QApplication.topLevelWidgets():
                if isinstance(widget, QtWidgets.QDialog):
                    widget.reject()

            self.hide()
            
            if hasattr(self, 'vault_window') and self.vault_window.isVisible():
                self.vault_window.close()
            
            QMessageBox.warning(self, self.tr("Session Expired"), self.tr("Your session has expired due to inactivity/lockdown.\nPlease log in again."))
            
            self.handle_logout()

    # --- VAULT LOGIC ---
    def load_vaults_table(self):
        self.table_vaults.setRowCount(0)
        
        vaults = backend.list_vaults_GUI(self.current_user, self.user_password)

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

                btn_change_vault_pass = QPushButton("🔑")  # Alternatif: "🔐" veya "🔄"
                btn_change_vault_pass.setToolTip("Change Vault Password")
                btn_change_vault_pass.setFixedSize(35, 30)
                btn_change_vault_pass.setStyleSheet("background-color: #a6e3a1; border: none; border-radius: 4px;")
                btn_change_vault_pass.clicked.connect(lambda _, v=v_name: self.change_vault_pass(v))

                btn_del = QPushButton("🗑️")
                btn_del.setToolTip("Delete Vault")
                btn_del.setFixedSize(35, 30)
                btn_del.setStyleSheet("background-color: #f38ba8; border: none; border-radius: 4px;")
                btn_del.clicked.connect(lambda _, v=v_name: self.delete_vault_click(v))
                
                layout.addWidget(btn_unlock)
                layout.addWidget(btn_change_vault_pass)
                layout.addWidget(btn_del)
                layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
                
                self.table_vaults.setCellWidget(row, 1, action_widget)

    def delete_vault_click(self, vault_name):
        dialog = VaultLoginDialog(vault_name, self.user_password, self)
        if dialog.exec():
            vault_keys = dialog.vault_keys
            question_text = self.tr("Delete vault '{0}' permanently?").format(vault_name)
            confirm = QMessageBox.question(self, self.tr("Confirm Delete"), question_text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if confirm == QMessageBox.StandardButton.Yes:
                backend.delete_vault(self.current_user, vault_name, vault_keys, self.user_password)
                self.load_vaults_table()

    def open_create_vault_dialog(self):
        dialog = CreateVaultDialog(self.user_password, self)
        if dialog.exec():
            self.load_vaults_table()

    def change_vault_pass(self, vault_name):
        VaultPasswordChangeDialog(vault_name, self.user_password).exec()

    def on_vault_double_click(self, row, column):
        vault_name = self.table_vaults.item(row, 0).text()
        login_dialog = VaultLoginDialog(vault_name, self.user_password, self)
        
        if login_dialog.exec():
            vault_keys = login_dialog.vault_keys
            self.vault_window = VaultMenuWindow(vault_name, vault_keys, self.user_password, parent_menu=self)
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
            QMessageBox.warning(self, self.tr("Error"), self.tr("Incorrect Password."))

    def handle_pm_register(self):
        passMngr_pass = self.input_pm_reg_pass.text()
        confirm = self.input_pm_reg_pass_confirm.text()
        if passMngr_pass == confirm and passMngr_pass:
            score, strength_msg = backend.audit_password_strenght(passMngr_pass)
            if score <= 40:
                QMessageBox.warning(self, self.tr("Weak Password"), self.tr("Your password is too weak!\nPlease use a longer password with uppercase, lowercase, numbers and symbols."))
                return
            if backend.create_passMngr(passMngr_pass):
                self.master_pm_password = passMngr_pass
                QMessageBox.information(self, self.tr("Success"), self.tr("Password Manager Created!"))
                self.input_pm_reg_pass.clear()
                self.input_pm_reg_pass_confirm.clear()
                self.stack_pass_manager.setCurrentIndex(2)
        else:
            self.input_pm_reg_pass.clear()
            self.input_pm_reg_pass_confirm.clear()
            QMessageBox.warning(self, self.tr("Error"), self.tr("Passwords do not match."))

    def load_pm_table(self):
        self.table_pm_list.setRowCount(0)
        
        services = backend.list_services_in_passMngr()
            
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
            btn_copy.clicked.connect(lambda _, p=s_pass: secure_copy_to_clipboard(p))

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
        question_text = self.tr("Remove '{0}'?").format(service_name)
        reply = QMessageBox.question(self, self.tr("Delete"), question_text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            
            backend.remove_password_service(service_name)

            self.load_pm_table()

    def logout_pm_only(self):
        backend.logout_passMngr()
        if hasattr(self, 'master_pm_password'):
            self.master_pm_password = None
        clear_sensitive_clipboard()
        self.stack_pass_manager.setCurrentIndex(0) 

    # --- SETTINGS & LOGOUT ---
    def show_settings(self):
        self.stackedWidget.setCurrentIndex(2)

    def move_storage_logic(self):
        new_path = QFileDialog.getExistingDirectory(self, "Select New Location to Move Your Data")
        if not new_path:
            return
        
        confirm = QMessageBox.warning(self, self.tr("Move Data"), self.tr("Your data will be moved to the new location.\nYou will be logged out after this operation to secure your files.\nProceed?"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if confirm == QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, self.tr("Processing"), self.tr("Moving your data... Please wait."))
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
                QMessageBox.information(self, self.tr("Success"), self.tr("Your data has been successfully moved!\nPlease select your new storage on the login screen next time."))
            elif result == "EXISTS":
                QMessageBox.warning(self, self.tr("Error"), self.tr("Your user data already exists in the target location."))
            else:
                QMessageBox.critical(self, self.tr("Error"), self.tr("An error occurred while moving your data."))

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

    def open_account_pass_change_dialog(self):
        AccountPasswordChangeDialog(self).exec()

    def open_pm_pass_change_dialog(self):
        PasswordManagerPasswordChangeDialog(self).exec()
  
    def delete_account_logic(self):
        confirm = QMessageBox.warning(self, self.tr("DANGER"), self.tr("All data will be lost.\nProceed?"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            try:
                backend.delete_user(self.current_user, self.user_password)
            except Exception as e:
                print(f"Error during deletion: {e}")
            
            self.session_monitor.stop()
            self.is_logging_out = True 
            self.close()

    def delete_pm_logic(self):
        confirm = QMessageBox.question(self, self.tr("Delete Password Manager"), self.tr("All Password(s) will be deleted.\n Proceed?"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            if backend.delete_passMngr(self.current_user, self.user_password):
                QMessageBox.information(self, self.tr("Success!"), self.tr("Password Manager deleted."))
                self.check_pm_status()
            else:
                QMessageBox.warning(self, self.tr("Warning!"), self.tr("Password Manager not deleted."))
                self.check_pm_status()

    def handle_logout(self):
        self.session_monitor.stop()
        clear_sensitive_clipboard()
        self.is_logging_out = True 
        self.close() 

    def changeEvent(self, event):

        if event.type() == QEvent.Type.LanguageChange:
            self.retranslateUi(self)

        super().changeEvent(event)

    def closeEvent(self, event):
        print("[INFO] Cleaning up and encrypting data...")
        
        backend.logout_user()
        clear_sensitive_clipboard()

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
class VaultMenuWindow(QtWidgets.QWidget, UI_VaultMenu):
    def __init__(self, vault_name, vault_keys, user_password, parent_menu=None):
        super().__init__()
        #uic.loadUi(get_ui_path("vault_menu.ui"), self)
        self.setupUi(self)
        
        self.vault_name = vault_name
        self.vault_keys = vault_keys 
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

        files = backend.list_files_in_vault_GUI(self.vault_name, self.current_user, self.vault_keys)
            
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

            btn_view = QPushButton("👁️")
            btn_view.setToolTip("Preview")
            btn_view.setFixedSize(30, 25)
            btn_view.setStyleSheet("background-color: #a6e3a1; border: none; border-radius: 4px; color: #1e1e2e;")
            btn_view.clicked.connect(lambda _, n=f_name: self.preview_file(n))
            
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

            layout.addWidget(btn_view)
            layout.addWidget(btn_ext)
            layout.addWidget(btn_del)
            layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table_files.setCellWidget(row, 4, action_widget)

    def import_file_dialog(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files to Encrypt")
        if not files: return

        reply = QMessageBox.question(self, self.tr("Secure Delete"), self.tr("Do you want to Securely Delete the original files from your computer after they encrypted in the vault?"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        delete_originals = (reply == QMessageBox.StandardButton.Yes)
        for f in files:
            self.process_file_import(f, delete_originals)
        self.load_files()

    def import_folder_dialog(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder to Encrypt")
        if folder_path:
            reply = QMessageBox.question(self, self.tr("Secure Delete"), self.tr("Do you want to Securely Delete the original folder and all its contents after encryption?"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            delete_originals = (reply == QMessageBox.StandardButton.Yes)

            QMessageBox.information(self, self.tr("Processing"), self.tr("Encrypting folder contents... This may take a moment."))
            QApplication.processEvents()
            
            try:
                count = backend.add_folder_recursive(self.vault_name, self.vault_keys, folder_path, self.current_user, delete_original=delete_originals)
                msg_text = self.tr("{0} files encrypted successfully.").format(count)
                QMessageBox.information(self, self.tr("Success"), msg_text)
            except Exception as e:
                error_msg = self.tr("An unexpected error occured:\n{0}").format(str(e))
                QMessageBox.critical(self, self.tr("Error"), error_msg)
            
            self.load_files()

    def process_file_import(self, filepath, delete_originals):
        backend.add_file_to_vault(self.vault_name, self.vault_keys, filepath, self.current_user, delete_original=delete_originals)

    def preview_file(self, file_name):
        temp_path = backend.multimedia_manager(self.vault_name, self.vault_keys, file_name)
        
        if temp_path and os.path.exists(temp_path):
            dialog = MultimediaManagerDialog(temp_path, file_name, self)
            dialog.exec()
            self.load_files()
        else:
            QMessageBox.critical(self, self.tr("ERROR"), self.tr("Multimedia file cannot decrypted!"))

    def extract_file(self, file_name):
        dest_folder = QFileDialog.getExistingDirectory(self, "Select Destination")
        if dest_folder:
                backend.extract_file_from_vault(self.vault_name, self.vault_keys, file_name, dest_folder)
                msg_text = self.tr("File extracted to {0}").format(dest_folder)
                QMessageBox.information(self, self.tr("Success"), msg_text)

    def delete_file(self, file_name):
        question_text = self.tr("Delete {0}?").format(file_name)
        confirm = QMessageBox.question(self, self.tr("Delete"), question_text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
                backend.remove_file_from_vault(self.vault_name, file_name, self.current_user, self.vault_keys)
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
        
        reply = QMessageBox.question(self, self.tr("Secure Delete"), self.tr("Do you want to Securely Delete the original files/folders from your computer after they are encrypted into the vault?"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        delete_originals = (reply == QMessageBox.StandardButton.Yes)

        QMessageBox.information(self, self.tr("Processing"), self.tr("Encrypting dropped items..."))
        QApplication.processEvents()
        
        try:
            for u in urls:
                local_path = u.toLocalFile()
                if os.path.isdir(local_path):
                    backend.add_folder_recursive(self.vault_name, self.vault_keys, local_path, self.current_user, delete_original=delete_originals)
                elif os.path.isfile(local_path):
                    backend.add_file_to_vault(self.vault_name, self.vault_keys, local_path, self.current_user, delete_original=delete_originals)
        except Exception as e:
            error_msg = self.tr("An error occurred during import:\n{0}").format(str(e))
            QMessageBox.warning(self, self.tr("Error"), error_msg)
        
        self.load_files()

    def closeEvent(self, event):

        self.vault_keys = None
        self.user_password = None
        
        if self.parent_menu:
            self.parent_menu.show()
            self.parent_menu.load_vaults_table()
        
        event.accept()

# =============================================================================
# 4. DIALOG CLASSES
# =============================================================================
class CreateVaultDialog(QtWidgets.QDialog, UI_CreateVaultDialog):
    def __init__(self, user_password, parent=None):
        super().__init__(parent)
        #uic.loadUi(get_ui_path("dialog_create_vault.ui"), self)
        self.setupUi(self)

        self.user_password = user_password

        setup_password_toggle(self.input_dialog_vpassword)
        setup_password_toggle(self.input_dialog_vcpassword)
        
        self.btn_dialog_vCreate_create.clicked.connect(self.validate)
        self.btn_dialog_vCreate_cancel.clicked.connect(self.reject)

    def validate(self):
        vault_name = self.input_dialog_vname.text()
        pwd = self.input_dialog_vpassword.text()
        confirm = self.input_dialog_vcpassword.text()
        
        if not vault_name or not pwd:
            QMessageBox.warning(self, self.tr("Error"), self.tr("Fields cannot be empty."))
            return
        if pwd != confirm:
            QMessageBox.warning(self, self.tr("Error"), self.tr("Passwords do not match."))
            return
        
        score, strength_msg = backend.audit_password_strenght(pwd)
        if score <= 40:
            QMessageBox.warning(self, self.tr("Weak Password"), self.tr("Your password is too weak!\nPlease use a longer password with uppercase, lowercase, numbers and symbols."))
            return
        
        result = backend.create_vault(vault_name, pwd, self.user_password)
            
        if result == "SUCCESS":
            msg_text = self.tr("Vault '{0}' created.").format(vault_name)
            QMessageBox.information(self, self.tr("Success"), msg_text)
            self.accept()
        elif result == "SAME_NAME":
            QMessageBox.warning(self, self.tr("Error"), self.tr("Vault name already exists."))
        else:
            QMessageBox.warning(self, self.tr("Error"), self.tr("Could not create vault."))

class VaultLoginDialog(QtWidgets.QDialog, UI_VaultLoginDialog):
    def __init__(self, vault_name, user_password, parent=None):
        super().__init__(parent)
        #uic.loadUi(get_ui_path("dialog_vault_login.ui"), self)
        self.setupUi(self)
        
        self.vault_name = vault_name
        self.user_password = user_password
        self.vault_key = None
        self.setWindowTitle(f"Unlock {vault_name}")

        setup_password_toggle(self.input_dialog_vLogin_vpassword)
        
        self.btn_dialog_vLogin_auth.clicked.connect(self.attempt_login)
        self.btn_dialog_vLogin_cancel.clicked.connect(self.reject)

    def attempt_login(self):
        vault_pwd = self.input_dialog_vLogin_vpassword.text()

        keys = backend.authenticate_vault(self.vault_name, vault_pwd, self.user_password)
            
        if keys:
            self.vault_keys = keys
            self.accept()
        else:
            QMessageBox.warning(self, self.tr("Error"), self.tr("Incorrect Password."))

class AddPasswordDialog(QtWidgets.QDialog, UI_AddPasswordDialog):
    def __init__(self, master_password, parent=None):
        super().__init__(parent)
        #uic.loadUi(get_ui_path("dialog_pm_addP.ui"), self)
        self.setupUi(self)

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
            QMessageBox.warning(self, self.tr("Error"), self.tr("Passwords do not match."))
            return
        
        backend.add_password_to_PassMngr(s_name, s_user_mail, s_pass)
        
        self.accept()

class AuthCheckDialog(QtWidgets.QDialog, UI_AuthCheckDialog):
    def __init__(self, service_name, master_password, parent=None):
        super().__init__(parent)
        #uic.loadUi(get_ui_path("dialog_pm_auth_check.ui"), self)
        self.setupUi(self)

        self.lbl_service_title.setText(f"Service: {service_name}")
        self.master_password = master_password
        self.service_name = service_name

        setup_password_toggle(self.input_dialog_reqP_masterP)
        
        self.stackedWidget.setCurrentIndex(0) 
        self.btn_dialog_reqP_auth.clicked.connect(self.check_master_pass)
        self.btn_dialog_reqP_close.clicked.connect(self.accept)
        self.btn_dialog_reqP_copy.clicked.connect(self.copy_to_clipboard)
        self.btn_dialog_reqP_reveal.clicked.connect(self.toggle_reveal)

    def check_master_pass(self):
        mp = self.input_dialog_reqP_masterP.text()
        
        auth_ok = backend.authenticate_passMngr(mp)
        if auth_ok:
            raw_pass = backend.extract_password_service(self.service_name)

        if auth_ok:
            self.show_revealed_password(raw_pass)
            self.stackedWidget.setCurrentIndex(1) 
        else:
            QMessageBox.warning(self, self.tr("Error"), self.tr("Incorrect Master Password."))

    def show_revealed_password(self, password):
        self.output_dialog_reqP_serviceP.setText(password)

    def toggle_reveal(self):
        if self.output_dialog_reqP_serviceP.echoMode() == QtWidgets.QLineEdit.EchoMode.Password:
            self.output_dialog_reqP_serviceP.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        else:
            self.output_dialog_reqP_serviceP.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

    def copy_to_clipboard(self):
        secure_copy_to_clipboard(self.output_dialog_reqP_serviceP.text())
        original_text = self.btn_dialog_reqP_copy.text()
        self.btn_dialog_reqP_copy.setText("Copied!")
        QtCore.QTimer.singleShot(1000, lambda: self.btn_dialog_reqP_copy.setText(original_text))

class AuditPasswordDialog(QtWidgets.QDialog, UI_AuditPasswordDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        #uic.loadUi(get_ui_path("dialog_pm_auditP.ui"), self)
        self.setupUi(self)

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

class GeneratePasswordDialog(QtWidgets.QDialog, UI_GeneratePasswordDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        #uic.loadUi(get_ui_path("dialog_pm_genP.ui"), self)
        self.setupUi(self)

        self.layout().setSizeConstraint(QtWidgets.QLayout.SizeConstraint.SetFixedSize)

        # Default Settings
        # Password
        self.spinBox_length.setValue(16)
        self.chk_upper.setChecked(True)
        self.chk_lower.setChecked(True)
        self.chk_digits.setChecked(True)
        self.chk_specials.setChecked(True)
        self.chk_advanced_specials.setChecked(False)

        self.spinBox_minUpper.setValue(1)
        self.spinBox_minLower.setValue(1)
        self.spinBox_minDigits.setValue(1)
        self.spinBox_minSpecials.setValue(1)

        # Passphrase
        self.spinBox_wordCount.setValue(4)
        self.combo_separator.setCurrentIndex(0)        
        self.chk_capitalize.setChecked(True)
        self.chk_includeNum.setChecked(False)

        # No Focus Policy
        self.btn_gen_password.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.btn_gen_passphrase.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.btn_dialog_genP_copy.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.btn_dialog_genP_reveal.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.btn_dialog_genP_close.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)

        # Top Buttons
        self.btn_gen_password.clicked.connect(lambda:self.switch_page(0))
        self.btn_gen_passphrase.clicked.connect(lambda:self.switch_page(1))

        # Bottom Buttons
        self.btn_dialog_genP_close.clicked.connect(self.accept)
        self.btn_dialog_genP_copy.clicked.connect(self.copy_to_clipboard)
        self.btn_dialog_genP_reveal.clicked.connect(self.toggle_reveal)

        # Generate Password
        self.spinBox_length.valueChanged.connect(self.generate)
        self.chk_upper.toggled.connect(self.generate)
        self.chk_lower.toggled.connect(self.generate)
        self.chk_digits.toggled.connect(self.generate)
        self.chk_specials.toggled.connect(self.generate)
        self.chk_advanced_specials.toggled.connect(self.generate)
        
        self.spinBox_minUpper.valueChanged.connect(self.generate)
        self.spinBox_minLower.valueChanged.connect(self.generate)
        self.spinBox_minDigits.valueChanged.connect(self.generate)
        self.spinBox_minSpecials.valueChanged.connect(self.generate)

        # Generate Passphrase
        self.spinBox_wordCount.valueChanged.connect(self.generate)
        self.combo_separator.currentTextChanged.connect(self.generate)
        self.chk_capitalize.toggled.connect(self.generate)
        self.chk_includeNum.toggled.connect(self.generate)


        self.switch_page(0)

    def switch_page(self, index):
        self.stackedWidget.setCurrentIndex(index)

        active_style = """
            QPushButton {
                background-color: #89b4fa;
                color: #1e1e2e;
                border: 2px solid #89b4fa;
                border-radius: 4px;
                font-size: 14pt;
                font-weight: bold;
            }
        """
        inactive_style = """
            QPushButton {
                background-color: transparent;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-radius: 4px;
                font-size: 14pt;
                font-weight: bold;
            }
        """

        if index == 0:
            self.btn_gen_password.setStyleSheet(active_style)
            self.btn_gen_passphrase.setStyleSheet(inactive_style)
        else:
            self.btn_gen_password.setStyleSheet(inactive_style)
            self.btn_gen_passphrase.setStyleSheet(active_style)

        for i in range(self.stackedWidget.count()):
            page = self.stackedWidget.widget(i)
            if i == index:
                page.setSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Minimum)
            else:
                page.setSizePolicy(QtWidgets.QSizePolicy.Policy.Ignored, QtWidgets.QSizePolicy.Policy.Ignored)

        #self.adjustSize()

        self.generate()

    def generate(self):
        current_page = self.stackedWidget.currentIndex()

        if current_page == 0:
            self.lbl_dialog_genP_outputTitle.setText("Generated Password:")

            length = self.spinBox_length.value()
            upper = self.chk_upper.isChecked()
            lower = self.chk_lower.isChecked()
            digits = self.chk_digits.isChecked()
            specials = self.chk_specials.isChecked()
            adv_specials = self.chk_advanced_specials.isChecked()

            min_upper = self.spinBox_minUpper.value() if upper else 0
            min_lower = self.spinBox_minLower.value() if lower else 0
            min_digits = self.spinBox_minDigits.value() if digits else 0
            min_specials = self.spinBox_minSpecials.value() if (specials or adv_specials) else 0

            generated_password = backend.generate_password(length, upper, lower, digits, specials, adv_specials, min_upper, min_lower, min_digits, min_specials)

            if generated_password:
                self.output_dialog_genP_generatedP.setText(generated_password)
            else:
                self.output_dialog_genP_generatedP.setText("Invalid Settings!")
        
        elif current_page == 1:
            self.lbl_dialog_genP_outputTitle.setText("Generated Passphrase:")

            wordCount = self.spinBox_wordCount.value()
            sep_text = self.combo_separator.currentText()

            separator = "-"
            if "Space" in sep_text: separator = " "
            if "_" in sep_text: separator = "_"
            elif "." in sep_text: separator = "."

            capitalize = self.chk_capitalize.isChecked()
            number = self.chk_includeNum.isChecked()

            phrase = backend.generate_passphrase(wordCount, separator, capitalize, number)
            self.output_dialog_genP_generatedP.setText(phrase)


    def toggle_reveal(self):
        if self.output_dialog_genP_generatedP.echoMode() == QtWidgets.QLineEdit.EchoMode.Password:
            self.output_dialog_genP_generatedP.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        else:
            self.output_dialog_genP_generatedP.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

    def copy_to_clipboard(self):
        text_to_copy = self.output_dialog_genP_generatedP.text()
        if text_to_copy and text_to_copy != "Invalid Settings!":
            secure_copy_to_clipboard(self.output_dialog_genP_generatedP.text())
            original_text = self.btn_dialog_genP_copy.text()
            self.btn_dialog_genP_copy.setText("Copied!")
            QtCore.QTimer.singleShot(1000, lambda: self.btn_dialog_genP_copy.setText(original_text))

class AccountPasswordChangeDialog(QtWidgets.QDialog, UI_ChangePasswordDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.stackedWidget.setCurrentIndex(0)
        setup_password_toggle(self.input_old_usr_pass)
        setup_password_toggle(self.input_new_usr_pass)
        setup_password_toggle(self.input_confirm_new_usr_pass)
        self.setWindowTitle(self.tr("Change Account Password"))
        self.btn_account_change_pass.clicked.connect(self.change_account_pass)
        self.btn_account_cancel.clicked.connect(self.reject)
        self.input_new_usr_pass.textChanged.connect(self.update_meter)

    def change_account_pass(self):
        old_usr_pass = self.input_old_usr_pass.text().strip()
        new_usr_pass = self.input_new_usr_pass.text().strip()
        confirm_new_usr_pass = self.input_confirm_new_usr_pass.text().strip()

        if not old_usr_pass or not new_usr_pass or not confirm_new_usr_pass:
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Please fill in all fields."))
            return
        if not backend.authenticate_user(old_usr_pass):
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Invalid old user password."))
            return
        if new_usr_pass != confirm_new_usr_pass:
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Passwords do not match."))
            return
        if old_usr_pass == new_usr_pass:
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Your old and new passwords are the same."))
            return
        score, msg = backend.audit_password_strenght(new_usr_pass)
        if score <= 40:
            QMessageBox.warning(self, self.tr("Weak Password"), self.tr("Your new user password is too weak!\nPlease use a longer password with uppercase, lowercase, numbers and symbols."))
            return
        self.username = backend.session["authenticated_user"]
        result, new_recovery_codes = backend.change_user_password(self.username, old_usr_pass, new_usr_pass)
        if result:
            msg_text = self.tr("Account password changed!")
            msg_text += ("\nNew Recovery codes Created.")
            code_str = "\n".join(new_recovery_codes)
            msg_text += self.tr("\nIMPORTANT: SAVE THESE NEW RECOVERY CODES!\n")
            msg_text += self.tr("If you lose your password, these are the ONLY way to recover your account.\n\n")
            msg_text += code_str
            QMessageBox.information(self, self.tr("Success"), msg_text)
            self.accept()
        else:
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Account password could not be changed."))
            return

    def update_meter(self):
        text = self.input_new_usr_pass.text()
        total, msg = backend.audit_password_strenght(text)
        self.progressBar_account_pass.setValue(total)
        color = "#f38ba8" 
        if msg == "Moderate":
            color = "#fab387"
        elif msg == "Strong":
            color = "#a6e3a1"
        self.progressBar_account_pass.setStyleSheet(f"""
            QProgressBar {{ border: none; background-color: #313244; border-radius: 2px; height: 9px; text-align: center; }}
            QProgressBar::chunk {{ background-color: {color}; border-radius: 2px; }}
        """)
        

class PasswordManagerPasswordChangeDialog(QtWidgets.QDialog, UI_ChangePasswordDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.stackedWidget.setCurrentIndex(1)
        setup_password_toggle(self.input_old_PM_pass)
        setup_password_toggle(self.input_new_PM_pass)
        setup_password_toggle(self.input_confirm_new_PM_pass)
        self.setWindowTitle(self.tr("Change Password Manager Password"))
        self.btn_PM_change_pass.clicked.connect(self.change_PM_pass)
        self.btn_PM_cancel.clicked.connect(self.reject)
        self.input_new_PM_pass.textChanged.connect(self.update_meter)

    def change_PM_pass(self):
        old_PM_pass = self.input_old_PM_pass.text().strip()
        new_PM_pass = self.input_new_PM_pass.text().strip()
        confirm_new_PM_pass = self.input_confirm_new_PM_pass.text().strip()

        if not old_PM_pass or not new_PM_pass or not confirm_new_PM_pass:
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Please fill in all fields."))
            return
        if not backend.authenticate_passMngr(old_PM_pass):
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Invalid old Password Manager password."))
            return
        if new_PM_pass != confirm_new_PM_pass:
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Passwords do not match."))
            return
        if old_PM_pass == new_PM_pass:
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Your old and new passwords are the same."))
            return
        score, msg = backend.audit_password_strenght(new_PM_pass)
        if score <= 40:
            QMessageBox.warning(self, self.tr("Weak Password"), self.tr("Your new Password Manager password is too weak!\nPlease use a longer password with uppercase, lowercase, numbers and symbols."))
            return
        result = backend.change_passMngr_password(old_PM_pass, new_PM_pass)
        if result:
            self.accept()
        else:
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Password Manager password could not be changed."))
            return

    def update_meter(self):
        text = self.input_new_PM_pass.text()
        total, msg = backend.audit_password_strenght(text)
        self.progressBar_PM_pass.setValue(total)
        color = "#f38ba8" 
        if msg == "Moderate":
            color = "#fab387"
        elif msg == "Strong":
            color = "#a6e3a1"
        self.progressBar_account_pass.setStyleSheet(f"""
            QProgressBar {{ border: none; background-color: #313244; border-radius: 2px; height: 9px; text-align: center; }}
            QProgressBar::chunk {{ background-color: {color}; border-radius: 2px; }}
        """)


class VaultPasswordChangeDialog(QtWidgets.QDialog, UI_ChangePasswordDialog):
    def __init__(self, vault_name, user_password, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.vault_name = vault_name
        self.user_password = user_password
        self.stackedWidget.setCurrentIndex(2)
        setup_password_toggle(self.input_old_vault_pass)
        setup_password_toggle(self.input_new_vault_pass)
        setup_password_toggle(self.input_confirm_new_vault_pass)
        self.setWindowTitle(self.tr("Change Vault Password"))
        self.btn_vault_change_pass.clicked.connect(self.change_vault_pass)
        self.btn_vault_cancel.clicked.connect(self.reject)
        self.input_new_vault_pass.textChanged.connect(self.update_meter)

    def change_vault_pass(self):
        old_vault_pass = self.input_old_vault_pass.text().strip()
        new_vault_pass = self.input_new_vault_pass.text().strip()
        confirm_new_vault_pass = self.input_confirm_new_vault_pass.text().strip()

        if not old_vault_pass or not new_vault_pass or not confirm_new_vault_pass:
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Please fill in all fields."))
            return
        if not backend.authenticate_vault(self.vault_name, old_vault_pass, self.user_password):
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Invalid old vault password."))
            return
        if new_vault_pass != confirm_new_vault_pass:
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Passwords do not match."))
            return
        if old_vault_pass == new_vault_pass:
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Your old and new passwords are the same."))
            return
        score, msg = backend.audit_password_strenght(new_vault_pass)
        if score <= 40:
            QMessageBox.warning(self, self.tr("Weak Password"), self.tr("Your new vault password is too weak!\nPlease use a longer password with uppercase, lowercase, numbers and symbols."))
            return
        result = backend.change_vault_password(self.user_password, self.vault_name, old_vault_pass, new_vault_pass)
        if result:
            self.accept()
        else:
            QMessageBox.warning(self, self.tr("Warning"), self.tr("Vault password could not be changed."))
            return

    def update_meter(self):
        text = self.input_new_vault_pass.text()
        total, msg = backend.audit_password_strenght(text)
        self.progressBar_vault_pass.setValue(total)
        color = "#f38ba8" 
        if msg == "Moderate":
            color = "#fab387"
        elif msg == "Strong":
            color = "#a6e3a1"
        self.progressBar_account_pass.setStyleSheet(f"""
            QProgressBar {{ border: none; background-color: #313244; border-radius: 2px; height: 9px; text-align: center; }}
            QProgressBar::chunk {{ background-color: {color}; border-radius: 2px; }}
        """)


class RecoveryDialog(QtWidgets.QDialog, UI_RecoveryDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        #uic.loadUi(get_ui_path("dialog_recovery.ui"), self)
        self.setupUi(self)

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
            QMessageBox.warning(self, self.tr("Error"), self.tr("Please fill in all fields."))
            return

        QApplication.processEvents()
        
        recovered_pass = backend.recover_account_with_code(user, code)
        
        if recovered_pass:
            self.recovered_password = recovered_pass
            self.recovered_username = user
            
            self.output_recovered_pass.setText(recovered_pass)
            
            self.stackedWidget.setCurrentIndex(1)
            
        else:
            QMessageBox.critical(self, self.tr("Failed"), self.tr("Invalid Username or Recovery Code.\nPlease check your inputs."))

    def copy_to_clipboard(self):
        secure_copy_to_clipboard(self.output_recovered_pass.text())
        original_text = self.btn_dialog_rec_copy.text()
        self.btn_dialog_rec_copy.setText("Copied!")
        QtCore.QTimer.singleShot(1000, lambda: self.btn_dialog_rec_copy.setText(original_text))

class MultimediaManagerDialog(QtWidgets.QDialog, UI_MultimediaPreviewDialog):
    def __init__(self, temp_path, file_name, parent=None):
        super().__init__(parent)
        #uic.loadUi(get_ui_path("dialog_mm_preview.ui"), self)
        self.setupUi(self)

        self.temp_path = temp_path
        self.file_name = file_name
        self.setWindowTitle(f"Multimedia Preview - {file_name}")

        self.player = None
        self.audio_output = None
        self.video_widget = None

        self.control_layout = None
        self.btn_play_pause = None
        self.slider_progress = None
        self.lbl_time = None

        self.load_content()

    def load_content(self):

        mime_type, _ = mimetypes.guess_type(self.file_name)
        if not mime_type:
            mime_type = "application/octet-stream"

        ext = os.path.splitext(self.file_name)[1].lower()

        # Text Files
        if mime_type.startswith('text/') or ext in ['.py', '.json', '.log', '.ini', '.csv', '.env']:
            self.stackedWidget_viewer.setCurrentIndex(0)
            if hasattr(self, 'lbl_file_name'):
                self.lbl_file_name.setText("Text Preview")
                self.lbl_file_name.setStyleSheet("color: #cdd6f4;")
            try:
                with open(self.temp_path, 'r', encoding='utf-8') as f:
                    self.textEdit_viewer.setText(f.read())
            except:
                with open(self.temp_path, 'r', encoding='iso-8859-1') as f:
                    self.textEdit_viewer.setText(f.read())
        # Image Files
        elif mime_type.startswith('image/'):
            self.stackedWidget_viewer.setCurrentIndex(1)
            if hasattr(self, 'lbl_file_name'):
                self.lbl_file_name.setText("Image Preview")
                self.lbl_file_name.setStyleSheet("color: #cdd6f4;")
            pixmap = QPixmap(self.temp_path)
            scaled_pixmap = pixmap.scaled(
                self.lbl_image_viewer.size(), 
                Qt.AspectRatioMode.KeepAspectRatio, 
                Qt.TransformationMode.SmoothTransformation
            )
            self.lbl_image_viewer.setPixmap(scaled_pixmap)
        # Video/Audio Files
        elif mime_type.startswith('video/') or mime_type.startswith('audio/'):
            self.stackedWidget_viewer.setCurrentIndex(2)
            self.player = QMediaPlayer()
            self.audio_output = QAudioOutput()
            self.player.setAudioOutput(self.audio_output)

            if mime_type.startswith('video/'):
                if hasattr(self, 'lbl_file_name'):
                    self.lbl_file_name.setText("Video playing on safe mode")
                    self.lbl_file_name.setStyleSheet("font-weight: bold; color: #89b4fa;")
                self.video_widget = QVideoWidget()
                self.layout_media.addWidget(self.video_widget, stretch=1)
                self.player.setVideoOutput(self.video_widget)
            else:
                if hasattr(self, 'lbl_file_name'):
                    self.lbl_file_name.setText("Audio file playing on safe mode")
                    self.lbl_file_name.setStyleSheet("font-size: 14px; font-weight: bold; color: #a6e3a1;")
                lbl_space = QtWidgets.QLabel("", self)
                self.layout_media.addWidget(lbl_space, stretch=1)

            self.control_layout = QtWidgets.QHBoxLayout()

            self.btn_skip_back = QtWidgets.QPushButton("⏪")
            self.btn_skip_back.setFixedSize(30, 30)
            self.btn_skip_back.setStyleSheet("background-color: #313244; color: white; border-radius: 4px;")
            self.btn_skip_back.clicked.connect(self.skip_backward)

            self.btn_play_pause = QtWidgets.QPushButton("⏸️")
            self.btn_play_pause.setFixedSize(40, 30)
            self.btn_play_pause.setStyleSheet("background-color: #313244; color: white; border-radius: 4px;")
            self.btn_play_pause.clicked.connect(self.toggle_play_pause)

            self.btn_skip_forward = QtWidgets.QPushButton("⏩")
            self.btn_skip_forward.setFixedSize(30, 30)
            self.btn_skip_forward.setStyleSheet("background-color: #313244; color: white; border-radius: 4px;")
            self.btn_skip_forward.clicked.connect(self.skip_forward)

            self.slider_progress = JumpSlider(Qt.Orientation.Horizontal)
            self.slider_progress.setMaximumHeight(20)
            self.slider_progress.setStyleSheet("QSlider::handle:horizontal { background: #89b4fa; border-radius: 5px; width: 10px; }")
            self.slider_progress.sliderMoved.connect(self.set_media_position)

            self.lbl_time = QtWidgets.QLabel("00:00 / 00:00")
            self.lbl_time.setMaximumHeight(20)
            self.lbl_time.setStyleSheet("color: #cdd6f4; font-weight: bold;")

            self.lbl_volume = QtWidgets.QLabel("🔊")
            self.lbl_volume.setStyleSheet("color: #cdd6f4;")
            self.lbl_volume.setMaximumHeight(20)

            self.slider_volume = JumpSlider(Qt.Orientation.Horizontal)
            self.slider_volume.setRange(0, 100)
            self.slider_volume.setValue(50)
            self.slider_volume.setMaximumWidth(80)
            self.slider_volume.setMaximumHeight(20)
            self.slider_volume.setStyleSheet("QSlider::handle:horizontal { background: #a6e3a1; border-radius: 5px; width: 10px; }")
            self.slider_volume.valueChanged.connect(self.set_volume)
            self.audio_output.setVolume(0.5)

            self.control_layout.addWidget(self.btn_skip_back)
            self.control_layout.addWidget(self.btn_play_pause)
            self.control_layout.addWidget(self.btn_skip_forward)
            self.control_layout.addWidget(self.slider_progress)
            self.control_layout.addWidget(self.lbl_time)
            self.control_layout.addWidget(self.lbl_volume)
            self.control_layout.addWidget(self.slider_volume)
            self.layout_media.addLayout(self.control_layout, stretch=0)

            self.player.positionChanged.connect(self.update_slider_position)
            self.player.durationChanged.connect(self.update_slider_duration)
            self.player.playbackStateChanged.connect(self.update_play_button_state)

            media_url = QUrl.fromLocalFile(self.temp_path)
            self.player.setSource(media_url)
            self.player.play()
        else:
            self.stackedWidget_viewer.setCurrentIndex(1)
            if hasattr(self, 'lbl_file_name'):
                self.lbl_file_name.setText("⚠️ Unsupported Format")
                self.lbl_file_name.setStyleSheet("color: #f38ba8;")
            self.lbl_image_viewer.setText(
                f"No built-in preview supported for files with extension '{ext}'.\n"
            )

    def skip_backward(self):
        new_position = max(0, self.player.position() - 10000)
        self.player.setPosition(new_position)

    def toggle_play_pause(self):
        if self.player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self.player.pause()
        else:
            self.player.play()

    def update_play_button_state(self, state):
        if state == QMediaPlayer.PlaybackState.PlayingState:
            self.btn_play_pause.setText("⏸️")
        else:
            self.btn_play_pause.setText("▶️")

    def skip_forward(self):
        new_position = min(self.player.duration(), self.player.position() + 10000)
        self.player.setPosition(new_position)

    def update_slider_position(self, position):
        self.slider_progress.setValue(position)
        self.update_time_label(position, self.player.duration())

    def update_slider_duration(self, duration):
        self.slider_progress.setRange(0, duration)
        self.update_time_label(self.player.position(), duration)

    def set_media_position(self, position):
        self.player.setPosition(position)

    def update_time_label(self, position, duration):
        def format_time(ms):
            total_seconds = round(ms / 1000)
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            if hours > 0:
                return f"{hours:02}:{minutes:02}:{seconds:02}"
            else:
                return f"{minutes:02}:{seconds:02}"
        self.lbl_time.setText(f"{format_time(position)} / {format_time(duration)}")

    def set_volume(self, value):
        volume_float = value / 100.0
        self.audio_output.setVolume(volume_float)

        if value == 0:
            self.lbl_volume.setText("🔇")
        elif value < 50:
            self.lbl_volume.setText("🔉")
        else:
            self.lbl_volume.setText("🔊")

    def closeEvent(self, event):
        if self.player:
            self.player.stop()
            self.player.setVideoOutput(None)
            self.player.setAudioOutput(None)
            self.player = None
            self. audio_output = None

        if self.video_widget:
            self.layout_media.removeWidget(self.video_widget)
            self.video_widget.deleteLater()
            self.video_widget = None

        time.sleep(0.1)

        backend.secure_delete(self.temp_path)
        print(f"[INFO] Temporary preview file successfully deleted: {self.temp_path}")
        event.accept()

