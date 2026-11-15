import os
import sys
import SiriusVaultFunctions as backend
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QObject, QEvent, QTranslator
from PyQt6.QtGui import QIcon
from SiriusVaultGUI import LoginWindow, clear_sensitive_clipboard

class InactivityFilter(QObject):
    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress, QEvent.Type.MouseMove):
            backend.reset_session_timer()

        return super().eventFilter(obj, event)

def main():
    if hasattr(Qt.ApplicationAttribute, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    if hasattr(Qt.ApplicationAttribute, 'AA_UseHighDpiPixmaps'):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("Sirius Vault")
    icon_path = os.path.join(backend.BASE_DIR, "assets", "siriusvault.ico")
    app.setWindowIcon(QIcon(icon_path))

    # TRANSLATOR
    translator = QTranslator()
    app.translator = translator
    supported_locales = ["tr_TR", "en_EN"]
    saved_lang_index = backend.get_config_settings("language_index", 1)

    if 0 <= saved_lang_index < len(supported_locales):
      selected_locale = supported_locales[saved_lang_index]
      if selected_locale != "en_EN":
        qm_path = backend.get_resource_path(f"locales/{selected_locale}.qm")
        if translator.load(qm_path):
          app.installTranslator(translator)
          app._translator = translator

    inactivity_filter = InactivityFilter()
    app.installEventFilter(inactivity_filter)

    app.aboutToQuit.connect(clear_sensitive_clipboard)

    window = LoginWindow()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()