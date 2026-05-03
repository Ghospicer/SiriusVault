import sys
import SiriusVaultFunctions as backend
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QObject, QEvent
from SiriusVaultGUI import LoginWindow

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

    inactivity_filter = InactivityFilter()
    app.installEventFilter(inactivity_filter)

    window = LoginWindow()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()