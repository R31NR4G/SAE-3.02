import sys
import threading
import time

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QGridLayout, QLabel, QTextEdit, QListWidget
)

from database.onion_bdd import get_routers


# ======================================================
# INTERFACE MASTER GUI (MONITOR)
# ======================================================
class MasterGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("MASTER SAE 3.02 — Monitor")

        self.setStyleSheet("""
            QWidget { background-color: #2B2D31; color: #DCDDDE; font-size: 14px; }
            QListWidget, QTextEdit {
                background-color: #1E1F22;
                border: 1px solid #111;
            }
        """)

        root = QWidget()
        grid = QGridLayout(root)
        self.setCentralWidget(root)

        grid.addWidget(QLabel("Routeurs enregistrés"), 0, 0)
        self.router_list = QListWidget()
        grid.addWidget(self.router_list, 1, 0)

        grid.addWidget(QLabel("Logs"), 0, 1)
        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        grid.addWidget(self.logs, 1, 1)

        threading.Thread(target=self.refresh_loop, daemon=True).start()

    # --------------------------------------------------
    def log(self, txt):
        self.logs.append(txt)

    # --------------------------------------------------
    def refresh_loop(self):
        while True:
            time.sleep(2)
            self.refresh_routers()

    def refresh_routers(self):
        try:
            routers = get_routers()
            self.router_list.clear()
            for name, ip, port, _ in routers:
                self.router_list.addItem(f"{name}  {ip}:{port}")
        except Exception as e:
            self.log(f"Erreur lecture BDD : {e}")


# ======================================================
# MAIN
# ======================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MasterGUI()
    win.show()
    sys.exit(app.exec())
