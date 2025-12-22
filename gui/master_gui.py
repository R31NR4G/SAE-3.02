import sys
import socket
import threading
import time

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QGridLayout, QLabel, QTextEdit, QListWidget
)

from client.onion_tools import send_packet, recv_packet, load_node
from database.onion_bdd import get_routers


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

        grid.addWidget(QLabel("Clients enregistrés"), 2, 0)
        self.client_list = QListWidget()
        grid.addWidget(self.client_list, 3, 0)

        grid.addWidget(QLabel("Logs Monitor"), 0, 1)
        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        grid.addWidget(self.logs, 1, 1, 3, 1)

        self.master_host = "127.0.0.1"
        self.master_port = 5000
        try:
            h, p = load_node("MASTER")
            self.master_host, self.master_port = h, p
        except:
            pass

        threading.Thread(target=self.refresh_loop, daemon=True).start()

    def log(self, txt):
        self.logs.append(txt)

    def refresh_loop(self):
        while True:
            time.sleep(2)
            self.refresh_routers()
            self.refresh_clients()

    def refresh_routers(self):
        try:
            routers = get_routers()
            self.router_list.clear()
            for name, ip, port, _ in routers:
                self.router_list.addItem(f"{name}  {ip}:{port}")
        except Exception as e:
            self.log(f"[MONITOR] Erreur lecture BDD routeurs : {e}")

    def refresh_clients(self):
        self.client_list.clear()
        try:
            s = socket.socket()
            s.settimeout(0.7)
            s.connect((self.master_host, self.master_port))
            send_packet(s, "CLIENT_LIST_REQUEST")
            rep = recv_packet(s)
            s.close()

            if rep and rep.startswith("CLIENT_LIST|"):
                ids = [x for x in rep.split("|", 1)[1].split(";") if x]
                for cid in ids:
                    self.client_list.addItem(cid)

        except Exception as e:
            self.log(f"[MONITOR] Master injoignable : {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MasterGUI()
    win.show()
    sys.exit(app.exec())
