import sys
import socket
import threading
import time

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QGridLayout, QLabel, QPushButton,
    QTextEdit, QListWidget
)

from database.onion_bdd import get_routers, reset_routers
from client.onion_tools import send_packet, recv_packet, load_node


# ======================================================
# THREAD SERVEUR MASTER (logique existante)
# ======================================================
def master_server(gui):
    _, port = load_node("MASTER")

    reset_routers()

    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind(("0.0.0.0", port))
    serv.listen()

    gui.log(f"[MASTER] En écoute sur 0.0.0.0:{port}")

    while True:
        conn, addr = serv.accept()
        threading.Thread(
            target=handle_connection,
            args=(gui, conn, addr),
            daemon=True
        ).start()


def handle_connection(gui, conn, addr):
    try:
        pkt = recv_packet(conn)
        if not pkt:
            return

        # Demande routeurs
        if pkt == "ROUTER_INFO_REQUEST":
            routers = get_routers()
            parts = []

            for rid, host, port, pub in routers:
                n, e = pub.split(",")
                parts.append(f"{rid},{host},{port},{n},{e}")

            send_packet(conn, "ROUTER_INFO|" + ";".join(parts))
            gui.log("[MASTER] Client a demandé la liste des routeurs.")

        # Enregistrement routeur
        elif pkt.startswith("REGISTER|"):
            _, rid, h, p, n, e = pkt.split("|")
            from database.onion_bdd import add_router
            add_router(rid, h, int(p), f"{n},{e}")
            gui.log(f"[MASTER] Routeur {rid} enregistré.")

    finally:
        conn.close()


# ======================================================
# INTERFACE GRAPHIQUE MASTER
# ======================================================
class MasterGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("MASTER SAE 3.02")

        self.setStyleSheet("""
            QWidget { background-color: #2B2D31; color: #DCDDDE; font-size: 14px; }
            QPushButton {
                background-color: #5865F2;
                color: white;
                padding: 6px;
                border-radius: 6px;
            }
            QListWidget, QTextEdit {
                background-color: #1E1F22;
                border: 1px solid #111;
            }
        """)

        root = QWidget()
        grid = QGridLayout(root)
        self.setCentralWidget(root)

        # --- Bouton démarrage ---
        self.btn_start = QPushButton("Démarrer le Master")
        self.btn_start.clicked.connect(self.start_master)
        grid.addWidget(self.btn_start, 0, 0, 1, 2)

        # --- Liste routeurs ---
        grid.addWidget(QLabel("Routeurs enregistrés"), 1, 0)
        self.router_list = QListWidget()
        grid.addWidget(self.router_list, 2, 0)

        # --- Logs ---
        grid.addWidget(QLabel("Logs"), 1, 1)
        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        grid.addWidget(self.logs, 2, 1)

        self.running = False

        # Rafraîchissement auto
        threading.Thread(target=self.refresh_loop, daemon=True).start()

    # --------------------------------------------------
    def log(self, txt):
        self.logs.append(txt)

    # --------------------------------------------------
    def start_master(self):
        if self.running:
            return

        threading.Thread(
            target=master_server,
            args=(self,),
            daemon=True
        ).start()

        self.running = True
        self.log("[GUI] Master démarré.")

    # --------------------------------------------------
    def refresh_loop(self):
        while True:
            time.sleep(2)
            self.refresh_routers()

    def refresh_routers(self):
        self.router_list.clear()
        routers = get_routers()

        for r in routers:
            name, ip, port, _ = r
            self.router_list.addItem(f"{name}  {ip}:{port}")


# ======================================================
# MAIN
# ======================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MasterGUI()
    win.show()
    sys.exit(app.exec())
