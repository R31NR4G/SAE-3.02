import sys
import socket
import threading
import random

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QGridLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QComboBox, QSpinBox
)
from PyQt5.QtCore import Qt

from crypto.onion_rsa import encrypt_str
from client.onion_tools import send_packet, recv_packet, load_node, get_routers


# ============================================================
# THREAD DE RÉCEPTION (identique à ton client actuel)
# ============================================================
def listen_thread(gui, cid, host, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen()

    gui.log(f"[CLIENT {cid}] En écoute sur {host}:{port}")

    while True:
        conn, addr = s.accept()
        pkt = recv_packet(conn)
        conn.close()

        if pkt and pkt.startswith("DELIVER|"):
            _, frm, msg = pkt.split("|", 2)
            gui.show_received(frm, msg)


# ============================================================
#      INTERFACE GRAPHIQUE SIMPLE + DARK MODE
# ============================================================
class ClientGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Client SAE 3.02 — Mode Graphique")

        # ---- DARK MODE SIMPLIFIÉ ----
        self.setStyleSheet("""
            QWidget { background-color: #2B2D31; color: #DCDDDE; font-size: 14px; }
            QLineEdit, QTextEdit, QComboBox, QSpinBox {
                background-color: #1E1F22;
                border: 1px solid #111;
                border-radius: 4px;
                padding: 4px;
            }
            QPushButton {
                background-color: #5865F2;
                color: white;
                padding: 8px;
                border-radius: 6px;
            }
            QPushButton:hover { background-color: #4752C4; }
        """)

        root = QWidget()
        grid = QGridLayout(root)
        self.setCentralWidget(root)

        # ============================================================
        #   COLONNE 1 — Infos client
        # ============================================================
        grid.addWidget(QLabel("Client ID :"), 0, 0)
        self.cid = QLineEdit("A")
        grid.addWidget(self.cid, 0, 1)

        grid.addWidget(QLabel("IP Client :"), 1, 0)
        self.ip = QLineEdit("127.0.0.1")
        grid.addWidget(self.ip, 1, 1)

        grid.addWidget(QLabel("Port Client :"), 2, 0)
        self.port = QLineEdit("7001")
        grid.addWidget(self.port, 2, 1)

        # ============================================================
        #   COLONNE 2 — Infos master
        # ============================================================
        grid.addWidget(QLabel("IP Master :"), 0, 2)
        self.master_ip = QLineEdit("127.0.0.1")
        grid.addWidget(self.master_ip, 0, 3)

        grid.addWidget(QLabel("Port Master :"), 1, 2)
        self.master_port = QLineEdit("5000")
        grid.addWidget(self.master_port, 1, 3)

        # ============================================================
        #   ROUTAGE & DESTINATION
        # ============================================================
        grid.addWidget(QLabel("Nb routeurs :"), 2, 2)
        self.nb = QSpinBox()
        self.nb.setMinimum(3)
        self.nb.setValue(3)
        grid.addWidget(self.nb, 2, 3)

        grid.addWidget(QLabel("Destinataire :"), 3, 0)
        self.dest = QComboBox()
        self.dest.addItems(["A", "B", "C"])
        grid.addWidget(self.dest, 3, 1)

        # ============================================================
        #   MESSAGE
        # ============================================================
        grid.addWidget(QLabel("Message :"), 4, 0, 1, 4)
        self.msg = QTextEdit()
        grid.addWidget(self.msg, 5, 0, 1, 4)

        # ============================================================
        #   BOUTON ENVOYER
        # ============================================================
        self.btn = QPushButton("ENVOYER")
        self.btn.clicked.connect(self.send_message)
        grid.addWidget(self.btn, 6, 0, 1, 4, alignment=Qt.AlignCenter)

        # ============================================================
        #   MESSAGES REÇUS
        # ============================================================
        grid.addWidget(QLabel("Messages reçus :"), 7, 0, 1, 4)
        self.received = QTextEdit()
        self.received.setReadOnly(True)
        grid.addWidget(self.received, 8, 0, 1, 4)

        # ============================================================
        #   LOGS
        # ============================================================
        grid.addWidget(QLabel("Logs :"), 9, 0, 1, 4)
        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        grid.addWidget(self.logs, 10, 0, 1, 4)

        self.started = False

    # ============================================================
    #   OUTILS AFFICHAGE
    # ============================================================
    def log(self, txt):
        self.logs.append(txt)

    def show_received(self, frm, msg):
        self.received.append(f"[{frm}] {msg}")

    # ============================================================
    #   THREAD ÉCOUTE
    # ============================================================
    def start_client(self):
        if self.started:
            return

        cid = self.cid.text().upper()
        host = self.ip.text()
        port = int(self.port.text())

        threading.Thread(
            target=listen_thread,
            args=(self, cid, host, port),
            daemon=True
        ).start()

        self.log("Client démarré.")
        self.started = True

    # ============================================================
    #   ENVOI MESSAGE (Ton code existant)
    # ============================================================
    def send_message(self):
        self.start_client()

        cid = self.cid.text().upper()
        mip = self.master_ip.text()
        mport = int(self.master_port.text())

        dest = self.dest.currentText().upper()
        msg = self.msg.toPlainText().strip()

        if not msg:
            return

        # ---- trouver l'IP du destinataire ----
        d_ip, d_port = load_node(dest)

        # ---- récupérer les routeurs ----
        routers = get_routers(mip, mport)
        if len(routers) < 3:
            self.log("[ERREUR] Pas assez de routeurs.")
            return

        nb = self.nb.value()
        path = random.sample(routers, nb)

        self.log("Chemin choisi : " + " → ".join([r[0] for r in path]))

        # ---- couche finale ----
        plain = f"{d_ip}|{d_port}|{cid}|{msg}"
        cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))

        # ---- couches intermédiaires ----
        for i in range(nb - 2, -1, -1):
            nh, np = path[i+1][1], path[i+1][2]
            layer = f"{nh}|{np}|{cipher}"
            cipher = encrypt_str(layer, (path[i][3], path[i][4]))

        entry = path[0]

        # ---- envoi ----
        try:
            s = socket.socket()
            s.connect((entry[1], entry[2]))
            send_packet(s, "ONION|" + cipher)
            s.close()

            self.log("Message envoyé ✔")
            self.msg.clear()

        except Exception as e:
            self.log("Erreur envoi : " + str(e))


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ClientGUI()
    win.show()
    sys.exit(app.exec())
