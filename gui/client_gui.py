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
from client.onion_tools import send_packet, recv_packet, get_routers


# ============================================================
# THREAD DE RÉCEPTION
# ============================================================
def listen_thread(gui, server_socket):
    while True:
        try:
            conn, _ = server_socket.accept()
        except OSError:
            return

        pkt = recv_packet(conn)
        conn.close()

        if pkt and pkt.startswith("DELIVER|"):
            _, frm, msg = pkt.split("|", 2)
            gui.show_received(frm, msg)


def detect_local_ip(master_h, master_p):
    try:
        tmp = socket.socket()
        tmp.connect((master_h, master_p))
        ip = tmp.getsockname()[0]
        tmp.close()
        return ip
    except:
        return "127.0.0.1"


# ============================================================
# INTERFACE CLIENT GUI
# ============================================================
class ClientGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Client SAE 3.02 — Mode Graphique")

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

        # -------- Infos master --------
        grid.addWidget(QLabel("IP Master :"), 0, 0)
        self.master_ip = QLineEdit("127.0.0.1")
        grid.addWidget(self.master_ip, 0, 1)

        grid.addWidget(QLabel("Port Master :"), 1, 0)
        self.master_port = QLineEdit("5000")
        grid.addWidget(self.master_port, 1, 1)

        # -------- Client --------
        grid.addWidget(QLabel("Client ID :"), 2, 0)
        self.cid = QLineEdit()
        self.cid.setReadOnly(True)
        grid.addWidget(self.cid, 2, 1)

        # -------- Routage --------
        grid.addWidget(QLabel("Nb routeurs :"), 0, 2)
        self.nb = QSpinBox()
        self.nb.setMinimum(3)
        self.nb.setValue(3)
        grid.addWidget(self.nb, 0, 3)

        grid.addWidget(QLabel("Destinataire :"), 1, 2)
        self.dest = QComboBox()
        grid.addWidget(self.dest, 1, 3)

        # -------- Message --------
        grid.addWidget(QLabel("Message :"), 3, 0, 1, 4)
        self.msg = QTextEdit()
        grid.addWidget(self.msg, 4, 0, 1, 4)

        # -------- Bouton --------
        self.btn = QPushButton("ENVOYER")
        self.btn.clicked.connect(self.send_message)
        grid.addWidget(self.btn, 5, 0, 1, 4, alignment=Qt.AlignCenter)

        # -------- Réception --------
        grid.addWidget(QLabel("Messages reçus :"), 6, 0, 1, 4)
        self.received = QTextEdit()
        self.received.setReadOnly(True)
        grid.addWidget(self.received, 7, 0, 1, 4)

        # -------- Logs --------
        grid.addWidget(QLabel("Logs :"), 8, 0, 1, 4)
        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        grid.addWidget(self.logs, 9, 0, 1, 4)

        self.server_socket = None
        self.started = False

    # --------------------------------------------------
    def log(self, txt):
        self.logs.append(txt)

    def show_received(self, frm, msg):
        self.received.append(f"[{frm}] {msg}")

    # --------------------------------------------------
    def start_client(self):
        if self.started:
            return

        mip = self.master_ip.text()
        mport = int(self.master_port.text())

        serv = socket.socket()
        serv.bind(("0.0.0.0", 0))
        serv.listen()
        self.server_socket = serv

        real_port = serv.getsockname()[1]
        advertise_host = detect_local_ip(mip, mport)

        # register client
        s = socket.socket()
        s.connect((mip, mport))
        send_packet(s, f"REGISTER_CLIENT_DYNAMIC|{advertise_host}|{real_port}")
        rep = recv_packet(s)
        s.close()

        cid = "C?"
        if rep and rep.startswith("ASSIGNED_CLIENT|"):
            cid = rep.split("|", 1)[1]

        self.cid.setText(cid)
        self.log(f"[CLIENT {cid}] En écoute sur {advertise_host}:{real_port}")

        threading.Thread(
            target=listen_thread,
            args=(self, serv),
            daemon=True
        ).start()

        self.refresh_destinations()
        self.started = True

    # --------------------------------------------------
    def refresh_destinations(self):
        mip = self.master_ip.text()
        mport = int(self.master_port.text())

        s = socket.socket()
        s.connect((mip, mport))
        send_packet(s, "CLIENT_LIST_REQUEST")
        rep = recv_packet(s)
        s.close()

        self.dest.clear()
        if rep and rep.startswith("CLIENT_LIST|"):
            ids = rep.split("|", 1)[1].split(";")
            self.dest.addItems(ids)

    # --------------------------------------------------
    def send_message(self):
        self.start_client()

        msg = self.msg.toPlainText().strip()
        if not msg:
            self.log("⚠️ Message vide.")
            return

        mip = self.master_ip.text()
        mport = int(self.master_port.text())

        dest = self.dest.currentText()
        routers = get_routers(mip, mport)

        if len(routers) < 3:
            self.log("❌ Pas assez de routeurs.")
            return

        nb = self.nb.value()
        if nb > len(routers):
            self.log("❌ Trop de routeurs demandés.")
            return

        path = random.sample(routers, nb)
        self.log("Chemin : " + " → ".join([r[0] for r in path]))

        # destination
        s = socket.socket()
        s.connect((mip, mport))
        send_packet(s, f"CLIENT_INFO_REQUEST|{dest}")
        rep = recv_packet(s)
        s.close()

        if not rep or not rep.startswith("CLIENT_INFO|OK|"):
            self.log(f"❌ Destination inconnue : {dest}")
            return

        _, _, d_ip, d_port = rep.split("|")

        cid = self.cid.text()

        plain = f"{d_ip}|{d_port}|{cid}|{msg}"
        cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))

        for i in range(nb - 2, -1, -1):
            nh, np = path[i + 1][1], path[i + 1][2]
            cipher = encrypt_str(f"{nh}|{np}|{cipher}", (path[i][3], path[i][4]))

        entry = path[0]
        s = socket.socket()
        s.connect((entry[1], entry[2]))
        send_packet(s, "ONION|" + cipher)
        s.close()

        self.log("Message envoyé ✔")
        self.msg.clear()


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ClientGUI()
    win.show()
    sys.exit(app.exec())
