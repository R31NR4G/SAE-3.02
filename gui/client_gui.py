import sys
import socket
import threading
import random

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QGridLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QSpinBox, QListWidget
)
from PyQt5.QtCore import Qt

from crypto.onion_rsa import encrypt_str
from client.onion_tools import send_packet, recv_packet, get_routers


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


class ClientGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Client SAE 3.02 — Mode Graphique")

        self.setStyleSheet("""
            QWidget { background-color: #2B2D31; color: #DCDDDE; font-size: 14px; }
            QLineEdit, QTextEdit, QSpinBox, QListWidget {
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

        # Destinataire tapable
        grid.addWidget(QLabel("Destinataire :"), 1, 2)
        self.dest = QLineEdit()
        self.dest.setPlaceholderText("Ex: C1, C2, A, B ...")
        grid.addWidget(self.dest, 1, 3)

        # liste clients (optionnel)
        grid.addWidget(QLabel("Clients connus :"), 2, 2)
        self.client_list = QListWidget()
        self.client_list.setMaximumHeight(70)
        grid.addWidget(self.client_list, 2, 3)

        self.btn_refresh = QPushButton("Rafraîchir clients")
        self.btn_refresh.clicked.connect(self.refresh_clients)
        grid.addWidget(self.btn_refresh, 3, 2, 1, 2)

        # -------- Message --------
        grid.addWidget(QLabel("Message :"), 4, 0, 1, 4)
        self.msg = QTextEdit()
        grid.addWidget(self.msg, 5, 0, 1, 4)

        # -------- Bouton --------
        self.btn = QPushButton("ENVOYER")
        self.btn.clicked.connect(self.send_message)
        grid.addWidget(self.btn, 6, 0, 1, 4, alignment=Qt.AlignCenter)

        # -------- Réception --------
        grid.addWidget(QLabel("Messages reçus :"), 7, 0, 1, 4)
        self.received = QTextEdit()
        self.received.setReadOnly(True)
        grid.addWidget(self.received, 8, 0, 1, 4)

        # -------- Logs --------
        grid.addWidget(QLabel("Logs :"), 9, 0, 1, 4)
        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        grid.addWidget(self.logs, 10, 0, 1, 4)

        self.server_socket = None
        self.started = False

    def log(self, txt):
        self.logs.append(txt)

    def show_received(self, frm, msg):
        self.received.append(f"[{frm}] {msg}")

    def start_client(self):
        if self.started:
            return

        mip = self.master_ip.text().strip()
        mport = int(self.master_port.text().strip())

        serv = socket.socket()
        serv.bind(("0.0.0.0", 0))
        serv.listen()
        self.server_socket = serv

        real_port = serv.getsockname()[1]
        advertise_host = detect_local_ip(mip, mport)

        # register client
        cid = "C?"
        try:
            s = socket.socket()
            s.connect((mip, mport))
            send_packet(s, f"REGISTER_CLIENT_DYNAMIC|{advertise_host}|{real_port}")
            rep = recv_packet(s)
            s.close()
            if rep and rep.startswith("ASSIGNED_CLIENT|"):
                cid = rep.split("|", 1)[1].strip()
        except Exception as e:
            self.log(f"Impossible de joindre le master: {e}")

        self.cid.setText(cid)
        self.log(f"[CLIENT {cid}] En écoute sur {advertise_host}:{real_port}")

        threading.Thread(target=listen_thread, args=(self, serv), daemon=True).start()

        self.started = True
        self.refresh_clients()

    def refresh_clients(self):
        mip = self.master_ip.text().strip()
        mport = int(self.master_port.text().strip())

        self.client_list.clear()
        try:
            s = socket.socket()
            s.connect((mip, mport))
            send_packet(s, "CLIENT_LIST_REQUEST")
            rep = recv_packet(s)
            s.close()
        except:
            self.log("Impossible de récupérer la liste des clients.")
            return

        if rep and rep.startswith("CLIENT_LIST|"):
            ids = [x for x in rep.split("|", 1)[1].split(";") if x]
            for cid in ids:
                self.client_list.addItem(cid)

    def send_message(self):
        self.start_client()

        msg = self.msg.toPlainText().strip()
        if not msg:
            self.log("Message vide.")
            return

        dest = self.dest.text().strip().upper()
        if not dest:
            self.log("Destinataire vide.")
            return

        mip = self.master_ip.text().strip()
        mport = int(self.master_port.text().strip())

        routers = get_routers(mip, mport)
        if len(routers) < 3:
            self.log("Pas assez de routeurs.")
            return

        nb = self.nb.value()
        if nb > len(routers):
            self.log("Trop de routeurs demandés.")
            return

        # résolution destination
        try:
            s = socket.socket()
            s.connect((mip, mport))
            send_packet(s, f"CLIENT_INFO_REQUEST|{dest}")
            rep = recv_packet(s)
            s.close()
        except:
            self.log("Master injoignable pour résoudre la destination.")
            return

        if not rep or not rep.startswith("CLIENT_INFO|OK|"):
            self.log(f"Destination inconnue : {dest}")
            return

        _, _, d_ip, d_port = rep.split("|")
        cid = self.cid.text().strip()

        path = random.sample(routers, nb)
        self.log("Chemin : " + " → ".join([r[0] for r in path]))

        plain = f"{d_ip}|{d_port}|{cid}|{msg}"
        cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))

        for i in range(nb - 2, -1, -1):
            nh, np = path[i + 1][1], path[i + 1][2]
            cipher = encrypt_str(f"{nh}|{np}|{cipher}", (path[i][3], path[i][4]))

        entry = path[0]
        try:
            s = socket.socket()
            s.connect((entry[1], entry[2]))
            send_packet(s, "ONION|" + cipher)
            s.close()
            self.log("Message envoyé ✔")
            self.msg.clear()
        except Exception as e:
            self.log(f"Envoi impossible : {e}")

    # Désenregistrement propre quand tu fermes la fenêtre
    def closeEvent(self, event):
        try:
            cid = self.cid.text().strip().upper()
            mip = self.master_ip.text().strip()
            mport = int(self.master_port.text().strip())

            if cid and cid != "C?":
                s = socket.socket()
                s.connect((mip, mport))
                send_packet(s, f"UNREGISTER_CLIENT|{cid}")
                recv_packet(s)
                s.close()
        except:
            pass

        try:
            if self.server_socket:
                self.server_socket.close()
        except:
            pass

        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ClientGUI()
    win.show()
    sys.exit(app.exec())
