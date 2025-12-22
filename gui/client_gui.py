# gui/client_gui.py
import sys
import socket
import threading
import random

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QGridLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QSpinBox
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal

from client.onion_tools import send_packet, recv_packet, get_routers
from crypto.onion_rsa import encrypt_str


def detect_local_ip(master_h, master_p):
    s = None
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((master_h, master_p))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        try:
            if s:
                s.close()
        except:
            pass


def register_client(master_h, master_p, advertise_host, real_port):
    s = None
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((master_h, master_p))
        send_packet(s, f"REGISTER_CLIENT_DYNAMIC|{advertise_host}|{real_port}")
        rep = recv_packet(s)

        if not rep:
            return None

        if rep.startswith("CLIENT_REGISTERED|"):
            return rep.split("|")[1]

        parts = rep.split("|")
        if len(parts) >= 2:
            return parts[1]

        return None
    except:
        return None
    finally:
        try:
            if s:
                s.close()
        except:
            pass


def request_client_info(master_h, master_p, dest):
    s = None
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((master_h, master_p))
        send_packet(s, f"CLIENT_INFO_REQUEST|{dest}")
        rep = recv_packet(s)

        if not rep or not rep.startswith("CLIENT_INFO|OK|"):
            return None

        _, _, d_ip, d_port = rep.split("|")
        return d_ip, int(d_port)
    except:
        return None
    finally:
        try:
            if s:
                s.close()
        except:
            pass


def build_onion(d_ip, d_port, cid, msg, path):
    plain = f"{d_ip}|{d_port}|{cid}|{msg}"
    cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))
    for i in range(len(path) - 2, -1, -1):
        nh, np = path[i + 1][1], path[i + 1][2]
        cipher = encrypt_str(f"{nh}|{np}|{cipher}", (path[i][3], path[i][4]))
    return cipher


def send_onion(entry_host, entry_port, onion_cipher):
    s = None
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((entry_host, entry_port))
        send_packet(s, "ONION|" + onion_cipher)
        return True
    except:
        return False
    finally:
        try:
            if s:
                s.close()
        except:
            pass


class Signals(QObject):
    received = pyqtSignal(str)
    status = pyqtSignal(str)


class ClientGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Client SAE 3.02")

        self.sig = Signals()
        self.sig.received.connect(self._append_received)
        self.sig.status.connect(self._append_status)

        root = QWidget()
        grid = QGridLayout(root)
        self.setCentralWidget(root)

        grid.addWidget(QLabel("IP Master"), 0, 0)
        self.master_ip = QLineEdit("127.0.0.1")
        grid.addWidget(self.master_ip, 0, 1)

        grid.addWidget(QLabel("Port Master"), 1, 0)
        self.master_port = QLineEdit("5000")
        grid.addWidget(self.master_port, 1, 1)

        grid.addWidget(QLabel("Client ID"), 2, 0)
        self.cid = QLineEdit()
        self.cid.setReadOnly(True)
        grid.addWidget(self.cid, 2, 1)

        grid.addWidget(QLabel("Nb routeurs"), 0, 2)
        self.nb = QSpinBox()
        self.nb.setMinimum(3)
        self.nb.setValue(3)
        grid.addWidget(self.nb, 0, 3)

        grid.addWidget(QLabel("Dest (ex: C1)"), 1, 2)
        self.dest = QLineEdit()
        grid.addWidget(self.dest, 1, 3)

        grid.addWidget(QLabel("Message"), 3, 0, 1, 4)
        self.msg = QTextEdit()
        grid.addWidget(self.msg, 4, 0, 1, 4)

        self.btn = QPushButton("Envoyer")
        self.btn.clicked.connect(self.send_message)
        grid.addWidget(self.btn, 5, 0, 1, 4, alignment=Qt.AlignCenter)

        grid.addWidget(QLabel("Reçus / Statut"), 6, 0, 1, 4)
        self.received = QTextEdit()
        self.received.setReadOnly(True)
        grid.addWidget(self.received, 7, 0, 1, 4)

        self.started = False
        self.serv = None

    def _append_received(self, text):
        self.received.append(text)

    def _append_status(self, text):
        self.received.append(f"[INFO] {text}")

    def start_client(self):
        if self.started:
            return True

        master_h = self.master_ip.text().strip()
        master_p = int(self.master_port.text().strip())

        serv = socket.socket()
        serv.bind(("0.0.0.0", 0))
        serv.listen()
        self.serv = serv

        real_port = serv.getsockname()[1]
        advertise_host = detect_local_ip(master_h, master_p)

        cid = register_client(master_h, master_p, advertise_host, real_port)
        if not cid:
            self.sig.status.emit("Impossible de s'enregistrer au master.")
            return False

        self.cid.setText(cid)
        self.sig.status.emit(f"En écoute sur {advertise_host}:{real_port}")

        threading.Thread(target=self._listen_loop, args=(serv,), daemon=True).start()
        self.started = True
        return True

    def _listen_loop(self, serv):
        while True:
            conn = None
            try:
                conn, _ = serv.accept()
                pkt = recv_packet(conn)
                if pkt and pkt.startswith("DELIVER|"):
                    _, frm, msg = pkt.split("|", 2)
                    self.sig.received.emit(f"[{frm}] {msg}")
            except:
                pass
            finally:
                try:
                    if conn:
                        conn.close()
                except:
                    pass

    def send_message(self):
        if not self.start_client():
            return

        master_h = self.master_ip.text().strip()
        master_p = int(self.master_port.text().strip())

        dest = self.dest.text().strip().upper()
        msg = self.msg.toPlainText().strip()
        if not dest or not msg:
            return

        routers = get_routers(master_h, master_p)
        if len(routers) < 3:
            self.sig.status.emit("Pas assez de routeurs.")
            return

        nb = self.nb.value()
        if nb > len(routers):
            nb = len(routers)

        info = request_client_info(master_h, master_p, dest)
        if not info:
            self.sig.status.emit("Destination inconnue.")
            return

        d_ip, d_port = info
        cid = self.cid.text().strip()

        path = random.sample(routers, nb)
        onion = build_onion(d_ip, d_port, cid, msg, path)

        entry = path[0]
        ok = send_onion(entry[1], entry[2], onion)
        self.sig.status.emit("Message envoyé." if ok else "Erreur d'envoi (routeur d'entrée).")
        if ok:
            self.msg.clear()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ClientGUI()
    win.show()
    sys.exit(app.exec())
