import sys
import socket
import threading
import random

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QGridLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QSpinBox
)
from PyQt5.QtCore import Qt

from crypto.onion_rsa import encrypt_str
from client.onion_tools import send_packet, recv_packet, get_routers


def detect_local_ip(master_h, master_p):
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def listen_thread(gui, serv):
    while True:
        conn, _ = serv.accept()
        pkt = recv_packet(conn)
        conn.close()

        if pkt and pkt.startswith("DELIVER|"):
            _, frm, msg = pkt.split("|", 2)
            gui.received.append(f"[{frm}] {msg}")


class ClientGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Client SAE 3.02")

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

        grid.addWidget(QLabel("Destinataire (ex: C1)"), 1, 2)
        self.dest = QLineEdit()
        grid.addWidget(self.dest, 1, 3)

        grid.addWidget(QLabel("Message"), 3, 0, 1, 4)
        self.msg = QTextEdit()
        grid.addWidget(self.msg, 4, 0, 1, 4)

        self.btn = QPushButton("Envoyer")
        self.btn.clicked.connect(self.send_message)
        grid.addWidget(self.btn, 5, 0, 1, 4, alignment=Qt.AlignCenter)

        grid.addWidget(QLabel("Messages reçus"), 6, 0, 1, 4)
        self.received = QTextEdit()
        self.received.setReadOnly(True)
        grid.addWidget(self.received, 7, 0, 1, 4)

        self.started = False
        self.serv = None

    def start_client(self):
        if self.started:
            return

        master_h = self.master_ip.text()
        master_p = int(self.master_port.text())

        serv = socket.socket()
        serv.bind(("0.0.0.0", 0))
        serv.listen()
        self.serv = serv

        real_port = serv.getsockname()[1]
        advertise_host = detect_local_ip(master_h, master_p)

        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, f"REGISTER_CLIENT_DYNAMIC|{advertise_host}|{real_port}")
        rep = recv_packet(s)
        s.close()

        cid = rep.split("|")[1] if rep else "C?"
        self.cid.setText(cid)

        threading.Thread(
            target=listen_thread,
            args=(self, serv),
            daemon=True
        ).start()

        self.started = True

    def send_message(self):
        self.start_client()

        master_h = self.master_ip.text()
        master_p = int(self.master_port.text())

        dest = self.dest.text().strip().upper()
        msg = self.msg.toPlainText().strip()

        if not dest or not msg:
            return

        routers = get_routers(master_h, master_p)
        if len(routers) < 3:
            return

        nb = self.nb.value()
        if nb > len(routers):
            nb = len(routers)

        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, f"CLIENT_INFO_REQUEST|{dest}")
        rep = recv_packet(s)
        s.close()

        if not rep or not rep.startswith("CLIENT_INFO|OK|"):
            self.received.append("Destination inconnue.")
            return

        _, _, d_ip, d_port = rep.split("|")

        cid = self.cid.text()
        path = random.sample(routers, nb)

        plain = f"{d_ip}|{d_port}|{cid}|{msg}"
        cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))

        for i in range(len(path) - 2, -1, -1):
            nh, np = path[i + 1][1], path[i + 1][2]
            cipher = encrypt_str(
                f"{nh}|{np}|{cipher}",
                (path[i][3], path[i][4])
            )

        entry = path[0]
        s = socket.socket()
        s.connect((entry[1], entry[2]))
        send_packet(s, "ONION|" + cipher)
        s.close()

        self.msg.clear()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ClientGUI()
    win.show()
    sys.exit(app.exec())
