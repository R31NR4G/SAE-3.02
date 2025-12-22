# gui/master_gui.py
import sys
import socket
import threading

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QGridLayout, QLabel, QPushButton, QTextEdit, QLineEdit
)
from PyQt5.QtCore import QObject, pyqtSignal

from client.onion_tools import send_packet, recv_packet


class Signals(QObject):
    log = pyqtSignal(str)


class Master(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Master SAE 3.02")

        self.sig = Signals()
        self.sig.log.connect(self.log)

        self.clients = {}
        self.routers = {}
        self.cpt_c = 0
        self.cpt_r = 0

        root = QWidget()
        grid = QGridLayout(root)
        self.setCentralWidget(root)

        grid.addWidget(QLabel("Host"), 0, 0)
        self.host = QLineEdit("0.0.0.0")
        grid.addWidget(self.host, 0, 1)

        grid.addWidget(QLabel("Port"), 0, 2)
        self.port = QLineEdit("5000")
        grid.addWidget(self.port, 0, 3)

        btn = QPushButton("Démarrer")
        btn.clicked.connect(self.start)
        grid.addWidget(btn, 0, 4)

        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        grid.addWidget(self.logs, 1, 0, 1, 5)

    def log(self, txt):
        self.logs.append(txt)

    def start(self):
        t = threading.Thread(target=self.server, daemon=True)
        t.start()
        self.log("Master démarré.")

    def server(self):
        s = socket.socket()
        s.bind((self.host.text(), int(self.port.text())))
        s.listen()

        while True:
            conn, _ = s.accept()
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        pkt = recv_packet(conn)
        if not pkt:
            conn.close()
            return

        if pkt.startswith("REGISTER_CLIENT_DYNAMIC|"):
            _, ip, port = pkt.split("|")
            self.cpt_c += 1
            cid = f"C{self.cpt_c}"
            self.clients[cid] = (ip, port)
            send_packet(conn, f"CLIENT_REGISTERED|{cid}")
            self.sig.log.emit(f"Client {cid} enregistré")

        elif pkt.startswith("CLIENT_INFO_REQUEST|"):
            dest = pkt.split("|")[1]
            if dest in self.clients:
                ip, port = self.clients[dest]
                send_packet(conn, f"CLIENT_INFO|OK|{ip}|{port}")
            else:
                send_packet(conn, "CLIENT_INFO|ERR")

        elif pkt == "ROUTER_INFO_REQUEST":
            items = []
            for rid, (ip, port, n, e) in self.routers.items():
                items.append(f"{rid},{ip},{port},{n},{e}")
            send_packet(conn, "ROUTER_INFO|" + ";".join(items))

        conn.close()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = Master()
    w.show()
    sys.exit(app.exec())
