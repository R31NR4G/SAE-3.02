# gui/master_gui.py
import sys
import socket
import threading
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QGridLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit
)
from PyQt5.QtCore import QObject, pyqtSignal

from client.onion_tools import send_packet, recv_packet


# ======================================================
# Chargement noeuds.txt (si tu veux utiliser des IDs)
# ======================================================
CONFIG = Path(__file__).parents[1] / "config" / "noeuds.txt"


def load_node(node_id):
    """Lit config/noeuds.txt au format: ID;HOST;PORT"""
    with CONFIG.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            nid, host, port = line.split(";")
            if nid.upper() == node_id.upper():
                return host, int(port)
    raise RuntimeError(f"Noeud {node_id} introuvable.")


# ======================================================
# Master serveur (compatible client)
# ======================================================
class MasterState:
    def __init__(self):
        self.lock = threading.Lock()
        self.client_counter = 0
        self.router_counter = 0
        self.clients = {}   # CID -> (ip, port)
        self.routers = {}   # RID -> (ip, port, n, e)


class Signals(QObject):
    log = pyqtSignal(str)
    refresh = pyqtSignal()


class MasterServer:
    def __init__(self, host, port, signals: Signals, state: MasterState):
        self.host = host
        self.port = port
        self.sig = signals
        self.state = state

        self._sock = None
        self._running = False

    def start(self):
        if self._running:
            return

        self._running = True
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def stop(self):
        self._running = False
        try:
            if self._sock:
                self._sock.close()
        except:
            pass

    def _run(self):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen()
        self._sock = s

        self.sig.log.emit(f"[MASTER] Écoute sur {self.host}:{self.port}")

        while self._running:
            try:
                conn, addr = s.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
            except:
                # socket fermé / arrêt
                break

        self.sig.log.emit("[MASTER] Arrêt.")

    def _handle_client(self, conn, addr):
        try:
            pkt = recv_packet(conn)
            if not pkt:
                return

            # -------------------------
            # REGISTER_CLIENT_DYNAMIC|ip|port
            # Réponse: CLIENT_REGISTERED|C1
            # -------------------------
            if pkt.startswith("REGISTER_CLIENT_DYNAMIC|"):
                parts = pkt.split("|")
                if len(parts) != 3:
                    send_packet(conn, "ERROR|BAD_REGISTER_CLIENT")
                    return

                ip = parts[1]
                port = int(parts[2])

                with self.state.lock:
                    self.state.client_counter += 1
                    cid = f"C{self.state.client_counter}"
                    self.state.clients[cid] = (ip, port)

                send_packet(conn, f"CLIENT_REGISTERED|{cid}")
                self.sig.log.emit(f"[MASTER] Client enregistré: {cid} -> {ip}:{port}")
                self.sig.refresh.emit()
                return

            # -------------------------
            # CLIENT_INFO_REQUEST|C2
            # Réponse: CLIENT_INFO|OK|ip|port
            # -------------------------
            if pkt.startswith("CLIENT_INFO_REQUEST|"):
                parts = pkt.split("|", 1)
                if len(parts) != 2:
                    send_packet(conn, "CLIENT_INFO|ERR|BAD_REQUEST")
                    return

                dest = parts[1].strip().upper()

                with self.state.lock:
                    info = self.state.clients.get(dest)

                if not info:
                    send_packet(conn, "CLIENT_INFO|ERR|UNKNOWN")
                    return

                ip, port = info
                send_packet(conn, f"CLIENT_INFO|OK|{ip}|{port}")
                return

            # -------------------------
            # ROUTER_REGISTER|ip|port|n|e
            # Réponse: ROUTER_REGISTERED|R1
            # (si tes routeurs font autrement, dis-moi le format exact et j’adapte)
            # -------------------------
            if pkt.startswith("ROUTER_REGISTER|"):
                parts = pkt.split("|")
                if len(parts) != 5:
                    send_packet(conn, "ERROR|BAD_REGISTER_ROUTER")
                    return

                ip = parts[1]
                port = int(parts[2])
                n = int(parts[3])
                e = int(parts[4])

                with self.state.lock:
                    self.state.router_counter += 1
                    rid = f"R{self.state.router_counter}"
                    self.state.routers[rid] = (ip, port, n, e)

                send_packet(conn, f"ROUTER_REGISTERED|{rid}")
                self.sig.log.emit(f"[MASTER] Routeur enregistré: {rid} -> {ip}:{port}")
                self.sig.refresh.emit()
                return

            # -------------------------
            # ROUTER_INFO_REQUEST
            # Réponse: ROUTER_INFO|RID,IP,PORT,N,E;RID,IP,PORT,N,E;...
            # -------------------------
            if pkt.strip() == "ROUTER_INFO_REQUEST":
                with self.state.lock:
                    items = []
                    for rid, (ip, port, n, e) in self.state.routers.items():
                        items.append(f"{rid},{ip},{port},{n},{e}")
                send_packet(conn, "ROUTER_INFO|" + ";".join(items))
                return

            # -------------------------
            # Sinon
            # -------------------------
            send_packet(conn, "ERROR|UNKNOWN_CMD")

        except Exception as ex:
            try:
                self.sig.log.emit(f"[MASTER] Erreur: {ex}")
            except:
                pass
        finally:
            try:
                conn.close()
            except:
                pass


# ======================================================
# GUI
# ======================================================
class MasterGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Master SAE 3.02")

        self.state = MasterState()
        self.sig = Signals()
        self.sig.log.connect(self._log)
        self.sig.refresh.connect(self._refresh_lists)

        self.server = None

        root = QWidget()
        grid = QGridLayout(root)
        self.setCentralWidget(root)

        grid.addWidget(QLabel("Host"), 0, 0)
        self.host_in = QLineEdit("0.0.0.0")
        grid.addWidget(self.host_in, 0, 1)

        grid.addWidget(QLabel("Port"), 0, 2)
        self.port_in = QLineEdit("5000")
        grid.addWidget(self.port_in, 0, 3)

        self.btn_start = QPushButton("Démarrer")
        self.btn_start.clicked.connect(self.start_master)
        grid.addWidget(self.btn_start, 0, 4)

        self.btn_stop = QPushButton("Arrêter")
        self.btn
