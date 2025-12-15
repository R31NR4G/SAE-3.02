# ======================================================
# Outils communs client (console + GUI)
# ======================================================

import socket
from pathlib import Path

# Chemin vers noeuds.txt (comme dans ton client)
CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")


# ------------------------------------------------------
# Charger un noeud depuis noeuds.txt
# ------------------------------------------------------
def load_node(node_id):
    with CONFIG.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            nid, host, port = line.split(";")
            if nid.upper() == node_id.upper():
                return host, int(port)
    raise RuntimeError(f"Noeud {node_id} introuvable.")


# ------------------------------------------------------
# Envoi paquet ASCII length + \n + payload
# ------------------------------------------------------
def send_packet(sock, payload):
    data = payload.encode()
    header = str(len(data)).encode() + b"\n"
    sock.sendall(header + data)


# ------------------------------------------------------
# Réception paquet ASCII length
# ------------------------------------------------------
def recv_packet(sock):
    size_bytes = b""
    while not size_bytes.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            return None
        size_bytes += chunk

    try:
        size = int(size_bytes.strip())
    except:
        return None

    if size <= 0 or size > 20000:
        return None

    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk

    return data.decode(errors="ignore")


# ------------------------------------------------------
# Demande au MASTER la liste des routeurs
# ------------------------------------------------------
def get_routers(master_host, master_port):
    try:
        s = socket.socket()
        s.connect((master_host, master_port))
        send_packet(s, "ROUTER_INFO_REQUEST")
        resp = recv_packet(s)
        s.close()

        if not resp or not resp.startswith("ROUTER_INFO|"):
            return []

        data = resp.split("|", 1)[1]
        routers = []

        for item in data.split(";"):
            if not item:
                continue
            rid, h, p, n, e = item.split(",")
            routers.append((rid, h, int(p), int(n), int(e)))

        return routers

    except:
        return []
