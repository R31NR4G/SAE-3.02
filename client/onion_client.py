import socket
import threading
import sys
import random
import os
from pathlib import Path

from crypto.onion_rsa import encrypt_str

CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")


# -----------------------------------------------------
# OUTILS
# -----------------------------------------------------
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


def send_packet(sock, payload):
    data = payload.encode()
    header = str(len(data)).encode() + b"\n"
    sock.sendall(header + data)


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


def looks_like_id(s: str) -> bool:
    if not s or ":" in s or "." in s:
        return False
    return True


# -----------------------------------------------------
# MASTER -> CLIENT
# -----------------------------------------------------
def register_client_dynamic(master_h, master_p, advertise_host, listen_port):
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, f"REGISTER_CLIENT_DYNAMIC|{advertise_host}|{listen_port}")
        rep = recv_packet(s)
        s.close()
        if rep and rep.startswith("ASSIGNED_CLIENT|"):
            return rep.split("|", 1)[1].strip().upper()
        return None
    except:
        return None


def resolve_client_via_master(master_h, master_p, dest_id):
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, f"CLIENT_INFO_REQUEST|{dest_id}")
        rep = recv_packet(s)
        s.close()
        if rep and rep.startswith("CLIENT_INFO|OK|"):
            _, _, h, p = rep.split("|")
            return h, int(p)
        return None
    except:
        return None


def get_routers(master_h, master_p):
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
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


# -----------------------------------------------------
# CLIENT PRINCIPAL
# -----------------------------------------------------
def main():
    # MASTER par défaut depuis noeuds.txt
    master_h, master_p = load_node("MASTER")

    # Surcharge via variables d’environnement (portable SAE)
    env_h = os.getenv("MASTER_HOST")
    env_p = os.getenv("MASTER_PORT")
    if env_h:
        master_h = env_h
    if env_p:
        master_p = int(env_p)

    cid = None
    listen_host = "0.0.0.0"
    listen_port = 0
    advertise_host = "127.0.0.1"

    if len(sys.argv) >= 2 and looks_like_id(sys.argv[1]):
        cid = sys.argv[1].upper()
        c_host, c_port = load_node(cid)
        listen_host, listen_port = c_host, c_port
        advertise_host = c_host if c_host != "0.0.0.0" else "127.0.0.1"
    else:
        if len(sys.argv) >= 2:
            listen_host = sys.argv[1]
        if len(sys.argv) >= 3:
            listen_port = int(sys.argv[2])
        if len(sys.argv) >= 4:
            advertise_host = sys.argv[3]

    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind((listen_host, listen_port))
    serv.listen()

    real_host, real_port = serv.getsockname()
    my_id_ref = [cid]

    threading.Thread(
        target=lambda: None,
        daemon=True
    ).start()

    if cid is None:
        assigned = register_client_dynamic(master_h, master_p, advertise_host, real_port)
        cid = assigned if assigned else "C?"
        my_id_ref[0] = cid
        print(f"[CLIENT {cid}] En écoute sur {listen_host}:{real_port}")
    else:
        print(f"[CLIENT {cid}] En écoute sur {listen_host}:{real_port}")

    while True:
        line = input("> ").strip()
        if not line or ":" not in line:
            continue

        dest, message = line.split(":", 1)
        dest = dest.strip().upper()
        message = message.strip()

        try:
            d_host, d_port = load_node(dest)
        except:
            resolved = resolve_client_via_master(master_h, master_p, dest)
            if not resolved:
                print("Destination inconnue.")
                continue
            d_host, d_port = resolved

        routers = get_routers(master_h, master_p)
        if len(routers) < 3:
            print("Pas assez de routeurs.")
            continue

        path = random.sample(routers, 3)

        plain = f"{d_host}|{d_port}|{cid}|{message}"
        cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))

        for i in range(1, -1, -1):
            nh, np = path[i + 1][1], path[i + 1][2]
            layer = f"{nh}|{np}|{cipher}"
            cipher = encrypt_str(layer, (path[i][3], path[i][4]))

        entry = path[0]
        try:
            s = socket.socket()
            s.connect((entry[1], entry[2]))
            send_packet(s, "ONION|" + cipher)
            s.close()
            print("[CLIENT] Message envoyé.")
        except Exception as e:
            print("Erreur d'envoi :", e)


if __name__ == "__main__":
    main()
