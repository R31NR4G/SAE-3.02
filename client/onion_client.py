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

    size = int(size_bytes.strip())
    data = b""
    while len(data) < size:
        data += sock.recv(size - len(data))
    return data.decode(errors="ignore")


def looks_like_id(s: str) -> bool:
    return s and ":" not in s and "." not in s


# -----------------------------------------------------
# ÉCOUTE DES MESSAGES
# -----------------------------------------------------
def listen_incoming(my_id_ref, server_socket):
    while True:
        conn, _ = server_socket.accept()
        pkt = recv_packet(conn)
        conn.close()

        if pkt and pkt.startswith("DELIVER|"):
            _, fid, msg = pkt.split("|", 2)
            cid = my_id_ref[0] if my_id_ref[0] else "?"
            print(f"\n[CLIENT {cid}] Message de {fid} : {msg}")
            print("> ", end="", flush=True)


# -----------------------------------------------------
# MASTER COMMUNICATION
# -----------------------------------------------------
def register_client_dynamic(master_h, master_p, advertise_host, listen_port):
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, f"REGISTER_CLIENT_DYNAMIC|{advertise_host}|{listen_port}")
        rep = recv_packet(s)
        s.close()
        if rep and rep.startswith("ASSIGNED_CLIENT|"):
            return rep.split("|", 1)[1]
    except:
        pass
    return None


def resolve_client(master_h, master_p, dest_id):
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, f"CLIENT_INFO_REQUEST|{dest_id}")
        rep = recv_packet(s)
        s.close()
        if rep and rep.startswith("CLIENT_INFO|OK|"):
            _, _, h, p = rep.split("|")
            return h, int(p)
    except:
        pass
    return None


def get_routers(master_h, master_p):
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, "ROUTER_INFO_REQUEST")
        resp = recv_packet(s)
        s.close()

        routers = []
        if resp and resp.startswith("ROUTER_INFO|"):
            for item in resp.split("|", 1)[1].split(";"):
                if item:
                    rid, h, p, n, e = item.split(",")
                    routers.append((rid, h, int(p), int(n), int(e)))
        return routers
    except:
        return []


# -----------------------------------------------------
# CLIENT PRINCIPAL
# -----------------------------------------------------
def main():
    master_h, master_p = load_node("MASTER")
    if os.getenv("MASTER_HOST"):
        master_h = os.getenv("MASTER_HOST")
    if os.getenv("MASTER_PORT"):
        master_p = int(os.getenv("MASTER_PORT"))

    cid = None
    listen_host = "0.0.0.0"
    listen_port = 0
    advertise_host = socket.gethostbyname(socket.gethostname())

    if len(sys.argv) >= 2 and looks_like_id(sys.argv[1]):
        cid = sys.argv[1].upper()
        listen_host, listen_port = load_node(cid)

    serv = socket.socket()
    serv.bind((listen_host, listen_port))
    serv.listen()

    _, real_port = serv.getsockname()
    my_id_ref = [cid]

    threading.Thread(
        target=listen_incoming,
        args=(my_id_ref, serv),
        daemon=True
    ).start()

    if cid is None:
        cid = register_client_dynamic(master_h, master_p, advertise_host, real_port) or "C?"
        my_id_ref[0] = cid

    print(f"[CLIENT {cid}] En écoute sur {listen_host}:{real_port}")
    print("Format : DEST: message")

    while True:
        line = input("> ").strip()
        if ":" not in line:
            continue

        dest, msg = line.split(":", 1)
        dest = dest.strip().upper()
        msg = msg.strip()

        try:
            d_host, d_port = load_node(dest)
        except:
            resolved = resolve_client(master_h, master_p, dest)
            if not resolved:
                print("Destination inconnue.")
                continue
            d_host, d_port = resolved

        routers = get_routers(master_h, master_p)
        if len(routers) < 3:
            print("Pas assez de routeurs.")
            continue

        path = random.sample(routers, 3)

        plain = f"{d_host}|{d_port}|{cid}|{msg}"
        cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))

        for i in range(1, -1, -1):
            nh, np = path[i + 1][1], path[i + 1][2]
            cipher = encrypt_str(f"{nh}|{np}|{cipher}", (path[i][3], path[i][4]))

        entry = path[0]
        s = socket.socket()
        s.connect((entry[1], entry[2]))
        send_packet(s, "ONION|" + cipher)
        s.close()
        print("[CLIENT] Message envoyé.")


if __name__ == "__main__":
    main()
