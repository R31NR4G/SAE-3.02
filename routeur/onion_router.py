import socket
import threading
import sys
import os
from pathlib import Path

from crypto.onion_rsa import generate_keypair, decrypt_str

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
    sock.sendall(str(len(data)).encode() + b"\n" + data)


def recv_packet(sock):
    size = int(sock.recv(32).split(b"\n")[0])
    return sock.recv(size).decode(errors="ignore")


# -----------------------------------------------------
# ROUTAGE
# -----------------------------------------------------
def handle_onion(conn, priv, rid):
    pkt = recv_packet(conn)
    conn.close()

    if not pkt.startswith("ONION|"):
        return

    plain = decrypt_str(pkt.split("|", 1)[1], priv)
    parts = plain.split("|")

    if len(parts) == 3:
        h, p, cipher = parts
        forward(h, int(p), cipher)
    elif len(parts) == 4:
        h, p, fid, msg = parts
        deliver(h, int(p), fid, msg)


def forward(host, port, cipher):
    s = socket.socket()
    s.connect((host, port))
    send_packet(s, "ONION|" + cipher)
    s.close()


def deliver(host, port, fid, msg):
    s = socket.socket()
    s.connect((host, port))
    send_packet(s, f"DELIVER|{fid}|{msg}")
    s.close()


# -----------------------------------------------------
# ROUTEUR PRINCIPAL
# -----------------------------------------------------
def main():
    master_h, master_p = load_node("MASTER")
    if os.getenv("MASTER_HOST"):
        master_h = os.getenv("MASTER_HOST")
    if os.getenv("MASTER_PORT"):
        master_p = int(os.getenv("MASTER_PORT"))

    listen_host = "0.0.0.0"
    listen_port = 0

    pub, priv = generate_keypair()
    n, e = pub

    serv = socket.socket()
    serv.bind((listen_host, listen_port))
    serv.listen()

    _, real_port = serv.getsockname()

    tmp = socket.socket()
    tmp.connect((master_h, master_p))
    advertise_host = tmp.getsockname()[0]
    tmp.close()

    s = socket.socket()
    s.connect((master_h, master_p))
    send_packet(s, f"REGISTER_DYNAMIC|{advertise_host}|{real_port}|{n}|{e}")
    rid = recv_packet(s).split("|")[1]
    s.close()

    print(f"[ROUTEUR {rid}] En écoute sur {listen_host}:{real_port}")

    while True:
        conn, _ = serv.accept()
        threading.Thread(
            target=handle_onion,
            args=(conn, priv, rid),
            daemon=True
        ).start()


if __name__ == "__main__":
    main()
