import socket
import threading
import sys
import os
from pathlib import Path

from crypto.onion_rsa import generate_keypair, decrypt_str

CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")


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


def forward(host, port, cipher):
    try:
        s = socket.socket()
        s.connect((host, port))
        send_packet(s, "ONION|" + cipher)
        s.close()
    except:
        pass


def deliver(host, port, from_id, msg):
    try:
        s = socket.socket()
        s.connect((host, port))
        send_packet(s, f"DELIVER|{from_id}|{msg}")
        s.close()
    except:
        pass


def handle_conn(conn, private_key, rid):
    try:
        pkt = recv_packet(conn)
        if not pkt:
            return

        # Santé (PING)
        if pkt == "PING":
            send_packet(conn, "PONG")
            return

        # Onion
        if not pkt.startswith("ONION|"):
            return

        cipher = pkt.split("|", 1)[1]
        plain = decrypt_str(cipher, private_key)
        if not plain:
            return

        parts = [p for p in plain.split("|") if p]

        if len(parts) == 3:
            nh, np, next_cipher = parts
            forward(nh, int(np), next_cipher)

        elif len(parts) == 4:
            dh, dp, fid, msg = parts
            deliver(dh, int(dp), fid, msg)

    finally:
        conn.close()


def unregister(master_host, master_port, rid):
    if not rid or rid == "R?":
        return
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((master_host, master_port))
        send_packet(s, f"UNREGISTER|{rid}")
        _ = recv_packet(s)
        s.close()
    except:
        pass


def main():
    master_host, master_port = load_node("MASTER")

    # Args : python -m routeur.onion_router IP PORT
    if len(sys.argv) >= 3 and "." in sys.argv[1]:
        master_host = sys.argv[1]
        master_port = int(sys.argv[2])

    # Env
    if os.getenv("MASTER_HOST"):
        master_host = os.getenv("MASTER_HOST")
    if os.getenv("MASTER_PORT"):
        master_port = int(os.getenv("MASTER_PORT"))

    pub, priv = generate_keypair()
    n, e = pub

    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind(("0.0.0.0", 0))
    serv.listen()

    _, real_port = serv.getsockname()

    # IP à annoncer
    try:
        tmp = socket.socket()
        tmp.connect((master_host, master_port))
        advertise_host = tmp.getsockname()[0]
        tmp.close()
    except:
        advertise_host = "127.0.0.1"

    # REGISTER
    rid = "R?"
    try:
        s = socket.socket()
        s.connect((master_host, master_port))
        send_packet(s, f"REGISTER_DYNAMIC|{advertise_host}|{real_port}|{n}|{e}")
        rep = recv_packet(s)
        if rep and rep.startswith("ASSIGNED|"):
            rid = rep.split("|", 1)[1].strip().upper()
        s.close()
    except:
        pass

    print(f"[ROUTEUR {rid}] En écoute sur 0.0.0.0:{real_port} (annonce {advertise_host}:{real_port})")

    try:
        while True:
            conn, _ = serv.accept()
            threading.Thread(
                target=handle_conn,
                args=(conn, priv, rid),
                daemon=True
            ).start()

    except KeyboardInterrupt:
        # arrêt propre
        print(f"\n[ROUTEUR {rid}] Arrêt demandé.")
        unregister(master_host, master_port, rid)

    finally:
        try:
            serv.close()
        except:
            pass


if __name__ == "__main__":
    main()
