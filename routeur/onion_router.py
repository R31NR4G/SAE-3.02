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


def handle_onion(conn, addr, private_key, rid):
    try:
        pkt = recv_packet(conn)
        if not pkt:
            return
        if not pkt.startswith("ONION|"):
            return

        cipher = pkt.split("|", 1)[1]
        plain = decrypt_str(cipher, private_key)
        if not plain:
            return

        parts = [p for p in plain.split("|") if p]

        if len(parts) == 3:
            nh, np, next_cipher = parts
            forward(rid, nh, int(np), next_cipher)
        elif len(parts) == 4:
            dh, dp, fid, msg = parts
            deliver(rid, dh, int(dp), fid, msg)

    finally:
        conn.close()


def forward(rid, host, port, cipher):
    try:
        s = socket.socket()
        s.connect((host, port))
        send_packet(s, "ONION|" + cipher)
        s.close()
        print(f"[{rid}] Transmission d'une couche onion.")
    except:
        print(f"[{rid}] Échec transmission.")


def deliver(rid, host, port, from_id, msg):
    try:
        s = socket.socket()
        s.connect((host, port))
        send_packet(s, f"DELIVER|{from_id}|{msg}")
        s.close()
        print(f"[{rid}] Couche finale délivrée.")
    except:
        print(f"[{rid}] Échec livraison finale.")


def main():
    # MASTER par défaut depuis noeuds.txt + surcharge env
    master_host, master_port = load_node("MASTER")
    env_h = os.getenv("MASTER_HOST")
    env_p = os.getenv("MASTER_PORT")
    if env_h:
        master_host = env_h
    if env_p:
        master_port = int(env_p)

    rid = None
    listen_host = "0.0.0.0"
    listen_port = 0

    if len(sys.argv) >= 2 and sys.argv[1].upper().startswith("R") and sys.argv[1][1:].isdigit():
        rid = sys.argv[1].upper()
        r_host, r_port = load_node(rid)
        listen_host, listen_port = r_host, r_port

        if len(sys.argv) == 4:
            listen_host = sys.argv[2]
            listen_port = int(sys.argv[3])
        elif len(sys.argv) == 3 and ":" in sys.argv[2]:
            hp = sys.argv[2].split(":")
            listen_host = hp[0]
            listen_port = int(hp[1])
    else:
        if len(sys.argv) >= 2:
            listen_host = sys.argv[1]
        if len(sys.argv) >= 3:
            listen_port = int(sys.argv[2])
        else:
            listen_port = 0

    pub, priv = generate_keypair()
    n, e = pub

    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind((listen_host, listen_port))
    serv.listen()

    _, real_port = serv.getsockname()

    # --- annonce IP correcte (pas 127.0.0.1 sur VM) ---
    advertise_host = listen_host
    if advertise_host == "0.0.0.0":
        # on déduit l'IP locale utilisée pour joindre le master
        try:
            tmp = socket.socket()
            tmp.connect((master_host, master_port))
            advertise_host = tmp.getsockname()[0]
            tmp.close()
        except:
            advertise_host = "127.0.0.1"

    # REGISTER auprès du master
    try:
        s = socket.socket()
        s.connect((master_host, master_port))

        if rid is None:
            send_packet(s, f"REGISTER_DYNAMIC|{advertise_host}|{real_port}|{n}|{e}")
            rep = recv_packet(s)
            if rep and rep.startswith("ASSIGNED|"):
                rid = rep.split("|", 1)[1].strip().upper()
            else:
                rid = "R?"
                print("[ROUTEUR] Enregistrement dynamique échoué (pas de réponse master).")
        else:
            send_packet(s, f"REGISTER|{rid}|{advertise_host}|{real_port}|{n}|{e}")

        s.close()
    except Exception as e:
        if rid is None:
            rid = "R?"
        print(f"[{rid}] Impossible de s'enregistrer auprès du master :", e)

    print(f"[ROUTEUR {rid}] En écoute sur {listen_host}:{real_port} (annonce {advertise_host}:{real_port})")

    while True:
        conn, addr = serv.accept()
        threading.Thread(target=handle_onion, args=(conn, addr, priv, rid), daemon=True).start()


if __name__ == "__main__":
    main()
