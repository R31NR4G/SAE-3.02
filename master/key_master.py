import socket
import struct
import threading
from pathlib import Path

from database.onion_bdd import (
    add_router,
    get_routers
)

CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")


# -----------------------------------------------------
# LECTURE noeuds.txt
# -----------------------------------------------------
def load_node(node_id: str):
    with CONFIG.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            nid, host, port = line.split(";")
            if nid.upper() == node_id.upper():
                return host, int(port)

    raise RuntimeError(f"Noeud {node_id} introuvable.")


# -----------------------------------------------------
# PROTOCOLE DE COMMUNICATION
# -----------------------------------------------------
def send_packet(sock: socket.socket, payload: str):
    data = payload.encode()
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_packet(sock: socket.socket):
    header = sock.recv(4)
    if len(header) < 4:
        return None

    size = struct.unpack(">I", header)[0]
    if size <= 0 or size > 4096:
        return None

    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk

    return data.decode(errors="ignore")


# -----------------------------------------------------
# TRAITEMENT DES CLIENTS ET ROUTEURS
# -----------------------------------------------------
def handle_client(conn, addr):
    try:
        while True:
            pkt = recv_packet(conn)
            if not pkt:
                break

            # ----------------------
            # 1. Client demande la liste des routeurs
            # ----------------------
            if pkt == "ROUTER_INFO_REQUEST":
                routers = get_routers()  # Depuis la BDD !

                # Format envoyé au client :
                # ROUTER_INFO|R1,ip,port,n,e;R2,ip,port,n,e;...
                parts = []
                for rid, host, port, pub in routers:
                    # pub = "n,e"
                    n, e = pub.split(",")
                    parts.append(f"{rid},{host},{port},{n},{e}")

                resp = "ROUTER_INFO|" + ";".join(parts)
                send_packet(conn, resp)

            # ----------------------
            # 2. Un routeur s’enregistre
            # ----------------------
            elif pkt.startswith("REGISTER|"):
                # REGISTER|R1|host|port|n|e
                _, rid, h, p, n, e = pkt.split("|")
                pub = f"{n},{e}"

                # On enregistre en BDD
                add_router(rid, h, int(p), pub)

                print(f"[MASTER] Routeur {rid} enregistré en BDD.")

            else:
                print("[MASTER] Message inconnu :", pkt)

    finally:
        conn.close()
        print("[MASTER] Connexion fermée :", addr)


# -----------------------------------------------------
# MASTER PRINCIPAL
# -----------------------------------------------------
def main():
    host, port = load_node("MASTER")

    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind((host, port))
    serv.listen()

    print(f"[MASTER] En écoute sur {host}:{port}")
    print("[MASTER] En attente de clients/routeurs...")

    while True:
        conn, addr = serv.accept()
        threading.Thread(
            target=handle_client,
            args=(conn, addr),
            daemon=True
        ).start()


if __name__ == "__main__":
    main()
