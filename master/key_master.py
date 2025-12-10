import socket
import threading
from pathlib import Path

from database.onion_bdd import (
    add_router,
    get_routers,
    reset_routers,
    reset_routing_table
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
# PROTOCOLE ASCII LENGTH
# -----------------------------------------------------
def send_packet(sock: socket.socket, payload: str):
    data = payload.encode()
    header = str(len(data)).encode() + b"\n"
    sock.sendall(header + data)


def recv_packet(sock: socket.socket):
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


# -----------------------------------------------------
# TRAITEMENT CLIENTS ET ROUTEURS
# -----------------------------------------------------
def handle_client(conn, addr):
    try:
        while True:
            pkt = recv_packet(conn)
            if not pkt:
                break

            # CLIENT → demande liste des routeurs
            if pkt == "ROUTER_INFO_REQUEST":
                routers = get_routers()

                parts = []
                for rid, host, port, pub in routers:
                    n, e = pub.split(",")
                    parts.append(f"{rid},{host},{port},{n},{e}")

                resp = "ROUTER_INFO|" + ";".join(parts)
                send_packet(conn, resp)

            # ROUTEUR → REGISTER
            elif pkt.startswith("REGISTER|"):
                _, rid, h, p, n, e = pkt.split("|")
                pub = f"{n},{e}"

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

    # ⚠️ RESET des deux tables important
    reset_routers()
    reset_routing_table()

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
