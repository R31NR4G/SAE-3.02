import socket
import threading
from pathlib import Path

from database.onion_bdd import (
    add_router,
    get_routers,
    reset_routers,
    delete_router
)

CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")

routers_mem = []      # fallback mémoire
clients_mem = {}      # cid -> (host, port)
mem_lock = threading.Lock()


# --------------------------------------------------
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


def send_packet(sock: socket.socket, payload: str):
    data = payload.encode()
    sock.sendall(str(len(data)).encode() + b"\n" + data)


def recv_packet(sock: socket.socket):
    size_bytes = b""
    while not size_bytes.endswith(b"\n"):
        b = sock.recv(1)
        if not b:
            return None
        size_bytes += b
    size = int(size_bytes.strip())
    data = b""
    while len(data) < size:
        data += sock.recv(size - len(data))
    return data.decode(errors="ignore")


# --------------------------------------------------
def safe_reset_routers():
    try:
        reset_routers()
    except:
        routers_mem.clear()


def safe_add_router(rid, host, port, pub):
    try:
        add_router(rid, host, port, pub)
    except:
        routers_mem.append((rid, host, port, pub))


def safe_delete_router(rid):
    try:
        delete_router(rid)
    except:
        routers_mem[:] = [r for r in routers_mem if r[0] != rid]


def safe_get_routers():
    try:
        return get_routers()
    except:
        return list(routers_mem)


def allocate_router_id():
    routers = safe_get_routers()
    used = {r[0] for r in routers}
    i = 1
    while True:
        rid = f"R{i}"
        if rid not in used:
            return rid
        i += 1


def allocate_client_id():
    used = set(clients_mem.keys())
    i = 1
    while True:
        cid = f"C{i}"
        if cid not in used:
            return cid
        i += 1


# --------------------------------------------------
def handle_client(conn, addr):
    try:
        while True:
            pkt = recv_packet(conn)
            if not pkt:
                break

            # ROUTER LIST
            if pkt == "ROUTER_INFO_REQUEST":
                routers = safe_get_routers()

                # 🔥 MODIF CLÉ : suppression doublons
                uniq = {}
                for r in routers:
                    uniq[r[0]] = r
                routers = list(uniq.values())

                parts = []
                for rid, h, p, pub in routers:
                    n, e = pub.split(",")
                    parts.append(f"{rid},{h},{p},{n},{e}")

                send_packet(conn, "ROUTER_INFO|" + ";".join(parts))
                continue

            # ROUTER REGISTER DYN
            if pkt.startswith("REGISTER_DYNAMIC|"):
                _, h, p, n, e = pkt.split("|")
                rid = allocate_router_id()
                safe_add_router(rid, h, int(p), f"{n},{e}")
                send_packet(conn, f"ASSIGNED|{rid}")
                print(f"[MASTER] Routeur {rid} enregistré")
                continue

            # CLIENT REGISTER DYN
            if pkt.startswith("REGISTER_CLIENT_DYNAMIC|"):
                _, h, p = pkt.split("|")
                cid = allocate_client_id()
                clients_mem[cid] = (h, int(p))
                send_packet(conn, f"ASSIGNED_CLIENT|{cid}")
                print(f"[MASTER] Client {cid} enregistré")
                continue

            # CLIENT RESOLUTION
            if pkt.startswith("CLIENT_INFO_REQUEST|"):
                _, cid = pkt.split("|", 1)
                if cid in clients_mem:
                    h, p = clients_mem[cid]
                    send_packet(conn, f"CLIENT_INFO|OK|{h}|{p}")
                else:
                    send_packet(conn, "CLIENT_INFO|NOT_FOUND")
                continue

            send_packet(conn, "ERR|UNKNOWN")

    finally:
        conn.close()


# --------------------------------------------------
def main():
    _, port = load_node("MASTER")
    safe_reset_routers()

    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind(("0.0.0.0", port))
    serv.listen()

    print(f"[MASTER] En écoute sur 0.0.0.0:{port}")

    while True:
        conn, addr = serv.accept()
        threading.Thread(
            target=handle_client,
            args=(conn, addr),
            daemon=True
        ).start()


if __name__ == "__main__":
    main()
