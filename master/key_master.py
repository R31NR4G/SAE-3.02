import socket
import threading
from pathlib import Path

from database.onion_bdd import (
    add_router,
    get_routers,
    reset_routers
)

CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")

# ---------------------------
# Fallback mémoire (si BDD KO)
# ---------------------------
routers_mem = []  # list of (rid, host, port, pub)
clients_mem = {}  # cid -> (host, port)
mem_lock = threading.Lock()


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


def safe_reset_routers():
    """Reset BDD si possible, sinon reset fallback mémoire."""
    try:
        reset_routers()
        return True
    except Exception as e:
        print("[MASTER] BDD indisponible (reset_routers) -> fallback mémoire. Erreur:", e)
        with mem_lock:
            routers_mem.clear()
        return False


def safe_add_router(rid: str, host: str, port: int, pub: str):
    """Ajoute routeur en BDD si possible, sinon en mémoire."""
    try:
        add_router(rid, host, port, pub)
        return True
    except Exception as e:
        print("[MASTER] BDD indisponible (add_router) -> fallback mémoire. Erreur:", e)
        with mem_lock:
            # Remplace si même RID
            for i, (rr, _, _, _) in enumerate(routers_mem):
                if rr.upper() == rid.upper():
                    routers_mem[i] = (rid, host, port, pub)
                    break
            else:
                routers_mem.append((rid, host, port, pub))
        return False


def safe_get_routers():
    """Lit la liste routeurs depuis BDD, sinon fallback mémoire."""
    try:
        return get_routers()  # attendu: list of (rid, host, port, pub)
    except Exception as e:
        print("[MASTER] BDD indisponible (get_routers) -> fallback mémoire. Erreur:", e)
        with mem_lock:
            return list(routers_mem)


def allocate_router_id() -> str:
    routers = safe_get_routers()
    used = set(rid.upper() for rid, host, port, pub in routers)

    i = 1
    while True:
        rid = f"R{i}"
        if rid not in used:
            return rid
        i += 1


def allocate_client_id() -> str:
    with mem_lock:
        used = set(k.upper() for k in clients_mem.keys())
    i = 1
    while True:
        cid = f"C{i}"
        if cid not in used:
            return cid
        i += 1


def handle_client(conn, addr):
    try:
        while True:
            pkt = recv_packet(conn)
            if not pkt:
                break

            # 1) CLIENT -> demande liste routeurs
            if pkt == "ROUTER_INFO_REQUEST":
                routers = safe_get_routers()
                parts = []
                for rid, host, port, pub in routers:
                    n, e = pub.split(",")
                    parts.append(f"{rid},{host},{port},{n},{e}")
                send_packet(conn, "ROUTER_INFO|" + ";".join(parts))

            # 2) ROUTEUR statique
            elif pkt.startswith("REGISTER|"):
                _, rid, h, p, n, e = pkt.split("|")
                pub = f"{n},{e}"
                safe_add_router(rid, h, int(p), pub)
                print(f"[MASTER] Routeur {rid} enregistré : {h}:{p}")

            # 3) ROUTEUR dynamique
            elif pkt.startswith("REGISTER_DYNAMIC|"):
                _, h, p, n, e = pkt.split("|")
                rid = allocate_router_id()
                pub = f"{n},{e}"
                safe_add_router(rid, h, int(p), pub)
                send_packet(conn, f"ASSIGNED|{rid}")
                print(f"[MASTER] Routeur {rid} (dyn) enregistré : {h}:{p}")

            # 4) CLIENT dynamique
            elif pkt.startswith("REGISTER_CLIENT_DYNAMIC|"):
                # REGISTER_CLIENT_DYNAMIC|host|port
                _, h, p = pkt.split("|")
                cid = allocate_client_id()
                with mem_lock:
                    clients_mem[cid] = (h, int(p))
                send_packet(conn, f"ASSIGNED_CLIENT|{cid}")
                print(f"[MASTER] Client {cid} (dyn) enregistré : {h}:{p}")

            # 5) Résolution client (statique/dynamique)
            elif pkt.startswith("CLIENT_INFO_REQUEST|"):
                _, dest_id = pkt.split("|", 1)
                dest_id = dest_id.strip().upper()

                # d'abord noeuds.txt (mode statique A/B/C)
                try:
                    h, p = load_node(dest_id)
                    send_packet(conn, f"CLIENT_INFO|OK|{h}|{p}")
                    continue
                except:
                    pass

                # sinon mémoire (dyn)
                with mem_lock:
                    info = clients_mem.get(dest_id)

                if info:
                    h, p = info
                    send_packet(conn, f"CLIENT_INFO|OK|{h}|{p}")
                else:
                    send_packet(conn, "CLIENT_INFO|NOT_FOUND")

            else:
                print("[MASTER] Message inconnu :", pkt)

    except Exception as e:
        print("[MASTER] Erreur handle_client:", e)
    finally:
        conn.close()
        print("[MASTER] Connexion fermée :", addr)


def main():
    _, port = load_node("MASTER")  # on ignore l'IP du fichier
    safe_reset_routers()

    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind(("0.0.0.0", port))
    serv.listen()

    print(f"[MASTER] En écoute sur 0.0.0.0:{port}")
    print("[MASTER] En attente de clients/routeurs...")

    while True:
        conn, addr = serv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
