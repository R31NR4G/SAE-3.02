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

routers_mem = []      # fallback si BDD KO : list (rid, host, port, pub)
clients_mem = {}      # cid -> (host, port)
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
    try:
        reset_routers()
        return True
    except Exception as e:
        print("[MASTER] BDD indisponible (reset) -> fallback mémoire. Erreur:", e)
        with mem_lock:
            routers_mem.clear()
        return False


def safe_add_router(rid: str, host: str, port: int, pub: str):
    try:
        add_router(rid, host, port, pub)
        return True
    except Exception as e:
        print("[MASTER] BDD indisponible (add) -> fallback mémoire. Erreur:", e)
        with mem_lock:
            for i, (rr, _, _, _) in enumerate(routers_mem):
                if rr.upper() == rid.upper():
                    routers_mem[i] = (rid, host, port, pub)
                    break
            else:
                routers_mem.append((rid, host, port, pub))
        return False


def safe_delete_router(rid: str):
    try:
        delete_router(rid)
        return True
    except Exception as e:
        print("[MASTER] BDD indisponible (delete) -> fallback mémoire. Erreur:", e)
        with mem_lock:
            routers_mem[:] = [t for t in routers_mem if t[0].upper() != rid.upper()]
        return False


def safe_get_routers():
    try:
        return get_routers()
    except Exception as e:
        print("[MASTER] BDD indisponible (get) -> fallback mémoire. Erreur:", e)
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


# CLIENT IDs SANS TROUS : C1 C3 => prochain C2
def allocate_client_id() -> str:
    with mem_lock:
        used = set(k.upper() for k in clients_mem.keys())
    i = 1
    while True:
        cid = f"C{i}"
        if cid not in used:
            return cid
        i += 1


def is_router_alive(host: str, port: int, timeout=0.4) -> bool:
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        send_packet(s, "PING")
        rep = recv_packet(s)
        s.close()
        return rep == "PONG"
    except:
        return False


def prune_dead_routers():
    routers = safe_get_routers()
    dead = []
    for rid, host, port, pub in routers:
        if not is_router_alive(host, int(port)):
            dead.append(rid)

    for rid in dead:
        safe_delete_router(rid)

    if dead:
        print(f"[MASTER] Nettoyage routeurs morts : {', '.join(dead)}")


def is_client_alive(host: str, port: int, timeout=0.35) -> bool:
    """
    Test simple: on tente une connexion TCP.
    Si le client n'écoute plus, la connexion échoue.
    """
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, int(port)))
        s.close()
        return True
    except:
        return False


def prune_dead_clients():
    with mem_lock:
        items = list(clients_mem.items())

    dead = []
    for cid, (h, p) in items:
        if not is_client_alive(h, p):
            dead.append(cid)

    if dead:
        with mem_lock:
            for cid in dead:
                clients_mem.pop(cid, None)
        print(f"[MASTER] Nettoyage clients morts : {', '.join(dead)}")


def handle_client(conn, addr):
    try:
        while True:
            pkt = recv_packet(conn)
            if not pkt:
                break

            # 0) ROUTEUR -> désenregistrement propre
            if pkt.startswith("UNREGISTER|"):
                _, rid = pkt.split("|", 1)
                rid = rid.strip().upper()
                safe_delete_router(rid)
                send_packet(conn, "OK")
                print(f"[MASTER] Routeur {rid} désenregistré.")
                continue

            # 0bis) CLIENT -> désenregistrement propre
            if pkt.startswith("UNREGISTER_CLIENT|"):
                _, cid = pkt.split("|", 1)
                cid = cid.strip().upper()
                with mem_lock:
                    existed = cid in clients_mem
                    clients_mem.pop(cid, None)
                send_packet(conn, "OK")
                if existed:
                    print(f"[MASTER] Client {cid} désenregistré.")
                continue

            # 1) CLIENT -> liste routeurs
            if pkt == "ROUTER_INFO_REQUEST":
                prune_dead_routers()
                routers = safe_get_routers()
                parts = []
                for rid, host, port, pub in routers:
                    n, e = pub.split(",")
                    parts.append(f"{rid},{host},{port},{n},{e}")
                send_packet(conn, "ROUTER_INFO|" + ";".join(parts))
                continue

            # 1bis) CLIENT -> liste clients (pour GUI)
            if pkt == "CLIENT_LIST_REQUEST":
                prune_dead_clients()
                with mem_lock:
                    ids = sorted(clients_mem.keys(), key=lambda x: int(x[1:]) if x[1:].isdigit() else 10**9)
                send_packet(conn, "CLIENT_LIST|" + ";".join(ids))
                continue

            # 2) ROUTEUR statique
            if pkt.startswith("REGISTER|"):
                _, rid, h, p, n, e = pkt.split("|")
                pub = f"{n},{e}"
                safe_add_router(rid, h, int(p), pub)
                send_packet(conn, "OK")
                print(f"[MASTER] Routeur {rid} enregistré : {h}:{p}")
                continue

            # 3) ROUTEUR dynamique
            if pkt.startswith("REGISTER_DYNAMIC|"):
                _, h, p, n, e = pkt.split("|")
                rid = allocate_router_id()
                pub = f"{n},{e}"
                safe_add_router(rid, h, int(p), pub)
                send_packet(conn, f"ASSIGNED|{rid}")
                print(f"[MASTER] Routeur {rid} (dyn) enregistré : {h}:{p}")
                continue

            # 4) CLIENT dynamique
            if pkt.startswith("REGISTER_CLIENT_DYNAMIC|"):
                _, h, p = pkt.split("|")
                cid = allocate_client_id()
                with mem_lock:
                    clients_mem[cid] = (h, int(p))
                send_packet(conn, f"ASSIGNED_CLIENT|{cid}")
                print(f"[MASTER] Client {cid} (dyn) enregistré : {h}:{p}")
                continue

            # 5) Résolution client
            if pkt.startswith("CLIENT_INFO_REQUEST|"):
                _, dest_id = pkt.split("|", 1)
                dest_id = dest_id.strip().upper()

                # d'abord noeuds.txt (clients statiques)
                try:
                    h, p = load_node(dest_id)
                    send_packet(conn, f"CLIENT_INFO|OK|{h}|{p}")
                    continue
                except:
                    pass

                with mem_lock:
                    info = clients_mem.get(dest_id)

                if info:
                    h, p = info
                    send_packet(conn, f"CLIENT_INFO|OK|{h}|{p}")
                else:
                    send_packet(conn, "CLIENT_INFO|NOT_FOUND")
                continue

            # Sinon
            send_packet(conn, "ERR|UNKNOWN_COMMAND")
            print("[MASTER] Message inconnu :", pkt)

    except Exception as e:
        print("[MASTER] Erreur handle_client:", e)
    finally:
        conn.close()


def main():
    _, port = load_node("MASTER")
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
