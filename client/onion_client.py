import socket
import threading
import sys
import random
from pathlib import Path

from crypto.onion_rsa import encrypt_str

CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")

# -----------------------------------------------------
# OUTILS
# -----------------------------------------------------

def load_node(node_id):
    with CONFIG.open() as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#"):
                continue
            nid, host, port = line.split(";")
            if nid.upper()==node_id.upper():
                return host, int(port)
    raise RuntimeError(f"Noeud {node_id} introuvable.")


def send_packet(sock, payload):
    """Envoie taille ASCII + \n + payload."""
    data = payload.encode()
    header = str(len(data)).encode() + b"\n"
    sock.sendall(header + data)


def recv_packet(sock):
    """Reçoit paquet : taille ASCII sur une ligne puis payload."""
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
# RÉCEPTION DES MESSAGES
# -----------------------------------------------------

def listen_incoming(my_id, host, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    s.bind((host, port))
    s.listen()

    print(f"[CLIENT {my_id}] En écoute sur {host}:{port}")

    while True:
        conn,addr = s.accept()
        pkt = recv_packet(conn)
        conn.close()

        if pkt and pkt.startswith("DELIVER|"):
            _, fid, msg = pkt.split("|",2)
            print(f"\n[CLIENT {my_id}] Message de {fid} : {msg}")
            print("> ", end="", flush=True)


# -----------------------------------------------------
# MASTER → liste des routeurs
# -----------------------------------------------------

def get_routers(master_h, master_p):
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, "ROUTER_INFO_REQUEST")
        resp = recv_packet(s)
        s.close()

        if not resp or not resp.startswith("ROUTER_INFO|"):
            return []

        data = resp.split("|",1)[1]
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
# SELECTION NOMBRE DE ROUTEURS
# -----------------------------------------------------

def demander_nb_routeurs(total, actuel):
    if total < 3:
        raise RuntimeError("Il faut au moins 3 routeurs.")

    while True:
        if actuel is None:
            prompt = f"Nombre de routeurs (min 3, max {total}) : "
        else:
            prompt = f"Nombre de routeurs (min 3, max {total}, Entrée = {actuel}) : "

        s = input(prompt).strip()

        if not s:
            if actuel is not None:
                return actuel
            print("Veuillez entrer un nombre.")
            continue

        try:
            n = int(s)
        except:
            print("Entrez un nombre entier.")
            continue

        if n < 3:
            print("Minimum = 3.")
        elif n > total:
            print(f"Maximum = {total}.")
        else:
            return n


# -----------------------------------------------------
# CLIENT PRINCIPAL
# -----------------------------------------------------

def main():
    if len(sys.argv) >= 2:
        cid = sys.argv[1].upper()
    else:
        cid = input("Id client : ").upper()

    c_host, c_port = load_node(cid)

    threading.Thread(
        target=listen_incoming,
        args=(cid, c_host, c_port),
        daemon=True
    ).start()

    master_h, master_p = load_node("MASTER")
    nb_hops = None

    print(f"[CLIENT {cid}] Prêt. Format : DEST: message")

    while True:
        line = input("> ").strip()
        if not line or ":" not in line:
            continue

        dest, message = line.split(":",1)
        dest = dest.strip().upper()
        message = message.strip()

        if not message:
            continue

        d_host, d_port = load_node(dest)
        routers = get_routers(master_h, master_p)

        if len(routers) < 3:
            print("Pas assez de routeurs.")
            continue

        nb_hops = demander_nb_routeurs(len(routers), nb_hops)
        path = random.sample(routers, nb_hops)

        print(f"[CLIENT {cid}] Chemin :", [r[0] for r in path])

        # couche finale
        plain = f"{d_host}|{d_port}|{cid}|{message}".strip()
        cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))

        # couches intermédiaires
        for i in range(nb_hops - 2, -1, -1):
            nh, np = path[i+1][1], path[i+1][2]
            layer = f"{nh}|{np}|{cipher}"
            cipher = encrypt_str(layer, (path[i][3], path[i][4]))

        entry = path[0]

        try:
            s = socket.socket()
            s.connect((entry[1], entry[2]))
            send_packet(s, "ONION|" + cipher)
            s.close()
            print(f"[CLIENT {cid}] Message envoyé.")
        except Exception as e:
            print("[CLIENT] Erreur d'envoi :", e)


if __name__ == "__main__":
    main()
