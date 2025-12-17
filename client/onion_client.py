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


def looks_like_id(s: str) -> bool:
    # ID simple type A, B, C, C12, CLIENT1, etc.
    if not s:
        return False
    if ":" in s:
        return False
    if "." in s:
        return False
    return True


# -----------------------------------------------------
# MASTER -> ENREGISTREMENT DYNAMIQUE CLIENT
# -----------------------------------------------------
def register_client_dynamic(master_h, master_p, advertise_host, listen_port):
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, f"REGISTER_CLIENT_DYNAMIC|{advertise_host}|{listen_port}")
        rep = recv_packet(s)
        s.close()

        if rep and rep.startswith("ASSIGNED_CLIENT|"):
            return rep.split("|", 1)[1].strip().upper()
        return None
    except:
        return None


def resolve_client_via_master(master_h, master_p, dest_id):
    """Demande au master l'IP/port d'un client dynamique (ou statique)."""
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, f"CLIENT_INFO_REQUEST|{dest_id}")
        rep = recv_packet(s)
        s.close()

        # OK|host|port  ou  NOT_FOUND
        if rep and rep.startswith("CLIENT_INFO|OK|"):
            _, _, h, p = rep.split("|")
            return h, int(p)

        return None
    except:
        return None


# -----------------------------------------------------
# RÉCEPTION DES MESSAGES
# -----------------------------------------------------
def listen_incoming(my_id_ref, server_socket):
    # my_id_ref : liste à 1 élément, pour afficher l'ID même s'il arrive après REGISTER
    while True:
        conn, addr = server_socket.accept()
        pkt = recv_packet(conn)
        conn.close()

        if pkt and pkt.startswith("DELIVER|"):
            _, fid, msg = pkt.split("|", 2)
            cid = my_id_ref[0] if my_id_ref[0] else "?"
            print(f"\n[CLIENT {cid}] Message de {fid} : {msg}")
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

        data = resp.split("|", 1)[1]
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
    master_h, master_p = load_node("MASTER")

    # -------------------------
    # MODE STATIQUE (ancien) :
    #   py -m client.onion_client A
    # MODE DYNAMIQUE (infini) :
    #   py -m client.onion_client
    #   py -m client.onion_client 0.0.0.0 0 192.168.1.50   (VM)
    # -------------------------

    cid = None
    listen_host = "0.0.0.0"
    listen_port = 0
    advertise_host = "127.0.0.1"

    # Parsing simple :
    # - si arg1 ressemble à un ID -> statique
    # - sinon -> dynamique avec host/port/advertise optionnels
    if len(sys.argv) >= 2 and looks_like_id(sys.argv[1]):
        cid = sys.argv[1].upper()
        c_host, c_port = load_node(cid)
        listen_host, listen_port = c_host, c_port
        # En statique, on annonce l'host du fichier
        advertise_host = c_host if c_host != "0.0.0.0" else "127.0.0.1"
    else:
        # dynamique
        if len(sys.argv) >= 2:
            listen_host = sys.argv[1]
        if len(sys.argv) >= 3:
            listen_port = int(sys.argv[2])
        else:
            listen_port = 0
        if len(sys.argv) >= 4:
            advertise_host = sys.argv[3]

    # Crée la socket d'écoute tout de suite (pour connaître le port réel si 0)
    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind((listen_host, listen_port))
    serv.listen()

    real_host, real_port = serv.getsockname()

    my_id_ref = [cid]  # pour l'affichage dans le thread

    threading.Thread(
        target=listen_incoming,
        args=(my_id_ref, serv),
        daemon=True
    ).start()

    # Si dynamique -> REGISTER au master pour recevoir un ID
    if cid is None:
        assigned = register_client_dynamic(master_h, master_p, advertise_host, real_port)
        if not assigned:
            print("[CLIENT ?] Impossible de s'enregistrer auprès du master.")
            cid = "C?"
        else:
            cid = assigned

        my_id_ref[0] = cid
        print(f"[CLIENT {cid}] En écoute sur {listen_host}:{real_port} (annonce {advertise_host}:{real_port})")
    else:
        print(f"[CLIENT {cid}] En écoute sur {listen_host}:{real_port}")

    nb_hops = None
    print(f"[CLIENT {cid}] Prêt. Format : DEST: message (DEST = ID client)")

    while True:
        line = input("> ").strip()
        if not line or ":" not in line:
            continue

        dest, message = line.split(":", 1)
        dest = dest.strip().upper()
        message = message.strip()
        if not message:
            continue

        # Résolution destination :
        # 1) si dans noeuds.txt -> OK (ancien mode A/B/C)
        # 2) sinon -> demande au master (clients dynamiques C1/C2/...)
        try:
            d_host, d_port = load_node(dest)
        except:
            resolved = resolve_client_via_master(master_h, master_p, dest)
            if not resolved:
                print(f"[CLIENT {cid}] Destination inconnue : {dest}")
                continue
            d_host, d_port = resolved

        routers = get_routers(master_h, master_p)
        if len(routers) < 3:
            print("Pas assez de routeurs.")
            continue

        nb_hops = demander_nb_routeurs(len(routers), nb_hops)
        path = random.sample(routers, nb_hops)

        # couche finale
        plain = f"{d_host}|{d_port}|{cid}|{message}"
        cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))

        # couches intermédiaires
        for i in range(nb_hops - 2, -1, -1):
            nh, np = path[i + 1][1], path[i + 1][2]
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
