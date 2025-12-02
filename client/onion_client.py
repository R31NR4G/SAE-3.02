import socket
import struct
import threading
import sys
import random
from pathlib import Path

from crypto.onion_rsa import encrypt_str

CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")

# -----------------------------------------------------
# OUTILS GÉNÉRAUX
# -----------------------------------------------------

def load_node(node_id: str):
    """Lit config/noeuds.txt → (host, port)."""
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
    """Envoie [4 octets longueur] + [payload en UTF-8]."""
    data = payload.encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_packet(sock: socket.socket):
    """Reçoit un paquet complet."""
    header = sock.recv(4)
    if len(header) < 4:
        return None

    size = struct.unpack(">I", header)[0]
    if size <= 0 or size > 16384:
        return None

    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk

    return data.decode(errors="ignore")


# -----------------------------------------------------
# Écoute des messages finaux (DELIVER) côté client
# -----------------------------------------------------

def listen_incoming(my_id, host, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen()
    print(f"[CLIENT {my_id}] En écoute sur {host}:{port}")

    while True:
        conn, addr = s.accept()
        pkt = recv_packet(conn)
        conn.close()

        if not pkt:
            continue

        if pkt.startswith("DELIVER|"):
            _, from_id, message = pkt.split("|", 2)
            print(f"\n[CLIENT {my_id}] Message de {from_id} : {message}")
            print("> ", end="", flush=True)


# -----------------------------------------------------
# Récupération des routeurs auprès du master
# -----------------------------------------------------

def get_routers(master_h, master_p):
    """
    Retourne une liste :
    [
        (rid, host, port, n, e),
        ...
    ]
    """
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
# Choix dynamique du nombre de routeurs
# -----------------------------------------------------

def demander_nb_routeurs(total: int, actuel: int | None) -> int:
    """
    Demande à l'utilisateur combien de routeurs utiliser :
    - min = 3
    - max = total (routeurs actifs)
    - Enter = garder valeur précédente
    """
    if total < 3:
        raise RuntimeError("Il faut au moins 3 routeurs actifs.")

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
            val = int(s)
        except ValueError:
            print("Entrez un nombre.")
            continue

        if val < 3:
            print("Minimum = 3.")
        elif val > total:
            print(f"Maximum = {total}.")
        else:
            return val


# -----------------------------------------------------
# CLIENT PRINCIPAL
# -----------------------------------------------------

def main():
    # ID du client
    if len(sys.argv) >= 2:
        cid = sys.argv[1].upper()
    else:
        cid = input("Id client (A,B,C...) : ").upper()

    # Adresse du client
    c_host, c_port = load_node(cid)

    # Thread écoute des messages entrants
    threading.Thread(
        target=listen_incoming,
        args=(cid, c_host, c_port),
        daemon=True
    ).start()

    # Adresse du master
    master_h, master_p = load_node("MASTER")

    # Cache de nombre de routeurs
    nb_hops = None

    print(f"[CLIENT {cid}] Prêt. Format message : DEST: texte")

    while True:
        line = input("> ").strip()
        if not line or ":" not in line:
            continue

        dest, message = line.split(":", 1)
        dest = dest.strip().upper()
        message = message.strip()

        if not message:
            continue

        # Adresse du destinataire
        d_host, d_port = load_node(dest)

        # Liste des routeurs
        routers = get_routers(master_h, master_p)
        if len(routers) < 3:
            print("[CLIENT] Pas assez de routeurs en ligne.")
            continue

        # Choix dynamique du nombre de routeurs
        nb_hops = demander_nb_routeurs(len(routers), nb_hops)

        # Chemin aléatoire
        path = random.sample(routers, nb_hops)
        print(f"[CLIENT {cid}] Chemin : {[r[0] for r in path]}")

        # Construction de l'oignon
        # Dernière couche
        plain = f"{d_host}|{d_port}|{cid}|{message}"
        cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))

        # Couches intermédiaires
        for i in range(nb_hops - 2, -1, -1):
            next_h = path[i + 1][1]
            next_p = path[i + 1][2]
            layer = f"{next_h}|{next_p}|{cipher}"
            cipher = encrypt_str(layer, (path[i][3], path[i][4]))

        # Envoi au premier routeur
        entry = path[0]

        try:
            s = socket.socket()
            s.connect((entry[1], entry[2]))
            send_packet(s, "ONION|" + cipher)
            s.close()

            print(f"[CLIENT {cid}] Message envoyé via {[r[0] for r in path]}")
        except Exception as e:
            print("[CLIENT] Erreur d’envoi :", e)


if __name__ == "__main__":
    main()
