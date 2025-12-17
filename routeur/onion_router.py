import socket
import threading
import sys
from pathlib import Path

from crypto.onion_rsa import generate_keypair, decrypt_str

CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")


# -----------------------------------------------------
# OUTILS
# -----------------------------------------------------
def load_node(node_id):
    """Lit noeuds.txt et renvoie (host, port)."""
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
    """Envoie taille ASCII + '\\n' + payload."""
    data = payload.encode()
    header = str(len(data)).encode() + b"\n"
    sock.sendall(header + data)


def recv_packet(sock):
    """Reçoit un paquet avec longueur ASCII."""
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
# COEUR DU ROUTEUR (ROUTAGE ONION)
# -----------------------------------------------------
def handle_onion(conn, addr, private_key, rid):
    try:
        pkt = recv_packet(conn)
        if not pkt:
            return

        if not pkt.startswith("ONION|"):
            return

        cipher = pkt.split("|", 1)[1]

        # Déchiffrement
        plain = decrypt_str(cipher, private_key)
        if not plain:
            print(f"[{rid}] Couche vide / invalide.")
            return

        parts = [p for p in plain.split("|") if p]

        # Couche intermédiaire
        if len(parts) == 3:
            nh, np, next_cipher = parts
            forward(rid, nh, int(np), next_cipher)

        # Couche finale
        elif len(parts) == 4:
            dh, dp, fid, msg = parts
            deliver(rid, dh, int(dp), fid, msg)

        else:
            print(f"[{rid}] Couche onion invalide.")

    finally:
        conn.close()


def forward(rid, host, port, cipher):
    """Forward vers routeur suivant - logs anonymisés."""
    try:
        s = socket.socket()
        s.connect((host, port))
        send_packet(s, "ONION|" + cipher)
        s.close()
        print(f"[{rid}] Transmission d'une couche onion.")
    except:
        print(f"[{rid}] Échec transmission.")


def deliver(rid, host, port, from_id, msg):
    """Envoie au client final - logs anonymisés."""
    try:
        s = socket.socket()
        s.connect((host, port))
        send_packet(s, f"DELIVER|{from_id}|{msg}")
        s.close()
        print(f"[{rid}] Couche finale délivrée.")
    except:
        print(f"[{rid}] Échec livraison finale.")


# -----------------------------------------------------
# MAIN ROUTEUR - MODE ILLIMITÉ
# -----------------------------------------------------
def main():
    # MASTER depuis noeuds.txt (OK de garder ça statique)
    master_host, master_port = load_node("MASTER")

    # -------------------------------------------------
    # MODE 1 (ancien) : python -m routeur.onion_router R1 [host port]
    # MODE 2 (nouveau) : python -m routeur.onion_router [host] [port]
    #   - sans rid -> le master attribue un rid automatiquement
    #   - port=0 -> port libre automatiquement
    # -------------------------------------------------

    rid = None
    listen_host = "0.0.0.0"
    listen_port = 0

    # Si le 1er argument ressemble à "R12" => mode ancien avec RID
    if len(sys.argv) >= 2 and sys.argv[1].upper().startswith("R") and sys.argv[1][1:].isdigit():
        rid = sys.argv[1].upper()

        # Valeurs par défaut venant de noeuds.txt (si existant)
        # (si tu veux garder la compat rétro, sinon tu peux supprimer ces 2 lignes)
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
        # Mode dynamique (illimité)
        # Ex: python -m routeur.onion_router
        # Ex: python -m routeur.onion_router 127.0.0.1 6001
        if len(sys.argv) >= 2:
            listen_host = sys.argv[1]
        if len(sys.argv) >= 3:
            listen_port = int(sys.argv[2])
        else:
            listen_port = 0  # port libre

    # Génération de clés RSA
    pub, priv = generate_keypair()
    n, e = pub

    # Socket d’écoute
    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind((listen_host, listen_port))
    serv.listen()

    # Récupère le port réel si bind sur 0
    real_host, real_port = serv.getsockname()

    # Host à annoncer aux clients :
    # - si on écoute sur 0.0.0.0, on annonce plutôt 127.0.0.1 en local
    advertise_host = listen_host
    if advertise_host == "0.0.0.0":
        advertise_host = "127.0.0.1"

    # REGISTER auprès du master
    try:
        s = socket.socket()
        s.connect((master_host, master_port))

        if rid is None:
            # Mode dynamique -> master attribue un rid
            send_packet(s, f"REGISTER_DYNAMIC|{advertise_host}|{real_port}|{n}|{e}")
            rep = recv_packet(s)
            if rep and rep.startswith("ASSIGNED|"):
                rid = rep.split("|", 1)[1].strip().upper()
            else:
                rid = "R?"
                print("[ROUTEUR] Enregistrement dynamique échoué (pas de réponse master).")
        else:
            # Mode ancien
            send_packet(s, f"REGISTER|{rid}|{advertise_host}|{real_port}|{n}|{e}")

        s.close()
    except:
        if rid is None:
            rid = "R?"
        print(f"[{rid}] Impossible de s'enregistrer auprès du master.")

    print(f"[ROUTEUR {rid}] En écoute sur {listen_host}:{real_port} (annonce {advertise_host}:{real_port})")

    while True:
        conn, addr = serv.accept()
        threading.Thread(
            target=handle_onion,
            args=(conn, addr, priv, rid),
            daemon=True
        ).start()


if __name__ == "__main__":
    main()
