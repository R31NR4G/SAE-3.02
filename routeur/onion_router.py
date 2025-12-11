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
# MAIN ROUTEUR - SUPPORT DES ARGUMENTS CLI
# -----------------------------------------------------
def main():
    # -------------------------------------------------
    # ARG 1 → ID du routeur (R1, R2…)
    # ARG 2 → host OU host:port
    # ARG 3 → port (optionnel si host:port utilisé)
    # -------------------------------------------------
    if len(sys.argv) >= 2:
        rid = sys.argv[1].upper()
    else:
        rid = input("Id routeur (R1, R2...) : ").upper()

    # Valeurs par défaut venant de noeuds.txt
    r_host, r_port = load_node(rid)

    # Si l'utilisateur force une IP : python router.py R1 1.2.3.4 6001
    if len(sys.argv) == 4:
        r_host = sys.argv[2]
        r_port = int(sys.argv[3])

    # Si format host:port → python router.py R1 1.2.3.4:6001
    elif len(sys.argv) == 3 and ":" in sys.argv[2]:
        host_port = sys.argv[2].split(":")
        r_host = host_port[0]
        r_port = int(host_port[1])

    master_host, master_port = load_node("MASTER")

    # Génération de clés RSA
    pub, priv = generate_keypair()
    n, e = pub

    # REGISTER auprès du master
    try:
        s = socket.socket()
        s.connect((master_host, master_port))
        send_packet(s, f"REGISTER|{rid}|{r_host}|{r_port}|{n}|{e}")
        s.close()
    except:
        print(f"[{rid}] Impossible de s'enregistrer auprès du master.")

    # Socket d’écoute
    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind((r_host, r_port))
    serv.listen()

    print(f"[ROUTEUR {rid}] En écoute sur {r_host}:{r_port}")

    while True:
        conn, addr = serv.accept()
        threading.Thread(
            target=handle_onion,
            args=(conn, addr, priv, rid),
            daemon=True
        ).start()


if __name__ == "__main__":
    main()
