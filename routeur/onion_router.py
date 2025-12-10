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

        # Déchiffrement couche
        plain = decrypt_str(cipher, private_key)

        if not plain:
            print(f"[{rid}] Couche vide / invalide.")
            return

        # Nettoyage pour éviter champs vides
        parts = [p for p in plain.split("|") if p]

        # -----------------------------------------
        # COUCHE INTERMÉDIAIRE
        # next_host | next_port | next_cipher
        # -----------------------------------------
        if len(parts) == 3:
            nh, np, next_cipher = parts

            try:
                np = int(np)
            except:
                print(f"[{rid}] Port intermédiaire invalide.")
                return

            forward(rid, nh, np, next_cipher)

        # -----------------------------------------
        # COUCHE FINALE
        # dest_host | dest_port | from_id | message
        # -----------------------------------------
        elif len(parts) == 4:
            dh, dp, fid, msg = parts

            try:
                dp = int(dp)
            except:
                print(f"[{rid}] Port destinataire invalide.")
                return

            deliver(rid, dh, dp, fid, msg)

        else:
            print(f"[{rid}] Couche onion invalide :", plain)

    finally:
        conn.close()


def forward(rid, host, port, cipher):
    """Envoie au routeur suivant."""
    try:
        s = socket.socket()
        s.connect((host, port))
        send_packet(s, "ONION|" + cipher)
        s.close()
        print(f"[{rid}] Forward -> {host}:{port}")
    except:
        print(f"[{rid}] Échec du forward vers {host}:{port}")


def deliver(rid, host, port, from_id, msg):
    """Envoie au destinataire final (client)."""
    try:
        s = socket.socket()
        s.connect((host, port))
        send_packet(s, f"DELIVER|{from_id}|{msg}")
        s.close()
        print(f"[{rid}] Message livré -> {host}:{port}")
    except:
        print(f"[{rid}] Échec livraison -> {host}:{port}")

# -----------------------------------------------------
# MAIN
# -----------------------------------------------------

def main():
    # ID du routeur
    if len(sys.argv) >= 2:
        rid = sys.argv[1].upper()
    else:
        rid = input("Id routeur (R1, R2...) : ").upper()

    r_host, r_port = load_node(rid)
    m_host, m_port = load_node("MASTER")

    # Génération clé RSA
    pub, priv = generate_keypair()
    n, e = pub

    # Enregistrement auprès du master
    try:
        s = socket.socket()
        s.connect((m_host, m_port))
        send_packet(s, f"REGISTER|{rid}|{r_host}|{r_port}|{n}|{e}")
        s.close()
    except:
        print(f"[{rid}] Impossible de s'enregistrer auprès du master.")

    # Socket d'écoute
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
