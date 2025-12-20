import socket
import threading
import sys
import random
import os

from crypto.onion_rsa import encrypt_str


# -----------------------------------------------------
# OUTILS TCP (taille + \n + payload)
# -----------------------------------------------------
def send_packet(sock, payload: str):
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
    except ValueError:
        return None

    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data.decode(errors="ignore")


def detect_local_ip(master_h, master_p):
    """Détecte l'IP locale utilisée pour joindre le master."""
    try:
        tmp = socket.socket()
        tmp.connect((master_h, master_p))
        ip = tmp.getsockname()[0]
        tmp.close()
        return ip
    except:
        return "127.0.0.1"


# -----------------------------------------------------
# ÉCOUTE DES MESSAGES ENTRANTS
# -----------------------------------------------------
def listen_incoming(my_id_ref, server_socket):
    while True:
        conn, _ = server_socket.accept()
        pkt = recv_packet(conn)
        conn.close()

        if pkt and pkt.startswith("DELIVER|"):
            _, fid, msg = pkt.split("|", 2)
            cid = my_id_ref[0] or "?"
            print(f"\n[CLIENT {cid}] Message de {fid} : {msg}")
            print("> ", end="", flush=True)


# -----------------------------------------------------
# MASTER COMMUNICATION
# -----------------------------------------------------
def register_client_dynamic(master_h, master_p, advertise_host, listen_port):
    """
    Inscription dynamique auprès du master.
    Le master renvoie: ASSIGNED_CLIENT|C3 (exemple)
    """
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, f"REGISTER_CLIENT_DYNAMIC|{advertise_host}|{listen_port}")
        rep = recv_packet(s)
        s.close()

        if rep and rep.startswith("ASSIGNED_CLIENT|"):
            return rep.split("|", 1)[1].strip()
    except:
        pass
    return None


def resolve_client(master_h, master_p, dest_id):
    """Demande au master où se trouve un client DEST."""
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, f"CLIENT_INFO_REQUEST|{dest_id}")
        rep = recv_packet(s)
        s.close()

        if rep and rep.startswith("CLIENT_INFO|OK|"):
            _, _, h, p = rep.split("|")
            return h, int(p)
    except:
        pass
    return None


def get_routers(master_h, master_p):
    """
    Demande au master la liste des routeurs.
    Réponse attendue: ROUTER_INFO|RID,IP,PORT,n,e;RID,IP,PORT,n,e;...
    """
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, "ROUTER_INFO_REQUEST")
        resp = recv_packet(s)
        s.close()

        routers = []
        if resp and resp.startswith("ROUTER_INFO|"):
            body = resp.split("|", 1)[1]
            for item in body.split(";"):
                if not item:
                    continue
                rid, h, p, n, e = item.split(",")
                routers.append((rid.strip(), h.strip(), int(p), int(n), int(e)))
        return routers
    except:
        return []


# -----------------------------------------------------
# CLIENT PRINCIPAL
# -----------------------------------------------------
def main():
    # ---- MASTER HOST/PORT (priorité: args -> env -> défaut) ----
    master_h = "127.0.0.1"
    master_p = 5000

    # Args: python -m client.onion_client <MASTER_IP> <MASTER_PORT>
    if len(sys.argv) >= 3:
        if "." in sys.argv[1] and sys.argv[2].isdigit():
            master_h = sys.argv[1]
            master_p = int(sys.argv[2])

    # Env: MASTER_HOST / MASTER_PORT
    if os.getenv("MASTER_HOST"):
        master_h = os.getenv("MASTER_HOST")
    if os.getenv("MASTER_PORT"):
        try:
            master_p = int(os.getenv("MASTER_PORT"))
        except:
            pass

    # ---- Serveur local du client (réception) ----
    serv = socket.socket()
    serv.bind(("0.0.0.0", 0))  # port dynamique
    serv.listen()

    real_port = serv.getsockname()[1]
    advertise_host = detect_local_ip(master_h, master_p)

    my_id_ref = [None]
    threading.Thread(
        target=listen_incoming,
        args=(my_id_ref, serv),
        daemon=True
    ).start()

    cid = register_client_dynamic(master_h, master_p, advertise_host, real_port) or "C?"
    my_id_ref[0] = cid

    print(f"[CLIENT {cid}] En écoute sur {advertise_host}:{real_port}")
    print("Format : DEST: message")
    print("Le client utilise tous les routeurs disponibles (min 3), ordre aléatoire.\n")

    while True:
        line = input("> ").strip()
        if ":" not in line:
            continue

        dest, msg = line.split(":", 1)
        dest = dest.strip().upper()
        msg = msg.strip()

        # --- Résolution destination via master ---
        resolved = resolve_client(master_h, master_p, dest)
        if not resolved:
            print("Destination inconnue (non enregistrée au master).")
            continue
        d_host, d_port = resolved

        # --- Récupération routeurs ---
        routers = get_routers(master_h, master_p)
        if len(routers) < 3:
            print("Pas assez de routeurs (min 3).")
            continue

        # --- Chemin = tous les routeurs (ordre aléatoire) ---
        path = routers[:]            # tous
        random.shuffle(path)         # ordre aléatoire

        # --- Construction onion ---
        # Payload final pour le dernier routeur:
        plain = f"{d_host}|{d_port}|{cid}|{msg}"
        last = path[-1]
        cipher = encrypt_str(plain, (last[3], last[4]))

        # Wrap des couches: de l'avant-dernier vers le premier
        # Chaque couche contient nextHopHost|nextHopPort|<reste>
        for i in range(len(path) - 2, -1, -1):
            nh, np = path[i + 1][1], path[i + 1][2]
            cipher = encrypt_str(f"{nh}|{np}|{cipher}", (path[i][3], path[i][4]))

        # --- Envoi au routeur d'entrée UNIQUEMENT ---
        entry = path[0]
        try:
            s = socket.socket()
            s.connect((entry[1], entry[2]))
            send_packet(s, "ONION|" + cipher)
            s.close()
            print("[CLIENT] Message envoyé.")
        except ConnectionRefusedError:
            print(f"[ERREUR] Routeur d'entrée {entry[0]} refuse la connexion ({entry[1]}:{entry[2]}).")
        except Exception as e:
            print(f"[ERREUR] Envoi impossible : {e}")


if __name__ == "__main__":
    main()
