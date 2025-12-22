# client/onion_client.py
import socket
import threading
import random
import os

from client.onion_tools import send_packet, recv_packet, get_routers
from crypto.onion_rsa import encrypt_str


def detect_local_ip(master_h, master_p):
    s = None
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((master_h, master_p))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        try:
            if s:
                s.close()
        except:
            pass


def listen_incoming(serv):
    while True:
        conn = None
        try:
            conn, _ = serv.accept()
            pkt = recv_packet(conn)
            if pkt and pkt.startswith("DELIVER|"):
                _, frm, msg = pkt.split("|", 2)
                print(f"\n[{frm}] {msg}")
                print("> ", end="", flush=True)
        except:
            pass
        finally:
            try:
                if conn:
                    conn.close()
            except:
                pass


def register_client(master_h, master_p, advertise_host, real_port):
    s = None
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((master_h, master_p))
        send_packet(s, f"REGISTER_CLIENT_DYNAMIC|{advertise_host}|{real_port}")
        rep = recv_packet(s)

        if not rep:
            return None

        # attendu : CLIENT_REGISTERED|C1 (ou similaire)
        if rep.startswith("CLIENT_REGISTERED|"):
            return rep.split("|")[1]

        # fallback si ton master renvoie autre chose
        parts = rep.split("|")
        if len(parts) >= 2:
            return parts[1]

        return None
    except:
        return None
    finally:
        try:
            if s:
                s.close()
        except:
            pass


def request_client_info(master_h, master_p, dest):
    s = None
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((master_h, master_p))
        send_packet(s, f"CLIENT_INFO_REQUEST|{dest}")
        rep = recv_packet(s)

        if not rep or not rep.startswith("CLIENT_INFO|OK|"):
            return None

        _, _, d_ip, d_port = rep.split("|")
        return d_ip, int(d_port)

    except:
        return None
    finally:
        try:
            if s:
                s.close()
        except:
            pass


def build_onion(d_ip, d_port, cid, msg, path):
    # Dernière couche : "d_ip|d_port|cid|msg"
    plain = f"{d_ip}|{d_port}|{cid}|{msg}"
    cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))

    # Couches intermédiaires : "nextHopIP|nextHopPort|<cipher>"
    for i in range(len(path) - 2, -1, -1):
        nh, np = path[i + 1][1], path[i + 1][2]
        cipher = encrypt_str(f"{nh}|{np}|{cipher}", (path[i][3], path[i][4]))

    return cipher


def send_onion(entry_host, entry_port, onion_cipher):
    s = None
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((entry_host, entry_port))
        send_packet(s, "ONION|" + onion_cipher)
        return True
    except:
        return False
    finally:
        try:
            if s:
                s.close()
        except:
            pass


def main():
    master_h = os.getenv("MASTER_HOST", "127.0.0.1")
    master_p = int(os.getenv("MASTER_PORT", "5000"))

    # serveur client (port dynamique)
    serv = socket.socket()
    serv.bind(("0.0.0.0", 0))
    serv.listen()

    real_port = serv.getsockname()[1]
    advertise_host = detect_local_ip(master_h, master_p)

    cid = register_client(master_h, master_p, advertise_host, real_port)
    if not cid:
        print("[CLIENT] Impossible de s'enregistrer auprès du master.")
        return

    print(f"[CLIENT {cid}] En écoute sur {advertise_host}:{real_port}")
    print("Format : DEST: message (ex: C1: salut)")

    threading.Thread(target=listen_incoming, args=(serv,), daemon=True).start()

    hop_count = 3

    while True:
        routers = get_routers(master_h, master_p)
        if len(routers) < 3:
            print("Pas assez de routeurs.")
            continue

        choice = input(f"Nb routeurs [min=3 | max={len(routers)}] (Entrée = {hop_count}) : ").strip()
        if choice:
            try:
                n = int(choice)
            except:
                print("Entrez un nombre.")
                continue
            if not 3 <= n <= len(routers):
                print("Valeur hors limites.")
                continue
            hop_count = n

        line = input("> ").strip()
        if ":" not in line:
            print("Format invalide.")
            continue

        dest, msg = line.split(":", 1)
        dest = dest.strip().upper()
        msg = msg.strip()

        if not dest or not msg:
            print("Destination/message vide.")
            continue

        info = request_client_info(master_h, master_p, dest)
        if not info:
            print("Destination inconnue.")
            continue
        d_ip, d_port = info

        path = random.sample(routers, hop_count)
        onion = build_onion(d_ip, d_port, cid, msg, path)

        entry = path[0]
        ok = send_onion(entry[1], entry[2], onion)
        print("Message envoyé." if ok else "Erreur d'envoi vers le routeur d'entrée.")


if __name__ == "__main__":
    main()
