# client/onion_client.py
import socket
import threading
import random
import sys

from client.onion_tools import send_packet, recv_packet
from crypto.onion_rsa import encrypt_str


# ------------------------------------------------------
# Détection IP locale
# ------------------------------------------------------
def detect_local_ip(master_h, master_p):
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


# ------------------------------------------------------
# Réception messages
# ------------------------------------------------------
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


# ------------------------------------------------------
# MAIN
# ------------------------------------------------------
def main():
    # ===== OPTION 2 : arguments ligne de commande =====
    if len(sys.argv) >= 3:
        master_h = sys.argv[1]
        master_p = int(sys.argv[2])
    else:
        master_h = "127.0.0.1"
        master_p = 5000

    # serveur client
    serv = socket.socket()
    serv.bind(("0.0.0.0", 0))
    serv.listen()

    real_port = serv.getsockname()[1]
    advertise_host = detect_local_ip(master_h, master_p)

    # enregistrement client
    s = socket.socket()
    try:
        s.connect((master_h, master_p))
        send_packet(s, f"REGISTER_CLIENT_DYNAMIC|{advertise_host}|{real_port}")
        rep = recv_packet(s)
    except:
        print("[CLIENT] Impossible de s'enregistrer auprès du master.")
        return
    finally:
        s.close()

    if not rep or not rep.startswith("CLIENT_REGISTERED|"):
        print("[CLIENT] Enregistrement refusé.")
        return

    cid = rep.split("|")[1]
    print(f"[CLIENT {cid}] En écoute sur {advertise_host}:{real_port}")
    print("Format : DEST: message (ex: C1: salut)")

    threading.Thread(target=listen_incoming, args=(serv,), daemon=True).start()

    while True:
        line = input("> ").strip()
        if ":" not in line:
            print("Format invalide.")
            continue

        dest, msg = line.split(":", 1)
        dest = dest.strip().upper()
        msg = msg.strip()

        # demande info client destination
        s = socket.socket()
        try:
            s.connect((master_h, master_p))
            send_packet(s, f"CLIENT_INFO_REQUEST|{dest}")
            rep = recv_packet(s)
        except:
            print("Master injoignable.")
            continue
        finally:
            s.close()

        if not rep or not rep.startswith("CLIENT_INFO|OK|"):
            print("Destination inconnue.")
            continue

        _, _, d_ip, d_port = rep.split("|")

        # récup routeurs
        s = socket.socket()
        try:
            s.connect((master_h, master_p))
            send_packet(s, "ROUTER_INFO_REQUEST")
            rep = recv_packet(s)
        finally:
            s.close()

        routers = []
        if rep and rep.startswith("ROUTER_INFO|"):
            for item in rep.split("|", 1)[1].split(";"):
                if not item:
                    continue
                rid, h, p, n, e = item.split(",")
                routers.append((rid, h, int(p), int(n), int(e)))

        if len(routers) < 3:
            print("Pas assez de routeurs.")
            continue

        path = random.sample(routers, 3)

        # onion
        plain = f"{d_ip}|{d_port}|{cid}|{msg}"
        cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))

        for i in range(len(path) - 2, -1, -1):
            nh, np = path[i + 1][1], path[i + 1][2]
            cipher = encrypt_str(f"{nh}|{np}|{cipher}", (path[i][3], path[i][4]))

        entry = path[0]
        s = socket.socket()
        s.connect((entry[1], entry[2]))
        send_packet(s, "ONION|" + cipher)
        s.close()

        print("Message envoyé.")


if __name__ == "__main__":
    main()
