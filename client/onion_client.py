import socket
import threading
import random
import os

from crypto.onion_rsa import encrypt_str
from client.onion_tools import send_packet, recv_packet, get_routers


def detect_local_ip(master_h, master_p):
    try:
        s = socket.socket()
        s.connect((master_h, master_p))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def listen_incoming(cid_ref, serv):
    while True:
        conn, _ = serv.accept()
        pkt = recv_packet(conn)
        conn.close()
        if pkt and pkt.startswith("DELIVER|"):
            _, frm, msg = pkt.split("|", 2)
            print(f"\n[{frm}] {msg}")
            print("> ", end="", flush=True)


def main():
    master_h = os.getenv("MASTER_HOST", "127.0.0.1")
    master_p = int(os.getenv("MASTER_PORT", "5000"))

    serv = socket.socket()
    serv.bind(("0.0.0.0", 0))
    serv.listen()

    real_port = serv.getsockname()[1]
    advertise_host = detect_local_ip(master_h, master_p)

    s = socket.socket()
    s.connect((master_h, master_p))
    send_packet(s, f"REGISTER_CLIENT_DYNAMIC|{advertise_host}|{real_port}")
    rep = recv_packet(s)
    s.close()

    cid = rep.split("|")[1] if rep else "C?"
    print(f"[CLIENT {cid}] En écoute sur {advertise_host}:{real_port}")

    threading.Thread(
        target=listen_incoming,
        args=([cid], serv),
        daemon=True
    ).start()

    hop_count = 3

    while True:
        routers = get_routers(master_h, master_p)

        max_hops = len(routers)
        if max_hops < 3:
            print("Pas assez de routeurs.")
            continue

        choice = input(
            f"Nombre de routeurs [min=3 | max={max_hops}] (Entrée = {hop_count}) : "
        ).strip()

        if choice:
            try:
                n = int(choice)
                if not 3 <= n <= max_hops:
                    print("Valeur hors limites.")
                    continue
                hop_count = n
            except ValueError:
                continue

        line = input("> ").strip()
        if ":" not in line:
            print("Format: DEST: message")
            continue

        dest, msg = line.split(":", 1)
        dest = dest.strip()
        msg = msg.strip()

        s = socket.socket()
        s.connect((master_h, master_p))
        send_packet(s, f"CLIENT_INFO_REQUEST|{dest}")
        rep = recv_packet(s)
        s.close()

        if not rep or not rep.startswith("CLIENT_INFO|OK|"):
            print("Destination inconnue.")
            continue

        _, _, d_ip, d_port = rep.split("|")

        path = random.sample(routers, hop_count)

        plain = f"{d_ip}|{d_port}|{cid}|{msg}"
        cipher = encrypt_str(plain, (path[-1][3], path[-1][4]))

        for i in range(len(path) - 2, -1, -1):
            nh, np = path[i + 1][1], path[i + 1][2]
            cipher = encrypt_str(
                f"{nh}|{np}|{cipher}",
                (path[i][3], path[i][4])
            )

        entry = path[0]
        s = socket.socket()
        s.connect((entry[1], entry[2]))
        send_packet(s, "ONION|" + cipher)
        s.close()

        print("Message envoyé.")


if __name__ == "__main__":
    main()
