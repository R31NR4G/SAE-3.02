import socket
import threading
import sys
import random
import os

from crypto.onion_rsa import encrypt_str


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

    if size <= 0 or size > 20000:
        return None

    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data.decode(errors="ignore")


def detect_local_ip(master_h, master_p):
    try:
        tmp = socket.socket()
        tmp.connect((master_h, master_p))
        ip = tmp.getsockname()[0]
        tmp.close()
        return ip
    except:
        return "127.0.0.1"


def listen_incoming(my_id_ref, server_socket):
    while True:
        try:
            conn, _ = server_socket.accept()
        except OSError:
            return
        pkt = recv_packet(conn)
        conn.close()

        if pkt and pkt.startswith("DELIVER|"):
            _, fid, msg = pkt.split("|", 2)
            cid = my_id_ref[0] or "?"
            print(f"\n[CLIENT {cid}] Message de {fid} : {msg}")
            print("> ", end="", flush=True)


def register_client_dynamic(master_h, master_p, advertise_host, listen_port):
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
                routers.append((rid, h, int(p), int(n), int(e)))
        return routers
    except:
        return []


def main():
    master_h = "127.0.0.1"
    master_p = 5000

    if len(sys.argv) >= 3 and "." in sys.argv[1]:
        master_h = sys.argv[1]
        master_p = int(sys.argv[2])

    if os.getenv("MASTER_HOST"):
        master_h = os.getenv("MASTER_HOST")
    if os.getenv("MASTER_PORT"):
        master_p = int(os.getenv("MASTER_PORT"))

    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind(("0.0.0.0", 0))
    serv.listen()

    real_port = serv.getsockname()[1]
    advertise_host = detect_local_ip(master_h, master_p)

    my_id_ref = [None]
    t = threading.Thread(target=listen_incoming, args=(my_id_ref, serv), daemon=True)
    t.start()

    cid = register_client_dynamic(master_h, master_p, advertise_host, real_port) or "C?"
    my_id_ref[0] = cid

    print(f"[CLIENT {cid}] En écoute sur {advertise_host}:{real_port}")
    print("Format : DEST: message (ex: C2: salut)\n")

    hop_count = 3

    try:
        while True:
            routers = get_routers(master_h, master_p)
            max_hops = len(routers)

            if max_hops < 3:
                print("Pas assez de routeurs disponibles (min 3).")
                continue

            choice = input(f"Nombre de routeurs [min=3 | max={max_hops}] (Entrée = {hop_count}) : ").strip()
            if choice:
                try:
                    new_count = int(choice)
                    if 3 <= new_count <= max_hops:
                        hop_count = new_count
                    else:
                        print("Valeur hors limites.")
                        continue
                except ValueError:
                    print("Veuillez entrer un nombre valide.")
                    continue

            line = input("> ").strip()

            if not line:
                print("Format invalide. Exemple : C2: Bonjour")
                continue

            if ":" not in line:
                print("Format invalide. Exemple : C2: Bonjour")
                continue

            dest, msg = line.split(":", 1)
            dest = dest.strip().upper()
            msg = msg.strip()

            if not dest or not msg:
                print("Format invalide. Exemple : C2: Bonjour")
                continue

            resolved = resolve_client(master_h, master_p, dest)
            if not resolved:
                print(f"Destination inconnue : {dest}")
                continue
            d_host, d_port = resolved

            path = random.sample(routers, hop_count)

            plain = f"{d_host}|{d_port}|{cid}|{msg}"
            last = path[-1]
            cipher = encrypt_str(plain, (last[3], last[4]))

            for i in range(len(path) - 2, -1, -1):
                nh, np = path[i + 1][1], path[i + 1][2]
                cipher = encrypt_str(f"{nh}|{np}|{cipher}", (path[i][3], path[i][4]))

            entry = path[0]
            try:
                s = socket.socket()
                s.connect((entry[1], entry[2]))
                send_packet(s, "ONION|" + cipher)
                s.close()
                print("[CLIENT] Message envoyé.")
            except Exception as e:
                print(f"[ERREUR] Envoi impossible : {e}")

    except KeyboardInterrupt:
        print(f"\n[CLIENT {cid}] Arrêt demandé.")

    finally:
        try:
            serv.close()
        except:
            pass


if __name__ == "__main__":
    main()
