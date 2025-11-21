import json
import socket
import threading
from pathlib import Path
import sys


def load_config():
    config_path = Path(__file__).parents[1] / "config" / "config.json"
    with config_path.open(encoding="utf-8") as f:
        return json.load(f)


def encrypt(plaintext: str, key: int) -> str:
    data = plaintext.encode("utf-8")
    xored = bytes(b ^ key for b in data)
    return xored.hex()


def decrypt(cipher_hex: str, key: int) -> str:
    data = bytes.fromhex(cipher_hex)
    xored = bytes(b ^ key for b in data)
    return xored.decode("utf-8")


def send_json(sock: socket.socket, obj: dict):
    data = json.dumps(obj) + "\n"
    sock.sendall(data.encode("utf-8"))


def listen_incoming(my_id: str, listen_host: str, listen_port: int):
    """Thread qui écoute les messages que lui envoie R3."""
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.bind((listen_host, listen_port))
    ls.listen()
    print(f"[CLIENT {my_id}] En écoute sur {listen_host}:{listen_port}")

    try:
        while True:
            conn, addr = ls.accept()
            t = threading.Thread(
                target=handle_delivery,
                args=(conn, addr, my_id),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        print(f"\n[CLIENT {my_id}] Arrêt écoute")
    finally:
        ls.close()


def handle_delivery(conn: socket.socket, addr, my_id: str):
    try:
        f = conn.makefile("r", encoding="utf-8")
        line = f.readline()
        if not line:
            return
        msg = json.loads(line)
        if msg.get("type") != "deliver":
            print("[CLIENT] Message inconnu reçu", msg)
            return
        src = msg["from_id"]
        m = msg["message"]
        print(f"\n[CLIENT {my_id}] Message de {src} : {m}")
        print("> ", end="", flush=True)
    finally:
        conn.close()


def get_router_info_from_master(config):
    master_h = config["master"]["host"]
    master_p = config["master"]["port"]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((master_h, master_p))
        send_json(s, {"type": "get_router_info"})
        f = s.makefile("r", encoding="utf-8")
        line = f.readline()
        info = json.loads(line)
        return info["routers"]


def main():
    config = load_config()

    # --- id du client ---
    if len(sys.argv) >= 2:
        my_id = sys.argv[1].upper()
    else:
        my_id = input("Id du client (A,B,C) : ").strip().upper()

    clients_cfg = config["clients"]
    my_info = next(c for c in clients_cfg if c["id"] == my_id)
    listen_host = my_info["host"]
    listen_port = my_info["listen_port"]

    # thread de réception
    t_listen = threading.Thread(
        target=listen_incoming,
        args=(my_id, listen_host, listen_port),
        daemon=True
    )
    t_listen.start()

    # --- récupère infos et clés des routeurs ---
    routers = get_router_info_from_master(config)
    # on suppose un chemin R1 -> R2 -> R3 = premiers 3 routeurs
    r1, r2, r3 = routers[0], routers[1], routers[2]
    k1, k2, k3 = r1["public_key"], r2["public_key"], r3["public_key"]

    print(f"[CLIENT {my_id}] Chemin utilisé : R{r1['id']} -> R{r2['id']} -> R{r3['id']}")
    print(f"[CLIENT {my_id}] Clés (simplifiées) : {k1}, {k2}, {k3}")

    # boucle d'envoi
    print("Format : DEST: message   (ex: B: salut)")
    try:
        while True:
            txt = input("> ").strip()
            if txt.lower() in ("bye", "quit", "exit"):
                break

            if ":" not in txt:
                print("Format invalide, utilise DEST: message")
                continue

            dest_id, msg_plain = txt.split(":", 1)
            dest_id = dest_id.strip().upper()
            msg_plain = msg_plain.strip()

            dest_info = next(c for c in clients_cfg if c["id"] == dest_id)
            dest_host = dest_info["host"]
            dest_port = dest_info["listen_port"]

            # --- construction des couches C3, C2, C1 ---
            # C3 = Enc_{K3} ( Dest(Client B), M )
            layer3 = {
                "dest_host": dest_host,
                "dest_port": dest_port,
                "from_id": my_id,
                "to_id": dest_id,
                "message": msg_plain
            }
            C3 = encrypt(json.dumps(layer3), k3)

            # C2 = Enc_{K2} ( Dest(R3), C3 )
            layer2 = {
                "next_host": r3["host"],
                "next_port": r3["port"],
                "inner": C3
            }
            C2 = encrypt(json.dumps(layer2), k2)

            # C1 = Enc_{K1} ( Dest(R2), C2 )
            layer1 = {
                "next_host": r2["host"],
                "next_port": r2["port"],
                "inner": C2
            }
            C1 = encrypt(json.dumps(layer1), k1)

            # envoi de C1 à R1
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((r1["host"], r1["port"]))
                send_json(s, {"type": "onion", "cipher": C1})

            print(f"[CLIENT {my_id}] Message envoyé vers {dest_id} via R{r1['id']}->{r2['id']}->{r3['id']}")


    except KeyboardInterrupt:
        print("\n[CLIENT] Interruption")
    finally:
        print(f"[CLIENT {my_id}] Fin du client.")


if __name__ == "__main__":
    main()
