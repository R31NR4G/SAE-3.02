import json
import socket
import threading
from pathlib import Path
import random
import sys


def load_config():
    config_path = Path(__file__).parents[1] / "config" / "config.json"
    with config_path.open(encoding="utf-8") as f:
        return json.load(f)


# === "chiffrement" jouet (XOR + hex) ===

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


def forward_to(host: str, port: int, cipher: str):
    """Ouvre une connexion TCP courte, envoie le cipher, ferme."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        send_json(s, {"type": "onion", "cipher": cipher})


def handle_onion(conn: socket.socket, addr, key: int):
    print(f"[R] Message onion reçu de {addr}")
    try:
        f = conn.makefile("r", encoding="utf-8")
        line = f.readline()
        if not line:
            return

        msg = json.loads(line)
        if msg.get("type") != "onion":
            print("[R] Type inconnu :", msg)
            return

        cipher = msg["cipher"]
        inner_plain = decrypt(cipher, key)
        inner = json.loads(inner_plain)

        # Deux cas:
        # 1) On a encore un routeur intermédiaire
        if "next_host" in inner:
            nh = inner["next_host"]
            np = inner["next_port"]
            nc = inner["inner"]
            print(f"[R] Forward vers prochain routeur {nh}:{np}")
            forward_to(nh, np, nc)

        # 2) Dernier routeur : on envoie au client destination
        else:
            dest_h = inner["dest_host"]
            dest_p = inner["dest_port"]
            plain_msg = inner["message"]
            src = inner["from_id"]
            dst = inner["to_id"]

            print(f"[R] Dernier saut, envoi au client {dst} sur {dest_h}:{dest_p}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((dest_h, dest_p))
                send_json(s, {
                    "type": "deliver",
                    "from_id": src,
                    "to_id": dst,
                    "message": plain_msg
                })

    except Exception as e:
        print("[R] Erreur handle_onion :", e)
    finally:
        conn.close()


def main():
    config = load_config()

    # --- choix de l'id du routeur ---
    if len(sys.argv) >= 2:
        router_id = int(sys.argv[1])
    else:
        router_id = int(input("Id du routeur (1,2,3) : ").strip())

    r_info = next(r for r in config["routeurs"] if r["id"] == router_id)
    r_host = r_info["host"]
    r_port = r_info["port"]

    # clé "publique" simplifiée
    key = random.randint(1, 255)
    print(f"[ROUTEUR {router_id}] Clé (simplifiée) = {key}")

    # --- connexion au master pour envoyer la clé ---
    master_h = config["master"]["host"]
    master_p = config["master"]["port"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ms:
        ms.connect((master_h, master_p))
        send_json(ms, {
            "type": "register_router",
            "router_id": router_id,
            "public_key": key
        })
    print(f"[ROUTEUR {router_id}] Clé envoyée au master")

    # --- écoute pour les messages onion ---
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.bind((r_host, r_port))
    listen_sock.listen()
    print(f"[ROUTEUR {router_id}] En écoute sur {r_host}:{r_port}")

    try:
        while True:
            conn, addr = listen_sock.accept()
            t = threading.Thread(
                target=handle_onion,
                args=(conn, addr, key),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        print(f"\n[ROUTEUR {router_id}] Arrêt")
    finally:
        listen_sock.close()


if __name__ == "__main__":
    main()
