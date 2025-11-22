import json
import socket
import threading
from pathlib import Path
import random
import sys


def load_config():
    """Charge config/config.json à partir de la racine du projet."""
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
    """Ouvre une connexion courte vers le prochain routeur et envoie le paquet onion."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        send_json(s, {"type": "onion_packet", "cipher": cipher})


def handle_onion(conn: socket.socket, addr, key: int):
    """
    Gère un paquet onion :
      - déchiffre une couche avec la clé du routeur
      - si 'next_host' présent -> forward au routeur suivant
      - sinon -> dernier routeur : envoie au client destination
    """
    print(f"[ROUTEUR] Paquet onion reçu de {addr}")
    try:
        f = conn.makefile("r", encoding="utf-8")
        line = f.readline()
        if not line:
            return

        msg = json.loads(line)
        if msg.get("type") != "onion_packet":
            print("[ROUTEUR] Type inconnu :", msg)
            return

        cipher = msg["cipher"]
        inner_plain = decrypt(cipher, key)
        inner = json.loads(inner_plain)

        # Cas 1 : encore un routeur dans la chaîne
        if "next_host" in inner:
            nh = inner["next_host"]
            np = inner["next_port"]
            nc = inner["inner"]
            print(f"[ROUTEUR] Transfert vers prochain routeur {nh}:{np}")
            forward_to(nh, np, nc)

        # Cas 2 : dernier routeur -> on envoie au client destinataire
        else:
            dest_h = inner["dest_host"]
            dest_p = inner["dest_port"]
            src = inner["from_id"]
            dst = inner["to_id"]
            plain_msg = inner["message"]

            print(f"[ROUTEUR] Dernier saut, envoi au client {dst} sur {dest_h}:{dest_p}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((dest_h, dest_p))
                send_json(s, {
                    "type": "deliver_message",
                    "from_id": src,
                    "to_id": dst,
                    "message": plain_msg
                })

    except Exception as e:
        print("[ROUTEUR] Erreur handle_onion :", e)
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

    # Clé simplifiée (1..255)
    key = random.randint(1, 255)
    print(f"[ROUTEUR {router_id}] Clé (simplifiée) = {key}")

    # --- connexion au master pour envoyer la clé publique ---
    master_h = config["master"]["host"]
    master_p = config["master"]["port"]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ms:
            ms.connect((master_h, master_p))
            send_json(ms, {
                "type": "router_register",
                "router_id": router_id,
                "public_key": key
            })
        print(f"[ROUTEUR {router_id}] Clé envoyée au master")
    except OSError as e:
        print(f"[ROUTEUR {router_id}] Impossible de joindre le master : {e}")

    # --- écoute des paquets onion ---
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
        print(f"\n[ROUTEUR {router_id}] Arrêt demandé (Ctrl+C)")
    finally:
        listen_sock.close()
        print(f"[ROUTEUR {router_id}] Fermé.")


if __name__ == "__main__":
    main()
