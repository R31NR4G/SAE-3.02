import json
import socket
import threading
from pathlib import Path
import sys

# --- pour pouvoir importer crypto.onion_rsa même si on lance client/onion_client.py directement ---
PROJECT_ROOT = Path(__file__).parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from crypto.onion_rsa import encrypt_str, PublicKey  # RSA


def load_config():
    """Charge config/config.json à partir de la racine du projet."""
    config_path = Path(__file__).parents[1] / "config" / "config.json"
    with config_path.open(encoding="utf-8") as f:
        return json.load(f)


def send_json(sock: socket.socket, obj: dict):
    data = json.dumps(obj) + "\n"
    sock.sendall(data.encode("utf-8"))


def handle_delivery(conn: socket.socket, addr, my_id: str):
    """Gère un message final reçu depuis le dernier routeur."""
    try:
        f = conn.makefile("r", encoding="utf-8")
        line = f.readline()
        if not line:
            return

        msg = json.loads(line)
        if msg.get("type") != "deliver_message":
            print("[CLIENT] Message inconnu reçu :", msg)
            return

        src = msg["from_id"]
        m = msg["message"]
        print(f"\n[CLIENT {my_id}] Message de {src} : {m}")
        print("> ", end="", flush=True)
    finally:
        conn.close()


def listen_incoming(my_id: str, listen_host: str, listen_port: int):
    """Thread d’écoute pour recevoir les messages envoyés par les routeurs."""
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
        print(f"\n[CLIENT {my_id}] Arrêt de l'écoute")
    finally:
        ls.close()


def get_router_info_from_master(config):
    """Demande au master la liste des routeurs et leurs clés publiques RSA."""
    master_h = config["master"]["host"]
    master_p = config["master"]["port"]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((master_h, master_p))
        send_json(s, {"type": "router_info_request"})
        f = s.makefile("r", encoding="utf-8")
        line = f.readline()
        info = json.loads(line)
        if info.get("type") != "router_info":
            raise ValueError("Réponse inattendue du master")
        return info["routers"]


def main():
    config = load_config()

    # --- id du client ---
    if len(sys.argv) >= 2:
        my_id = sys.argv[1].upper()
    else:
        my_id = input("Id du client (A,B) : ").strip().upper()

    clients_cfg = config["clients"]
    try:
        my_info = next(c for c in clients_cfg if c["id"] == my_id)
    except StopIteration:
        print(f"[CLIENT] Id {my_id} introuvable dans la config.")
        return

    listen_host = my_info["host"]
    listen_port = my_info["listen_port"]

    # Thread de réception
    t_listen = threading.Thread(
        target=listen_incoming,
        args=(my_id, listen_host, listen_port),
        daemon=True
    )
    t_listen.start()

    # --- récupère infos et clés publiques RSA des routeurs ---
    routers = get_router_info_from_master(config)

    # on ne garde que ceux qui ont une clé publique
    routers_with_key = [r for r in routers if r["public_key"] is not None]

    if len(routers_with_key) < 3:
        print("[CLIENT] Moins de 3 routeurs avec clé publique disponibles.")
        return

    # Chemin R1 -> R2 -> R3 = 3 premiers routeurs avec clé
    r1, r2, r3 = routers_with_key[0], routers_with_key[1], routers_with_key[2]

    # reconstruction des clés publiques RSA (n, e)
    def to_pubkey(r) -> PublicKey:
        pk = r["public_key"]
        return pk["n"], pk["e"]

    k1: PublicKey = to_pubkey(r1)
    k2: PublicKey = to_pubkey(r2)
    k3: PublicKey = to_pubkey(r3)

    print(f"[CLIENT {my_id}] Chemin utilisé : R{r1['id']} -> R{r2['id']} -> R{r3['id']}")
    print(f"[CLIENT {my_id}] Clés publiques récupérées.")
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

            # Recherche du destinataire (A ou B)
            try:
                dest_info = next(c for c in clients_cfg if c["id"] == dest_id)
            except StopIteration:
                print(f"[CLIENT] Destinataire {dest_id} inconnu.")
                continue

            dest_host = dest_info["host"]
            dest_port = dest_info["listen_port"]

            # --- construction des couches C3, C2, C1 avec RSA ---
            # C3 = Enc_{K3} ( {dest_host, dest_port, from_id, to_id, message} )
            layer3 = {
                "dest_host": dest_host,
                "dest_port": dest_port,
                "from_id": my_id,
                "to_id": dest_id,
                "message": msg_plain
            }
            C3 = encrypt_str(json.dumps(layer3), k3)

            # C2 = Enc_{K2} ( Dest(R3) + C3 )
            layer2 = {
                "next_host": r3["host"],
                "next_port": r3["port"],
                "inner": C3
            }
            C2 = encrypt_str(json.dumps(layer2), k2)

            # C1 = Enc_{K1} ( Dest(R2) + C2 )
            layer1 = {
                "next_host": r2["host"],
                "next_port": r2["port"],
                "inner": C2
            }
            C1 = encrypt_str(json.dumps(layer1), k1)

            # Envoi de C1 au premier routeur du chemin
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((r1["host"], r1["port"]))
                    send_json(s, {"type": "onion_packet", "cipher": C1})
                print(f"[CLIENT {my_id}] Message envoyé vers {dest_id} via R{r1['id']}->R{r2['id']}->R{r3['id']}")
            except OSError as e:
                print(f"[CLIENT {my_id}] Erreur lors de l'envoi : {e}")

    except KeyboardInterrupt:
        print("\n[CLIENT] Interruption clavier.")
    finally:
        print(f"[CLIENT {my_id}] Fin du client.")


if __name__ == "__main__":
    main()
