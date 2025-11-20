import json
import socket
import threading
from pathlib import Path


def load_config():
    config_path = Path(__file__).parents[1] / "config" / "config.json"
    with config_path.open(encoding="utf-8") as f:
        return json.load(f)


def send_json(sock: socket.socket, obj: dict):
    data = json.dumps(obj) + "\n"
    sock.sendall(data.encode("utf-8"))


def handle_connection(conn: socket.socket, addr, state):
    print(f"[MASTER] Connexion de {addr}")
    try:
        f = conn.makefile("r", encoding="utf-8")
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                print("[MASTER] JSON invalide")
                continue

            mtype = msg.get("type")

            # --- enregistrement d'un routeur ---
            if mtype == "register_router":
                rid = msg["router_id"]
                pubkey = msg["public_key"]
                state["routers"][rid] = pubkey
                print(f"[MASTER] Routeur {rid} enregistré, clé={pubkey}")

            # --- demande de la part d'un client ---
            elif mtype == "get_router_info":
                config = state["config"]
                routers_cfg = config["routeurs"]

                routers = []
                for r in routers_cfg:
                    rid = r["id"]
                    routers.append({
                        "id": rid,
                        "host": r["host"],
                        "port": r["port"],
                        "public_key": state["routers"].get(rid)
                    })

                reply = {"type": "router_info", "routers": routers}
                send_json(conn, reply)
                print(f"[MASTER] Infos routeurs envoyées à {addr}")

            else:
                print("[MASTER] Type de message inconnu :", msg)

    except (ConnectionResetError, OSError):
        print("[MASTER] Connexion perdue avec", addr)
    finally:
        conn.close()
        print(f"[MASTER] Connexion fermée {addr}")


def main():
    config = load_config()
    host = config["master"]["host"]
    port = config["master"]["port"]

    state = {
        "config": config,
        "routers": {}   # id -> public_key
    }

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"[MASTER] En écoute sur {host}:{port}")

    try:
        while True:
            conn, addr = server_socket.accept()
            t = threading.Thread(
                target=handle_connection,
                args=(conn, addr, state),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[MASTER] Arrêt")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
