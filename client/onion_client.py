import json
import socket
import threading
from pathlib import Path
import sys
import random
import time

# Permet d'importer crypto.onion_rsa depuis ce script
PROJET_RACINE = Path(__file__).parents[1]
if str(PROJET_RACINE) not in sys.path:
    sys.path.insert(0, str(PROJET_RACINE))

from crypto.onion_rsa import encrypt_str, PublicKey

DOSSIER_LOGS = PROJET_RACINE / "logs"
DOSSIER_LOGS.mkdir(exist_ok=True)
TAILLE_MSG_MAX = 4096


def journaliser_evenement(client_id: str, niveau: str, evenement: str, **infos):
    """
    Log côté client : un fichier par client.
    Fichier : logs/client_<id>.log
    """
    fichier_log = DOSSIER_LOGS / f"client_{client_id}.log"
    entree = {
        "instant": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "niveau": niveau,
        "evenement": evenement,
        "client_id": client_id,
        **infos
    }
    try:
        ligne = json.dumps(entree, ensure_ascii=False)
    except TypeError:
        entree_str = {k: str(v) for k, v in entree.items()}
        ligne = json.dumps(entree_str, ensure_ascii=False)

    try:
        with fichier_log.open("a", encoding="utf-8") as f:
            f.write(ligne + "\n")
    except OSError:
        pass


def load_config():
    """Charge config/config.json à partir de la racine du projet."""
    config_path = PROJET_RACINE / "config" / "config.json"
    with config_path.open(encoding="utf-8") as f:
        return json.load(f)


def envoyer_json(sock: socket.socket, obj: dict, client_id: str) -> bool:
    """Envoie un objet JSON + \\n, avec journalisation en cas d'échec."""
    try:
        data = json.dumps(obj) + "\n"
    except (TypeError, ValueError) as e:
        journaliser_evenement(
            client_id,
            "ERREUR",
            "json_non_serialisable",
            erreur=str(e),
            objet=str(obj),
        )
        return False

    try:
        sock.sendall(data.encode("utf-8"))
        return True
    except OSError as e:
        journaliser_evenement(
            client_id,
            "ERREUR",
            "envoi_json_echec",
            erreur=str(e),
        )
        return False


def handle_delivery(conn: socket.socket, addr, my_id: str):
    """Reçoit un message final du dernier routeur."""
    try:
        f = conn.makefile("r", encoding="utf-8")
        line = f.readline()
        if not line:
            journaliser_evenement(
                my_id,
                "AVERTISSEMENT",
                "ligne_vide_reception",
                adresse=str(addr),
            )
            return

        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            journaliser_evenement(
                my_id,
                "AVERTISSEMENT",
                "json_invalide_reception",
                adresse=str(addr),
                erreur=str(e),
                ligne=line[:TAILLE_MSG_MAX],
            )
            print("[CLIENT] Message JSON invalide reçu :", e)
            return

        if msg.get("type") != "deliver_message":
            journaliser_evenement(
                my_id,
                "AVERTISSEMENT",
                "type_message_inattendu",
                type_message=msg.get("type"),
                contenu=str(msg),
            )
            print("[CLIENT] Message inconnu :", msg)
            return

        src = msg.get("from_id")
        text = msg.get("message")
        journaliser_evenement(
            my_id,
            "INFO",
            "message_recu",
            expediteur_id=src,
        )
        print(f"\n[CLIENT {my_id}] Message de {src} : {text}")
        print("> ", end="", flush=True)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def listen_incoming(my_id: str, host: str, port: int):
    """Thread d'écoute pour réception de messages."""
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((host, port))
    ls.listen()
    journaliser_evenement(
        my_id,
        "INFO",
        "client_en_ecoute",
        host=host,
        port=port,
    )
    print(f"[CLIENT {my_id}] En écoute sur {host}:{port}")

    while True:
        try:
            conn, addr = ls.accept()
        except OSError as e:
            journaliser_evenement(
                my_id,
                "ERREUR",
                "erreur_accept",
                erreur=str(e),
            )
            print(f"[CLIENT {my_id}] Erreur sur accept() :", e)
            break

        threading.Thread(
            target=handle_delivery,
            args=(conn, addr, my_id),
            daemon=True
        ).start()


def get_router_info_from_master(config, my_id: str):
    """Demande les infos + clés publiques des routeurs au master."""
    master_h = config["master"]["host"]
    master_p = config["master"]["port"]

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((master_h, master_p))
            envoyer_json(s, {"type": "router_info_request"}, my_id)
            f = s.makefile("r", encoding="utf-8")
            line = f.readline()
            if not line:
                raise ValueError("Réponse vide du master")

            info = json.loads(line)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        journaliser_evenement(
            my_id,
            "ERREUR",
            "echec_recuperation_routeurs_master",
            master=f"{master_h}:{master_p}",
            erreur=str(e),
        )
        raise

    if info.get("type") != "router_info":
        journaliser_evenement(
            my_id,
            "ERREUR",
            "type_reponse_inattendu_master",
            reponse=str(info),
        )
        raise ValueError("Master → réponse invalide")

    return info["routers"]


def main():
    config = load_config()

    # --- ID du client ---
    if len(sys.argv) >= 2:
        my_id = sys.argv[1].upper()
    else:
        my_id = input("Id du client (A,B) : ").strip().upper()

    # Infos client (A/B)
    try:
        client_cfg = next(c for c in config["clients"] if c["id"] == my_id)
    except StopIteration:
        print(f"[CLIENT] Id {my_id} introuvable dans config.json")
        journaliser_evenement(
            my_id,
            "ERREUR",
            "client_id_introuvable_config",
        )
        return

    listen_host = client_cfg["host"]
    listen_port = client_cfg["listen_port"]

    journaliser_evenement(
        my_id,
        "INFO",
        "client_demarre",
        host=listen_host,
        port=listen_port,
    )

    # Lancement du thread de réception
    threading.Thread(
        target=listen_incoming,
        args=(my_id, listen_host, listen_port),
        daemon=True
    ).start()

    # Récupération des routeurs dispos
    try:
        routers = get_router_info_from_master(config, my_id)
    except Exception as e:
        print("[CLIENT] Impossible de récupérer la liste des routeurs :", e)
        return

    routers = [r for r in routers if r.get("public_key") is not None]

    if len(routers) < 3:
        print("[CLIENT] Il faut au moins 3 routeurs actifs !")
        journaliser_evenement(
            my_id,
            "ERREUR",
            "nombre_routeurs_insuffisant",
            nb_routeurs=len(routers),
        )
        return

    print(f"[CLIENT {my_id}] Prêt. Format : DEST: message (ex: B: salut)")

    while True:
        txt = input("> ").strip()
        if txt.lower() in ("bye", "quit", "exit"):
            journaliser_evenement(my_id, "INFO", "commande_sortie")
            break

        if ":" not in txt:
            print("Format invalide. Utilise DEST: message")
            continue

        dest_id, msg = txt.split(":", 1)
        dest_id = dest_id.strip().upper()
        msg = msg.strip()

        # trouver infos du destinataire
        try:
            dest_cfg = next(c for c in config["clients"] if c["id"] == dest_id)
        except StopIteration:
            print("[CLIENT] Destinataire inconnu.")
            journaliser_evenement(
                my_id,
                "AVERTISSEMENT",
                "destinataire_inconnu",
                destinataire_id=dest_id,
            )
            continue

        # == 3 routeurs tirés ALÉATOIREMENT pour CHAQUE message ==
        path = routers[:]     # copie
        random.shuffle(path)  # mélange
        path = path[:3]       # on garde 3 routeurs

        # affichage du chemin
        chain_str = " → ".join(f"R{r['id']}" for r in path)
        print(f"[CLIENT {my_id}] Chemin choisi : {chain_str}")
        journaliser_evenement(
            my_id,
            "INFO",
            "chemin_construit",
            chemin=chain_str,
        )

        # conversion clé publique → (n, e)
        def to_pubkey(r) -> PublicKey:
            pk = r["public_key"]
            return pk["n"], pk["e"]

        pubkeys = [to_pubkey(r) for r in path]

        # ==========================================================
        # Construction des 3 couches d'oignon (C3 → C2 → C1)
        # ==========================================================

        # C3 : dernière couche, vers destinataire final
        layer3 = {
            "dest_host": dest_cfg["host"],
            "dest_port": dest_cfg["listen_port"],
            "from_id": my_id,
            "to_id": dest_id,
            "message": msg
        }
        C3 = encrypt_str(json.dumps(layer3), pubkeys[2])

        # C2 : vers le routeur 3
        layer2 = {
            "next_host": path[2]["host"],
            "next_port": path[2]["port"],
            "inner": C3
        }
        C2 = encrypt_str(json.dumps(layer2), pubkeys[1])

        # C1 : vers le routeur 2
        layer1 = {
            "next_host": path[1]["host"],
            "next_port": path[1]["port"],
            "inner": C2
        }
        C1 = encrypt_str(json.dumps(layer1), pubkeys[0])

        # envoi vers le premier routeur
        try:
            first = path[0]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((first["host"], first["port"]))
                envoyer_json(s, {"type": "onion_packet", "cipher": C1}, my_id)
            print(f"[CLIENT {my_id}] Message envoyé via {chain_str}")
            journaliser_evenement(
                my_id,
                "INFO",
                "message_envoye",
                destinataire_id=dest_id,
                chemin=chain_str,
            )
        except Exception as e:
            print(f"[CLIENT] Erreur d’envoi : {e}")
            journaliser_evenement(
                my_id,
                "ERREUR",
                "erreur_envoi_message",
                destinataire_id=dest_id,
                erreur=str(e),
            )


if __name__ == "__main__":
    main()
