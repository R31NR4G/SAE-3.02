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


def envoyer_json(sock: socket.socket, obj: dict, client_id: str) -> bool:
    try:
        data = json.dumps(obj) + "\n"
    except (TypeError, ValueError) as e:
        journaliser_evenement(
            client_id, "ERREUR", "json_non_serialisable",
            erreur=str(e), objet=str(obj),
        )
        return False

    try:
        sock.sendall(data.encode("utf-8"))
        return True
    except OSError as e:
        journaliser_evenement(
            client_id, "ERREUR", "envoi_json_echec", erreur=str(e),
        )
        return False


def handle_delivery(conn: socket.socket, addr, my_id: str):
    try:
        f = conn.makefile("r", encoding="utf-8")
        line = f.readline()
        if not line:
            journaliser_evenement(
                my_id, "AVERTISSEMENT", "ligne_vide_reception",
                adresse=str(addr),
            )
            return

        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            journaliser_evenement(
                my_id, "AVERTISSEMENT", "json_invalide_reception",
                adresse=str(addr), erreur=str(e),
                ligne=line[:TAILLE_MSG_MAX],
            )
            print("[CLIENT] Message JSON invalide reçu :", e)
            return

        if msg.get("type") != "deliver_message":
            journaliser_evenement(
                my_id, "AVERTISSEMENT", "type_message_inattendu",
                type_message=msg.get("type"), contenu=str(msg),
            )
            print("[CLIENT] Message inconnu :", msg)
            return

        src = msg.get("from_id")
        text = msg.get("message")
        journaliser_evenement(
            my_id, "INFO", "message_recu", expediteur_id=src,
        )
        print(f"\n[CLIENT {my_id}] Message de {src} : {text}")
        print("> ", end="", flush=True)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def listen_incoming(my_id: str, host: str, port: int):
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((host, port))
    ls.listen()
    journaliser_evenement(
        my_id, "INFO", "client_en_ecoute",
        host=host, port=port,
    )
    print(f"[CLIENT {my_id}] En écoute sur {host}:{port}")

    while True:
        try:
            conn, addr = ls.accept()
        except OSError as e:
            journaliser_evenement(
                my_id, "ERREUR", "erreur_accept", erreur=str(e),
            )
            print(f"[CLIENT {my_id}] Erreur sur accept() :", e)
            break

        threading.Thread(
            target=handle_delivery,
            args=(conn, addr, my_id),
            daemon=True
        ).start()


def get_router_info_from_master(master_h: str, master_p: int, my_id: str):
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
            my_id, "ERREUR", "echec_recuperation_routeurs_master",
            master=f"{master_h}:{master_p}", erreur=str(e),
        )
        raise

    if info.get("type") != "router_info":
        journaliser_evenement(
            my_id, "ERREUR", "type_reponse_inattendu_master",
            reponse=str(info),
        )
        raise ValueError("Master → réponse invalide")

    return info["routers"]


def main():
    # ID du client
    if len(sys.argv) >= 2:
        my_id = sys.argv[1].upper()
    else:
        my_id = input("Id du client (A,B,...) : ").strip().upper()

    # Adresse locale
    listen_host = input("Adresse IP locale de ce client : ").strip() or "127.0.0.1"
    listen_port_str = input("Port d'écoute local de ce client : ").strip() or "7000"
    listen_port = int(listen_port_str)

    journaliser_evenement(
        my_id, "INFO", "client_demarre",
        host=listen_host, port=listen_port,
    )

    # Adresse du master
    master_h = input("Adresse IP du MASTER : ").strip() or "127.0.0.1"
    master_p_str = input("Port du MASTER : ").strip() or "5000"
    master_p = int(master_p_str)

    # Thread écoute
    threading.Thread(
        target=listen_incoming,
        args=(my_id, listen_host, listen_port),
        daemon=True
    ).start()

    # Récupération des routeurs
    try:
        routers = get_router_info_from_master(master_h, master_p, my_id)
    except Exception as e:
        print("[CLIENT] Impossible de récupérer la liste des routeurs :", e)
        return

    routers = [r for r in routers if r.get("public_key") is not None]

    if len(routers) < 1:
        print("[CLIENT] Il faut au moins 1 routeur actif !")
        journaliser_evenement(
            my_id, "ERREUR", "nombre_routeurs_insuffisant",
            nb_routeurs=len(routers),
        )
        return

    # Dictionnaire local pour mémoriser les autres clients
    dest_infos = {}

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

        # Adresse du destinataire (mémorisée après la 1re fois)
        if dest_id not in dest_infos:
            dh = input(f"Adresse IP de {dest_id} : ").strip() or "127.0.0.1"
            dp_str = input(f"Port d'écoute de {dest_id} : ").strip() or "7000"
            dp = int(dp_str)
            dest_infos[dest_id] = (dh, dp)
            journaliser_evenement(
                my_id, "INFO", "destinataire_enregistre_localement",
                destinataire_id=dest_id, host=dh, port=dp,
            )

        dest_host, dest_port = dest_infos[dest_id]

        # === NOUVEAU : on prend TOUS les routeurs, mais dans un ordre aléatoire ===
        path = routers[:]      # copie
        random.shuffle(path)   # on mélange, mais on ne coupe pas

        # affichage du chemin (tous les routeurs utilisés)
        chain_str = " → ".join(f"R{r['id']}" for r in path)
        print(f"[CLIENT {my_id}] Chemin choisi : {chain_str}")
        journaliser_evenement(
            my_id, "INFO", "chemin_construit", chemin=chain_str,
        )

        # Clés publiques
        def to_pubkey(r) -> PublicKey:
            pk = r["public_key"]
            return pk["n"], pk["e"]

        pubkeys = [to_pubkey(r) for r in path]

        # ==========================================================
        # Construction de l'oignon avec N routeurs (N = len(path))
        # ==========================================================
        # Dernière couche : vers le client final
        inner = {
            "dest_host": dest_host,
            "dest_port": dest_port,
            "from_id": my_id,
            "to_id": dest_id,
            "message": msg
        }
        cipher = encrypt_str(json.dumps(inner), pubkeys[-1])

        # Couches intermédiaires : on remonte la chaîne à l'envers
        # path[i] enverra vers path[i+1]
        for i in range(len(path) - 2, -1, -1):
            layer = {
                "next_host": path[i + 1]["host"],
                "next_port": path[i + 1]["port"],
                "inner": cipher
            }
            cipher = encrypt_str(json.dumps(layer), pubkeys[i])

        # cipher = couche d'entrée (C1) pour le premier routeur
        try:
            first = path[0]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((first["host"], first["port"]))
                envoyer_json(s, {"type": "onion_packet", "cipher": cipher}, my_id)
            print(f"[CLIENT {my_id}] Message envoyé via {chain_str}")
            journaliser_evenement(
                my_id, "INFO", "message_envoye",
                destinataire_id=dest_id, chemin=chain_str,
            )
        except Exception as e:
            print(f"[CLIENT] Erreur d’envoi : {e}")
            journaliser_evenement(
                my_id, "ERREUR", "erreur_envoi_message",
                destinataire_id=dest_id, erreur=str(e),
            )


if __name__ == "__main__":
    main()
