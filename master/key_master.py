import json
import socket
import threading
from pathlib import Path
import time

# --- Constantes simples ---
TAILLE_MSG_MAX = 4096

# Dossier de logs : <racine_projet>/logs/master.log
PROJET_RACINE = Path(__file__).parents[1]
DOSSIER_LOGS = PROJET_RACINE / "logs"
DOSSIER_LOGS.mkdir(exist_ok=True)
FICHIER_LOG = DOSSIER_LOGS / "master.log"


def journaliser_evenement(niveau: str, evenement: str, **infos):
    """
    Écrit un événement de log au format JSON dans le fichier de logs du master.
    niveau   : "INFO" / "AVERTISSEMENT" / "ERREUR"
    evenement: nom court de l'événement (ex: "connexion_ouverte", "routeur_enregistre")
    infos    : champs supplémentaires (ex: adresse, routeur_id, etc.)
    """
    entree = {
        "instant": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "niveau": niveau,
        "evenement": evenement,
        **infos
    }
    try:
        ligne = json.dumps(entree, ensure_ascii=False)
    except TypeError:
        # fallback si un objet non-sérialisable se glisse dans infos
        entree_str = {k: str(v) for k, v in entree.items()}
        ligne = json.dumps(entree_str, ensure_ascii=False)

    try:
        with FICHIER_LOG.open("a", encoding="utf-8") as f:
            f.write(ligne + "\n")
    except OSError:
        # On ne fait jamais planter le master à cause du log.
        pass


def envoyer_json(sock: socket.socket, obj: dict) -> bool:
    """Envoie un objet JSON suivi d'un \\n, avec journalisation en cas d'échec."""
    try:
        data = json.dumps(obj) + "\n"
    except (TypeError, ValueError) as e:
        journaliser_evenement(
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
            "ERREUR",
            "envoi_json_echec",
            erreur=str(e),
        )
        return False


def handle_connection(conn: socket.socket, addr, state: dict):
    """
    Gère une connexion (routeur ou client) dans un thread.

    Messages possibles :
      - router_register      : un routeur envoie son id + host + port + clé publique RSA
      - router_info_request  : un client demande la liste des routeurs
      - router_info          : réponse envoyée au client
    """
    journaliser_evenement("INFO", "connexion_ouverte", adresse=str(addr))
    print(f"[MASTER] Connexion de {addr}")
    try:
        f = conn.makefile("r", encoding="utf-8")
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                msg = json.loads(line)
            except json.JSONDecodeError as e:
                journaliser_evenement(
                    "AVERTISSEMENT",
                    "json_invalide",
                    adresse=str(addr),
                    erreur=str(e),
                    ligne=line[:TAILLE_MSG_MAX],
                )
                print("[MASTER] JSON invalide reçu de", addr)
                continue

            mtype = msg.get("type")
            if not mtype:
                journaliser_evenement(
                    "AVERTISSEMENT",
                    "type_message_manquant",
                    adresse=str(addr),
                    message=msg,
                )
                print("[MASTER] Message sans champ 'type' de", addr)
                continue

            # 1) Enregistrement d'un routeur : id + host + port + clé publique RSA
            if mtype == "router_register":
                try:
                    rid = msg["router_id"]
                    pubkey = msg["public_key"]   # dict {"n": ..., "e": ...}
                    r_host = msg["host"]
                    r_port = msg["port"]

                    # petite validation de base
                    if not isinstance(pubkey, dict) or "n" not in pubkey or "e" not in pubkey:
                        raise ValueError("clé publique mal formée")
                    if not isinstance(r_host, str):
                        raise ValueError("host invalide")
                    if not isinstance(r_port, int) or not (1 <= r_port <= 65535):
                        raise ValueError("port invalide")

                    state["routers"][rid] = {
                        "id": rid,
                        "host": r_host,
                        "port": r_port,
                        "public_key": pubkey,
                    }

                    journaliser_evenement(
                        "INFO",
                        "routeur_enregistre",
                        routeur_id=rid,
                        host=r_host,
                        port=r_port,
                    )
                    print(f"[MASTER] Routeur {rid} enregistré, {r_host}:{r_port}, clé_publique={pubkey}")
                except (KeyError, ValueError) as e:
                    journaliser_evenement(
                        "AVERTISSEMENT",
                        "routeur_register_invalide",
                        adresse=str(addr),
                        erreur=str(e),
                        message=msg,
                    )
                    print("[MASTER] Message router_register invalide de", addr, ":", e)

            # 2) Demande d'info routeurs par un client
            elif mtype == "router_info_request":
                # On renvoie simplement la liste dynamique des routeurs enregistrés
                routers = list(state["routers"].values())

                reply = {
                    "type": "router_info",
                    "routers": routers
                }
                envoyer_json(conn, reply)
                journaliser_evenement(
                    "INFO",
                    "infos_routeurs_envoyees",
                    adresse=str(addr),
                    nb_routeurs=len(routers),
                )
                print(f"[MASTER] Infos routeurs envoyées à {addr} ({len(routers)} routeurs)")

            else:
                journaliser_evenement(
                    "AVERTISSEMENT",
                    "type_message_inconnu",
                    adresse=str(addr),
                    type_message=mtype,
                )
                print("[MASTER] Type de message inconnu :", msg)

    except (ConnectionResetError, OSError) as e:
        journaliser_evenement(
            "AVERTISSEMENT",
            "connexion_perdue",
            adresse=str(addr),
            erreur=str(e),
        )
        print("[MASTER] Connexion perdue avec", addr)
    except Exception as e:
        journaliser_evenement(
            "ERREUR",
            "exception_non_capturee_connexion",
            adresse=str(addr),
            erreur=str(e),
        )
        print("[MASTER] Erreur inattendue pour", addr, ":", e)
    finally:
        try:
            conn.close()
        except OSError:
            pass
        journaliser_evenement("INFO", "connexion_fermee", adresse=str(addr))
        print(f"[MASTER] Connexion fermée {addr}")


def main():
    # --- IP / port du master demandés à l'utilisateur ---
    host = input("Adresse IP du MASTER (ex: 0.0.0.0) : ").strip() or "0.0.0.0"
    port_str = input("Port du MASTER (ex: 5000) : ").strip() or "5000"
    port = int(port_str)

    # state partagé entre les threads
    state = {
        # id_routeur -> {id, host, port, public_key}
        "routers": {}
    }

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen()
    journaliser_evenement(
        "INFO",
        "master_demarre",
        host=host,
        port=port,
    )
    print(f"[MASTER] En écoute sur {host}:{port}")

    try:
        while True:
            try:
                conn, addr = server_socket.accept()
            except OSError as e:
                journaliser_evenement(
                    "ERREUR",
                    "erreur_accept",
                    erreur=str(e),
                )
                print("[MASTER] Erreur sur accept():", e)
                break

            t = threading.Thread(
                target=handle_connection,
                args=(conn, addr, state),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        journaliser_evenement("INFO", "arret_clavier")
        print("\n[MASTER] Arrêt demandé (Ctrl+C)")
    finally:
        try:
            server_socket.close()
        except OSError:
            pass
        journaliser_evenement("INFO", "master_ferme")
        print("[MASTER] Fermé.")


if __name__ == "__main__":
    main()
