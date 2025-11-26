import json
import socket
import threading
from pathlib import Path
import sys
import time

# --- pour pouvoir importer crypto.onion_rsa même en lançant ce fichier directement ---
PROJET_RACINE = Path(__file__).parents[1]
if str(PROJET_RACINE) not in sys.path:
    sys.path.insert(0, str(PROJET_RACINE))

from crypto.onion_rsa import decrypt_str, generate_keypair, PrivateKey, PublicKey

# Dossier de logs : <racine_projet>/logs/routeur_<id>.log
DOSSIER_LOGS = PROJET_RACINE / "logs"
DOSSIER_LOGS.mkdir(exist_ok=True)

TAILLE_MSG_MAX = 8192


def journaliser_evenement(routeur_id: int, niveau: str, evenement: str, **infos):
    """
    Log dédié au routeur.
    Fichier : logs/routeur_<id>.log
    """
    fichier_log = DOSSIER_LOGS / f"routeur_{routeur_id}.log"
    entree = {
        "instant": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "niveau": niveau,
        "evenement": evenement,
        "routeur_id": routeur_id,
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


def envoyer_json(sock: socket.socket, obj: dict, routeur_id: int) -> bool:
    """Envoie un objet JSON + \\n, avec journalisation en cas d'échec."""
    try:
        data = json.dumps(obj) + "\n"
    except (TypeError, ValueError) as e:
        journaliser_evenement(
            routeur_id, "ERREUR", "json_non_serialisable",
            erreur=str(e), objet=str(obj),
        )
        return False

    try:
        sock.sendall(data.encode("utf-8"))
        return True
    except OSError as e:
        journaliser_evenement(
            routeur_id, "ERREUR", "envoi_json_echec", erreur=str(e)
        )
        return False


def valider_couche_routeur(inner: dict, routeur_id: int) -> bool:
    """
    Valide la structure d'une couche déchiffrée.
    Retourne True si OK, False sinon.
    """
    # Cas : routeur intermédiaire
    if "next_host" in inner:
        champs = ["next_host", "next_port", "inner"]
        for c in champs:
            if c not in inner:
                journaliser_evenement(
                    routeur_id, "AVERTISSEMENT", "couche_incomplete",
                    champ_manquant=c, contenu=str(inner)
                )
                return False
        return True

    # Cas : dernier routeur
    champs_final = ["dest_host", "dest_port", "from_id", "to_id", "message"]
    for c in champs_final:
        if c not in inner:
            journaliser_evenement(
                routeur_id, "AVERTISSEMENT", "couche_finale_incomplete",
                champ_manquant=c, contenu=str(inner)
            )
            return False
    return True


def forward_to(host: str, port: int, cipher: str, routeur_id: int):
    """Forward le paquet au routeur suivant."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            envoyer_json(s, {"type": "onion_packet", "cipher": cipher}, routeur_id)
        journaliser_evenement(routeur_id, "INFO", "paquet_transfere",
                              prochain_hop=f"{host}:{port}")
    except OSError as e:
        journaliser_evenement(routeur_id, "ERREUR",
                              "echec_transfert_routeur_suivant",
                              prochain_hop=f"{host}:{port}", erreur=str(e))


def handle_onion(conn: socket.socket, addr, private_key: PrivateKey, routeur_id: int):
    """Décapsule une couche d'oignon et route le paquet."""
    journaliser_evenement(routeur_id, "INFO", "paquet_onion_recu",
                          adresse=str(addr))
    print(f"[ROUTEUR {routeur_id}] Paquet onion reçu de {addr}")

    try:
        f = conn.makefile("r", encoding="utf-8")
        line = f.readline()
        if not line:
            return

        msg = json.loads(line)
        if msg.get("type") != "onion_packet":
            return

        cipher = msg.get("cipher")
        if not isinstance(cipher, str):
            return

        # Déchiffrement RSA
        inner_plain = decrypt_str(cipher, private_key)
        inner = json.loads(inner_plain)

        if not valider_couche_routeur(inner, routeur_id):
            return

        # Routeur intermédiaire
        if "next_host" in inner:
            print(f"[ROUTEUR {routeur_id}] → Vers {inner['next_host']}:{inner['next_port']}")
            forward_to(inner["next_host"], inner["next_port"], inner["inner"], routeur_id)

        # Dernier routeur
        else:
            print(f"[ROUTEUR {routeur_id}] Dernier saut vers {inner['dest_host']}:{inner['dest_port']}")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((inner["dest_host"], inner["dest_port"]))
                    envoyer_json(
                        s,
                        {
                            "type": "deliver_message",
                            "from_id": inner["from_id"],
                            "to_id": inner["to_id"],
                            "message": inner["message"]
                        },
                        routeur_id
                    )
            except OSError as e:
                journaliser_evenement(routeur_id, "ERREUR",
                                      "echec_connexion_client_final",
                                      erreur=str(e))

    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    # ID du routeur
    if len(sys.argv) >= 2:
        router_id = int(sys.argv[1])
    else:
        router_id = int(input("Id du routeur : ").strip())

    # Adresse locale
    r_host = input("Adresse IP locale du routeur : ").strip() or "127.0.0.1"
    r_port = int(input("Port local du routeur : ").strip() or "6000")

    # Adresse du master
    master_h = input("Adresse IP du MASTER : ").strip() or "127.0.0.1"
    master_p = int(input("Port du MASTER : ").strip() or "5000")

    # Génération des clés RSA
    public_key, private_key = generate_keypair(bits=2048)
    n_pub, e = public_key

    print(f"[ROUTEUR {router_id}] Clé publique RSA générée.")
    print(f"  n = {n_pub}")
    print(f"  e = {e}")

    # Enregistrement au master
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ms:
            ms.connect((master_h, master_p))
            envoyer_json(ms, {
                "type": "router_register",
                "router_id": router_id,
                "host": r_host,
                "port": r_port,
                "public_key": {"n": n_pub, "e": e}
            }, router_id)
        print(f"[ROUTEUR {router_id}] Infos envoyées au master")
    except Exception as e:
        print(f"[ROUTEUR {router_id}] ERREUR envoi au master : {e}")

    # Socket d'écoute
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((r_host, r_port))
    listen_sock.listen()

    print(f"[ROUTEUR {router_id}] En écoute sur {r_host}:{r_port}")

    try:
        while True:
            conn, addr = listen_sock.accept()
            threading.Thread(
                target=handle_onion,
                args=(conn, addr, private_key, router_id),
                daemon=True
            ).start()

    except KeyboardInterrupt:
        print(f"\n[ROUTEUR {router_id}] Arrêt demandé (Ctrl+C)")

    finally:
        try:
            listen_sock.close()
        except OSError:
            pass
        print(f"[ROUTEUR {router_id}] Fermé.")


if __name__ == "__main__":
    main()
