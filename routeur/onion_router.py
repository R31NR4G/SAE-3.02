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


def load_config():
    """Charge config/config.json à partir de la racine du projet."""
    config_path = PROJET_RACINE / "config" / "config.json"
    with config_path.open(encoding="utf-8") as f:
        return json.load(f)


def envoyer_json(sock: socket.socket, obj: dict, routeur_id: int) -> bool:
    """Envoie un objet JSON + \\n, avec journalisation en cas d'échec."""
    try:
        data = json.dumps(obj) + "\n"
    except (TypeError, ValueError) as e:
        journaliser_evenement(
            routeur_id,
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
            routeur_id,
            "ERREUR",
            "envoi_json_echec",
            erreur=str(e),
        )
        return False


def valider_couche_routeur(inner: dict, routeur_id: int) -> bool:
    """
    Valide la structure d'une couche déchiffrée.
    Retourne True si OK, False sinon (avec logs).
    """
    # Cas 1 : encore un routeur dans la chaîne
    if "next_host" in inner:
        champs = ["next_host", "next_port", "inner"]
        for c in champs:
            if c not in inner:
                journaliser_evenement(
                    routeur_id,
                    "AVERTISSEMENT",
                    "couche_incomplete",
                    champ_manquant=c,
                    contenu=str(inner),
                )
                return False
        if not isinstance(inner["next_port"], int) or not (1 <= inner["next_port"] <= 65535):
            journaliser_evenement(
                routeur_id,
                "AVERTISSEMENT",
                "port_suivant_invalide",
                port=inner["next_port"],
            )
            return False
        if not isinstance(inner["inner"], str):
            journaliser_evenement(
                routeur_id,
                "AVERTISSEMENT",
                "champ_inner_non_chaine",
                type_inner=str(type(inner["inner"])),
            )
            return False
        return True

    # Cas 2 : dernier routeur -> livraison au client
    champs_final = ["dest_host", "dest_port", "from_id", "to_id", "message"]
    for c in champs_final:
        if c not in inner:
            journaliser_evenement(
                routeur_id,
                "AVERTISSEMENT",
                "couche_finale_incomplete",
                champ_manquant=c,
                contenu=str(inner),
            )
            return False
    if not isinstance(inner["dest_port"], int) or not (1 <= inner["dest_port"] <= 65535):
        journaliser_evenement(
            routeur_id,
            "AVERTISSEMENT",
            "port_destination_invalide",
            port=inner["dest_port"],
        )
        return False
    return True


def forward_to(host: str, port: int, cipher: str, routeur_id: int):
    """Ouvre une connexion courte vers le prochain routeur et envoie le paquet onion."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            ok = envoyer_json(s, {"type": "onion_packet", "cipher": cipher}, routeur_id)
        if ok:
            journaliser_evenement(
                routeur_id,
                "INFO",
                "paquet_transfere",
                prochain_hop=f"{host}:{port}",
            )
    except OSError as e:
        journaliser_evenement(
            routeur_id,
            "ERREUR",
            "echec_transfert_routeur_suivant",
            prochain_hop=f"{host}:{port}",
            erreur=str(e),
        )


def handle_onion(conn: socket.socket, addr, private_key: PrivateKey, routeur_id: int):
    """
    Gère un paquet onion :
      - déchiffre une couche avec la clé privée du routeur (RSA)
      - si 'next_host' présent -> forward au routeur suivant
      - sinon -> dernier routeur : envoie au client destination
    """
    journaliser_evenement(
        routeur_id,
        "INFO",
        "paquet_onion_recu",
        adresse=str(addr),
    )
    print(f"[ROUTEUR {routeur_id}] Paquet onion reçu de {addr}")
    try:
        f = conn.makefile("r", encoding="utf-8")
        line = f.readline()
        if not line:
            journaliser_evenement(
                routeur_id,
                "AVERTISSEMENT",
                "ligne_vide",
                adresse=str(addr),
            )
            return

        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            journaliser_evenement(
                routeur_id,
                "AVERTISSEMENT",
                "json_invalide",
                adresse=str(addr),
                erreur=str(e),
                ligne=line[:TAILLE_MSG_MAX],
            )
            print(f"[ROUTEUR {routeur_id}] JSON invalide reçu :", e)
            return

        if msg.get("type") != "onion_packet":
            journaliser_evenement(
                routeur_id,
                "AVERTISSEMENT",
                "type_message_inattendu",
                type_message=msg.get("type"),
                contenu=str(msg),
            )
            print(f"[ROUTEUR {routeur_id}] Type inconnu :", msg)
            return

        cipher = msg.get("cipher")
        if not isinstance(cipher, str):
            journaliser_evenement(
                routeur_id,
                "AVERTISSEMENT",
                "cipher_manquant_ou_invalide",
                contenu=str(msg),
            )
            return

        # --- déchiffrement RSA de la couche de ce routeur ---
        try:
            inner_plain = decrypt_str(cipher, private_key)
        except Exception as e:
            journaliser_evenement(
                routeur_id,
                "ERREUR",
                "erreur_dechiffrement_rsa",
                erreur=str(e),
            )
            print(f"[ROUTEUR {routeur_id}] Erreur de déchiffrement RSA :", e)
            return

        # inner_plain est une chaîne JSON
        try:
            inner = json.loads(inner_plain)
        except json.JSONDecodeError as e:
            journaliser_evenement(
                routeur_id,
                "AVERTISSEMENT",
                "couche_dechiffree_non_json",
                erreur=str(e),
                contenu=inner_plain[:TAILLE_MSG_MAX],
            )
            return

        if not valider_couche_routeur(inner, routeur_id):
            # la validation logue déjà l'erreur
            return

        # Cas 1 : encore un routeur dans la chaîne
        if "next_host" in inner:
            nh = inner["next_host"]
            np = inner["next_port"]
            nc = inner["inner"]
            print(f"[ROUTEUR {routeur_id}] Transfert vers prochain routeur {nh}:{np}")
            forward_to(nh, np, nc, routeur_id)

        # Cas 2 : dernier routeur -> on envoie au client destinataire
        else:
            dest_h = inner["dest_host"]
            dest_p = inner["dest_port"]
            src = inner["from_id"]
            dst = inner["to_id"]
            plain_msg = inner["message"]

            journaliser_evenement(
                routeur_id,
                "INFO",
                "dernier_saut",
                destinataire_id=dst,
                client_adresse=f"{dest_h}:{dest_p}",
            )
            print(f"[ROUTEUR {routeur_id}] Dernier saut, envoi au client {dst} sur {dest_h}:{dest_p}")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((dest_h, dest_p))
                    envoyer_json(
                        s,
                        {
                            "type": "deliver_message",
                            "from_id": src,
                            "to_id": dst,
                            "message": plain_msg
                        },
                        routeur_id,
                    )
            except OSError as e:
                journaliser_evenement(
                    routeur_id,
                    "ERREUR",
                    "echec_connexion_client_final",
                    destinataire_id=dst,
                    client_adresse=f"{dest_h}:{dest_p}",
                    erreur=str(e),
                )

    except Exception as e:
        journaliser_evenement(
            routeur_id,
            "ERREUR",
            "exception_non_capturee_handle_onion",
            erreur=str(e),
        )
        print(f"[ROUTEUR {routeur_id}] Erreur handle_onion :", e)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    config = load_config()

    # --- choix de l'id du routeur ---
    if len(sys.argv) >= 2:
        router_id = int(sys.argv[1])
    else:
        router_id = int(input("Id du routeur (ex: 1,2,3,...) : ").strip())

    # récupération des infos de ce routeur dans la config
    try:
        r_info = next(r for r in config["routeurs"] if r["id"] == router_id)
    except StopIteration:
        print(f"[ROUTEUR] Id {router_id} introuvable dans config.json")
        journaliser_evenement(
            router_id,
            "ERREUR",
            "routeur_id_introuvable_config",
        )
        return

    r_host = r_info["host"]
    r_port = r_info["port"]

    # --- génération de la paire de clés RSA ---
    public_key: PublicKey
    private_key: PrivateKey
    public_key, private_key = generate_keypair(bits=2048)

    n_pub, e = public_key
    journaliser_evenement(
        router_id,
        "INFO",
        "cles_rsa_generees",
        n=str(n_pub),
        e=str(e),
    )
    print(f"[ROUTEUR {router_id}] Clé publique RSA générée.")
    print(f"  n = {n_pub}")
    print(f"  e = {e}")

    # --- connexion au master pour envoyer la clé publique ---
    master_h = config["master"]["host"]
    master_p = config["master"]["port"]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ms:
            ms.connect((master_h, master_p))
            envoyer_json(ms, {
                "type": "router_register",
                "router_id": router_id,
                "public_key": {
                    "n": n_pub,
                    "e": e
                }
            }, router_id)
        journaliser_evenement(
            router_id,
            "INFO",
            "cle_publique_envoyee_master",
            master=f"{master_h}:{master_p}",
        )
        print(f"[ROUTEUR {router_id}] Clé publique envoyée au master")
    except OSError as e:
        journaliser_evenement(
            router_id,
            "ERREUR",
            "echec_connexion_master",
            master=f"{master_h}:{master_p}",
            erreur=str(e),
        )
        print(f"[ROUTEUR {router_id}] Impossible de joindre le master : {e}")

    # --- écoute des paquets onion ---
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((r_host, r_port))
    listen_sock.listen()
    journaliser_evenement(
        router_id,
        "INFO",
        "routeur_en_ecoute",
        host=r_host,
        port=r_port,
    )
    print(f"[ROUTEUR {router_id}] En écoute sur {r_host}:{r_port}")

    try:
        while True:
            try:
                conn, addr = listen_sock.accept()
            except OSError as e:
                journaliser_evenement(
                    router_id,
                    "ERREUR",
                    "erreur_accept",
                    erreur=str(e),
                )
                print(f"[ROUTEUR {router_id}] Erreur sur accept() :", e)
                break

            t = threading.Thread(
                target=handle_onion,
                args=(conn, addr, private_key, router_id),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        journaliser_evenement(router_id, "INFO", "arret_clavier")
        print(f"\n[ROUTEUR {router_id}] Arrêt demandé (Ctrl+C)")
    finally:
        try:
            listen_sock.close()
        except OSError:
            pass
        journaliser_evenement(router_id, "INFO", "routeur_ferme")
        print(f"[ROUTEUR {router_id}] Fermé.")


if __name__ == "__main__":
    main()
