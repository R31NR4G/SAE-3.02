import socket
import struct
import threading
import sys
from pathlib import Path

# RSA simplifié sans JSON
from crypto.onion_rsa import generate_keypair, decrypt_str

CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")

# -----------------------------------------------------
# OUTILS
# -----------------------------------------------------

def load_node(node_id: str):
    with CONFIG.open() as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#"):
                continue
            nid, host, port = line.split(";")
            if nid.upper()==node_id.upper():
                return host, int(port)
    raise RuntimeError(f"Noeud {node_id} introuvable.")

def send_packet(sock: socket.socket, payload: str):
    data = payload.encode()
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_packet(sock: socket.socket):
    header = sock.recv(4)
    if len(header)<4:
        return None
    size = struct.unpack(">I", header)[0]
    if size<=0 or size>16384:
        return None
    data=b""
    while len(data)<size:
        chunk=sock.recv(size-len(data))
        if not chunk:
            return None
        data+=chunk
    return data.decode(errors="ignore")

# -----------------------------------------------------
# ROUTEUR
# -----------------------------------------------------

def handle_onion(conn, addr, private_key, router_id):
    try:
        pkt = recv_packet(conn)
        if not pkt:
            return

        if not pkt.startswith("ONION|"):
            return

        cipher = pkt.split("|",1)[1]

        # Déchiffre la couche
        plain = decrypt_str(cipher, private_key)
        # Format intermédiaire :
        # next_host|next_port|cipher_suivant
        # Format final :
        # dest_host|dest_port|from_id|message

        parts = plain.split("|")
        if len(parts)==3:
            # couche intermédiaire
            nh, np, inner = parts
            try:
                np=int(np)
            except:
                print("[ROUTEUR] Port invalide.")
                return
            forward(router_id, nh, np, inner)

        elif len(parts)==4:
            # dernière couche
            dh, dp, fid, msg = parts
            try:
                dp=int(dp)
            except:
                print("[ROUTEUR] Port dest invalide.")
                return

            deliver(router_id, dh, dp, fid, msg)

        else:
            print("[ROUTEUR] Couche invalide :", plain)

    finally:
        conn.close()


def forward(rid, host, port, cipher):
    try:
        s=socket.socket()
        s.connect((host,port))
        send_packet(s, "ONION|" + cipher)
        s.close()
        print(f"[ROUTEUR {rid}] Forward -> {host}:{port}")
    except:
        print(f"[ROUTEUR {rid}] Échec forward.")


def deliver(rid, host, port, from_id, msg):
    try:
        s=socket.socket()
        s.connect((host,port))
        send_packet(s, f"DELIVER|{from_id}|{msg}")
        s.close()
        print(f"[ROUTEUR {rid}] Message livré -> {host}:{port}")
    except:
        print(f"[ROUTEUR {rid}] Échec livraison.")


def main():
    if len(sys.argv)>=2:
        rid = sys.argv[1].upper()
    else:
        rid = input("Id routeur R1,R2... : ").upper()

    r_host, r_port = load_node(rid)
    m_host, m_port = load_node("MASTER")

    # clés RSA
    pub, priv = generate_keypair()
    n,e = pub

    # enregistrement au master
    try:
        s=socket.socket()
        s.connect((m_host,m_port))
        msg=f"REGISTER|{rid}|{r_host}|{r_port}|{n}|{e}"
        send_packet(s,msg)
        s.close()
    except:
        print("[ROUTEUR] Impossible de s'inscrire au master.")

    # écoute
    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    serv.bind((r_host,r_port))
    serv.listen()
    print(f"[ROUTEUR {rid}] En écoute sur {r_host}:{r_port}")

    while True:
        conn,addr=serv.accept()
        threading.Thread(target=handle_onion,
                         args=(conn,addr,priv,rid),
                         daemon=True).start()


if __name__=="__main__":
    main()
