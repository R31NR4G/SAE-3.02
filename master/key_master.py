import socket
import struct
import threading
from pathlib import Path

CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")

# -----------------------------------------------------
# OUTILS
# -----------------------------------------------------

def load_node(node_id: str):
    """Lit noeuds.txt → (host, port)."""
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
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)

def recv_packet(sock: socket.socket):
    """Lit un paquet : 4 octets longueur + payload."""
    header = sock.recv(4)
    if len(header)<4:
        return None
    size = struct.unpack(">I", header)[0]
    if size<=0 or size>4096:
        return None
    data = b""
    while len(data)<size:
        chunk = sock.recv(size-len(data))
        if not chunk:
            return None
        data += chunk
    return data.decode(errors="ignore")

# -----------------------------------------------------
# MASTER
# -----------------------------------------------------

def handle_client(conn, addr, routers):
    try:
        while True:
            pkt = recv_packet(conn)
            if not pkt:
                break

            if pkt == "ROUTER_INFO_REQUEST":
                # Format: ROUTER_INFO|R1,ip,port,n,e;R2,ip,port,n,e;...
                parts=[]
                for rid, info in routers.items():
                    h,p,n,e = info
                    parts.append(f"{rid},{h},{p},{n},{e}")
                resp = "ROUTER_INFO|" + ";".join(parts)
                send_packet(conn, resp)

            elif pkt.startswith("REGISTER|"):
                # REGISTER|R1|host|port|n|e
                _, rid, h, p, n, e = pkt.split("|")
                routers[rid] = (h,int(p),int(n),int(e))
                print(f"[MASTER] Routeur {rid} enregistré.")

            else:
                print("[MASTER] Message inconnu :", pkt)

    finally:
        conn.close()
        print("[MASTER] Connexion fermée :", addr)

def main():
    host, port = load_node("MASTER")
    routers = {}  # rid → (host,port,n,e)

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    s.bind((host, port))
    s.listen()
    print(f"[MASTER] En écoute sur {host}:{port}")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn,addr,routers), daemon=True).start()

if __name__ == "__main__":
    main()
