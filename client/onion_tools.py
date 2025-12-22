# client/onion_tools.py
import socket


# ------------------------------------------------------
# Envoi paquet ASCII length + \n + payload
# ------------------------------------------------------
def send_packet(sock, payload: str):
    data = payload.encode()
    header = str(len(data)).encode() + b"\n"
    sock.sendall(header + data)


# ------------------------------------------------------
# Réception paquet ASCII length + payload
# ------------------------------------------------------
def recv_packet(sock):
    size_bytes = b""
    while not size_bytes.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            return None
        size_bytes += chunk

    try:
        size = int(size_bytes.strip())
    except:
        return None

    if size <= 0 or size > 20000:
        return None

    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk

    return data.decode(errors="ignore")


# ------------------------------------------------------
# Demande au MASTER la liste des routeurs
# Format attendu :
#   ROUTER_INFO|RID,IP,PORT,N,E;RID,IP,PORT,N,E;...
# Retour : [(rid, host, port, n, e), ...]
# ------------------------------------------------------
def get_routers(master_host, master_port):
    routers = []
    s = None
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((master_host, master_port))
        send_packet(s, "ROUTER_INFO_REQUEST")
        resp = recv_packet(s)

        if not resp or not resp.startswith("ROUTER_INFO|"):
            return []

        data = resp.split("|", 1)[1]
        for item in data.split(";"):
            if not item:
                continue
            try:
                rid, h, p, n, e = item.split(",")
                routers.append((rid, h, int(p), int(n), int(e)))
            except:
                continue

        return routers

    except:
        return []
    finally:
        try:
            if s:
                s.close()
        except:
            pass
