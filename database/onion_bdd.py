import mariadb
from pathlib import Path

CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")


# -----------------------------------------------------
# Lit noeuds.txt → (host, port)
# Compatible avec tout le reste du projet
# -----------------------------------------------------
def load_node(node_id: str):
    with CONFIG.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            nid, host, port = line.split(";")
            if nid.upper() == node_id.upper():
                return host, int(port)

    raise RuntimeError(f"Noeud {node_id} introuvable dans noeuds.txt.")


# -----------------------------------------------------
# Connexion MariaDB sans JSON, sans IP en dur
# -----------------------------------------------------
def get_connection():
    host, port = load_node("DB")

    try:
        conn = mariadb.connect(
            user="root",          # le testeur changera si besoin
            password="toto",      # tu peux aussi mettre "" pour Linux
            host=host,
            port=port,
            database="onion_project"
        )
        return conn

    except mariadb.Error as e:
        print(f"[DB] Erreur connexion MariaDB : {e}")
        raise


# -----------------------------------------------------
# Création tables minimales
# -----------------------------------------------------
def init_database():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS routers (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(50) NOT NULL,
            ip VARCHAR(100) NOT NULL,
            port INT NOT NULL,
            public_key TEXT NOT NULL
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS routing_table (
            id INT PRIMARY KEY AUTO_INCREMENT,
            source VARCHAR(50) NOT NULL,
            next_hop VARCHAR(50) NOT NULL
        );
    """)

    conn.commit()
    conn.close()
    print("[DB] Base initialisée.")


# -----------------------------------------------------
# Fonctions ROUTERS
# -----------------------------------------------------
def add_router(name: str, ip: str, port: int, public_key: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO routers (name, ip, port, public_key)
        VALUES (?, ?, ?, ?);
    """, (name, ip, port, public_key))

    conn.commit()
    conn.close()


def get_routers():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT name, ip, port, public_key FROM routers;")
    rows = cur.fetchall()

    conn.close()
    return rows


# -----------------------------------------------------
# Fonctions ROUTING TABLE
# -----------------------------------------------------
def add_route(source: str, next_hop: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO routing_table (source, next_hop)
        VALUES (?, ?);
    """, (source, next_hop))

    conn.commit()
    conn.close()


def get_routes():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT source, next_hop FROM routing_table;")
    rows = cur.fetchall()

    conn.close()
    return rows
