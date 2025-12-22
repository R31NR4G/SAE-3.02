import mariadb
from pathlib import Path

CONFIG = (Path(__file__).parents[1] / "config" / "noeuds.txt")


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


def get_connection():
    host, port = load_node("DB")

    try:
        conn = mariadb.connect(
            user="sae",
            password="sae",
            host=host,
            port=port,
            database="onion_project"
        )
        return conn

    except mariadb.Error as e:
        print(f"[DB] Erreur connexion MariaDB : {e}")
        raise


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

    conn.commit()
    conn.close()
    print("[DB] Base initialisée.")


def reset_routers():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM routers;")
    conn.commit()
    conn.close()
    print("[DB] Table routers vidée.")


def delete_router(name: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM routers WHERE name = ?;", (name,))
    conn.commit()
    conn.close()


def add_router(name: str, ip: str, port: int, public_key: str):
    """
    Remplace si le même name existe déjà (évite doublons quand on relance un routeur).
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("DELETE FROM routers WHERE name = ?;", (name,))
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
