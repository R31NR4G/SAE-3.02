import random
from math import gcd
from sympy import isprime  # autorisé dans la SAE

# ---------------------------------------------------------
# GÉNÉRATION DES CLÉS
# ---------------------------------------------------------

def _generate_prime(bits):
    """Génère un nombre premier de 'bits' bits."""
    assert bits >= 8
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))  # force bit haut
        candidate |= 1                  # force impair
        if isprime(candidate):
            return candidate


def generate_keypair(bits=2048):
    """
    Génère une paire de clés RSA (publique, privée).
    Retourne :
       public_key = (n, e)
       private_key = (n, d)
    """
    half = bits // 2
    p = _generate_prime(half)
    q = _generate_prime(half)
    while q == p:
        q = _generate_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        # fallback si jamais 65537 ne fonctionne pas
        while True:
            e = random.randrange(3, phi - 1)
            if e % 2 == 1 and gcd(e, phi) == 1:
                break

    d = pow(e, -1, phi)

    return (n, e), (n, d)


# ---------------------------------------------------------
# CHIFFREMENT BAS NIVEAU
# ---------------------------------------------------------

def encrypt_bytes(plaintext, public_key):
    """
    Chiffre un bloc (bytes) avec RSA.
    Retourne des bytes.
    """
    n, e = public_key
    m = int.from_bytes(plaintext, "big")

    if m >= n:
        raise ValueError("Bloc RSA trop long")

    c = pow(m, e, n)
    out = c.to_bytes((c.bit_length() + 7) // 8, "big")
    return out if out else b"\x00"


def decrypt_bytes(ciphertext, private_key):
    """Déchiffre un bloc de bytes RSA."""
    n, d = private_key
    c = int.from_bytes(ciphertext, "big")
    m = pow(c, d, n)
    out = m.to_bytes((m.bit_length() + 7) // 8, "big")
    return out if out else b""


# ---------------------------------------------------------
# CHIFFREMENT TEXTE (SANS JSON)
# ---------------------------------------------------------

def encrypt_str(plaintext, public_key, encoding="utf-8"):
    """
    Chiffre une chaîne en utilisant RSA multi-blocs.
    Retourne : "hex1:hex2:hex3"
    """
    data = plaintext.encode(encoding)
    n, _ = public_key

    max_block = (n.bit_length() // 8) - 1  # marge de sécurité
    blocks_hex = []

    for i in range(0, len(data), max_block):
        block = data[i:i + max_block]
        encrypted = encrypt_bytes(block, public_key)
        blocks_hex.append(encrypted.hex())

    return ":".join(blocks_hex)


def decrypt_str(cipher, private_key, encoding="utf-8"):
    """
    Déchiffre "hex1:hex2:hex3" → string UTF-8.
    """
    cipher = cipher.strip()
    if cipher == "":
        return ""

    parts = cipher.split(":")
    plain_bytes = bytearray()

    for part in parts:
        if not part:
            continue
        cipher_block = bytes.fromhex(part)
        plain_bytes.extend(decrypt_bytes(cipher_block, private_key))

    return plain_bytes.decode(encoding)
