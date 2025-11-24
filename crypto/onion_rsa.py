# crypto/onion_rsa.py
# RSA très simplifié pour le projet SAE 3.02 (pédagogique)

import json
import random
from math import gcd
from typing import Tuple

from sympy import isprime  # autorisé dans le sujet

PublicKey = Tuple[int, int]   # (n, e)
PrivateKey = Tuple[int, int]  # (n, d)


# ---------- Génération de clés ----------

def _generate_prime(bits: int) -> int:
    """Génère un nombre premier de 'bits' bits en utilisant sympy.isprime."""
    assert bits >= 8, "Taille de prime trop petite"
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))  # force le bit de poids fort
        candidate |= 1                  # force impair
        if isprime(candidate):
            return candidate


def generate_keypair(bits: int = 2048) -> tuple[PublicKey, PrivateKey]:
    """
    Génère une paire de clés RSA (publique, privée).
    bits = taille du modulo n.
    """
    half = bits // 2

    p = _generate_prime(half)
    q = _generate_prime(half)
    while q == p:
        q = _generate_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)

    # exposant public classique
    e = 65537
    if gcd(e, phi) != 1:
        # fallback si jamais 65537 ne convient pas
        while True:
            e = random.randrange(3, phi - 1)
            if e % 2 == 1 and gcd(e, phi) == 1:
                break

    # inverse modulaire
    d = pow(e, -1, phi)

    public_key: PublicKey = (n, e)
    private_key: PrivateKey = (n, d)
    return public_key, private_key


# ---------- Chiffrement bas niveau (un seul bloc) ----------

def encrypt_bytes(plaintext: bytes, public_key: PublicKey) -> bytes:
    """
    Chiffre des bytes avec RSA et renvoie des bytes (représentation du nombre chiffré).
    ATTENTION : le message doit tenir sur un seul bloc (< n).
    """
    n, e = public_key
    m = int.from_bytes(plaintext, "big")
    if m >= n:
        raise ValueError("Message trop long pour cette taille de clé RSA (bloc)")
    c = pow(m, e, n)
    if c == 0:
        return b"\x00"
    return c.to_bytes((c.bit_length() + 7) // 8, "big")


def decrypt_bytes(ciphertext: bytes, private_key: PrivateKey) -> bytes:
    """Déchiffre des bytes chiffrés par encrypt_bytes."""
    n, d = private_key
    c = int.from_bytes(ciphertext, "big")
    m = pow(c, d, n)
    if m == 0:
        return b""
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


# ---------- Surcouche pratique (str <-> liste de blocs hex) ----------

def encrypt_str(plaintext: str, public_key: PublicKey, encoding: str = "utf-8") -> str:
    """
    Chiffre une chaîne et renvoie une chaîne JSON contenant une liste
    de blocs chiffrés en hex.
    -> tu peux l'envoyer telle quelle dans tes JSON existants.
    """
    plain_bytes = plaintext.encode(encoding)
    n, _ = public_key

    # taille max d'un bloc en bytes (on laisse une marge de sécurité)
    max_block_size = (n.bit_length() // 8) - 1
    if max_block_size <= 0:
        raise ValueError("Taille de clé RSA trop petite")

    chunks: list[str] = []

    # on découpe le message en blocs
    for i in range(0, len(plain_bytes), max_block_size):
        block = plain_bytes[i:i + max_block_size]
        cipher_block = encrypt_bytes(block, public_key)
        chunks.append(cipher_block.hex())

    # on renvoie la liste des blocs sous forme de string JSON
    return json.dumps(chunks)


def decrypt_str(cipher_text: str, private_key: PrivateKey, encoding: str = "utf-8") -> str:
    """
    Déchiffre une chaîne produite par encrypt_str (liste JSON de blocs hex).
    """
    # cipher_text est une string JSON représentant une liste de strings hex
    chunks_hex = json.loads(cipher_text)

    plain_bytes = bytearray()
    for ch in chunks_hex:
        cipher_block = bytes.fromhex(ch)
        block_plain = decrypt_bytes(cipher_block, private_key)
        plain_bytes.extend(block_plain)

    return plain_bytes.decode(encoding)

