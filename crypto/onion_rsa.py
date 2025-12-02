# crypto/onion_rsa.py
# RSA simplifié SAE 3.02 - Version SANS JSON
# Format des ciphertext : "hex1:hex2:hex3"

import random
from math import gcd
from typing import Tuple
from sympy import isprime  # autorisé

PublicKey = Tuple[int, int]   # (n, e)
PrivateKey = Tuple[int, int]  # (n, d)


# ---------- Génération de clés ----------

def _generate_prime(bits: int) -> int:
    """Génère un nombre premier de 'bits' bits."""
    assert bits >= 8
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))
        candidate |= 1
        if isprime(candidate):
            return candidate


def generate_keypair(bits: int = 2048) -> tuple[PublicKey, PrivateKey]:
    """Génère une paire de clés RSA."""
    half = bits // 2
    p = _generate_prime(half)
    q = _generate_prime(half)
    while q == p:
        q = _generate_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        while True:
            e = random.randrange(3, phi - 1)
            if e % 2 == 1 and gcd(e, phi) == 1:
                break

    d = pow(e, -1, phi)
    return (n, e), (n, d)


# ---------- Chiffrement bas niveau ----------

def encrypt_bytes(plaintext: bytes, public_key: PublicKey) -> bytes:
    """Chiffre des bytes avec RSA."""
    n, e = public_key
    m = int.from_bytes(plaintext, "big")
    if m >= n:
        raise ValueError("Bloc RSA trop long")
    c = pow(m, e, n)
    return c.to_bytes((c.bit_length() + 7) // 8, "big") or b"\x00"


def decrypt_bytes(ciphertext: bytes, private_key: PrivateKey) -> bytes:
    """Déchiffre un bloc de bytes."""
    n, d = private_key
    c = int.from_bytes(ciphertext, "big")
    m = pow(c, d, n)
    return m.to_bytes((m.bit_length() + 7) // 8, "big") or b""


# ---------- Chiffrement texte (sans JSON) ----------

def encrypt_str(plaintext: str, public_key: PublicKey, encoding: str = "utf-8") -> str:
    """
    Chiffre une chaîne et renvoie :
        "hexbloc1:hexbloc2:hexbloc3"
    Format simple, sans JSON.
    """
    data = plaintext.encode(encoding)
    n, _ = public_key
    max_block = (n.bit_length() // 8) - 1  # marge

    blocks_hex: list[str] = []

    for i in range(0, len(data), max_block):
        block = data[i : i + max_block]
        cipher_block = encrypt_bytes(block, public_key)
        blocks_hex.append(cipher_block.hex())

    return ":".join(blocks_hex)


def decrypt_str(cipher: str, private_key: PrivateKey, encoding: str = "utf-8") -> str:
    """
    Déchiffre "hex1:hex2:hex3" → string.
    """
    if cipher.strip() == "":
        return ""

    chunks = cipher.split(":")
    plain_bytes = bytearray()

    for ch in chunks:
        if not ch:
            continue
        cipher_block = bytes.fromhex(ch)
        block = decrypt_bytes(cipher_block, private_key)
        plain_bytes.extend(block)

    return plain_bytes.decode(encoding)
