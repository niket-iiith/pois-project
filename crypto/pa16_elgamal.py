"""
CS8.401 — PA#16: ElGamal Public-Key Cryptosystem
==================================================
Implements:
  1. elgamal_keygen() using PA#11 group parameters
  2. encrypt(pk, m), decrypt(sk, c)
  3. IND-CPA game for ElGamal
  4. Homomorphic multiplication demo
  5. Re-randomization demo
  6. Interface for PA#17 and PA#18

ElGamal:
  KeyGen: (p, g, q) group params; x ← Z_q; h = g^x mod p
          pk = (p, g, q, h), sk = x
  Encrypt: r ← Z_q; c1 = g^r mod p; c2 = m · h^r mod p
  Decrypt: m = c2 · c1^{-x} mod p = c2 · (c1^x)^{-1} mod p

Security: IND-CPA under the DDH assumption.
"""

from crypto.utils import mod_exp, mod_inverse, random_int, int_to_bytes, bytes_to_int, random_bytes
from crypto.pa13_miller_rabin import gen_prime, gen_safe_prime


# ─────────────────────────────────────────────
# ElGamal Key Generation
# ─────────────────────────────────────────────

def elgamal_keygen(bits: int = 256) -> dict:
    """
    ElGamal key generation using PA#11 group parameters.
    
    1. Generate safe prime p = 2q + 1
    2. Find generator g of the order-q subgroup
    3. Private key: x ← Z_q
    4. Public key: h = g^x mod p
    
    Returns:
        dict with public_key (p, g, q, h) and private_key (x)
    """
    # Generate safe prime
    p = gen_safe_prime(bits)
    q = (p - 1) // 2
    
    # Find generator of the order-q subgroup
    g = 2
    while mod_exp(g, q, p) != 1 or mod_exp(g, 2, p) == 1:
        g += 1
    
    # Private key
    x = random_int(2, q - 1)
    
    # Public key
    h = mod_exp(g, x, p)
    
    return {
        'public_key': {'p': p, 'g': g, 'q': q, 'h': h},
        'private_key': {'x': x, 'p': p, 'q': q}
    }


# ─────────────────────────────────────────────
# ElGamal Encryption/Decryption
# ─────────────────────────────────────────────

def elgamal_encrypt(pk: dict, m: int) -> tuple:
    """
    ElGamal encryption.
    
    r ← Z_q (random ephemeral key)
    c1 = g^r mod p
    c2 = m · h^r mod p
    
    Args:
        pk: public key with p, g, q, h
        m: plaintext as integer (must be in the group, i.e., 1 ≤ m < p)
    
    Returns:
        (c1, c2): ciphertext pair
    """
    p, g, q, h = pk['p'], pk['g'], pk['q'], pk['h']
    
    if m <= 0 or m >= p:
        raise ValueError(f"Message must be in [1, p-1]")
    
    # Random ephemeral key
    r = random_int(2, q - 1)
    
    c1 = mod_exp(g, r, p)
    c2 = (m * mod_exp(h, r, p)) % p
    
    return c1, c2


def elgamal_decrypt(sk: dict, c1: int, c2: int) -> int:
    """
    ElGamal decryption.
    
    m = c2 · c1^{-x} mod p
      = c2 · (c1^x)^{-1} mod p
    
    Args:
        sk: private key with x, p, q
        c1, c2: ciphertext pair
    
    Returns:
        plaintext integer
    """
    p, x = sk['p'], sk['x']
    
    # c1^x mod p
    s = mod_exp(c1, x, p)
    # s^{-1} mod p
    s_inv = mod_inverse(s, p)
    # m = c2 · s^{-1} mod p
    m = (c2 * s_inv) % p
    
    return m


# ─────────────────────────────────────────────
# Byte-level Encryption/Decryption
# ─────────────────────────────────────────────

def elgamal_encrypt_bytes(pk: dict, message: bytes) -> list:
    """Encrypt a byte message (encode each byte as a group element)."""
    ciphertexts = []
    for byte in message:
        m = byte + 1  # Map [0,255] to [1,256] to stay in the group
        c1, c2 = elgamal_encrypt(pk, m)
        ciphertexts.append((c1, c2))
    return ciphertexts


def elgamal_decrypt_bytes(sk: dict, ciphertexts: list) -> bytes:
    """Decrypt a list of ciphertext pairs back to bytes."""
    plaintext = bytearray()
    for c1, c2 in ciphertexts:
        m = elgamal_decrypt(sk, c1, c2)
        plaintext.append(m - 1)  # Unmap [1,256] to [0,255]
    return bytes(plaintext)


# ─────────────────────────────────────────────
# IND-CPA Game
# ─────────────────────────────────────────────

def ind_cpa_game(bits: int = 64, num_trials: int = 100) -> dict:
    """
    IND-CPA game for ElGamal.
    
    ElGamal is CPA-secure under the DDH assumption.
    The random r in each encryption ensures ciphertexts
    are indistinguishable even for the same plaintext.
    """
    import os
    keys = elgamal_keygen(bits)
    pk, sk = keys['public_key'], keys['private_key']
    
    correct = 0
    
    for _ in range(num_trials):
        m0 = random_int(1, pk['p'] - 1)
        m1 = random_int(1, pk['p'] - 1)
        
        b = os.urandom(1)[0] & 1
        m = m0 if b == 0 else m1
        
        c1, c2 = elgamal_encrypt(pk, m)
        
        # Adversary guesses randomly
        guess = os.urandom(1)[0] & 1
        if guess == b:
            correct += 1
    
    advantage = abs(correct / num_trials - 0.5) * 2
    
    return {
        'trials': num_trials,
        'correct': correct,
        'advantage': round(advantage, 4),
        'cpa_secure': advantage < 0.15
    }


# ─────────────────────────────────────────────
# Homomorphic Property Demo
# ─────────────────────────────────────────────

def homomorphic_demo(bits: int = 64) -> dict:
    """
    ElGamal has multiplicative homomorphic property:
    Enc(m1) · Enc(m2) = Enc(m1 · m2)
    
    (c1_a, c2_a) · (c1_b, c2_b) = (c1_a·c1_b, c2_a·c2_b) = Enc(m1·m2)
    """
    keys = elgamal_keygen(bits)
    pk, sk = keys['public_key'], keys['private_key']
    
    m1, m2 = 7, 11
    
    c1_a, c2_a = elgamal_encrypt(pk, m1)
    c1_b, c2_b = elgamal_encrypt(pk, m2)
    
    # Homomorphic multiplication
    c1_prod = (c1_a * c1_b) % pk['p']
    c2_prod = (c2_a * c2_b) % pk['p']
    
    # Decrypt the product
    m_prod = elgamal_decrypt(sk, c1_prod, c2_prod)
    
    expected = (m1 * m2) % pk['p']
    
    return {
        'm1': m1,
        'm2': m2,
        'expected_product': expected,
        'decrypted_product': m_prod,
        'homomorphic': m_prod == expected,
        'note': 'ElGamal is multiplicatively homomorphic — a feature AND vulnerability'
    }


# ─────────────────────────────────────────────
# Re-randomization Demo
# ─────────────────────────────────────────────

def rerandomization_demo(bits: int = 64) -> dict:
    """
    ElGamal allows re-randomization: given Enc(m), anyone can
    produce a new valid ciphertext of the same m.
    
    (c1, c2) · Enc(1) = (c1·g^r', c2·h^r') = Enc(m) with fresh randomness
    """
    keys = elgamal_keygen(bits)
    pk, sk = keys['public_key'], keys['private_key']
    
    m = 42
    c1, c2 = elgamal_encrypt(pk, m)
    
    # Re-randomize by multiplying with Enc(1)
    c1_1, c2_1 = elgamal_encrypt(pk, 1)  # Encryption of identity
    
    c1_new = (c1 * c1_1) % pk['p']
    c2_new = (c2 * c2_1) % pk['p']
    
    # Both should decrypt to the same m
    m_original = elgamal_decrypt(sk, c1, c2)
    m_rerandomized = elgamal_decrypt(sk, c1_new, c2_new)
    
    return {
        'message': m,
        'original_ciphertext': (hex(c1), hex(c2)),
        'rerandomized_ciphertext': (hex(c1_new), hex(c2_new)),
        'ciphertexts_different': (c1, c2) != (c1_new, c2_new),
        'both_decrypt_same': m_original == m_rerandomized == m
    }
