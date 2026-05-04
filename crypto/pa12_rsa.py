"""
CS8.401 — PA#12: Textbook RSA + PKCS#1 v1.5
==============================================
Implements:
  1. rsa_keygen(bits) using PA#13 Miller-Rabin
  2. Textbook RSA: encrypt(pk, m), decrypt(sk, c)
  3. PKCS#1 v1.5 padding
  4. Homomorphic property demo
  5. Small-exponent attack demo
  6. Interface: RSA keygen/encrypt/decrypt

RSA:
  KeyGen: p, q primes; N = p·q; e coprime to φ(N); d = e^{-1} mod φ(N)
  Encrypt: c = m^e mod N
  Decrypt: m = c^d mod N

Security: Based on the hardness of factoring N = p·q.
"""

from crypto.utils import mod_exp, mod_inverse, gcd, random_int, random_bytes, int_to_bytes, bytes_to_int
from crypto.pa13_miller_rabin import gen_prime, is_prime


# ─────────────────────────────────────────────
# RSA Key Generation
# ─────────────────────────────────────────────

def rsa_keygen(bits: int = 512) -> dict:
    """
    RSA key generation.
    
    1. Generate two large primes p, q (each bits/2 bits)
    2. Compute N = p · q
    3. Compute φ(N) = (p-1)(q-1)
    4. Choose e (commonly 65537)
    5. Compute d = e^{-1} mod φ(N)
    
    Args:
        bits: total modulus bit length (e.g., 512, 1024, 2048)
    
    Returns:
        dict with public_key (N, e) and private_key (N, d, p, q)
    """
    half_bits = bits // 2
    
    # Generate primes p and q
    while True:
        p = gen_prime(half_bits)
        q = gen_prime(half_bits)
        
        # Ensure p ≠ q
        if p == q:
            continue
        
        N = p * q
        phi_N = (p - 1) * (q - 1)
        
        # Standard public exponent
        e = 65537
        
        # Ensure gcd(e, φ(N)) = 1
        if gcd(e, phi_N) != 1:
            continue
        
        # Compute private exponent
        d = mod_inverse(e, phi_N)
        
        break
    
    return {
        'public_key': {'N': N, 'e': e},
        'private_key': {'N': N, 'd': d, 'p': p, 'q': q},
        'bits': N.bit_length()
    }


# ─────────────────────────────────────────────
# Textbook RSA Encryption/Decryption
# ─────────────────────────────────────────────

def rsa_encrypt(pk: dict, m: int) -> int:
    """
    Textbook RSA encryption: c = m^e mod N
    
    Args:
        pk: public key dict with 'N' and 'e'
        m: plaintext as integer (0 ≤ m < N)
    
    Returns:
        ciphertext as integer
    """
    N, e = pk['N'], pk['e']
    if m >= N:
        raise ValueError(f"Message {m} must be < N = {N}")
    return mod_exp(m, e, N)


def rsa_decrypt(sk: dict, c: int) -> int:
    """
    Textbook RSA decryption: m = c^d mod N
    
    Args:
        sk: private key dict with 'N' and 'd'
        c: ciphertext as integer
    
    Returns:
        plaintext as integer
    """
    N, d = sk['N'], sk['d']
    return mod_exp(c, d, N)


# ─────────────────────────────────────────────
# PKCS#1 v1.5 Padding
# ─────────────────────────────────────────────

def pkcs1_v15_pad(message: bytes, key_size_bytes: int) -> bytes:
    """
    PKCS#1 v1.5 padding for encryption.
    
    Format: 0x00 || 0x02 || PS || 0x00 || M
    where PS is at least 8 random non-zero bytes.
    
    Args:
        message: plaintext bytes
        key_size_bytes: size of the RSA modulus in bytes
    
    Returns:
        padded message bytes of length key_size_bytes
    """
    # Maximum message length
    max_msg_len = key_size_bytes - 11  # 2 + 8 + 1 = 11 overhead minimum
    if len(message) > max_msg_len:
        raise ValueError(f"Message too long: {len(message)} > {max_msg_len}")
    
    # Generate random padding (non-zero bytes)
    ps_len = key_size_bytes - len(message) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        byte = random_bytes(1)
        if byte[0] != 0:  # Must be non-zero
            ps.append(byte[0])
    
    # Construct padded message
    padded = b'\x00\x02' + bytes(ps) + b'\x00' + message
    assert len(padded) == key_size_bytes
    
    return padded


def pkcs1_v15_unpad(padded: bytes) -> bytes:
    """
    Remove PKCS#1 v1.5 padding.
    
    Returns:
        Original message bytes
    """
    if len(padded) < 11:
        raise ValueError("Padded message too short")
    if padded[0] != 0x00 or padded[1] != 0x02:
        raise ValueError("Invalid PKCS#1 v1.5 header")
    
    # Find the 0x00 separator after the padding string
    separator_idx = padded.index(b'\x00', 2)
    if separator_idx < 10:  # PS must be at least 8 bytes
        raise ValueError("Padding string too short")
    
    return padded[separator_idx + 1:]


def rsa_encrypt_padded(pk: dict, message: bytes) -> int:
    """RSA encryption with PKCS#1 v1.5 padding."""
    key_size_bytes = (pk['N'].bit_length() + 7) // 8
    padded = pkcs1_v15_pad(message, key_size_bytes)
    m = bytes_to_int(padded)
    return rsa_encrypt(pk, m)


def rsa_decrypt_padded(sk: dict, c: int) -> bytes:
    """RSA decryption with PKCS#1 v1.5 unpadding."""
    m = rsa_decrypt(sk, c)
    key_size_bytes = (sk['N'].bit_length() + 7) // 8
    padded = int_to_bytes(m, key_size_bytes)
    return pkcs1_v15_unpad(padded)


# ─────────────────────────────────────────────
# Homomorphic Property Demo
# ─────────────────────────────────────────────

def homomorphic_demo(bits: int = 256) -> dict:
    """
    Demonstrate RSA's multiplicative homomorphic property:
    Enc(m1) · Enc(m2) mod N = Enc(m1 · m2 mod N)
    
    This is a feature of textbook RSA but a VULNERABILITY —
    it means the scheme is malleable.
    """
    keys = rsa_keygen(bits)
    pk, sk = keys['public_key'], keys['private_key']
    
    m1, m2 = 42, 17
    
    c1 = rsa_encrypt(pk, m1)
    c2 = rsa_encrypt(pk, m2)
    
    # Homomorphic multiplication
    c_product = (c1 * c2) % pk['N']
    
    # Decrypt the product
    m_product = rsa_decrypt(sk, c_product)
    
    return {
        'm1': m1,
        'm2': m2,
        'c1': hex(c1),
        'c2': hex(c2),
        'c1_times_c2_mod_N': hex(c_product),
        'decrypt_product': m_product,
        'expected_product': (m1 * m2) % pk['N'],
        'homomorphic': m_product == (m1 * m2) % pk['N'],
        'vulnerability': 'Textbook RSA is malleable: adversary can multiply ciphertexts'
    }


# ─────────────────────────────────────────────
# Small Exponent Attack Demo
# ─────────────────────────────────────────────

def small_exponent_demo() -> dict:
    """
    Demonstrate vulnerability of small public exponent (e=3)
    when message is small and unpadded.
    
    If m^3 < N, then c = m^3 exactly (no modular reduction),
    and the adversary can recover m = c^{1/3} (integer cube root).
    """
    keys = rsa_keygen(512)
    pk, sk = keys['public_key'], keys['private_key']
    
    # Override e to 3 for the demo
    # (This requires regenerating d)
    p, q = sk['p'], sk['q']
    phi_N = (p - 1) * (q - 1)
    e = 3
    
    if gcd(e, phi_N) != 1:
        return {'note': 'Cannot demonstrate with these parameters (gcd(3, φ(N)) ≠ 1)'}
    
    d = mod_inverse(e, phi_N)
    pk_small = {'N': pk['N'], 'e': e}
    sk_small = {'N': pk['N'], 'd': d, 'p': p, 'q': q}
    
    # Small message: m^3 < N
    m = 42
    c = rsa_encrypt(pk_small, m)
    
    # Attack: integer cube root
    def integer_nth_root(x, n):
        """Newton's method for integer nth root."""
        if x < 0:
            return -integer_nth_root(-x, n)
        if x == 0:
            return 0
        # Initial guess
        guess = int(x ** (1.0 / n)) + 1
        while True:
            new_guess = ((n - 1) * guess + x // (guess ** (n - 1))) // n
            if new_guess >= guess:
                return guess
            guess = new_guess
    
    recovered = integer_nth_root(c, 3)
    
    return {
        'e': 3,
        'message': m,
        'ciphertext': hex(c),
        'm_cubed_less_than_N': m ** 3 < pk['N'],
        'recovered_message': recovered,
        'attack_success': recovered == m,
        'mitigation': 'Use PKCS#1 v1.5 or OAEP padding to randomize the message'
    }
