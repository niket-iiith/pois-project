"""
CS8.401 — PA#11: Diffie-Hellman Key Exchange (SKE)
====================================================
Implements:
  1. Group parameter generation (safe prime using PA#13)
  2. DH key exchange protocol simulation
  3. Man-in-the-Middle (MITM) attack demo
  4. Derived symmetric key for PA#3 encryption
  5. Interface: dh_keygen(), dh_exchange()

Protocol:
  Public: prime p, generator g of Z*_p (order q)
  1. Alice: a ← Z_q, sends A = g^a mod p
  2. Bob:   b ← Z_q, sends B = g^b mod p
  3. Shared: K = g^{ab} mod p

Security: Based on Computational Diffie-Hellman (CDH) assumption:
  given g^a and g^b, computing g^{ab} is hard.
"""

from crypto.utils import mod_exp, random_int, int_to_bytes, bytes_to_int, random_bytes
from crypto.pa13_miller_rabin import gen_prime, gen_safe_prime, is_prime


# ─────────────────────────────────────────────
# DH Group Parameters
# ─────────────────────────────────────────────

# Precomputed small safe prime for fast demos
# For real security, use 2048+ bit primes
DEMO_P = 0xB10B8F96A080E01DDE92DE5EAE5D54EC155C43B2F1B4CEF5  # 192-bit safe prime
DEMO_Q = (DEMO_P - 1) // 2
DEMO_G = 2


def generate_dh_params(bits: int = 64) -> dict:
    """
    Generate Diffie-Hellman group parameters.
    
    Args:
        bits: bit size for the safe prime p
    
    Returns:
        dict with p (safe prime), q ((p-1)/2), g (generator)
    """
    if bits <= 64:
        # Use precomputed for speed
        p = gen_safe_prime(bits)
    else:
        p = gen_safe_prime(bits)
    
    q = (p - 1) // 2
    
    # Find generator of the prime-order subgroup
    # g = any element where g^q ≡ 1 mod p and g ≠ 1
    g = 2
    while mod_exp(g, q, p) != 1 or mod_exp(g, 2, p) == 1:
        g += 1
    
    return {'p': p, 'q': q, 'g': g}


# ─────────────────────────────────────────────
# DH Key Exchange
# ─────────────────────────────────────────────

class DHParty:
    """Represents one party in a Diffie-Hellman key exchange."""
    
    def __init__(self, name: str, p: int, g: int, q: int):
        self.name = name
        self.p = p
        self.g = g
        self.q = q
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
    
    def generate_keypair(self) -> int:
        """Generate private key and compute public key."""
        self.private_key = random_int(2, self.q - 1)
        self.public_key = mod_exp(self.g, self.private_key, self.p)
        return self.public_key
    
    def compute_shared_secret(self, other_public: int) -> int:
        """Compute shared secret from other party's public key."""
        self.shared_secret = mod_exp(other_public, self.private_key, self.p)
        return self.shared_secret
    
    def derive_symmetric_key(self) -> bytes:
        """
        Derive a 16-byte symmetric key from the shared secret.
        Uses simple truncation (in practice, use a KDF).
        """
        if self.shared_secret is None:
            raise ValueError("Shared secret not computed yet")
        # Simple key derivation: hash the shared secret
        from crypto.pa08_dlp_hash import dlp_hash
        secret_bytes = int_to_bytes(self.shared_secret, 
                                     (self.shared_secret.bit_length() + 7) // 8)
        key = dlp_hash(secret_bytes)
        return key[:16]  # Truncate to 16 bytes for AES


def dh_exchange(bits: int = 64) -> dict:
    """
    Complete Diffie-Hellman key exchange simulation.
    
    Returns full trace of the exchange for visualization.
    """
    # Generate parameters (or use precomputed)
    if bits <= 64:
        params = generate_dh_params(bits)
    else:
        params = {'p': DEMO_P, 'q': DEMO_Q, 'g': DEMO_G}
    
    p, g, q = params['p'], params['g'], params['q']
    
    # Create parties
    alice = DHParty("Alice", p, g, q)
    bob = DHParty("Bob", p, g, q)
    
    # Step 1: Alice generates keypair
    A = alice.generate_keypair()
    
    # Step 2: Bob generates keypair
    B = bob.generate_keypair()
    
    # Step 3: Both compute shared secret
    K_alice = alice.compute_shared_secret(B)
    K_bob = bob.compute_shared_secret(A)
    
    # Verify they match
    assert K_alice == K_bob, "Shared secrets don't match!"
    
    # Derive symmetric keys
    sym_alice = alice.derive_symmetric_key()
    sym_bob = bob.derive_symmetric_key()
    
    return {
        'parameters': {
            'p': hex(p),
            'g': g,
            'q': hex(q),
            'bits': p.bit_length()
        },
        'alice': {
            'private_key': hex(alice.private_key),
            'public_key': hex(A),
            'shared_secret': hex(K_alice),
            'symmetric_key': sym_alice.hex()
        },
        'bob': {
            'private_key': hex(bob.private_key),
            'public_key': hex(B),
            'shared_secret': hex(K_bob),
            'symmetric_key': sym_bob.hex()
        },
        'shared_secret_match': K_alice == K_bob,
        'symmetric_key_match': sym_alice == sym_bob
    }


# ─────────────────────────────────────────────
# Man-in-the-Middle Attack Demo
# ─────────────────────────────────────────────

def mitm_attack_demo(bits: int = 64) -> dict:
    """
    Demonstrate the Man-in-the-Middle attack on DH.
    
    Without authentication, Mallory can intercept and establish
    separate shared secrets with Alice and Bob.
    
    Alice ↔ Mallory ↔ Bob
    Alice thinks she shares K_AM with Bob, but it's with Mallory.
    Bob thinks he shares K_MB with Alice, but it's with Mallory.
    """
    params = generate_dh_params(bits)
    p, g, q = params['p'], params['g'], params['q']
    
    # Honest parties
    alice = DHParty("Alice", p, g, q)
    bob = DHParty("Bob", p, g, q)
    
    # Attacker
    mallory_a = DHParty("Mallory (to Alice)", p, g, q)
    mallory_b = DHParty("Mallory (to Bob)", p, g, q)
    
    # Alice generates her public key
    A = alice.generate_keypair()
    
    # Mallory intercepts and sends her own public key to Bob
    M_to_bob = mallory_b.generate_keypair()
    
    # Bob generates his public key
    B = bob.generate_keypair()
    
    # Mallory intercepts and sends her own public key to Alice
    M_to_alice = mallory_a.generate_keypair()
    
    # Alice computes shared secret with Mallory (thinks it's Bob)
    K_AM = alice.compute_shared_secret(M_to_alice)
    K_MA = mallory_a.compute_shared_secret(A)
    
    # Bob computes shared secret with Mallory (thinks it's Alice)
    K_BM = bob.compute_shared_secret(M_to_bob)
    K_MB = mallory_b.compute_shared_secret(B)
    
    return {
        'attack_type': 'Man-in-the-Middle',
        'alice_shared_secret': hex(K_AM),
        'mallory_alice_secret': hex(K_MA),
        'alice_mallory_match': K_AM == K_MA,
        'bob_shared_secret': hex(K_BM),
        'mallory_bob_secret': hex(K_MB),
        'bob_mallory_match': K_BM == K_MB,
        'alice_bob_match': K_AM == K_BM,  # Should be False!
        'attack_success': K_AM == K_MA and K_BM == K_MB and K_AM != K_BM,
        'explanation': (
            'Mallory establishes separate shared secrets with Alice and Bob. '
            'She can decrypt, read, re-encrypt, and forward all messages. '
            'This is why DH alone is insufficient — you need authentication (PA#15).'
        )
    }


# ─────────────────────────────────────────────
# DH + PA#3 Encryption Demo
# ─────────────────────────────────────────────

def dh_encrypted_communication(bits: int = 64) -> dict:
    """
    End-to-end demo: DH key exchange followed by CPA-secure encryption.
    
    1. Alice and Bob perform DH to establish shared key
    2. Alice encrypts a message using the shared key
    3. Bob decrypts using the same shared key
    """
    from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt
    
    # DH exchange
    exchange = dh_exchange(bits)
    
    # Use derived symmetric key for encryption
    sym_key = bytes.fromhex(exchange['alice']['symmetric_key'])
    
    # Alice encrypts
    message = b"Hello Bob! This is a secret message."
    nonce, ciphertext = cpa_encrypt(sym_key, message)
    
    # Bob decrypts (using the same derived key)
    decrypted = cpa_decrypt(sym_key, nonce, ciphertext)
    
    return {
        'dh_exchange': exchange,
        'message': message.decode(),
        'ciphertext': ciphertext.hex()[:64] + '...',
        'decrypted': decrypted.decode(),
        'communication_successful': decrypted == message
    }
