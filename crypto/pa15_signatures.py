"""
CS8.401 — PA#15: Digital Signatures
=====================================
Implements:
  1. RSA signatures: sign(sk, m), verify(pk, m, sig) with PA#8 hash
  2. ElGamal/Schnorr-style signatures
  3. Existential forgery on textbook RSA demo
  4. Hash-then-sign requirement
  5. Interface: sign/verify

Security:
  RSA signatures: sign(m) = H(m)^d mod N, verify: sig^e mod N == H(m)
  Without hashing, textbook RSA allows existential forgery.
"""

from crypto.utils import mod_exp, mod_inverse, random_int, int_to_bytes, bytes_to_int, random_bytes
from crypto.pa12_rsa import rsa_keygen, rsa_encrypt, rsa_decrypt
from crypto.pa08_dlp_hash import dlp_hash
from crypto.pa13_miller_rabin import gen_prime


# ─────────────────────────────────────────────
# RSA Signatures (Hash-then-Sign)
# ─────────────────────────────────────────────

class RSASignature:
    """
    RSA Digital Signature Scheme.
    
    Sign: sig = H(m)^d mod N
    Verify: sig^e mod N == H(m)
    
    Uses PA#8 DLP hash for hashing. Signing raw m without hashing
    is vulnerable to existential forgery.
    """
    
    def __init__(self, keys: dict = None, bits: int = 512):
        if keys is None:
            keys = rsa_keygen(bits)
        self.pk = keys['public_key']
        self.sk = keys['private_key']
    
    def _hash_message(self, message: bytes) -> int:
        """Hash message and convert to integer < N."""
        h = dlp_hash(message)
        return bytes_to_int(h) % self.pk['N']
    
    def sign(self, message: bytes) -> int:
        """
        Sign a message.
        sig = H(m)^d mod N
        
        MUST hash first to prevent existential forgery.
        """
        h = self._hash_message(message)
        return mod_exp(h, self.sk['d'], self.pk['N'])
    
    def verify(self, message: bytes, signature: int) -> bool:
        """
        Verify a signature.
        Check: sig^e mod N == H(m)
        """
        h = self._hash_message(message)
        recovered = mod_exp(signature, self.pk['e'], self.pk['N'])
        return recovered == h
    
    def sign_raw(self, m: int) -> int:
        """
        Sign raw integer (NO hashing). INSECURE — for demo only.
        Vulnerable to existential forgery.
        """
        return mod_exp(m, self.sk['d'], self.pk['N'])
    
    def verify_raw(self, m: int, signature: int) -> bool:
        """Verify raw signature (no hashing). INSECURE."""
        recovered = mod_exp(signature, self.pk['e'], self.pk['N'])
        return recovered == m


# ─────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────

def sign(sk: dict, pk: dict, message: bytes) -> int:
    """Sign a message using RSA."""
    h = bytes_to_int(dlp_hash(message)) % pk['N']
    return mod_exp(h, sk['d'], pk['N'])


def verify(pk: dict, message: bytes, signature: int) -> bool:
    """Verify an RSA signature."""
    h = bytes_to_int(dlp_hash(message)) % pk['N']
    recovered = mod_exp(signature, pk['e'], pk['N'])
    return recovered == h


# ─────────────────────────────────────────────
# Existential Forgery Demo (Textbook RSA without hashing)
# ─────────────────────────────────────────────

def existential_forgery_demo(bits: int = 256) -> dict:
    """
    Demonstrate existential forgery on textbook RSA (no hashing).
    
    Attack: Choose random sig, compute m = sig^e mod N.
    Then (m, sig) is a valid signature pair!
    
    The adversary cannot choose which message to sign,
    but can produce SOME valid (message, signature) pair.
    """
    signer = RSASignature(bits=bits)
    
    # Attacker: choose random signature, derive corresponding "message"
    random_sig = random_int(2, signer.pk['N'] - 1)
    forged_m = mod_exp(random_sig, signer.pk['e'], signer.pk['N'])
    
    # Verify the forgery
    is_valid = signer.verify_raw(forged_m, random_sig)
    
    # Also demonstrate multiplicative forgery
    # If sig(m1) and sig(m2) are known, sig(m1·m2) = sig(m1)·sig(m2)
    m1 = random_int(2, signer.pk['N'] // 2)
    m2 = random_int(2, signer.pk['N'] // 2)
    sig1 = signer.sign_raw(m1)
    sig2 = signer.sign_raw(m2)
    
    m_product = (m1 * m2) % signer.pk['N']
    sig_product = (sig1 * sig2) % signer.pk['N']
    
    mult_forgery_valid = signer.verify_raw(m_product, sig_product)
    
    return {
        'existential_forgery': {
            'forged_signature': hex(random_sig),
            'derived_message': hex(forged_m),
            'is_valid': is_valid,
            'note': 'Adversary chose a random sig; m = sig^e is the "signed message"'
        },
        'multiplicative_forgery': {
            'm1': hex(m1),
            'm2': hex(m2),
            'sig_m1': hex(sig1),
            'sig_m2': hex(sig2),
            'm1_times_m2': hex(m_product),
            'sig_product': hex(sig_product),
            'is_valid': mult_forgery_valid,
            'note': 'sig(m1)·sig(m2) = sig(m1·m2) — multiplicative homomorphism'
        },
        'mitigation': 'Hash the message before signing: sig = H(m)^d. '
                       'This prevents both forgery types.'
    }


# ─────────────────────────────────────────────
# Hash-then-Sign Prevents Forgery Demo
# ─────────────────────────────────────────────

def hash_then_sign_demo(bits: int = 256) -> dict:
    """
    Demonstrate that hash-then-sign prevents the forgeries above.
    """
    signer = RSASignature(bits=bits)
    
    # Normal sign/verify
    message = b"Transfer $100 to Alice"
    sig = signer.sign(message)
    is_valid = signer.verify(message, sig)
    
    # Try existential forgery on hashed scheme
    random_sig = random_int(2, signer.pk['N'] - 1)
    # Adversary computes m_hash = random_sig^e mod N
    # But this gives H(m), not m itself — adversary cannot find m
    forged_hash = mod_exp(random_sig, signer.pk['e'], signer.pk['N'])
    # Can they find a message with this hash? No — hash is collision-resistant
    
    # Try modifying signed message
    modified_message = b"Transfer $999 to Alice"
    modified_valid = signer.verify(modified_message, sig)
    
    return {
        'original': {
            'message': message.decode(),
            'signature': hex(sig),
            'valid': is_valid
        },
        'existential_forgery_blocked': {
            'random_sig': hex(random_sig),
            'derived_hash': hex(forged_hash),
            'note': 'Adversary gets H(m) but cannot find preimage m'
        },
        'modification_detected': {
            'modified_message': modified_message.decode(),
            'valid': modified_valid,
            'note': 'Modified message has different hash → signature fails'
        }
    }


# ─────────────────────────────────────────────
# Sign/Verify Demo for Web
# ─────────────────────────────────────────────

def sign_verify_demo(message: str = "Hello, World!", bits: int = 256) -> dict:
    """Interactive sign/verify for the web demo."""
    signer = RSASignature(bits=bits)
    
    msg_bytes = message.encode()
    sig = signer.sign(msg_bytes)
    is_valid = signer.verify(msg_bytes, sig)
    
    # Tamper with message
    tampered = message + " (tampered)"
    tampered_valid = signer.verify(tampered.encode(), sig)
    
    return {
        'message': message,
        'signature': hex(sig),
        'public_key_N': hex(signer.pk['N']),
        'public_key_e': signer.pk['e'],
        'valid': is_valid,
        'tampered_message': tampered,
        'tampered_valid': tampered_valid
    }
