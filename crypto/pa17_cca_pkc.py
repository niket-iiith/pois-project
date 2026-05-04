"""
CS8.401 — PA#17: CCA-Secure Public-Key Cryptosystem
=====================================================
Implements:
  1. ElGamal + Digital Signatures for CCA security
  2. Encrypt-then-Sign construction
  3. CCA2 game simulation
  4. Malleability contrast with CPA-only ElGamal
  5. End-to-end lineage: PA#17 → PA#15 + PA#16 → PA#12/PA#13

Construction: Encrypt-then-Sign (Naor-Yung style)
  Enc(pk, m): 
    1. c = ElGamal.Enc(pk_enc, m)
    2. sig = RSA.Sign(sk_sig, c)
    3. Output (c, sig)
  Dec(sk, c, sig):
    1. Verify RSA.Verify(pk_sig, c, sig) — MUST pass
    2. If valid: return ElGamal.Dec(sk_enc, c)
    3. If invalid: return ⊥

Security: CCA2-secure assuming ElGamal is CPA-secure and RSA-Sig is EUF-CMA.
"""

from crypto.utils import random_int, random_bytes, int_to_bytes, bytes_to_int
from crypto.pa16_elgamal import elgamal_keygen, elgamal_encrypt, elgamal_decrypt
from crypto.pa15_signatures import RSASignature
from crypto.pa08_dlp_hash import dlp_hash


# ─────────────────────────────────────────────
# CCA-Secure PKC (Encrypt-then-Sign)
# ─────────────────────────────────────────────

class CCA_PKC:
    """
    CCA-Secure Public-Key Cryptosystem.
    
    Combines ElGamal encryption (PA#16) with RSA signatures (PA#15)
    using Encrypt-then-Sign.
    
    This mirrors the symmetric Encrypt-then-MAC paradigm (PA#6/PA#10)
    but in the public-key setting.
    
    Lineage:
    PA#17 → PA#15 (RSA Signatures) + PA#16 (ElGamal)
    PA#16 → PA#11 (DH group) + PA#13 (Miller-Rabin)
    PA#15 → PA#12 (RSA) + PA#13 (Miller-Rabin) + PA#8 (DLP Hash)
    """
    
    def __init__(self, eg_bits: int = 64, rsa_bits: int = 256):
        """
        Generate both ElGamal encryption keys and RSA signature keys.
        """
        # ElGamal for encryption (CPA-secure)
        self.eg_keys = elgamal_keygen(eg_bits)
        self.eg_pk = self.eg_keys['public_key']
        self.eg_sk = self.eg_keys['private_key']
        
        # RSA for signatures (EUF-CMA)
        self.rsa_sig = RSASignature(bits=rsa_bits)
    
    def encrypt(self, m: int) -> dict:
        """
        CCA-secure encryption.
        
        1. c = ElGamal.Enc(pk, m)
        2. sig = RSA.Sign(sk_sig, H(c1 || c2))
        3. Return {c1, c2, sig}
        """
        # ElGamal encrypt
        c1, c2 = elgamal_encrypt(self.eg_pk, m)
        
        # Sign the ciphertext
        ct_bytes = int_to_bytes(c1, (c1.bit_length() + 7) // 8) + \
                   int_to_bytes(c2, (c2.bit_length() + 7) // 8)
        sig = self.rsa_sig.sign(ct_bytes)
        
        return {'c1': c1, 'c2': c2, 'sig': sig}
    
    def decrypt(self, ct: dict):
        """
        CCA-secure decryption.
        
        1. Verify signature on ciphertext
        2. If invalid: return None (⊥)
        3. If valid: return ElGamal.Dec(sk, c1, c2)
        """
        c1, c2, sig = ct['c1'], ct['c2'], ct['sig']
        
        # Verify signature FIRST
        ct_bytes = int_to_bytes(c1, (c1.bit_length() + 7) // 8) + \
                   int_to_bytes(c2, (c2.bit_length() + 7) // 8)
        
        if not self.rsa_sig.verify(ct_bytes, sig):
            return None  # ⊥ — reject tampered ciphertext
        
        # Decrypt only if signature valid
        return elgamal_decrypt(self.eg_sk, c1, c2)
    
    def get_public_keys(self) -> dict:
        """Return public keys for both encryption and signing."""
        return {
            'elgamal_pk': self.eg_pk,
            'rsa_pk': self.rsa_sig.pk
        }


# ─────────────────────────────────────────────
# CCA2 Game Simulation
# ─────────────────────────────────────────────

def cca2_game(num_trials: int = 50) -> dict:
    """
    IND-CCA2 game for the CCA-PKC scheme.
    
    The adversary has access to a decryption oracle but cannot
    query it on the challenge ciphertext.
    Modified ciphertexts are rejected by signature verification.
    """
    import os
    
    pkc = CCA_PKC(eg_bits=64, rsa_bits=256)
    p = pkc.eg_pk['p']
    
    correct = 0
    rejections = 0
    
    for _ in range(num_trials):
        m0 = random_int(1, p - 1)
        m1 = random_int(1, p - 1)
        
        b = os.urandom(1)[0] & 1
        m = m0 if b == 0 else m1
        
        # Challenge ciphertext
        ct = pkc.encrypt(m)
        
        # Adversary modifies ciphertext (mallability attempt)
        modified_ct = {
            'c1': ct['c1'],
            'c2': (ct['c2'] * 2) % p,  # Multiply c2 by 2
            'sig': ct['sig']           # Keep original signature
        }
        
        # Try to decrypt modified ciphertext
        result = pkc.decrypt(modified_ct)
        if result is None:
            rejections += 1  # Signature check rejected it
        
        # Random guess
        guess = os.urandom(1)[0] & 1
        if guess == b:
            correct += 1
    
    advantage = abs(correct / num_trials - 0.5) * 2
    
    return {
        'trials': num_trials,
        'correct': correct,
        'advantage': round(advantage, 4),
        'rejections': rejections,
        'rejection_rate': round(rejections / num_trials, 4),
        'cca2_secure': advantage < 0.15 and rejections == num_trials
    }


# ─────────────────────────────────────────────
# Malleability Contrast Demo
# ─────────────────────────────────────────────

def malleability_contrast_demo() -> dict:
    """
    Side-by-side: CPA-only ElGamal (malleable) vs CCA-PKC (not malleable).
    """
    pkc = CCA_PKC(eg_bits=64, rsa_bits=256)
    p = pkc.eg_pk['p']
    
    m = 42
    
    # === CPA-only ElGamal ===
    c1, c2 = elgamal_encrypt(pkc.eg_pk, m)
    
    # Mallability: multiply by Enc(2) to get Enc(84)
    c1_2, c2_2 = elgamal_encrypt(pkc.eg_pk, 2)
    mod_c1 = (c1 * c1_2) % p
    mod_c2 = (c2 * c2_2) % p
    
    modified_plaintext = elgamal_decrypt(pkc.eg_sk, mod_c1, mod_c2)
    
    # === CCA-Secure PKC ===
    ct = pkc.encrypt(m)
    
    # Same attack
    modified_ct = {
        'c1': (ct['c1'] * c1_2) % p,
        'c2': (ct['c2'] * c2_2) % p,
        'sig': ct['sig']  # Original signature won't match
    }
    
    cca_result = pkc.decrypt(modified_ct)
    
    return {
        'original_message': m,
        'cpa_only_elgamal': {
            'modified_decryption': modified_plaintext,
            'expected': (m * 2) % p,
            'malleable': modified_plaintext == (m * 2) % p,
            'note': 'Multiplying ciphertexts multiplies plaintexts'
        },
        'cca_secure_pkc': {
            'result': cca_result,
            'rejected': cca_result is None,
            'note': 'Signature verification fails → ⊥'
        }
    }
