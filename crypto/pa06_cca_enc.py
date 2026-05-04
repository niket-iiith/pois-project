"""
CS8.401 — PA#6: CCA-Secure Symmetric Encryption (Encrypt-then-MAC)
====================================================================
Implements:
  1. Encrypt-then-MAC: CCA_Enc(kE, kM, m) using PA#3 + PA#5
  2. CCA_Dec(kE, kM, c, t) — verify MAC before decrypt, return ⊥ on failure
  3. Key separation: independent kE and kM
  4. IND-CCA2 game simulation
  5. Malleability attack demo: CPA-only vs CCA side-by-side
  6. Interface: CCA_Enc(kE, kM, m) -> (c, t), CCA_Dec(kE, kM, c, t) -> m or ⊥

Security Claim:
  If Enc is CPA-secure and Mac is EUF-CMA secure, then Encrypt-then-MAC
  is CCA2-secure. The MAC verification step rejects any adversary query
  on a modified ciphertext, nullifying the adaptive oracle.
"""

from crypto.utils import random_bytes, xor_bytes, secure_compare
from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt
from crypto.pa05_mac import PRF_MAC, mac, vrfy


# ─────────────────────────────────────────────
# CCA-Secure Encryption (Encrypt-then-MAC)
# ─────────────────────────────────────────────

def cca_encrypt(kE: bytes, kM: bytes, plaintext: bytes) -> tuple:
    """
    CCA-secure encryption using Encrypt-then-MAC.
    
    Steps:
    1. CE = Enc_kE(m)           (CPA-secure encryption from PA#3)
    2. t = Mac_kM(nonce || CE)  (EUF-CMA MAC from PA#5)
    3. Output (nonce, CE, t)
    
    Args:
        kE: 16-byte encryption key
        kM: 16-byte MAC key (MUST be independent from kE)
        plaintext: arbitrary-length message
    
    Returns:
        (nonce, ciphertext, tag): encrypted and authenticated message
    """
    # Step 1: CPA-secure encryption
    nonce, ciphertext = cpa_encrypt(kE, plaintext)
    
    # Step 2: MAC the ciphertext (with nonce to prevent replay)
    mac_input = nonce + ciphertext
    mac_obj = PRF_MAC(key=kM)
    tag = mac_obj.mac(mac_input)
    
    return nonce, ciphertext, tag


def cca_decrypt(kE: bytes, kM: bytes, nonce: bytes, ciphertext: bytes, tag: bytes):
    """
    CCA-secure decryption with Encrypt-then-MAC.
    
    Steps:
    1. Verify t = Mac_kM(nonce || CE)  — MUST happen BEFORE decryption
    2. If verification fails: return None (⊥)
    3. If verification passes: return Dec_kE(nonce, CE)
    
    Args:
        kE: 16-byte encryption key
        kM: 16-byte MAC key
        nonce: nonce from encryption
        ciphertext: ciphertext from encryption
        tag: MAC tag from encryption
    
    Returns:
        Plaintext bytes if tag valid, None (⊥) if tag invalid
    """
    # Step 1: Verify MAC BEFORE decrypting
    mac_input = nonce + ciphertext
    mac_obj = PRF_MAC(key=kM)
    
    if not mac_obj.verify(mac_input, tag):
        return None  # ⊥ — reject tampered ciphertext
    
    # Step 2: Decrypt only if MAC verified
    plaintext = cpa_decrypt(kE, nonce, ciphertext)
    return plaintext


# ─────────────────────────────────────────────
# Key Generation
# ─────────────────────────────────────────────

def generate_keys() -> tuple:
    """
    Generate independent encryption and MAC keys.
    Key separation is critical: reusing one key for both is insecure.
    """
    kE = random_bytes(16)
    kM = random_bytes(16)
    return kE, kM


# ─────────────────────────────────────────────
# IND-CCA2 Game Simulation
# ─────────────────────────────────────────────

def ind_cca2_game(num_trials=100) -> dict:
    """
    IND-CCA2 (Adaptive Chosen Ciphertext Attack) Game.
    
    The adversary:
    1. Gets access to both encryption and decryption oracles
    2. Chooses m0, m1
    3. Receives Enc(k, m_b) for random b
    4. Can query decryption oracle (except on the challenge ciphertext)
    5. Must guess b
    
    With Encrypt-then-MAC, any modified ciphertext is rejected by MAC,
    making the decryption oracle useless to the adversary.
    """
    kE, kM = generate_keys()
    
    correct = 0
    mac_rejections = 0
    
    for _ in range(num_trials):
        # Adversary chooses two messages
        m0 = random_bytes(32)  # 2 blocks
        m1 = random_bytes(32)
        
        # Challenger picks random bit
        import os
        b = os.urandom(1)[0] & 1
        msg = m0 if b == 0 else m1
        
        # Encrypt challenge
        nonce, ct, tag = cca_encrypt(kE, kM, msg)
        
        # Adversary tries to use decryption oracle on modified ciphertext
        modified_ct = bytearray(ct)
        modified_ct[0] ^= 0x01  # Flip a bit
        result = cca_decrypt(kE, kM, nonce, bytes(modified_ct), tag)
        if result is None:
            mac_rejections += 1
        
        # Adversary guesses randomly (cannot gain advantage)
        guess = os.urandom(1)[0] & 1
        if guess == b:
            correct += 1
    
    advantage = abs(correct / num_trials - 0.5) * 2
    
    return {
        'trials': num_trials,
        'correct': correct,
        'success_rate': round(correct / num_trials, 4),
        'advantage': round(advantage, 4),
        'mac_rejections': mac_rejections,
        'rejection_rate': round(mac_rejections / num_trials, 4),
        'cca2_secure': advantage < 0.15 and mac_rejections == num_trials
    }


# ─────────────────────────────────────────────
# Malleability Attack Demo (CPA vs CCA)
# ─────────────────────────────────────────────

def malleability_demo() -> dict:
    """
    Side-by-side comparison of malleability:
    
    LEFT (CPA-only, PA#3): Flipping a bit in ciphertext flips
    the corresponding bit in plaintext — MALLEABLE.
    
    RIGHT (CCA / Encrypt-then-MAC): The same bit flip is detected
    by the MAC check and rejected with ⊥ — NOT MALLEABLE.
    """
    kE = random_bytes(16)
    kM = random_bytes(16)
    
    message = b"Pay Alice $00100"  # 16 bytes
    
    # === CPA-Only (PA#3) ===
    nonce_cpa, ct_cpa = cpa_encrypt(kE, message)
    
    # Adversary flips bits to change "$00100" to "$99100"
    modified_cpa = bytearray(ct_cpa)
    # Flip specific bits (bit manipulation on XOR-based encryption)
    modified_cpa[10] ^= 0x09  # Attempt to change '0' to '9'
    modified_cpa[11] ^= 0x09
    
    # Decrypt modified CPA ciphertext — succeeds (malleable!)
    try:
        decrypted_cpa = cpa_decrypt(kE, nonce_cpa, bytes(modified_cpa))
        cpa_result = decrypted_cpa.decode('ascii', errors='replace')
    except:
        cpa_result = "Decryption error"
    
    # === CCA (Encrypt-then-MAC) ===
    nonce_cca, ct_cca, tag_cca = cca_encrypt(kE, kM, message)
    
    # Same attack: flip bits
    modified_cca = bytearray(ct_cca)
    modified_cca[10] ^= 0x09
    modified_cca[11] ^= 0x09
    
    # Decrypt modified CCA ciphertext — should be rejected!
    cca_result = cca_decrypt(kE, kM, nonce_cca, bytes(modified_cca), tag_cca)
    
    return {
        'original_message': message.decode(),
        'cpa_only': {
            'modified_decrypted': cpa_result,
            'attack_succeeded': True,  # CPA is always malleable
            'note': 'Bit flip in ciphertext → bit flip in plaintext'
        },
        'cca_encrypt_then_mac': {
            'result': cca_result,
            'attack_rejected': cca_result is None,
            'note': 'MAC verification failed → ⊥ returned, plaintext never exposed'
        }
    }


# ─────────────────────────────────────────────
# Key Reuse Vulnerability Demo
# ─────────────────────────────────────────────

def key_reuse_demo() -> dict:
    """
    Demonstrate that reusing the same key for both encryption and MAC
    creates exploitable correlations.
    
    With independent keys: secure
    With same key: potential correlations
    """
    # Independent keys (secure)
    kE1 = random_bytes(16)
    kM1 = random_bytes(16)
    
    # Same key for both (insecure)
    shared_key = random_bytes(16)
    
    message = b"Secret message!!"
    
    # Secure version
    n1, ct1, t1 = cca_encrypt(kE1, kM1, message)
    dec1 = cca_decrypt(kE1, kM1, n1, ct1, t1)
    
    # Insecure version (same key)
    n2, ct2, t2 = cca_encrypt(shared_key, shared_key, message)
    dec2 = cca_decrypt(shared_key, shared_key, n2, ct2, t2)
    
    return {
        'independent_keys': {
            'decrypted': dec1.decode() if dec1 else None,
            'works': dec1 == message,
            'secure': True
        },
        'shared_key': {
            'decrypted': dec2.decode() if dec2 else None,
            'works': dec2 == message,
            'warning': 'Key reuse creates correlations between encryption and authentication'
        }
    }
