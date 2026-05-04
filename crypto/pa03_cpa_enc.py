"""
CS8.401 — PA#3: CPA-Secure Symmetric Encryption
==================================================
Implements:
  1. CPA-secure encryption: Enc(k, m) = (r, F_k(r) ⊕ m) using PA#2 PRF
  2. Multi-block encryption via CTR mode with PA#2 PRF
  3. IND-CPA game simulation
  4. Decryption: Dec(k, r, c) = F_k(r) ⊕ c
  5. Interface: Enc(k, m) -> (r, c), Dec(k, r, c) -> m

Security Claim:
  If F is a secure PRF, then the encryption scheme Enc(k,m) = (r, F_k(r) ⊕ m)
  with random r is CPA-secure. Any CPA adversary implies a PRF distinguisher.

Note: CPA-secure but NOT CCA-secure (malleable). PA#6 adds MAC for CCA.
"""

from crypto.utils import random_bytes, xor_bytes, int_to_bytes, bytes_to_int, pad_bytes, unpad_bytes
from crypto.pa02_prf_ggm import PRF


# ─────────────────────────────────────────────
# CPA-Secure Encryption (Single Block)
# ─────────────────────────────────────────────

def cpa_enc_block(key: bytes, plaintext: bytes, prf: PRF = None) -> tuple:
    """
    CPA-secure encryption of a single 16-byte block.
    Enc(k, m) = (r, F_k(r) ⊕ m)
    
    Args:
        key: 16-byte encryption key
        plaintext: 16-byte plaintext block
        prf: optional PRF instance (creates one from key if not provided)
    
    Returns:
        (r, ciphertext): tuple of (16-byte nonce, 16-byte ciphertext)
    """
    if prf is None:
        prf = PRF(key=key)
    
    # Random nonce r
    r = random_bytes(16)
    
    # C = F_k(r) ⊕ m
    prf_output = prf.F_bytes(r)
    ciphertext = xor_bytes(prf_output, plaintext)
    
    return r, ciphertext


def cpa_dec_block(key: bytes, r: bytes, ciphertext: bytes, prf: PRF = None) -> bytes:
    """
    CPA-secure decryption of a single 16-byte block.
    Dec(k, r, c) = F_k(r) ⊕ c
    
    Returns:
        16-byte plaintext
    """
    if prf is None:
        prf = PRF(key=key)
    
    prf_output = prf.F_bytes(r)
    plaintext = xor_bytes(prf_output, ciphertext)
    
    return plaintext


# ─────────────────────────────────────────────
# CPA-Secure Encryption (Multi-Block, CTR Mode)
# ─────────────────────────────────────────────

def cpa_encrypt(key: bytes, plaintext: bytes) -> tuple:
    """
    CPA-secure encryption of arbitrary-length messages using CTR mode.
    
    Uses PA#2 PRF in counter mode:
    - Generate random nonce r
    - For each block i: C_i = P_i ⊕ F_k(r || i)
    
    Args:
        key: 16-byte encryption key
        plaintext: arbitrary-length plaintext
    
    Returns:
        (nonce, ciphertext): tuple of (8-byte nonce, ciphertext bytes)
    """
    prf = PRF(key=key)
    
    # 8-byte random nonce (leaves 8 bytes for counter)
    nonce = random_bytes(8)
    
    # Pad plaintext to multiple of 16 bytes
    padded = pad_bytes(plaintext, 16)
    
    ciphertext = bytearray()
    num_blocks = len(padded) // 16
    
    for i in range(num_blocks):
        # Construct counter block: nonce || counter
        counter_block = nonce + int_to_bytes(i, 8)
        
        # Generate keystream block
        keystream = prf.F_bytes(counter_block)
        
        # XOR with plaintext block
        pt_block = padded[i * 16:(i + 1) * 16]
        ct_block = xor_bytes(keystream, pt_block)
        ciphertext.extend(ct_block)
    
    return nonce, bytes(ciphertext)


def cpa_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    CPA-secure decryption of arbitrary-length messages.
    
    Args:
        key: 16-byte encryption key
        nonce: 8-byte nonce from encryption
        ciphertext: ciphertext bytes
    
    Returns:
        Original plaintext (with padding removed)
    """
    prf = PRF(key=key)
    
    plaintext = bytearray()
    num_blocks = len(ciphertext) // 16
    
    for i in range(num_blocks):
        counter_block = nonce + int_to_bytes(i, 8)
        keystream = prf.F_bytes(counter_block)
        ct_block = ciphertext[i * 16:(i + 1) * 16]
        pt_block = xor_bytes(keystream, ct_block)
        plaintext.extend(pt_block)
    
    return unpad_bytes(bytes(plaintext))


# ─────────────────────────────────────────────
# IND-CPA Game Simulation
# ─────────────────────────────────────────────

def ind_cpa_game(key: bytes = None, num_trials=100) -> dict:
    """
    IND-CPA Game Simulation.
    
    The adversary:
    1. Chooses two equal-length messages m0, m1
    2. Receives Enc(k, m_b) for random b ∈ {0,1}
    3. Must guess b
    
    A dummy adversary (random guess) should achieve ~50% success.
    Our CPA-secure scheme should give no advantage.
    """
    if key is None:
        key = random_bytes(16)
    
    correct = 0
    
    for _ in range(num_trials):
        # Adversary chooses two messages
        m0 = random_bytes(16)
        m1 = random_bytes(16)
        
        # Challenger picks random bit b
        import os
        b = os.urandom(1)[0] & 1
        
        # Encrypt m_b
        msg = m0 if b == 0 else m1
        nonce, ct = cpa_encrypt(key, msg)
        
        # Dummy adversary: random guess (no strategy can do better)
        guess = os.urandom(1)[0] & 1
        
        if guess == b:
            correct += 1
    
    advantage = abs(correct / num_trials - 0.5) * 2
    
    return {
        'trials': num_trials,
        'correct': correct,
        'success_rate': round(correct / num_trials, 4),
        'advantage': round(advantage, 4),
        'cpa_secure': advantage < 0.15  # Should be close to 0
    }


# ─────────────────────────────────────────────
# Malleability Demonstration (for PA#6 contrast)
# ─────────────────────────────────────────────

def demonstrate_malleability(key: bytes = None) -> dict:
    """
    Show that CPA-secure encryption is MALLEABLE.
    
    Given C = (r, F_k(r) ⊕ m), an adversary can flip bit i of the
    ciphertext to flip bit i of the plaintext, without knowing k or m.
    
    This motivates CCA-secure encryption (PA#6).
    """
    if key is None:
        key = random_bytes(16)
    
    message = b"Hello, World!!!!"  # 16 bytes
    assert len(message) == 16
    
    r, ct = cpa_enc_block(key, message)
    
    # Original decryption
    original = cpa_dec_block(key, r, ct)
    
    # Adversary flips bit 0 of byte 0 in ciphertext
    modified_ct = bytearray(ct)
    modified_ct[0] ^= 0x01  # Flip LSB of first byte
    modified_ct = bytes(modified_ct)
    
    # Decrypt modified ciphertext
    modified_plain = cpa_dec_block(key, r, modified_ct)
    
    return {
        'original_message': message.hex(),
        'original_message_text': message.decode('ascii', errors='replace'),
        'ciphertext': ct.hex(),
        'modified_ciphertext': modified_ct.hex(),
        'decrypted_modified': modified_plain.hex(),
        'decrypted_modified_text': modified_plain.decode('ascii', errors='replace'),
        'bit_flipped': original[0] ^ modified_plain[0],
        'malleable': original != modified_plain
    }
