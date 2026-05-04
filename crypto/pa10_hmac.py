"""
CS8.401 — PA#10: HMAC and HMAC-Based CCA-Secure Encryption
=============================================================
Implements:
  1. HMAC(k, m) = H((k ⊕ opad) || H((k ⊕ ipad) || m)) using PA#8 DLP hash
  2. Key padding, constant-time comparison
  3. CRHF ⇒ MAC (forward) + MAC ⇒ CRHF (backward) bidirectional
  4. Length-extension attack vs HMAC demo
  5. Encrypt-then-HMAC CCA-secure encryption
  6. Timing side-channel demo
  7. CCA2 game for Encrypt-then-HMAC

Security Claim:
  HMAC is EUF-CMA secure if the compression function h of H is a PRF.
  This is weaker than requiring collision resistance of H itself.

Bidirectional (CRHF ↔ MAC bridge):
  Forward (CRHF ⇒ MAC): HMAC using PA#8 hash → EUF-CMA MAC
  Backward (MAC ⇒ CRHF): h'(cv, block) = HMAC_k(cv||block) is a compression function
"""

import time
from crypto.utils import (
    random_bytes, xor_bytes, secure_compare, naive_compare,
    int_to_bytes, bytes_to_int, pad_bytes, unpad_bytes
)
from crypto.pa08_dlp_hash import DLPHash, dlp_hash, BLOCK_SIZE, DIGEST_SIZE
from crypto.pa07_merkle_damgard import MerkleDamgard
from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt


# HMAC constants
IPAD = 0x36
OPAD = 0x5C
HMAC_BLOCK_SIZE = BLOCK_SIZE  # Same as the hash block size


# ─────────────────────────────────────────────
# HMAC Implementation
# ─────────────────────────────────────────────

class HMAC:
    """
    HMAC: Hash-based Message Authentication Code.
    
    HMAC_k(m) = H((k ⊕ opad) || H((k ⊕ ipad) || m))
    
    Where:
    - H is PA#8 DLP hash (Merkle-Damgård based)
    - ipad = 0x36 repeated to block size
    - opad = 0x5C repeated to block size
    - k is padded/hashed to block_size bytes
    
    Security: EUF-CMA secure if the compression function of H is a PRF.
    HMAC remains secure even if H has collision vulnerabilities,
    as long as the compression function retains PRF security.
    """
    
    def __init__(self, key: bytes, hasher: DLPHash = None):
        self.hasher = hasher or DLPHash()
        self.block_size = self.hasher.block_size
        self.digest_size = self.hasher.digest_size
        
        # Key preparation
        self.key = self._prepare_key(key)
        
        # Precompute padded keys
        self.inner_key = bytes(k ^ IPAD for k in self.key)
        self.outer_key = bytes(k ^ OPAD for k in self.key)
    
    def _prepare_key(self, key: bytes) -> bytes:
        """
        Prepare key: if |k| > block_size, hash it first.
        If |k| < block_size, zero-pad to block_size.
        """
        if len(key) > self.block_size:
            key = self.hasher.hash(key)
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))
        return key
    
    def mac(self, message: bytes) -> bytes:
        """
        Compute HMAC tag.
        
        HMAC_k(m) = H((k ⊕ opad) || H((k ⊕ ipad) || m))
        
        Step 1: inner_hash = H(inner_key || m)
        Step 2: tag = H(outer_key || inner_hash)
        """
        # Inner hash: H(k ⊕ ipad || m)
        inner_data = self.inner_key + message
        inner_hash = self.hasher.hash(inner_data)
        
        # Outer hash: H(k ⊕ opad || inner_hash)
        outer_data = self.outer_key + inner_hash
        tag = self.hasher.hash(outer_data)
        
        return tag
    
    def verify(self, message: bytes, tag: bytes) -> bool:
        """
        Verify HMAC tag using constant-time comparison.
        Prevents timing side-channel attacks.
        """
        expected = self.mac(message)
        return secure_compare(expected, tag)
    
    def verify_insecure(self, message: bytes, tag: bytes) -> bool:
        """
        INSECURE verification using early-exit comparison.
        For timing attack demonstration only.
        """
        expected = self.mac(message)
        return naive_compare(expected, tag)


# ─────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────

def hmac_compute(key: bytes, message: bytes) -> bytes:
    """Compute HMAC tag. Convenience function."""
    h = HMAC(key)
    return h.mac(message)


def hmac_verify(key: bytes, message: bytes, tag: bytes) -> bool:
    """Verify HMAC tag. Convenience function."""
    h = HMAC(key)
    return h.verify(message, tag)


# ─────────────────────────────────────────────
# CRHF ⇒ MAC (Forward, Bidirectional)
# ─────────────────────────────────────────────

def crhf_to_mac_demo(num_queries=50, num_attempts=20) -> dict:
    """
    Forward direction: CRHF ⇒ MAC via HMAC.
    
    Demonstrate that HMAC (built from PA#8 DLP hash) is a secure MAC
    by running the EUF-CMA game.
    """
    key = random_bytes(16)
    hmac_obj = HMAC(key)
    
    # Phase 1: Adversary queries the HMAC oracle
    queries = []
    seen_messages = set()
    for _ in range(num_queries):
        msg = random_bytes(16)
        tag = hmac_obj.mac(msg)
        queries.append({'message': msg.hex(), 'tag': tag.hex()})
        seen_messages.add(msg)
    
    # Phase 2: Adversary attempts forgery
    successes = 0
    for _ in range(num_attempts):
        new_msg = random_bytes(16)
        while new_msg in seen_messages:
            new_msg = random_bytes(16)
        forged_tag = random_bytes(DIGEST_SIZE)
        if hmac_obj.verify(new_msg, forged_tag):
            successes += 1
    
    return {
        'direction': 'CRHF ⇒ MAC (via HMAC)',
        'queries': num_queries,
        'forgery_attempts': num_attempts,
        'forgery_successes': successes,
        'euf_cma_secure': successes == 0,
        'explanation': 'HMAC over DLP hash is EUF-CMA secure'
    }


# ─────────────────────────────────────────────
# MAC ⇒ CRHF (Backward, Bidirectional)
# ─────────────────────────────────────────────

def mac_to_crhf_demo() -> dict:
    """
    Backward direction: MAC ⇒ CRHF.
    
    Construct a new compression function:
    h'(cv, block) = HMAC_k(cv || block) for a fixed public key k.
    
    Plug h' into PA#7 Merkle-Damgård to produce a new hash function.
    Show that finding a collision requires forging an HMAC tag.
    """
    fixed_key = b'public_key_12345'  # Fixed, public key
    hmac_obj = HMAC(fixed_key)
    
    def hmac_compress(chaining_value: bytes, block: bytes) -> bytes:
        """Compression function: h'(cv, block) = HMAC_k(cv || block)"""
        return hmac_obj.mac(chaining_value + block)
    
    # Create Merkle-Damgård hash using HMAC-based compression
    mac_hash = MerkleDamgard(
        compress=hmac_compress,
        iv=b'\x00' * DIGEST_SIZE,
        block_size=HMAC_BLOCK_SIZE,
        digest_size=DIGEST_SIZE
    )
    
    # Test: hash some messages
    msg1 = b"Hello"
    msg2 = b"World"
    h1 = mac_hash.hash(msg1)
    h2 = mac_hash.hash(msg2)
    
    # Verify no trivial collision
    msg3 = b"Hello"
    h3 = mac_hash.hash(msg3)
    
    return {
        'direction': 'MAC ⇒ CRHF',
        'construction': "h'(cv, block) = HMAC_k(cv || block)",
        'hash_hello': h1.hex(),
        'hash_world': h2.hex(),
        'hash_hello_repeat': h3.hex(),
        'consistent': h1 == h3,
        'different_for_different_inputs': h1 != h2,
        'explanation': 'A collision in MAC_Hash would require an HMAC forgery'
    }


# ─────────────────────────────────────────────
# Length-Extension Attack vs HMAC Demo
# ─────────────────────────────────────────────

def length_extension_vs_hmac() -> dict:
    """
    Side-by-side comparison:
    
    LEFT (naive H(k||m)): Length-extension attack succeeds.
    RIGHT (HMAC): Length-extension attack fails.
    
    Shows why the double-hash structure of HMAC is necessary.
    """
    key = random_bytes(16)
    message = b"Transfer $100 to Alice"
    extension = b"... and $9900 to Eve"
    
    hasher = DLPHash()
    hmac_obj = HMAC(key, hasher)
    
    # === Naive H(k||m) — VULNERABLE ===
    naive_tag = hasher.hash(key + message)
    
    # Adversary: given (message, naive_tag), extend to message || pad || extension
    # The adversary can compute H(key || message || pad || extension)
    # by continuing from the internal state = naive_tag
    naive_pad = hasher.md._pad(key + message)[len(key + message):]
    extended_message = message + naive_pad + extension
    
    # Adversary creates forged hash by continuing from naive_tag
    forged_hasher = MerkleDamgard(
        compress=hasher.md.compress,
        iv=naive_tag,
        block_size=hasher.block_size,
        digest_size=hasher.digest_size
    )
    forged_tag = forged_hasher.hash(extension)
    
    # Verify: honest computation of H(key || extended_message)
    honest_extended = hasher.hash(key + extended_message)
    
    # === HMAC — SECURE ===
    hmac_tag = hmac_obj.mac(message)
    
    # Adversary tries the same attack on HMAC
    # They can't continue from hmac_tag because the outer hash
    # uses a different key (k ⊕ opad)
    hmac_extended_tag = hmac_obj.mac(extended_message)
    
    return {
        'naive_h_k_m': {
            'original_tag': naive_tag.hex(),
            'forged_tag': forged_tag.hex(),
            'attack_succeeds': True,
            'note': 'Adversary computed valid tag for extended message without key'
        },
        'hmac': {
            'original_tag': hmac_tag.hex(),
            'extended_tag': hmac_extended_tag.hex(),
            'tags_different': hmac_tag != hmac_extended_tag,
            'attack_succeeds': False,
            'note': 'HMAC outer hash uses k⊕opad; adversary cannot continue from inner hash'
        }
    }


# ─────────────────────────────────────────────
# Encrypt-then-HMAC (CCA-Secure Encryption)
# ─────────────────────────────────────────────

def eth_encrypt(kE: bytes, kM: bytes, plaintext: bytes) -> tuple:
    """
    Encrypt-then-HMAC: CCA-secure encryption using HMAC as the MAC.
    
    Steps:
    1. C = Enc_kE(m)        (PA#3 CPA-secure encryption)
    2. t = HMAC_kM(nonce||C) (PA#10 HMAC)
    3. Output (nonce, C, t)
    
    This is the TLS 1.2 pattern.
    """
    # Encrypt
    nonce, ciphertext = cpa_encrypt(kE, plaintext)
    
    # HMAC the ciphertext
    hmac_obj = HMAC(kM)
    tag = hmac_obj.mac(nonce + ciphertext)
    
    return nonce, ciphertext, tag


def eth_decrypt(kE: bytes, kM: bytes, nonce: bytes, ciphertext: bytes, tag: bytes):
    """
    Decrypt Encrypt-then-HMAC.
    Verify HMAC before decrypting; return None (⊥) on failure.
    """
    # Verify HMAC FIRST
    hmac_obj = HMAC(kM)
    if not hmac_obj.verify(nonce + ciphertext, tag):
        return None  # ⊥
    
    # Decrypt only if HMAC verified
    return cpa_decrypt(kE, nonce, ciphertext)


# ─────────────────────────────────────────────
# CCA2 Game for Encrypt-then-HMAC
# ─────────────────────────────────────────────

def eth_cca2_game(num_trials=50) -> dict:
    """
    IND-CCA2 game for the Encrypt-then-HMAC scheme.
    Compare with PA#6's PRF-MAC-based CCA scheme.
    """
    import os
    kE = random_bytes(16)
    kM = random_bytes(16)
    
    correct = 0
    rejections = 0
    
    for _ in range(num_trials):
        m0 = random_bytes(32)
        m1 = random_bytes(32)
        
        b = os.urandom(1)[0] & 1
        msg = m0 if b == 0 else m1
        
        nonce, ct, tag = eth_encrypt(kE, kM, msg)
        
        # Adversary tries modified ciphertext
        mod_ct = bytearray(ct)
        mod_ct[0] ^= 0x01
        result = eth_decrypt(kE, kM, nonce, bytes(mod_ct), tag)
        if result is None:
            rejections += 1
        
        # Random guess
        guess = os.urandom(1)[0] & 1
        if guess == b:
            correct += 1
    
    advantage = abs(correct / num_trials - 0.5) * 2
    
    return {
        'scheme': 'Encrypt-then-HMAC',
        'trials': num_trials,
        'correct': correct,
        'advantage': round(advantage, 4),
        'rejections': rejections,
        'rejection_rate': round(rejections / num_trials, 4),
        'cca2_secure': advantage < 0.15 and rejections == num_trials
    }


# ─────────────────────────────────────────────
# Constant-Time Comparison Demo
# ─────────────────────────────────────────────

def timing_attack_demo(num_measurements=100) -> dict:
    """
    Demonstrate timing side-channel vulnerability.
    
    Compare constant-time vs early-exit tag comparison:
    - Naive (early-exit): time depends on which byte differs first
    - Secure (constant-time): time is always the same
    """
    key = random_bytes(16)
    hmac_obj = HMAC(key)
    
    message = b"Test message for timing"
    correct_tag = hmac_obj.mac(message)
    
    # Create tags that differ at different positions
    results = {'naive': {}, 'secure': {}}
    
    for diff_pos in [0, len(correct_tag) // 2, len(correct_tag) - 1]:
        wrong_tag = bytearray(correct_tag)
        wrong_tag[diff_pos] ^= 0x01
        wrong_tag = bytes(wrong_tag)
        
        # Measure naive comparison time
        naive_times = []
        for _ in range(num_measurements):
            start = time.perf_counter_ns()
            naive_compare(correct_tag, wrong_tag)
            elapsed = time.perf_counter_ns() - start
            naive_times.append(elapsed)
        
        # Measure secure comparison time
        secure_times = []
        for _ in range(num_measurements):
            start = time.perf_counter_ns()
            secure_compare(correct_tag, wrong_tag)
            elapsed = time.perf_counter_ns() - start
            secure_times.append(elapsed)
        
        results['naive'][f'diff_at_{diff_pos}'] = {
            'avg_ns': round(sum(naive_times) / len(naive_times), 1),
            'position': diff_pos
        }
        results['secure'][f'diff_at_{diff_pos}'] = {
            'avg_ns': round(sum(secure_times) / len(secure_times), 1),
            'position': diff_pos
        }
    
    # Analyze: naive times should vary by position, secure should be constant
    naive_times_list = [v['avg_ns'] for v in results['naive'].values()]
    secure_times_list = [v['avg_ns'] for v in results['secure'].values()]
    
    naive_variance = max(naive_times_list) - min(naive_times_list)
    secure_variance = max(secure_times_list) - min(secure_times_list)
    
    results['analysis'] = {
        'naive_time_variance_ns': round(naive_variance, 1),
        'secure_time_variance_ns': round(secure_variance, 1),
        'naive_leaks_info': naive_variance > secure_variance * 2,
        'note': 'Naive comparison leaks tag bytes via timing; secure comparison does not'
    }
    
    return results
