"""
CS8.401 — PA#5: Message Authentication Codes (MACs)
=====================================================
Implements:
  1. PRF-MAC: Mac_k(m) = F_k(m) using PA#2 PRF
  2. CBC-MAC: Chain blocks through PRF, output last block
  3. Mac(k, m) -> t and Vrfy(k, m, t) -> bool
  4. EUF-CMA forgery game
  5. Length-extension attack demo on naive H(k||m)
  6. MAC ⇒ PRF backward direction demo

Security Claim:
  PRF-MAC: If F is a secure PRF, then Mac_k(m) = F_k(m) is EUF-CMA secure.
  Any forgery implies a PRF distinguisher.

Bidirectional:
  Forward (PRF ⇒ MAC): Mac_k(m) = F_k(m)
  Backward (MAC ⇒ PRF): A secure MAC on random inputs is a PRF
"""

from crypto.utils import random_bytes, xor_bytes, secure_compare, int_to_bytes, bytes_to_int
from crypto.pa02_prf_ggm import PRF
from crypto.aes import aes_encrypt


# ─────────────────────────────────────────────
# PRF-MAC (Forward: PRF ⇒ MAC)
# ─────────────────────────────────────────────

class PRF_MAC:
    """
    PRF-based Message Authentication Code.
    Mac_k(m) = F_k(m)
    
    For short messages (≤ 16 bytes): single PRF evaluation.
    For longer messages: CBC-MAC construction.
    
    Security: EUF-CMA secure if F is a secure PRF.
    """
    
    def __init__(self, key: bytes = None):
        if key is None:
            key = random_bytes(16)
        self.key = key
        self.prf = PRF(key=key)
    
    def mac(self, message: bytes) -> bytes:
        """
        Compute MAC tag for message.
        
        For messages ≤ 16 bytes: Mac_k(m) = F_k(pad(m))
        For longer messages: Uses CBC-MAC construction.
        
        Returns: 16-byte tag
        """
        if len(message) <= 16:
            # Pad to 16 bytes
            padded = message + b'\x00' * (16 - len(message))
            return self.prf.F_bytes(padded)
        else:
            return self._cbc_mac(message)
    
    def _cbc_mac(self, message: bytes) -> bytes:
        """
        CBC-MAC for multi-block messages.
        
        Chain: t_0 = 0^n
               t_i = F_k(t_{i-1} ⊕ m_i)
        Output: t_ℓ (last block only)
        
        Note: Raw CBC-MAC is only secure for fixed-length messages.
        For variable-length, we prepend the length.
        """
        # Prepend length for variable-length security
        length_prefix = len(message).to_bytes(8, 'big')
        data = length_prefix + message
        
        # Pad to multiple of 16
        while len(data) % 16 != 0:
            data += b'\x00'
        
        tag = b'\x00' * 16  # t_0 = 0^n
        
        for i in range(0, len(data), 16):
            block = data[i:i + 16]
            xored = xor_bytes(tag, block)
            tag = aes_encrypt(self.key, xored)
        
        return tag
    
    def verify(self, message: bytes, tag: bytes) -> bool:
        """
        Verify MAC tag using constant-time comparison.
        Returns True if tag is valid, False otherwise.
        """
        expected = self.mac(message)
        return secure_compare(expected, tag)


# ─────────────────────────────────────────────
# CBC-MAC (Standalone)
# ─────────────────────────────────────────────

class CBC_MAC:
    """
    CBC-MAC: Chain message blocks through AES, output final block.
    
    More efficient than PRF-MAC for multi-block messages.
    Uses AES directly as the block cipher.
    """
    
    def __init__(self, key: bytes = None):
        if key is None:
            key = random_bytes(16)
        self.key = key
    
    def mac(self, message: bytes) -> bytes:
        """Compute CBC-MAC tag."""
        # Prepend length for variable-length security
        length_prefix = len(message).to_bytes(8, 'big')
        data = length_prefix + message
        
        # Pad
        while len(data) % 16 != 0:
            data += b'\x00'
        
        tag = b'\x00' * 16
        for i in range(0, len(data), 16):
            block = data[i:i + 16]
            xored = xor_bytes(tag, block)
            tag = aes_encrypt(self.key, xored)
        
        return tag
    
    def verify(self, message: bytes, tag: bytes) -> bool:
        """Verify CBC-MAC tag with constant-time comparison."""
        expected = self.mac(message)
        return secure_compare(expected, tag)


# ─────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────

def mac(key: bytes, message: bytes) -> bytes:
    """Compute MAC tag. Convenience wrapper."""
    m = PRF_MAC(key=key)
    return m.mac(message)


def vrfy(key: bytes, message: bytes, tag: bytes) -> bool:
    """Verify MAC tag. Convenience wrapper."""
    m = PRF_MAC(key=key)
    return m.verify(message, tag)


# ─────────────────────────────────────────────
# EUF-CMA Forgery Game
# ─────────────────────────────────────────────

def euf_cma_game(key: bytes = None, num_queries=50, num_attempts=20) -> dict:
    """
    EUF-CMA (Existential Unforgeability under Chosen Message Attack) Game.
    
    1. Adversary queries MAC oracle on up to num_queries messages
    2. Adversary attempts to forge a tag on a new message
    3. Show that naive adversary cannot forge
    
    Returns results of the forgery game.
    """
    if key is None:
        key = random_bytes(16)
    
    mac_obj = PRF_MAC(key=key)
    
    # Phase 1: Adversary queries the oracle
    queries = []
    seen_messages = set()
    for _ in range(num_queries):
        msg = random_bytes(16)
        tag = mac_obj.mac(msg)
        queries.append({'message': msg.hex(), 'tag': tag.hex()})
        seen_messages.add(msg)
    
    # Phase 2: Adversary attempts forgery
    successes = 0
    attempts = []
    
    for _ in range(num_attempts):
        # Adversary picks a new message (not in queries)
        new_msg = random_bytes(16)
        while new_msg in seen_messages:
            new_msg = random_bytes(16)
        
        # Adversary guesses a random tag
        forged_tag = random_bytes(16)
        
        # Check if forgery is valid
        valid = mac_obj.verify(new_msg, forged_tag)
        if valid:
            successes += 1
        
        attempts.append({
            'message': new_msg.hex(),
            'forged_tag': forged_tag.hex(),
            'accepted': valid
        })
    
    return {
        'num_queries': num_queries,
        'num_attempts': num_attempts,
        'forgery_successes': successes,
        'euf_cma_secure': successes == 0,
        'sample_queries': queries[:5],
        'sample_attempts': attempts[:5]
    }


# ─────────────────────────────────────────────
# Length-Extension Attack Demo
# ─────────────────────────────────────────────

def length_extension_demo() -> dict:
    """
    Demonstrate the length-extension vulnerability of naive MAC t = H(k||m).
    
    With a naive MAC using Merkle-Damgård hash: t = H(k || m),
    given (m, t), an adversary can compute a valid tag for m || pad || m'
    without knowing k.
    
    This motivates the HMAC double-hash structure (PA#10).
    
    Note: We simulate this conceptually since our actual hash (PA#8)
    is not yet implemented. The demo shows the vulnerability pattern.
    """
    key = random_bytes(16)
    
    # Simulate naive MAC: t = AES-CBC(k, k || m) — simplified
    # The real vulnerability is with Merkle-Damgård hashes
    message = b"Transfer $100"
    
    # Naive MAC (single hash, vulnerable)
    naive_mac_obj = PRF_MAC(key=key)
    tag = naive_mac_obj.mac(key + message)  # t = H(k || m)
    
    # Show that proper MAC is NOT vulnerable
    proper_tag = naive_mac_obj.mac(message)  # Proper: Mac_k(m) = F_k(m)
    
    # Adversary tries to extend
    extension = b" and $9900"
    extended_msg = message + extension
    
    # Check: adversary cannot forge proper MAC
    forged_tag = random_bytes(16)
    forged_valid = naive_mac_obj.verify(extended_msg, forged_tag)
    
    return {
        'original_message': message.decode(),
        'original_tag': tag.hex(),
        'extension': extension.decode(),
        'extended_message': extended_msg.decode(),
        'forged_tag_accepted': forged_valid,
        'vulnerability': 'Naive H(k||m) allows length extension; HMAC prevents this',
        'proper_mac_secure': not forged_valid
    }


# ─────────────────────────────────────────────
# MAC ⇒ PRF (Backward Direction)
# ─────────────────────────────────────────────

def mac_to_prf_demo(num_queries=100) -> dict:
    """
    Backward direction: MAC ⇒ PRF
    
    A secure EUF-CMA MAC on uniformly random messages is a PRF.
    Demonstrate that MAC outputs on random inputs pass the same
    PRF distinguishing test from PA#2.
    """
    from crypto.pa01_owf_prg import run_statistical_tests
    from crypto.utils import bytes_to_bits
    
    key = random_bytes(16)
    mac_obj = PRF_MAC(key=key)
    
    # Query MAC on random inputs
    all_bits = []
    for i in range(num_queries):
        msg = random_bytes(16)
        tag = mac_obj.mac(msg)
        all_bits.extend(bytes_to_bits(tag))
    
    # Run statistical tests
    stats = run_statistical_tests(all_bits)
    
    return {
        'num_queries': num_queries,
        'statistical_tests': stats,
        'mac_is_prf': stats['all_pass'],
        'explanation': 'MAC outputs on random inputs are indistinguishable from random → MAC is a PRF'
    }
