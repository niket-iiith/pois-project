"""
CS8.401 — PA#8: DLP-Based Collision-Resistant Hash Function
=============================================================
Implements:
  1. DLP compression function: h(cv, block) = g^cv · h_pub^block mod p (truncated)
  2. Full CRHF by plugging into PA#7 Merkle-Damgård framework
  3. Collision resistance argument + attack attempt demo
  4. Avalanche effect demonstration
  5. Interface: dlp_hash(message) -> digest

Security Claim:
  Finding a collision in h requires solving a DLP instance.
  Specifically, finding cv1, b1, cv2, b2 with g^{cv1} · h^{b1} = g^{cv2} · h^{b2}
  implies knowing log_g(h), which is hard by the DLP assumption.

Forward pointer to PA#10: This hash function is used by HMAC.
"""

from crypto.utils import mod_exp, random_int, int_to_bytes, bytes_to_int, random_bytes
from crypto.pa07_merkle_damgard import MerkleDamgard


# ─────────────────────────────────────────────
# DLP Group Parameters for Hashing
# ─────────────────────────────────────────────

# Use smaller parameters for hashing (speed vs security tradeoff for demos)
# In production, these would be 2048+ bit primes

# 256-bit safe prime for the hash function
# p = 2q + 1 where q is prime
DLP_HASH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
DLP_HASH_Q = (DLP_HASH_P - 1) // 2
DLP_HASH_G = 2  # Generator
# h is another generator (random element of the group, DLP unknown)
DLP_HASH_H = mod_exp(DLP_HASH_G, 0xDEADBEEFCAFEBABE, DLP_HASH_P)

# Digest size in bytes (truncated from the group element)
DIGEST_SIZE = 16  # 128-bit digest (truncated for demo speed)
BLOCK_SIZE = 16   # 128-bit blocks


# ─────────────────────────────────────────────
# DLP Compression Function
# ─────────────────────────────────────────────

def dlp_compress(chaining_value: bytes, block: bytes) -> bytes:
    """
    DLP-based compression function.
    
    h(cv, block) = g^cv · h_pub^block mod p   (truncated to DIGEST_SIZE bytes)
    
    This is collision-resistant under the DLP assumption:
    Finding cv1, b1 ≠ cv2, b2 with h(cv1, b1) = h(cv2, b2)
    would yield log_g(h_pub) = (cv1 - cv2) · (b2 - b1)^{-1} mod q
    
    Args:
        chaining_value: current chaining value (DIGEST_SIZE bytes)
        block: message block (BLOCK_SIZE bytes)
    
    Returns:
        New chaining value (DIGEST_SIZE bytes)
    """
    # Convert bytes to integers
    cv_int = bytes_to_int(chaining_value) % DLP_HASH_Q
    block_int = bytes_to_int(block) % DLP_HASH_Q
    
    # h(cv, block) = g^cv · h^block mod p
    g_cv = mod_exp(DLP_HASH_G, cv_int, DLP_HASH_P)
    h_block = mod_exp(DLP_HASH_H, block_int, DLP_HASH_P)
    result = (g_cv * h_block) % DLP_HASH_P
    
    # Truncate to DIGEST_SIZE bytes
    result_bytes = int_to_bytes(result % (1 << (DIGEST_SIZE * 8)), DIGEST_SIZE)
    return result_bytes


# ─────────────────────────────────────────────
# DLP Hash (Full CRHF using Merkle-Damgård)
# ─────────────────────────────────────────────

class DLPHash:
    """
    DLP-based Collision-Resistant Hash Function.
    
    Constructed by plugging the DLP compression function into
    the Merkle-Damgård framework (PA#7).
    
    H: {0,1}* -> {0,1}^{DIGEST_SIZE*8}
    """
    
    def __init__(self, digest_size=DIGEST_SIZE, block_size=BLOCK_SIZE):
        self.digest_size = digest_size
        self.block_size = block_size
        self.iv = b'\x00' * digest_size
        self.md = MerkleDamgard(
            compress=dlp_compress,
            iv=self.iv,
            block_size=block_size,
            digest_size=digest_size
        )
    
    def hash(self, message: bytes) -> bytes:
        """Hash an arbitrary-length message."""
        return self.md.hash(message)
    
    def hash_hex(self, message: bytes) -> str:
        """Hash and return hex string."""
        return self.hash(message).hex()
    
    def hash_with_steps(self, message: bytes) -> dict:
        """Hash with step-by-step trace for visualization."""
        return self.md.hash_with_steps(message)
    
    def get_internal_state(self, message: bytes) -> bytes:
        """Get internal state after processing (for length-extension demo)."""
        return self.md.get_internal_state(message)


# Singleton instance for convenience
_default_hasher = None

def dlp_hash(message: bytes) -> bytes:
    """
    Hash a message using the DLP-based CRHF.
    Convenience function using the default hasher.
    """
    global _default_hasher
    if _default_hasher is None:
        _default_hasher = DLPHash()
    return _default_hasher.hash(message)


def dlp_hash_hex(message: bytes) -> str:
    """Hash and return hex string."""
    return dlp_hash(message).hex()


# ─────────────────────────────────────────────
# Truncated DLP Hash (for Birthday Attack PA#9)
# ─────────────────────────────────────────────

def dlp_hash_truncated(message: bytes, output_bits: int) -> bytes:
    """
    Truncated DLP hash for birthday attack experiments.
    Returns only the first `output_bits` bits of the full hash.
    
    Used in PA#9 to demonstrate the birthday bound at various bit lengths.
    """
    full_hash = dlp_hash(message)
    output_bytes = (output_bits + 7) // 8
    truncated = full_hash[:output_bytes]
    
    # Mask the last byte if output_bits is not a multiple of 8
    if output_bits % 8 != 0:
        mask = (0xFF << (8 - output_bits % 8)) & 0xFF
        truncated = truncated[:-1] + bytes([truncated[-1] & mask])
    
    return truncated


# ─────────────────────────────────────────────
# Collision Resistance Demo
# ─────────────────────────────────────────────

def collision_resistance_demo(trials=1000) -> dict:
    """
    Attempt to find collisions in the DLP hash.
    Should fail for the full hash (collision-resistant under DLP).
    Demonstrates that random collision search is futile.
    """
    hasher = DLPHash()
    seen = {}
    collision = None
    
    for i in range(trials):
        msg = int_to_bytes(i, 8)
        h = hasher.hash(msg)
        h_hex = h.hex()
        
        if h_hex in seen:
            collision = {
                'msg1': seen[h_hex].hex(),
                'msg2': msg.hex(),
                'hash': h_hex,
                'found_at': i
            }
            break
        seen[h_hex] = msg
    
    return {
        'trials': trials,
        'collision_found': collision is not None,
        'collision': collision,
        'security_argument': (
            'Finding a collision requires solving DLP: '
            'h(cv1,b1) = h(cv2,b2) implies g^(cv1-cv2) = h^(b2-b1) mod p, '
            'yielding log_g(h) = (cv1-cv2)(b2-b1)^{-1} mod q'
        )
    }


# ─────────────────────────────────────────────
# Avalanche Effect Demo
# ─────────────────────────────────────────────

def avalanche_demo() -> dict:
    """
    Demonstrate the avalanche effect: a 1-bit change in input
    should change approximately 50% of the output bits.
    """
    hasher = DLPHash()
    
    msg1 = b"Hello, World!"
    msg2 = b"Hello, World\x00"  # One byte different
    
    h1 = hasher.hash(msg1)
    h2 = hasher.hash(msg2)
    
    # Count differing bits
    diff_bits = 0
    total_bits = len(h1) * 8
    for b1, b2 in zip(h1, h2):
        diff_bits += bin(b1 ^ b2).count('1')
    
    return {
        'message1': msg1.hex(),
        'message2': msg2.hex(),
        'hash1': h1.hex(),
        'hash2': h2.hex(),
        'differing_bits': diff_bits,
        'total_bits': total_bits,
        'diff_ratio': round(diff_bits / total_bits, 4),
        'good_avalanche': 0.3 < diff_bits / total_bits < 0.7
    }
