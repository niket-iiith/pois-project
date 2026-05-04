"""
CS8.401 — PA#7: Merkle-Damgård Transform
==========================================
Implements:
  1. Generic MerkleDamgard(compress, IV, block_size) framework
  2. MD-strengthening padding: M || 1 || 0* || <|M|>_64
  3. Length-extension vulnerability demo
  4. Dummy compression plug-in for testing
  5. Interface: hash(message, compression_fn) -> digest

Security Claim:
  If h is a collision-resistant compression function, then the Merkle-Damgård
  transform H is collision-resistant. Any collision in H implies a collision in h.
"""

from crypto.utils import int_to_bytes, bytes_to_int


# ─────────────────────────────────────────────
# Merkle-Damgård Transform
# ─────────────────────────────────────────────

class MerkleDamgard:
    """
    Generic Merkle-Damgård hash function framework.
    
    Takes any compression function h: {0,1}^{n+b} -> {0,1}^n
    and produces a hash function for arbitrary-length inputs.
    
    Args:
        compress: compression function h(chaining_value, block) -> new_chaining_value
                  chaining_value is `digest_size` bytes
                  block is `block_size` bytes
                  returns `digest_size` bytes
        iv: initial chaining value (digest_size bytes)
        block_size: size of each message block in bytes
        digest_size: size of the hash output in bytes
    """
    
    def __init__(self, compress, iv: bytes, block_size: int, digest_size: int = None):
        self.compress = compress
        self.iv = iv
        self.block_size = block_size
        self.digest_size = digest_size or len(iv)
    
    def _pad(self, message: bytes) -> bytes:
        """
        MD-strengthening padding.
        
        Append:
        1. A single 1-bit (0x80 byte)
        2. Enough 0-bytes so total length ≡ (block_size - 8) mod block_size
        3. 8-byte big-endian encoding of original message length in bits
        
        Result: padded message is a multiple of block_size bytes.
        """
        msg_len_bits = len(message) * 8
        
        # Append 0x80
        padded = message + b'\x80'
        
        # Append zeros until length ≡ block_size - 8 (mod block_size)
        while (len(padded) + 8) % self.block_size != 0:
            padded += b'\x00'
        
        # Append 64-bit big-endian length
        padded += int_to_bytes(msg_len_bits, 8)
        
        return padded
    
    def hash(self, message: bytes) -> bytes:
        """
        Hash an arbitrary-length message using the Merkle-Damgård transform.
        
        Algorithm:
        1. Pad message M with MD-strengthening
        2. Parse into blocks M_1, M_2, ..., M_ℓ
        3. z_0 = IV
        4. For i = 1 to ℓ: z_i = h(z_{i-1}, M_i)
        5. Output z_ℓ
        """
        padded = self._pad(message)
        
        # Process blocks
        chaining_value = self.iv
        
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i + self.block_size]
            chaining_value = self.compress(chaining_value, block)
        
        return chaining_value
    
    def hash_with_steps(self, message: bytes) -> dict:
        """
        Hash with step-by-step trace for visualization.
        Returns the full chain of intermediate values.
        """
        padded = self._pad(message)
        
        steps = []
        chaining_value = self.iv
        steps.append({'step': 0, 'type': 'IV', 'value': chaining_value.hex()})
        
        blocks = []
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i + self.block_size]
            blocks.append(block)
            chaining_value = self.compress(chaining_value, block)
            steps.append({
                'step': len(blocks),
                'type': 'compress',
                'block': block.hex(),
                'value': chaining_value.hex()
            })
        
        return {
            'message': message.hex(),
            'padded': padded.hex(),
            'num_blocks': len(blocks),
            'steps': steps,
            'digest': chaining_value.hex()
        }
    
    def get_internal_state(self, message: bytes) -> bytes:
        """
        Return the internal state (chaining value) after processing message.
        Used for demonstrating length-extension attacks.
        """
        padded = self._pad(message)
        chaining_value = self.iv
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i + self.block_size]
            chaining_value = self.compress(chaining_value, block)
        return chaining_value


# ─────────────────────────────────────────────
# Dummy Compression Function (for testing)
# ─────────────────────────────────────────────

def dummy_compress(chaining_value: bytes, block: bytes) -> bytes:
    """
    Toy compression function for testing the MD framework.
    h(cv, block) = AES_cv(block[:16]) ⊕ cv
    
    This is NOT collision-resistant — just for testing the framework.
    """
    from crypto.aes import aes_encrypt
    
    # Use first 16 bytes of chaining value as AES key
    cv_key = chaining_value[:16]
    if len(cv_key) < 16:
        cv_key = cv_key + b'\x00' * (16 - len(cv_key))
    
    # Use first 16 bytes of block as AES input
    block_input = block[:16]
    if len(block_input) < 16:
        block_input = block_input + b'\x00' * (16 - len(block_input))
    
    encrypted = aes_encrypt(cv_key, block_input)
    
    # Davies-Meyer: h = E_cv(block) ⊕ cv
    from crypto.utils import xor_bytes
    return xor_bytes(encrypted, cv_key)


def create_dummy_hasher(block_size=32, digest_size=16) -> MerkleDamgard:
    """Create a MerkleDamgard instance with the dummy compression function."""
    iv = b'\x00' * digest_size
    return MerkleDamgard(
        compress=dummy_compress,
        iv=iv,
        block_size=block_size,
        digest_size=digest_size
    )


# ─────────────────────────────────────────────
# Length-Extension Vulnerability Demo
# ─────────────────────────────────────────────

def length_extension_demo() -> dict:
    """
    Demonstrate the length-extension vulnerability of Merkle-Damgård hashes.
    
    Given H(M) and |M|, an adversary can compute H(M || pad || M')
    for any suffix M' WITHOUT knowing M.
    
    This is because H(M) = the internal state after processing M || pad,
    and the adversary can continue the hash from this state.
    """
    hasher = create_dummy_hasher()
    
    # Original message
    message = b"secret key: transfer $100"
    h_m = hasher.hash(message)
    
    # The adversary knows H(M) and |M|, but not M itself
    # Adversary wants to compute H(M || pad || M') where M' = " to attacker"
    extension = b" to attacker"
    
    # Compute the padding that would be applied to M
    original_pad = hasher._pad(message)[len(message):]
    
    # Extended message = M || pad || M'
    extended_message = message + original_pad + extension
    
    # Method 1: Adversary computes by continuing from H(M)
    # Create new hasher starting from H(M) as IV
    forged_hasher = MerkleDamgard(
        compress=hasher.compress,
        iv=h_m,  # Start from H(M) — the leaked internal state
        block_size=hasher.block_size,
        digest_size=hasher.digest_size
    )
    forged_hash = forged_hasher.hash(extension)
    
    # Method 2: Honest computation of H(extended_message)
    honest_hash = hasher.hash(extended_message)
    
    return {
        'original_message': message.decode(),
        'original_hash': h_m.hex(),
        'extension': extension.decode(),
        'forged_hash': forged_hash.hex(),
        'honest_hash': honest_hash.hex(),
        'attack_note': 'Forged hash computed from H(M) alone, without knowing M',
        'vulnerability': 'MD hashes leak internal state → length extension possible'
    }


# ─────────────────────────────────────────────
# Collision Resistance Reduction
# ─────────────────────────────────────────────

def collision_resistance_demo() -> dict:
    """
    Demonstrate the security reduction:
    Any collision in H implies a collision in the compression function h.
    
    With the dummy (weak) compression function, we can find collisions
    more easily, demonstrating that the MD transform is only as strong
    as its compression function.
    """
    hasher = create_dummy_hasher()
    
    # Try to find collisions (should be hard with a good compression function)
    # With dummy compression, structure might allow easier collisions
    hashes_seen = {}
    collision_found = False
    collision = None
    
    for i in range(1000):
        msg = int_to_bytes(i, 8)
        h = hasher.hash(msg)
        h_hex = h.hex()
        
        if h_hex in hashes_seen:
            collision_found = True
            collision = {
                'message1': hashes_seen[h_hex].hex(),
                'message2': msg.hex(),
                'hash': h_hex
            }
            break
        hashes_seen[h_hex] = msg
    
    return {
        'tested_messages': min(i + 1, 1000),
        'collision_found': collision_found,
        'collision': collision,
        'note': 'Good compression functions should make collision finding infeasible'
    }
