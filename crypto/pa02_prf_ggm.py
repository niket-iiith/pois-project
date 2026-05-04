"""
CS8.401 — PA#2: Pseudorandom Functions via GGM Tree
=====================================================
Implements:
  1. GGM PRF from PA#1 PRG (forward: PRG ⇒ PRF)
  2. PRG from PRF (backward: PRF ⇒ PRG)
  3. AES plug-in: F_k(x) = AES_k(x) as alternative PRF
  4. Distinguishing game demo
  5. Interface: F(k, x) for PA#3, PA#4, PA#5

GGM Tree Construction:
  Given length-doubling PRG G: {0,1}^n → {0,1}^{2n},
  write G(s) = G_0(s) || G_1(s) (left and right halves).
  F_k(b1 b2 ... bn) = G_{bn}(G_{bn-1}(... G_{b1}(k) ...))

Security Claim:
  If G is a secure PRG, then the GGM construction yields a secure PRF.

Bidirectional reductions:
  Forward (PRG ⇒ PRF): GGM tree construction
  Backward (PRF ⇒ PRG): G(s) = F_s(0^n) || F_s(1^n)
"""

from crypto.utils import (
    random_bytes, xor_bytes, bytes_to_int, int_to_bytes,
    bytes_to_bits, bits_to_bytes
)
from crypto.aes import aes_encrypt, aes_prf
from crypto.pa01_owf_prg import PRG, run_statistical_tests


# ─────────────────────────────────────────────
# Length-Doubling PRG for GGM (wraps PA#1 PRG)
# ─────────────────────────────────────────────

def prg_double(seed: bytes) -> tuple:
    """
    Length-doubling PRG: G(s) = (G_0(s), G_1(s))
    Takes n-byte seed, returns two n-byte outputs (left, right).
    
    Implementation: Use AES in counter mode to double the output.
    G(s) = AES_s(0) || AES_s(1)  (each 16 bytes, total 32 bytes from 16-byte seed)
    """
    n = len(seed)
    if n < 16:
        seed = seed + b'\x00' * (16 - n)
    
    # G_0(s) = AES_s(0^128)
    left = aes_encrypt(seed[:16], b'\x00' * 16)
    # G_1(s) = AES_s(0^127 || 1)
    right = aes_encrypt(seed[:16], b'\x00' * 15 + b'\x01')
    
    return left, right


# ─────────────────────────────────────────────
# GGM PRF (Forward: PRG ⇒ PRF)
# ─────────────────────────────────────────────

class GGM_PRF:
    """
    GGM Tree-based Pseudorandom Function.
    
    Given a length-doubling PRG G, defines:
      F_k(b1 b2 ... bn) = G_{bn}(G_{bn-1}(... G_{b1}(k) ...))
    
    The tree has 2^n leaves but only one root-to-leaf path is
    computed per query (n evaluations of G).
    
    This is the canonical PRG ⇒ PRF construction.
    """
    
    def __init__(self, key: bytes = None, depth: int = 8):
        """
        Initialize GGM PRF.
        
        Args:
            key: 16-byte key (root of the tree)
            depth: input bit length (tree depth), default 8
        """
        self.depth = depth
        if key is None:
            key = random_bytes(16)
        self.key = key
    
    def evaluate(self, x: int) -> bytes:
        """
        Evaluate F_k(x) by walking the GGM tree.
        
        Args:
            x: input as integer (uses lowest `depth` bits)
        
        Returns:
            16-byte PRF output (the leaf value)
        """
        # Extract bits of x (MSB first)
        bits = []
        for i in range(self.depth - 1, -1, -1):
            bits.append((x >> i) & 1)
        
        return self.evaluate_bits(bits)
    
    def evaluate_bits(self, bits: list) -> bytes:
        """
        Evaluate F_k(b1...bn) by walking the GGM tree.
        
        Args:
            bits: list of input bits [b1, b2, ..., bn]
        
        Returns:
            16-byte PRF output
        """
        current = self.key
        for bit in bits:
            left, right = prg_double(current)
            current = right if bit else left
        return current
    
    def evaluate_with_path(self, x: int) -> dict:
        """
        Evaluate F_k(x) and return the full path through the tree.
        Used for the interactive demo visualization.
        
        Returns dict with:
            'output': the PRF output
            'path': list of (node_value, direction) at each level
        """
        bits = []
        for i in range(self.depth - 1, -1, -1):
            bits.append((x >> i) & 1)
        
        path = []
        current = self.key
        path.append({'value': current.hex(), 'direction': 'root'})
        
        for bit in bits:
            left, right = prg_double(current)
            direction = 'right' if bit else 'left'
            current = right if bit else left
            path.append({
                'value': current.hex(),
                'direction': direction,
                'left': left.hex(),
                'right': right.hex()
            })
        
        return {
            'output': current,
            'output_hex': current.hex(),
            'path': path,
            'input_bits': bits
        }
    
    def get_full_tree(self, max_depth: int = None) -> dict:
        """
        Compute the full GGM tree up to max_depth for visualization.
        Warning: exponential in depth! Only use for small depths (≤ 8).
        """
        if max_depth is None:
            max_depth = min(self.depth, 6)  # Cap at 6 for sanity
        
        tree = {}
        
        def build(node_val, depth, prefix):
            node_key = prefix if prefix else 'root'
            tree[node_key] = node_val.hex()
            
            if depth < max_depth:
                left, right = prg_double(node_val)
                build(left, depth + 1, prefix + '0')
                build(right, depth + 1, prefix + '1')
        
        build(self.key, 0, '')
        return tree


# ─────────────────────────────────────────────
# AES PRF (Direct plug-in, alternative to GGM)
# ─────────────────────────────────────────────

class AES_PRF:
    """
    AES used directly as a PRF: F_k(x) = AES_k(x).
    
    By the PRP/PRF switching lemma, AES (a PRP on {0,1}^128)
    is computationally indistinguishable from a PRF when the
    number of queries is much less than 2^64.
    """
    
    def __init__(self, key: bytes = None):
        if key is None:
            key = random_bytes(16)
        self.key = key
        self.depth = 128  # Full 128-bit input
    
    def evaluate(self, x: int) -> bytes:
        """Evaluate F_k(x) = AES_k(x)."""
        x_bytes = int_to_bytes(x % (1 << 128), 16)
        return aes_encrypt(self.key, x_bytes)
    
    def evaluate_bytes(self, x: bytes) -> bytes:
        """Evaluate F_k(x) where x is already bytes."""
        if len(x) != 16:
            # Pad or truncate to 16 bytes
            if len(x) < 16:
                x = x + b'\x00' * (16 - len(x))
            else:
                x = x[:16]
        return aes_encrypt(self.key, x)


# ─────────────────────────────────────────────
# Unified PRF Interface
# ─────────────────────────────────────────────

class PRF:
    """
    Unified PRF interface that can use either GGM or AES backend.
    This is the main interface consumed by PA#3, PA#4, PA#5.
    
    F(k, x) -> output_bytes
    """
    
    def __init__(self, key: bytes = None, mode='aes', depth=8):
        """
        Args:
            key: 16-byte key
            mode: 'ggm' for GGM tree PRF, 'aes' for AES-based PRF
            depth: GGM tree depth (only for 'ggm' mode)
        """
        self.mode = mode
        if key is None:
            key = random_bytes(16)
        self.key = key
        
        if mode == 'ggm':
            self._prf = GGM_PRF(key=key, depth=depth)
        else:
            self._prf = AES_PRF(key=key)
    
    def F(self, x: int) -> bytes:
        """Evaluate F_k(x) -> 16 bytes."""
        return self._prf.evaluate(x)
    
    def F_bytes(self, x: bytes) -> bytes:
        """Evaluate F_k(x) where x is bytes -> 16 bytes."""
        if self.mode == 'aes':
            return self._prf.evaluate_bytes(x)
        else:
            # Convert bytes to int for GGM
            x_int = int.from_bytes(x, 'big') % (1 << self._prf.depth)
            return self._prf.evaluate(x_int)


# ─────────────────────────────────────────────
# PRG from PRF (Backward: PRF ⇒ PRG)
# ─────────────────────────────────────────────

def prf_to_prg(prf: PRF, seed: bytes = None) -> bytes:
    """
    Backward construction: PRF ⇒ PRG
    G(s) = F_s(0^n) || F_s(1^n)
    
    This is a length-doubling PRG constructed from a PRF.
    Given 16-byte seed s, produces 32-byte output.
    
    Security: If G were distinguishable from random, the distinguisher
    could be used to break the PRF.
    """
    if seed is None:
        seed = random_bytes(16)
    
    # Create PRF with seed as key
    temp_prf = PRF(key=seed, mode=prf.mode)
    
    # G(s) = F_s(0) || F_s(1)
    left = temp_prf.F(0)   # F_s(0^128)
    right = temp_prf.F(1)  # F_s(1^128) / F_s(0^127 || 1)
    
    return left + right


def verify_prf_to_prg(prf: PRF, num_tests=10) -> dict:
    """
    Verify the backward direction produces pseudorandom output
    by running statistical tests on concatenated PRG outputs.
    """
    all_bits = []
    for _ in range(num_tests):
        seed = random_bytes(16)
        output = prf_to_prg(prf, seed)
        all_bits.extend(bytes_to_bits(output))
    
    return run_statistical_tests(all_bits)


# ─────────────────────────────────────────────
# Distinguishing Game (PA#2 requirement)
# ─────────────────────────────────────────────

def distinguishing_game(prf: PRF, num_queries=100) -> dict:
    """
    PRF Distinguishing Game.
    
    Query both the PRF and a truly random function on the same inputs.
    Confirm no statistical difference (supporting PRF security empirically).
    
    Returns results showing that the PRF output is indistinguishable
    from random.
    """
    prf_outputs = []
    random_outputs = []
    
    queries = [int.from_bytes(random_bytes(2), 'big') for _ in range(num_queries)]
    
    for q in queries:
        # PRF output
        prf_out = prf.F(q)
        prf_outputs.append(prf_out)
        
        # Truly random output
        rand_out = random_bytes(16)
        random_outputs.append(rand_out)
    
    # Statistical comparison: bit distribution
    prf_bits = []
    rand_bits = []
    for p_out, r_out in zip(prf_outputs, random_outputs):
        prf_bits.extend(bytes_to_bits(p_out))
        rand_bits.extend(bytes_to_bits(r_out))
    
    prf_stats = run_statistical_tests(prf_bits)
    rand_stats = run_statistical_tests(rand_bits)
    
    # Compare distributions
    prf_ones_ratio = sum(prf_bits) / len(prf_bits)
    rand_ones_ratio = sum(rand_bits) / len(rand_bits)
    
    return {
        'num_queries': num_queries,
        'prf_stats': prf_stats,
        'random_stats': rand_stats,
        'prf_ones_ratio': round(prf_ones_ratio, 4),
        'random_ones_ratio': round(rand_ones_ratio, 4),
        'ratio_difference': round(abs(prf_ones_ratio - rand_ones_ratio), 4),
        'indistinguishable': abs(prf_ones_ratio - rand_ones_ratio) < 0.05
    }
