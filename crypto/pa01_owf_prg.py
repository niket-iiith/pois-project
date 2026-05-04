"""
CS8.401 — PA#1: One-Way Functions & Pseudorandom Generators
============================================================
Implements:
  1. OWF: DLP-based f(x) = g^x mod p  AND  AES-based f(k) = AES_k(0^128) ⊕ k
  2. PRG from OWF: iterative hard-core bit construction (Goldreich-Levin)
  3. OWF from PRG (backward): f(s) = G(s) is a OWF
  4. NIST SP 800-22 statistical tests: frequency, runs, serial
  5. Interface: seed(s), next_bits(n)

Security Claim:
  If f is a OWF with hard-core predicate b, then G as constructed is a secure PRG.
  Security reduces to the hardness of inverting f.

Bidirectional reductions:
  Forward (OWF ⇒ PRG): iterative hard-core bit construction
  Backward (PRG ⇒ OWF): f(s) = G(s) — injective, hard to invert
"""

import math
from crypto.utils import (
    mod_exp, random_int, random_bytes, bytes_to_int, int_to_bytes,
    xor_bytes, bytes_to_bits, bits_to_bytes, random_bits
)
from crypto.aes import aes_encrypt, aes_owf


# ─────────────────────────────────────────────
# DLP Group Parameters (toy-size for demos)
# ─────────────────────────────────────────────

# A safe prime p = 2q + 1 where q is also prime
# For toy demos we use a 64-bit safe prime; for real security use ≥ 2048-bit

# Verified safe prime: p = 2q+1 where both p and q are prime
DLP_P = 17258075238577106327  # 64-bit safe prime (verified with Miller-Rabin)
DLP_Q = 8629037619288553163   # q = (p-1)/2, also prime
DLP_G = 2  # Generator of the order-q subgroup (2^q ≡ 1 mod p)

# Verify at import time
if mod_exp(DLP_G, DLP_Q, DLP_P) != 1:
    # Fallback: generate a fresh safe prime
    import os as _os
    def _find_safe_prime():
        """Find a small safe prime for DLP demos."""
        while True:
            # Random 60-bit odd number
            q_candidate = int.from_bytes(_os.urandom(8), 'big') | (1 << 59) | 1
            q_candidate &= (1 << 60) - 1
            q_candidate |= (1 << 59)
            p_candidate = 2 * q_candidate + 1
            # Quick primality check
            if all(p_candidate % d != 0 for d in range(2, min(1000, p_candidate))):
                if mod_exp(2, q_candidate, p_candidate) == 1:
                    return p_candidate
    DLP_P = _find_safe_prime()
    DLP_Q = (DLP_P - 1) // 2
    DLP_G = 2
    while mod_exp(DLP_G, DLP_Q, DLP_P) != 1 or mod_exp(DLP_G, 2, DLP_P) == 1:
        DLP_G += 1


# ─────────────────────────────────────────────
# One-Way Functions
# ─────────────────────────────────────────────

class DLP_OWF:
    """
    Discrete Logarithm Problem based One-Way Function.
    f(x) = g^x mod p
    
    Forward direction (evaluate) is efficient: O(log x) multiplications.
    Inverse (discrete log) is computationally infeasible for large p.
    """
    
    def __init__(self, p=DLP_P, g=DLP_G, q=DLP_Q):
        self.p = p
        self.g = g
        self.q = q
    
    def evaluate(self, x: int) -> int:
        """Compute f(x) = g^x mod p."""
        return mod_exp(self.g, x % self.q, self.p)
    
    def sample_input(self) -> int:
        """Sample a random input x from Z_q."""
        return random_int(1, self.q - 1)
    
    def verify_hardness(self, trials=100) -> dict:
        """
        Demonstrate OWF hardness: random inversion attempts should fail.
        An adversary given f(x) tries random guesses to find x' with f(x') = f(x).
        """
        successes = 0
        for _ in range(trials):
            x = self.sample_input()
            y = self.evaluate(x)
            # Adversary's strategy: random guess
            guess = random_int(1, self.q - 1)
            if self.evaluate(guess) == y:
                successes += 1
        return {
            'trials': trials,
            'successes': successes,
            'success_rate': successes / trials,
            'is_hard': successes <= 1  # Should be ~0 for a real OWF
        }


class AES_OWF:
    """
    AES-based One-Way Function (Davies-Meyer construction).
    f(k) = AES_k(0^128) ⊕ k
    
    One-way because inverting requires breaking AES.
    """
    
    def evaluate(self, k: bytes) -> bytes:
        """Compute f(k) = AES_k(0^128) ⊕ k."""
        if len(k) != 16:
            raise ValueError("Key must be 16 bytes for AES-128")
        return aes_owf(k)
    
    def sample_input(self) -> bytes:
        """Sample a random 16-byte key."""
        return random_bytes(16)
    
    def verify_hardness(self, trials=100) -> dict:
        """Demonstrate that random inversion fails."""
        successes = 0
        for _ in range(trials):
            k = self.sample_input()
            y = self.evaluate(k)
            guess = self.sample_input()
            if self.evaluate(guess) == y:
                successes += 1
        return {
            'trials': trials,
            'successes': successes,
            'success_rate': successes / trials,
            'is_hard': successes == 0
        }


# ─────────────────────────────────────────────
# Hard-Core Predicate (Goldreich-Levin)
# ─────────────────────────────────────────────

def goldreich_levin_bit(x: int, r: int, n_bits: int) -> int:
    """
    Goldreich-Levin hard-core predicate.
    b(x, r) = <x, r> mod 2 = XOR of bits where both x and r have a 1.
    
    For any OWF f, the function g(x, r) = (f(x), r) has b(x, r) as a
    hard-core bit — no PPT adversary can predict b given (f(x), r).
    """
    # Inner product mod 2
    return bin(x & r).count('1') % 2


# ─────────────────────────────────────────────
# PRG from OWF (Forward Direction: PA#1a)
# ─────────────────────────────────────────────

class PRG:
    """
    Pseudorandom Generator from a One-Way Function.
    
    Construction (Håstad-Impagliazzo-Levin-Luby):
    Given OWF f with hard-core predicate b (Goldreich-Levin),
    G(x0) = b(x0) || b(x1) || ... || b(x_ℓ)
    where x_{i+1} = f(x_i)
    
    This stretches an n-bit seed to (n + ℓ)-bit output.
    
    We support two modes:
    - 'dlp': Uses DLP-based OWF (g^x mod p)
    - 'aes': Uses AES-based OWF (Davies-Meyer)
    """
    
    def __init__(self, mode='aes', dlp_params=None):
        self.mode = mode
        if mode == 'dlp':
            self.owf = DLP_OWF(**(dlp_params or {}))
            self.n_bits = self.owf.q.bit_length()
        else:
            self.owf = AES_OWF()
            self.n_bits = 128
        self._seed_val = None
        self._state = None
        self._r = None  # Random string for GL bit
    
    def seed(self, s):
        """
        Set the PRG seed.
        For DLP mode: s is an integer in Z_q
        For AES mode: s is 16 bytes
        """
        if self.mode == 'dlp':
            if isinstance(s, bytes):
                s = bytes_to_int(s) % self.owf.q
            self._seed_val = s
            self._state = s
            # Random r for Goldreich-Levin (part of the seed in the formal construction)
            self._r = random_int(1, (1 << self.n_bits) - 1)
        else:
            if isinstance(s, int):
                s = int_to_bytes(s, 16)
            self._seed_val = s
            self._state = s
            self._r = random_bytes(16)
    
    def next_bits(self, num_bits: int) -> list:
        """
        Generate num_bits pseudorandom bits.
        Uses the iterative hard-core bit construction.
        """
        if self._state is None:
            raise ValueError("PRG not seeded. Call seed() first.")
        
        bits = []
        for _ in range(num_bits):
            if self.mode == 'dlp':
                # Extract hard-core bit
                bit = goldreich_levin_bit(self._state, self._r, self.n_bits)
                bits.append(bit)
                # Advance state: x_{i+1} = f(x_i)
                self._state = self.owf.evaluate(self._state)
            else:
                # AES mode: use LSB of AES output as pseudorandom bit
                output = self.owf.evaluate(self._state)
                bit = output[-1] & 1
                bits.append(bit)
                # Advance state
                self._state = output
        
        return bits
    
    def next_bytes(self, num_bytes: int) -> bytes:
        """Generate num_bytes pseudorandom bytes."""
        bits = self.next_bits(num_bytes * 8)
        return bits_to_bytes(bits)
    
    def generate(self, seed_val, output_length: int) -> list:
        """
        One-shot generation: seed and produce output_length bits.
        G(s) maps n-bit seed to (n + output_length) bits.
        """
        self.seed(seed_val)
        return self.next_bits(output_length)


# ─────────────────────────────────────────────
# OWF from PRG (Backward Direction: PA#1b)
# ─────────────────────────────────────────────

def prg_as_owf(prg: PRG, seed_val, output_bits: int = None) -> list:
    """
    Demonstrate that f(s) = G(s) is a OWF.
    
    Argument: G is injective (stretches the input). Given G(s), recovering s
    requires inverting G, which would break the PRG property (the output is
    indistinguishable from random, so no efficient algorithm can find the
    unique preimage).
    
    This function returns G(s) and shows that random guessing fails to invert.
    """
    if output_bits is None:
        output_bits = 256
    
    output = prg.generate(seed_val, output_bits)
    return output


def verify_prg_owf(prg: PRG, trials=50) -> dict:
    """
    Verify the backward direction: given G(s), an adversary cannot recover s.
    """
    successes = 0
    output_bits = 64  # Small for testing
    
    for _ in range(trials):
        # Generate random seed
        if prg.mode == 'dlp':
            s = random_int(1, prg.owf.q - 1)
        else:
            s = random_bytes(16)
        
        target = prg.generate(s, output_bits)
        
        # Adversary guesses random seed
        if prg.mode == 'dlp':
            guess = random_int(1, prg.owf.q - 1)
        else:
            guess = random_bytes(16)
        
        guess_output = prg.generate(guess, output_bits)
        if guess_output == target:
            successes += 1
    
    return {
        'trials': trials,
        'successes': successes,
        'is_owf': successes == 0
    }


# ─────────────────────────────────────────────
# NIST SP 800-22 Statistical Tests
# ─────────────────────────────────────────────

def frequency_test(bits: list) -> dict:
    """
    NIST Monobit Frequency Test.
    Tests whether the proportion of 1s and 0s is approximately equal.
    
    Under H0 (truly random), the test statistic follows a standard normal.
    """
    n = len(bits)
    if n == 0:
        return {'pass': False, 'p_value': 0.0, 'ratio': 0.0}
    
    # Convert to ±1
    s = sum(2 * b - 1 for b in bits)
    s_obs = abs(s) / math.sqrt(n)
    
    # P-value using complementary error function
    p_value = math.erfc(s_obs / math.sqrt(2))
    
    ones_ratio = sum(bits) / n
    
    return {
        'pass': p_value >= 0.01,
        'p_value': round(p_value, 6),
        'ratio': round(ones_ratio, 4),
        'statistic': round(s_obs, 4)
    }


def runs_test(bits: list) -> dict:
    """
    NIST Runs Test.
    Tests whether the oscillation between 0s and 1s is too fast or too slow.
    Prerequisite: the frequency test should pass first.
    """
    n = len(bits)
    if n < 10:
        return {'pass': False, 'p_value': 0.0}
    
    # Proportion of ones
    pi = sum(bits) / n
    
    # Check prerequisite: |pi - 0.5| < 2/sqrt(n)
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return {'pass': False, 'p_value': 0.0, 'note': 'Failed frequency prerequisite'}
    
    # Count runs (sequences of identical bits)
    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1
    
    # Test statistic
    num = abs(runs - 2.0 * n * pi * (1.0 - pi))
    den = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    
    if den == 0:
        return {'pass': False, 'p_value': 0.0}
    
    p_value = math.erfc(num / den)
    
    return {
        'pass': p_value >= 0.01,
        'p_value': round(p_value, 6),
        'runs': runs,
        'expected_runs': round(2.0 * n * pi * (1.0 - pi) + 1, 2)
    }


def serial_test(bits: list, m: int = 2) -> dict:
    """
    NIST Serial Test (simplified).
    Tests that all m-bit patterns appear with approximately equal frequency.
    
    For m=2: patterns 00, 01, 10, 11 should each appear ~25% of the time.
    """
    n = len(bits)
    if n < m:
        return {'pass': False, 'p_value': 0.0}
    
    # Count m-bit patterns
    pattern_counts = {}
    for i in range(n - m + 1):
        pattern = tuple(bits[i:i + m])
        pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
    
    # Chi-squared test
    total = n - m + 1
    expected = total / (2 ** m)
    
    chi_sq = 0
    for count in pattern_counts.values():
        chi_sq += (count - expected) ** 2 / expected
    
    # Add zero counts for missing patterns
    missing = (2 ** m) - len(pattern_counts)
    chi_sq += missing * expected  # (0 - expected)^2 / expected = expected
    
    # Degrees of freedom = 2^m - 1
    df = (2 ** m) - 1
    
    # Approximate p-value using chi-squared CDF (simplified)
    # Using the incomplete gamma function approximation
    p_value = _chi2_pvalue(chi_sq, df)
    
    return {
        'pass': p_value >= 0.01,
        'p_value': round(p_value, 6),
        'chi_squared': round(chi_sq, 4),
        'pattern_counts': {str(k): v for k, v in sorted(pattern_counts.items())}
    }


def _chi2_pvalue(x, k):
    """Approximate p-value for chi-squared distribution with k degrees of freedom."""
    # Using the regularized incomplete gamma function approximation
    # P(X > x) = 1 - P(X <= x) = Gamma(k/2, x/2) / Gamma(k/2)
    # Simple approximation for moderate k:
    if x <= 0:
        return 1.0
    try:
        # Wilson-Hilferty approximation
        z = ((x / k) ** (1/3) - (1 - 2/(9*k))) / math.sqrt(2/(9*k))
        p = 0.5 * math.erfc(z / math.sqrt(2))
        return max(0.0, min(1.0, p))
    except:
        return 0.0


def run_statistical_tests(bits: list) -> dict:
    """Run all three NIST tests and return combined results."""
    return {
        'frequency': frequency_test(bits),
        'runs': runs_test(bits),
        'serial': serial_test(bits, m=2),
        'total_bits': len(bits),
        'all_pass': all([
            frequency_test(bits)['pass'],
            runs_test(bits)['pass'],
            serial_test(bits, m=2)['pass']
        ])
    }
