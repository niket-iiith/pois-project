"""
CS8.401 — PA#13: Miller-Rabin Primality Testing
=================================================
Implements:
  1. miller_rabin(n, k) — k rounds of Miller-Rabin testing
  2. gen_prime(bits) — random prime generation
  3. Carmichael number 561 demo
  4. Performance benchmark: 512, 1024, 2048-bit primes
  5. Interface: is_prime(n) -> bool, gen_prime(bits) -> int

Algorithm:
  Write n-1 = 2^r · d (d odd).
  For each round: pick random a ∈ [2, n-2].
    Compute x = a^d mod n.
    If x = 1 or x = n-1: continue.
    For r-1 squarings: x = x^2 mod n.
      If x = n-1: break.
    If x ≠ n-1: return COMPOSITE.
  Return PROBABLY PRIME.

Error probability: ≤ 4^{-k} for k rounds. For k=40: ≈ 10^{-24}.
"""

import time
from crypto.utils import mod_exp, random_int, random_bytes, int_to_bytes


# ─────────────────────────────────────────────
# Miller-Rabin Primality Test
# ─────────────────────────────────────────────

def miller_rabin(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin probabilistic primality test.
    
    Args:
        n: integer to test
        k: number of rounds (error ≤ 4^{-k})
    
    Returns:
        True if n is probably prime, False if definitely composite.
    """
    # Handle small cases
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n - 1 = 2^r · d with d odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # k rounds of testing
    for _ in range(k):
        # Pick random witness a ∈ [2, n-2]
        a = random_int(2, n - 2)
        
        # Compute x = a^d mod n
        x = mod_exp(a, d, n)
        
        if x == 1 or x == n - 1:
            continue  # Pass this round
        
        # Square r-1 times
        composite = True
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                composite = False
                break
        
        if composite:
            return False  # Definitely COMPOSITE
    
    return True  # PROBABLY PRIME


def is_prime(n: int) -> bool:
    """
    Convenience function: test primality with 40 rounds.
    Error probability ≤ 4^{-40} ≈ 10^{-24}.
    """
    return miller_rabin(n, 40)


# ─────────────────────────────────────────────
# Prime Generation
# ─────────────────────────────────────────────

def gen_prime(bits: int, k: int = 40) -> int:
    """
    Generate a random probable prime of specified bit length.
    
    Repeatedly samples random odd numbers and tests with Miller-Rabin
    until a probable prime is found.
    
    By the Prime Number Theorem: expected O(bits) candidates needed.
    
    Args:
        bits: desired bit length (e.g., 512, 1024, 2048)
        k: Miller-Rabin rounds per candidate
    
    Returns:
        A probable prime of `bits` bits.
    """
    attempts = 0
    while True:
        attempts += 1
        # Generate random odd number of the right bit length
        # Set the top bit (ensures correct bit length) and bottom bit (ensures odd)
        n = int.from_bytes(random_bytes((bits + 7) // 8), 'big')
        n |= (1 << (bits - 1))  # Set top bit
        n |= 1                   # Set bottom bit (odd)
        n &= (1 << bits) - 1     # Mask to exact bit length
        n |= (1 << (bits - 1))   # Re-set top bit after mask
        
        if miller_rabin(n, k):
            # Sanity check with extra rounds
            if miller_rabin(n, 100):
                return n


def gen_safe_prime(bits: int) -> int:
    """
    Generate a safe prime p = 2q + 1 where q is also prime.
    Used for DH and ElGamal group parameters.
    
    Note: This is slower than generating regular primes.
    For toy parameters, use small bit sizes.
    """
    while True:
        q = gen_prime(bits - 1)
        p = 2 * q + 1
        if is_prime(p):
            return p


# ─────────────────────────────────────────────
# Carmichael Number Demo
# ─────────────────────────────────────────────

def fermat_test(n: int, a: int) -> bool:
    """
    Naive Fermat primality test: check if a^{n-1} ≡ 1 (mod n).
    Carmichael numbers pass this test for all a coprime to n.
    """
    from crypto.utils import gcd
    if gcd(a, n) != 1:
        return False
    return mod_exp(a, n - 1, n) == 1


def carmichael_demo() -> dict:
    """
    Show that n = 561 (the smallest Carmichael number) passes
    Fermat's test but is correctly rejected by Miller-Rabin.
    
    561 = 3 × 11 × 17
    """
    n = 561
    
    # Fermat test with multiple bases
    fermat_results = []
    for a in range(2, min(n, 20)):
        from crypto.utils import gcd
        if gcd(a, n) == 1:
            result = fermat_test(n, a)
            fermat_results.append({'a': a, 'passes_fermat': result})
    
    # Miller-Rabin test
    mr_result = miller_rabin(n, 10)
    
    # Miller-Rabin with specific witnesses that catch 561
    mr_witnesses = []
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for a in [2, 3, 5, 7]:
        x = mod_exp(a, d, n)
        witness_info = {'a': a, 'a^d mod n': x}
        
        is_witness = True
        if x == 1 or x == n - 1:
            is_witness = False
        else:
            for _ in range(r - 1):
                x = mod_exp(x, 2, n)
                if x == n - 1:
                    is_witness = False
                    break
        
        witness_info['is_witness_to_composite'] = is_witness
        mr_witnesses.append(witness_info)
    
    return {
        'n': 561,
        'factorization': '3 × 11 × 17',
        'is_carmichael': True,
        'fermat_results': fermat_results,
        'all_fermat_pass': all(r['passes_fermat'] for r in fermat_results),
        'miller_rabin_result': 'COMPOSITE' if not mr_result else 'PRIME',
        'miller_rabin_correct': not mr_result,
        'witnesses': mr_witnesses,
        'explanation': ('561 passes Fermat test for all coprime bases '
                       '(Carmichael number) but Miller-Rabin catches it '
                       'because 561 fails the strong probable prime test.')
    }


# ─────────────────────────────────────────────
# Performance Benchmark
# ─────────────────────────────────────────────

def prime_generation_benchmark(bit_sizes=None) -> dict:
    """
    Report average number of candidates and time to find primes
    of various bit sizes.
    
    Compare to theoretical O(ln n) ≈ O(bits · ln 2) candidates
    predicted by the Prime Number Theorem.
    """
    if bit_sizes is None:
        bit_sizes = [64, 128, 256]  # Use small sizes for demo speed
    
    results = {}
    
    for bits in bit_sizes:
        times = []
        
        num_trials = 5
        for _ in range(num_trials):
            start = time.time()
            p = gen_prime(bits, k=20)  # Fewer rounds for benchmarking
            elapsed = time.time() - start
            times.append(elapsed)
        
        avg_time = sum(times) / len(times)
        theoretical_candidates = bits * 0.693  # bits × ln(2)
        
        results[bits] = {
            'bit_size': bits,
            'trials': num_trials,
            'avg_time_seconds': round(avg_time, 4),
            'theoretical_candidates': round(theoretical_candidates, 1),
            'note': f'PNT predicts ~{theoretical_candidates:.0f} candidates for {bits}-bit primes'
        }
    
    return results


# ─────────────────────────────────────────────
# Miller-Rabin with Detailed Trace (for Web Demo)
# ─────────────────────────────────────────────

def miller_rabin_trace(n: int, k: int = 5) -> dict:
    """
    Run Miller-Rabin with a detailed trace of each round.
    Used for the interactive web demo.
    """
    if n < 2:
        return {'n': n, 'result': 'COMPOSITE', 'reason': 'n < 2', 'rounds': []}
    if n == 2 or n == 3:
        return {'n': n, 'result': 'PRIME', 'reason': 'small prime', 'rounds': []}
    if n % 2 == 0:
        return {'n': n, 'result': 'COMPOSITE', 'reason': 'even', 'rounds': []}
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    rounds = []
    
    for i in range(k):
        a = random_int(2, n - 2)
        x = mod_exp(a, d, n)
        
        round_info = {
            'round': i + 1,
            'witness': a,
            'a^d_mod_n': x,
            'squarings': [],
            'result': None
        }
        
        if x == 1 or x == n - 1:
            round_info['result'] = 'PASS (x=1 or x=n-1)'
            rounds.append(round_info)
            continue
        
        found_minus_one = False
        for j in range(r - 1):
            x = mod_exp(x, 2, n)
            round_info['squarings'].append({'step': j + 1, 'x^2_mod_n': x})
            if x == n - 1:
                found_minus_one = True
                break
        
        if found_minus_one:
            round_info['result'] = f'PASS (found n-1 after {len(round_info["squarings"])} squarings)'
        else:
            round_info['result'] = 'FAIL — COMPOSITE'
            rounds.append(round_info)
            return {
                'n': n,
                'r': r,
                'd': d,
                'result': 'COMPOSITE',
                'rounds': rounds
            }
        
        rounds.append(round_info)
    
    return {
        'n': n,
        'r': r,
        'd': d,
        'result': 'PROBABLY PRIME',
        'confidence': f'Error ≤ 4^{{-{k}}} = {4**(-k):.2e}',
        'rounds': rounds
    }
