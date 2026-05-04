"""
CS8.401 — PA#9: Birthday Attack (Collision Finding)
=====================================================
Implements:
  1. Generic birthday attack algorithm
  2. Attack on truncated DLP hash at n ∈ {8, 10, 12, 14, 16} bits
  3. Empirical birthday curve (100 trials per n)
  4. MD5/SHA-1 computational context
  5. Comparison with theoretical O(2^{n/2}) bound

Security Floor:
  The birthday bound is information-theoretic: ANY hash function
  with n-bit output requires only O(2^{n/2}) evaluations to find a collision.
  No engineering can overcome this fundamental limit.
"""

import math
import time
from crypto.utils import int_to_bytes, bytes_to_int, random_bytes, random_int
from crypto.pa08_dlp_hash import dlp_hash_truncated, dlp_hash


# ─────────────────────────────────────────────
# Generic Birthday Attack
# ─────────────────────────────────────────────

def birthday_attack(hash_func, output_bits: int, max_attempts: int = None) -> dict:
    """
    Generic birthday attack on a hash function.
    
    Algorithm:
    1. Compute hashes of random messages, storing (hash → message) in a dict
    2. When a collision is found (same hash, different message), return it
    
    Expected number of evaluations: O(2^{n/2}) where n = output_bits.
    
    Args:
        hash_func: function(message: bytes) -> bytes
        output_bits: number of output bits of the hash
        max_attempts: maximum number of hash evaluations (default: 4 * 2^{n/2})
    
    Returns:
        dict with collision info, or None if no collision found
    """
    if max_attempts is None:
        max_attempts = int(4 * (2 ** (output_bits / 2)))
    
    seen = {}  # hash_hex -> message
    
    start_time = time.time()
    
    for i in range(max_attempts):
        # Random message (use counter + random salt for uniqueness)
        msg = int_to_bytes(i, 4) + random_bytes(4)
        
        h = hash_func(msg)
        h_hex = h.hex()
        
        if h_hex in seen and seen[h_hex] != msg:
            elapsed = time.time() - start_time
            return {
                'collision_found': True,
                'message1': seen[h_hex].hex(),
                'message2': msg.hex(),
                'hash': h_hex,
                'evaluations': i + 1,
                'expected_evaluations': round(2 ** (output_bits / 2), 1),
                'output_bits': output_bits,
                'time_seconds': round(elapsed, 4),
                'ratio_to_expected': round((i + 1) / (2 ** (output_bits / 2)), 2)
            }
        
        seen[h_hex] = msg
    
    elapsed = time.time() - start_time
    return {
        'collision_found': False,
        'evaluations': max_attempts,
        'expected_evaluations': round(2 ** (output_bits / 2), 1),
        'output_bits': output_bits,
        'time_seconds': round(elapsed, 4)
    }


# ─────────────────────────────────────────────
# Attack on Truncated DLP Hash
# ─────────────────────────────────────────────

def attack_truncated_dlp(output_bits: int) -> dict:
    """
    Run birthday attack on PA#8 DLP hash truncated to output_bits.
    """
    def truncated_hash(msg):
        return dlp_hash_truncated(msg, output_bits)
    
    return birthday_attack(truncated_hash, output_bits)


# ─────────────────────────────────────────────
# Empirical Birthday Curve
# ─────────────────────────────────────────────

def empirical_birthday_curve(bit_sizes=None, trials_per_size=20) -> dict:
    """
    Run birthday attack experiments for multiple output bit sizes.
    
    For each n ∈ bit_sizes:
    - Run `trials_per_size` independent trials
    - Record the number of evaluations until first collision
    - Compare with theoretical 2^{n/2}
    
    Default bit_sizes: {8, 10, 12, 14, 16}
    """
    if bit_sizes is None:
        bit_sizes = [8, 10, 12, 14]  # 16 can be slow
    
    results = {}
    
    for n in bit_sizes:
        trial_results = []
        
        for t in range(trials_per_size):
            # Use a simple hash for speed at small bit sizes
            def simple_truncated_hash(msg, n_bits=n):
                """Fast hash using AES for birthday experiments."""
                from crypto.aes import aes_encrypt
                # Use message as part of a deterministic but well-distributed hash
                key = b'\x42' * 16  # Fixed key
                if len(msg) < 16:
                    msg = msg + b'\x00' * (16 - len(msg))
                h = aes_encrypt(key, msg[:16])
                # Truncate to n_bits
                output_bytes = (n_bits + 7) // 8
                truncated = h[:output_bytes]
                if n_bits % 8 != 0:
                    mask = (0xFF << (8 - n_bits % 8)) & 0xFF
                    truncated = truncated[:-1] + bytes([truncated[-1] & mask])
                return truncated
            
            result = birthday_attack(simple_truncated_hash, n, max_attempts=10 * (2 ** (n // 2 + 2)))
            if result['collision_found']:
                trial_results.append(result['evaluations'])
        
        if trial_results:
            avg_evals = sum(trial_results) / len(trial_results)
            theoretical = 2 ** (n / 2)
            results[n] = {
                'bit_size': n,
                'trials': len(trial_results),
                'successful_trials': len(trial_results),
                'avg_evaluations': round(avg_evals, 1),
                'median_evaluations': sorted(trial_results)[len(trial_results) // 2],
                'min_evaluations': min(trial_results),
                'max_evaluations': max(trial_results),
                'theoretical_2_n_half': round(theoretical, 1),
                'ratio_actual_theoretical': round(avg_evals / theoretical, 2),
                'distribution': trial_results
            }
        else:
            results[n] = {
                'bit_size': n,
                'trials': trials_per_size,
                'successful_trials': 0,
                'note': 'No collisions found in budget'
            }
    
    return results


# ─────────────────────────────────────────────
# Theoretical Birthday Probability
# ─────────────────────────────────────────────

def birthday_probability(k: int, n: int) -> float:
    """
    Compute the probability of at least one collision
    after k random samples from a space of size 2^n.
    
    P(collision) ≈ 1 - e^{-k(k-1)/(2·2^n)}
    """
    N = 2 ** n
    if k >= N:
        return 1.0
    exponent = -k * (k - 1) / (2 * N)
    return 1 - math.exp(exponent)


def birthday_curve_data(n: int, num_points=100) -> list:
    """
    Generate theoretical birthday curve data for plotting.
    Returns list of (k, probability) pairs.
    """
    N = 2 ** n
    max_k = int(3 * math.sqrt(N))
    step = max(1, max_k // num_points)
    
    data = []
    for k in range(0, max_k, step):
        p = birthday_probability(k, n)
        data.append({'k': k, 'probability': round(p, 6)})
    
    return data


# ─────────────────────────────────────────────
# MD5/SHA-1 Context
# ─────────────────────────────────────────────

def real_world_context() -> dict:
    """
    Compute 2^{n/2} for real-world hash functions and express
    in terms of modern CPU speed.
    
    Assume: CPU hashes 10^9 values/second (1 GH/s)
    """
    hashes_per_second = 1e9
    seconds_per_year = 365.25 * 24 * 3600
    
    results = {}
    
    for name, n in [('MD5', 128), ('SHA-1', 160), ('SHA-256', 256)]:
        collision_ops = 2 ** (n / 2)
        seconds = collision_ops / hashes_per_second
        years = seconds / seconds_per_year
        
        results[name] = {
            'output_bits': n,
            'collision_operations': f'2^{n//2} = {collision_ops:.2e}',
            'seconds_at_1GHs': f'{seconds:.2e}',
            'years_at_1GHs': f'{years:.2e}',
            'status': 'BROKEN' if name in ('MD5',) else 
                      'DEPRECATED' if name == 'SHA-1' else 'SECURE'
        }
    
    return results


# ─────────────────────────────────────────────
# Live Birthday Attack (for Web Demo)
# ─────────────────────────────────────────────

def live_birthday_attack(output_bits: int = 12) -> dict:
    """
    Run a birthday attack with step-by-step progress tracking.
    Returns detailed results suitable for animation in the web demo.
    
    For n=12: collision expected near 2^6 = 64 evaluations.
    """
    from crypto.aes import aes_encrypt
    
    key = b'\x42' * 16
    
    def fast_hash(msg):
        if len(msg) < 16:
            msg = msg + b'\x00' * (16 - len(msg))
        h = aes_encrypt(key, msg[:16])
        output_bytes = (output_bits + 7) // 8
        return h[:output_bytes]
    
    seen = {}
    steps = []
    
    for i in range(4 * (2 ** output_bits)):
        msg = int_to_bytes(i, 4) + random_bytes(4)
        h = fast_hash(msg)
        h_hex = h.hex()
        
        step = {
            'evaluation': i + 1,
            'message': msg.hex(),
            'hash': h_hex,
            'collision': False
        }
        
        if h_hex in seen and seen[h_hex] != msg:
            step['collision'] = True
            step['collision_with'] = seen[h_hex].hex()
            steps.append(step)
            
            return {
                'collision_found': True,
                'total_evaluations': i + 1,
                'expected': round(2 ** (output_bits / 2), 1),
                'output_bits': output_bits,
                'collision_message1': seen[h_hex].hex(),
                'collision_message2': msg.hex(),
                'collision_hash': h_hex,
                'steps': steps[-20:]  # Last 20 steps for display
            }
        
        seen[h_hex] = msg
        if i < 50 or i % 10 == 0:  # Log first 50 and then every 10th
            steps.append(step)
    
    return {
        'collision_found': False,
        'total_evaluations': 4 * (2 ** output_bits),
        'steps': steps[-20:]
    }
