"""
CS8.401 — PA#14: Chinese Remainder Theorem & Breaking Textbook RSA
====================================================================
Implements:
  1. CRT solver: crt(residues, moduli) -> x
  2. CRT-based RSA decryption (Garner's algorithm, ≈4× speedup)
  3. Håstad's broadcast attack
  4. Padding defeats the attack demo
  5. Interface: crt(), rsa_dec_crt(), hastad_attack()

CRT: For pairwise coprime n_1,...,n_k and any a_1,...,a_k, the system
  x ≡ a_i (mod n_i) has a unique solution mod N = ∏n_i.

Håstad's Attack: If m^e is broadcast to e recipients with different
  moduli, CRT recovers m^e exactly, and integer e-th root gives m.
"""

import time
from crypto.utils import mod_exp, mod_inverse, gcd, int_to_bytes, bytes_to_int, random_bytes
from crypto.pa12_rsa import rsa_keygen, rsa_encrypt, rsa_decrypt, rsa_encrypt_padded
from crypto.pa13_miller_rabin import gen_prime


# ─────────────────────────────────────────────
# Chinese Remainder Theorem
# ─────────────────────────────────────────────

def crt(residues: list, moduli: list) -> int:
    """
    Chinese Remainder Theorem solver.
    
    Given residues [a_1, ..., a_k] and pairwise coprime moduli [n_1, ..., n_k],
    find the unique x mod N = ∏n_i such that x ≡ a_i (mod n_i) for all i.
    
    Formula: x = Σ a_i · M_i · (M_i^{-1} mod n_i) mod N
    where M_i = N / n_i
    
    Args:
        residues: list of remainders
        moduli: list of pairwise coprime moduli
    
    Returns:
        x: the unique solution mod ∏moduli
    """
    if len(residues) != len(moduli):
        raise ValueError("residues and moduli must have same length")
    
    # Verify pairwise coprime
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if gcd(moduli[i], moduli[j]) != 1:
                raise ValueError(f"Moduli {moduli[i]} and {moduli[j]} are not coprime")
    
    N = 1
    for n in moduli:
        N *= n
    
    x = 0
    for a_i, n_i in zip(residues, moduli):
        M_i = N // n_i
        M_i_inv = mod_inverse(M_i, n_i)
        x += a_i * M_i * M_i_inv
    
    return x % N


# ─────────────────────────────────────────────
# CRT-Based RSA Decryption (Garner's Algorithm)
# ─────────────────────────────────────────────

def rsa_dec_crt(sk: dict, c: int) -> int:
    """
    CRT-based RSA decryption (Garner's algorithm).
    
    Instead of computing c^d mod N directly:
    1. Compute m_p = c^{d_p} mod p  (d_p = d mod (p-1))
    2. Compute m_q = c^{d_q} mod q  (d_q = d mod (q-1))
    3. Combine via CRT: h = q_inv · (m_p - m_q) mod p; m = m_q + h·q
    
    This gives ≈4× speedup (half-size exponents, half-size moduli).
    
    Args:
        sk: private key with 'N', 'd', 'p', 'q'
        c: ciphertext integer
    
    Returns:
        plaintext integer
    """
    p, q, d = sk['p'], sk['q'], sk['d']
    N = sk['N']
    
    # Precompute reduced exponents
    d_p = d % (p - 1)
    d_q = d % (q - 1)
    q_inv = mod_inverse(q, p)
    
    # Compute partial decryptions
    m_p = mod_exp(c, d_p, p)
    m_q = mod_exp(c, d_q, q)
    
    # Garner's recombination
    h = (q_inv * (m_p - m_q)) % p
    m = m_q + h * q
    
    return m % N


def crt_performance_comparison(bits: int = 512, num_decryptions: int = 50) -> dict:
    """
    Benchmark standard RSA decryption vs CRT-based decryption.
    Expect ≈3-4× speedup with CRT.
    """
    keys = rsa_keygen(bits)
    pk, sk = keys['public_key'], keys['private_key']
    
    # Generate random ciphertexts
    messages = [random_bytes(bits // 16) for _ in range(num_decryptions)]
    ciphertexts = [rsa_encrypt(pk, bytes_to_int(m) % pk['N']) for m in messages]
    
    # Standard decryption
    start = time.time()
    for c in ciphertexts:
        rsa_decrypt(sk, c)
    standard_time = time.time() - start
    
    # CRT decryption
    start = time.time()
    for c in ciphertexts:
        rsa_dec_crt(sk, c)
    crt_time = time.time() - start
    
    # Verify correctness
    correct = all(
        rsa_decrypt(sk, c) == rsa_dec_crt(sk, c)
        for c in ciphertexts[:10]
    )
    
    speedup = standard_time / crt_time if crt_time > 0 else float('inf')
    
    return {
        'bits': bits,
        'num_decryptions': num_decryptions,
        'standard_time': round(standard_time, 4),
        'crt_time': round(crt_time, 4),
        'speedup': round(speedup, 2),
        'all_correct': correct,
        'expected_speedup': '3-4×'
    }


# ─────────────────────────────────────────────
# Integer N-th Root (Newton's Method)
# ─────────────────────────────────────────────

def integer_nth_root(x: int, n: int) -> int:
    """
    Compute the integer n-th root of x using Newton's method.
    Returns the largest integer r such that r^n ≤ x.
    """
    if x < 0:
        raise ValueError("Cannot compute nth root of negative number")
    if x == 0 or x == 1:
        return x
    
    # Initial guess using floating point
    try:
        guess = int(x ** (1.0 / n)) + 2
    except OverflowError:
        guess = 2 ** ((x.bit_length() + n - 1) // n)
    
    # Newton's iteration: r_{i+1} = ((n-1) * r_i + x / r_i^{n-1}) / n
    while True:
        new_guess = ((n - 1) * guess + x // (guess ** (n - 1))) // n
        if new_guess >= guess:
            break
        guess = new_guess
    
    # Verify
    if guess ** n == x:
        return guess
    if (guess + 1) ** n == x:
        return guess + 1
    
    return guess


# ─────────────────────────────────────────────
# Håstad's Broadcast Attack
# ─────────────────────────────────────────────

def hastad_attack(ciphertexts: list, moduli: list, e: int) -> int:
    """
    Håstad's Broadcast Attack.
    
    If the same message m is encrypted to e different recipients
    using public exponent e and different moduli N_i:
      c_i = m^e mod N_i
    
    Then CRT recovers m^e mod (N_1·N_2·...·N_e) = m^e exactly
    (since m < N_i for all i, m^e < ∏N_i).
    
    Integer e-th root then recovers m.
    
    Args:
        ciphertexts: list of c_i = m^e mod N_i
        moduli: list of N_i
        e: public exponent
    
    Returns:
        recovered plaintext m
    """
    # Step 1: CRT to recover m^e mod ∏N_i
    m_e = crt(ciphertexts, moduli)
    
    # Step 2: Integer e-th root
    m = integer_nth_root(m_e, e)
    
    return m


def hastad_demo(e: int = 3, bits: int = 256) -> dict:
    """
    Full Håstad broadcast attack demonstration.
    
    1. Generate e independent RSA key pairs with public exponent e
    2. Encrypt the same message m to all e recipients
    3. Run the attack to recover m
    """
    # Generate e key pairs
    keys = []
    attempts = 0
    while len(keys) < e:
        attempts += 1
        try:
            k = rsa_keygen(bits)
            # Override e to the small value
            p, q = k['private_key']['p'], k['private_key']['q']
            phi_N = (p - 1) * (q - 1)
            if gcd(e, phi_N) == 1:
                d = mod_inverse(e, phi_N)
                k['public_key']['e'] = e
                k['private_key']['d'] = d
                keys.append(k)
        except:
            continue
        if attempts > 100:
            return {'error': f'Could not generate {e} suitable key pairs'}
    
    # Choose a message
    max_modulus = min(k['public_key']['N'] for k in keys)
    m = 12345678  # Small message for demo
    
    # Encrypt to all recipients
    ciphertexts = []
    moduli = []
    for k in keys:
        c = rsa_encrypt(k['public_key'], m)
        ciphertexts.append(c)
        moduli.append(k['public_key']['N'])
    
    # Run the attack
    recovered = hastad_attack(ciphertexts, moduli, e)
    
    return {
        'e': e,
        'num_recipients': e,
        'original_message': m,
        'ciphertexts': [hex(c) for c in ciphertexts],
        'moduli': [hex(n) for n in moduli],
        'recovered_message': recovered,
        'attack_success': recovered == m,
        'note': 'No private keys needed! CRT + integer root recovers the plaintext.'
    }


# ─────────────────────────────────────────────
# Padding Defeats the Attack
# ─────────────────────────────────────────────

def padding_defeats_hastad(bits: int = 256) -> dict:
    """
    Show that PKCS#1 v1.5 padding defeats Håstad's attack.
    
    With padding, each recipient encrypts a different padded value,
    so CRT does not recover m^3 and the cube root step fails.
    """
    e = 3
    
    # Generate 3 key pairs
    keys = []
    while len(keys) < 3:
        try:
            k = rsa_keygen(bits)
            p, q = k['private_key']['p'], k['private_key']['q']
            phi_N = (p - 1) * (q - 1)
            if gcd(e, phi_N) == 1:
                d = mod_inverse(e, phi_N)
                k['public_key']['e'] = e
                k['private_key']['d'] = d
                keys.append(k)
        except:
            continue
    
    message = b"Hello"
    
    # Encrypt with PKCS padding (each produces different padded value)
    ciphertexts = []
    moduli = []
    for k in keys:
        try:
            c = rsa_encrypt_padded(k['public_key'], message)
            ciphertexts.append(c)
            moduli.append(k['public_key']['N'])
        except:
            return {'error': 'Padding failed — message may be too long for key size'}
    
    # Try the attack
    try:
        m_e = crt(ciphertexts, moduli)
        recovered_int = integer_nth_root(m_e, e)
        
        # Try to unpad — should fail because the cube root is garbage
        key_size = (keys[0]['public_key']['N'].bit_length() + 7) // 8
        try:
            recovered_bytes = int_to_bytes(recovered_int, key_size)
            from crypto.pa12_rsa import pkcs1_v15_unpad
            recovered_msg = pkcs1_v15_unpad(recovered_bytes)
            attack_success = recovered_msg == message
        except:
            attack_success = False
    except:
        attack_success = False
    
    return {
        'original_message': message.decode(),
        'padding': 'PKCS#1 v1.5',
        'attack_success': attack_success,
        'note': ('With padding, each recipient encrypts a different padded value. '
                'CRT still works but the cube root is not an integer — attack fails.')
    }
