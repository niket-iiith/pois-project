"""
CS8.401 — Shared Cryptographic Utilities
=========================================
No external crypto libraries. Only os.urandom and Python built-in int.

Provides:
  - mod_exp: square-and-multiply modular exponentiation
  - xor_bytes: XOR two byte strings
  - int_to_bytes / bytes_to_int: conversion helpers
  - mod_inverse: extended Euclidean algorithm
  - random_bytes / random_int: OS-level randomness
  - gcd / egcd: greatest common divisor
"""

import os
import struct


# ─────────────────────────────────────────────
# Randomness (only permitted OS-level primitive)
# ─────────────────────────────────────────────

def random_bytes(n: int) -> bytes:
    """Return n cryptographically random bytes using OS entropy."""
    return os.urandom(n)


def random_int(low: int, high: int) -> int:
    """Return a random integer in [low, high] inclusive, using OS entropy."""
    if low > high:
        raise ValueError("low must be <= high")
    if low == high:
        return low
    range_size = high - low + 1
    # Determine how many bytes we need
    byte_count = (range_size.bit_length() + 7) // 8
    # Rejection sampling to avoid bias
    while True:
        rand_val = int.from_bytes(os.urandom(byte_count), 'big')
        if rand_val < range_size:
            return low + rand_val


def random_bits(n: int) -> list:
    """Return a list of n random bits."""
    result = []
    raw = os.urandom((n + 7) // 8)
    for i in range(n):
        byte_idx = i // 8
        bit_idx = 7 - (i % 8)
        result.append((raw[byte_idx] >> bit_idx) & 1)
    return result


# ─────────────────────────────────────────────
# Modular Arithmetic
# ─────────────────────────────────────────────

def mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Square-and-multiply modular exponentiation.
    Computes base^exp mod mod efficiently.
    
    This is our own implementation — not using Python's built-in pow(b,e,m)
    for educational purposes (though the result is identical).
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        # If exp is odd, multiply result with base
        if exp & 1:
            result = (result * base) % mod
        # exp must be even now
        exp >>= 1
        base = (base * base) % mod
    return result


def gcd(a: int, b: int) -> int:
    """Greatest common divisor using Euclidean algorithm."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def egcd(a: int, b: int) -> tuple:
    """
    Extended Euclidean algorithm.
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(a: int, n: int) -> int:
    """
    Compute modular inverse of a modulo n using extended Euclidean algorithm.
    Returns x such that a*x ≡ 1 (mod n).
    Raises ValueError if inverse does not exist.
    """
    g, x, _ = egcd(a % n, n)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {n}")
    return x % n


def jacobi_symbol(a: int, n: int) -> int:
    """
    Compute the Jacobi symbol (a/n) for odd n > 0.
    Used in Miller-Rabin and various number-theoretic algorithms.
    """
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be a positive odd integer")
    a = a % n
    result = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a = a % n
    if n == 1:
        return result
    return 0


# ─────────────────────────────────────────────
# Byte/Int Conversion
# ─────────────────────────────────────────────

def int_to_bytes(n: int, length: int) -> bytes:
    """Convert integer n to bytes of specified length (big-endian)."""
    return n.to_bytes(length, byteorder='big')


def bytes_to_int(b: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(b, byteorder='big')


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings. They must be the same length."""
    if len(a) != len(b):
        raise ValueError(f"Byte strings must be same length: {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


def pad_bytes(data: bytes, block_size: int) -> bytes:
    """PKCS#7 padding to block_size."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def unpad_bytes(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("Invalid padding")
    for i in range(pad_len):
        if data[-(i + 1)] != pad_len:
            raise ValueError("Invalid padding")
    return data[:-pad_len]


def bits_to_bytes(bits: list) -> bytes:
    """Convert a list of bits (0/1) to bytes."""
    # Pad to multiple of 8
    while len(bits) % 8 != 0:
        bits = [0] + bits
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def bytes_to_bits(data: bytes) -> list:
    """Convert bytes to a list of bits."""
    result = []
    for byte in data:
        for i in range(7, -1, -1):
            result.append((byte >> i) & 1)
    return result


def int_to_bits(n: int, bit_length: int) -> list:
    """Convert an integer to a list of bits with specified length."""
    bits = []
    for i in range(bit_length - 1, -1, -1):
        bits.append((n >> i) & 1)
    return bits


def bits_to_int(bits: list) -> int:
    """Convert a list of bits to an integer."""
    result = 0
    for bit in bits:
        result = (result << 1) | bit
    return result


# ─────────────────────────────────────────────
# Constant-time comparison (for MAC verification)
# ─────────────────────────────────────────────

def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison of two byte strings.
    XOR all bytes and check if result is zero — no early exit.
    Prevents timing side-channel attacks on MAC verification.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def naive_compare(a: bytes, b: bytes) -> bool:
    """
    INSECURE early-exit comparison (for timing attack demo only).
    Leaks information about which byte differs first.
    """
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True
