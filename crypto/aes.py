"""
CS8.401 — PA#0 Dependency: AES-128 Implementation
===================================================
Full from-scratch AES-128 (Advanced Encryption Standard).
No external libraries. This serves as our concrete PRP/PRF instantiation.

AES-128 operates on 16-byte (128-bit) blocks with a 16-byte key.
10 rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey
(final round omits MixColumns).

Reference: FIPS 197 (AES Standard)
"""


# ─────────────────────────────────────────────
# AES S-Box (precomputed from GF(2^8) inversion + affine transform)
# ─────────────────────────────────────────────

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

# Round constants for key expansion
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


# ─────────────────────────────────────────────
# GF(2^8) Arithmetic for MixColumns
# ─────────────────────────────────────────────

def _gf_mult(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1b  # Reduce by the irreducible polynomial
        b >>= 1
    return p


# Precompute multiplication tables for MixColumns (multiply by 2, 3, 9, 11, 13, 14)
_MUL2 = [_gf_mult(i, 2) for i in range(256)]
_MUL3 = [_gf_mult(i, 3) for i in range(256)]
_MUL9 = [_gf_mult(i, 9) for i in range(256)]
_MUL11 = [_gf_mult(i, 11) for i in range(256)]
_MUL13 = [_gf_mult(i, 13) for i in range(256)]
_MUL14 = [_gf_mult(i, 14) for i in range(256)]


# ─────────────────────────────────────────────
# Key Expansion
# ─────────────────────────────────────────────

def _key_expansion(key: bytes) -> list:
    """
    AES-128 key expansion.
    Expands 16-byte key into 11 round keys (44 words).
    Returns list of 11 round keys, each 16 bytes.
    """
    assert len(key) == 16, "AES-128 requires a 16-byte key"
    
    # Initialize with the original key as 4 words (32-bit each)
    words = []
    for i in range(4):
        words.append(list(key[4*i:4*i+4]))
    
    # Expand to 44 words
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            # RotWord: rotate left by 1
            temp = temp[1:] + temp[:1]
            # SubWord: apply S-box
            temp = [SBOX[b] for b in temp]
            # XOR with round constant
            temp[0] ^= RCON[i // 4]
        words.append([words[i-4][j] ^ temp[j] for j in range(4)])
    
    # Convert to 11 round keys of 16 bytes each
    round_keys = []
    for r in range(11):
        rk = []
        for i in range(4):
            rk.extend(words[r * 4 + i])
        round_keys.append(bytes(rk))
    
    return round_keys


# ─────────────────────────────────────────────
# AES Round Operations
# ─────────────────────────────────────────────

def _sub_bytes(state: list) -> list:
    """Apply S-box substitution to each byte of the 4x4 state."""
    return [SBOX[b] for b in state]


def _inv_sub_bytes(state: list) -> list:
    """Apply inverse S-box substitution."""
    return [INV_SBOX[b] for b in state]


def _shift_rows(state: list) -> list:
    """
    ShiftRows: cyclically shift each row of the 4x4 state matrix.
    State is stored column-major: state[row + 4*col]
    Row 0: no shift
    Row 1: shift left by 1
    Row 2: shift left by 2
    Row 3: shift left by 3
    """
    s = list(state)
    # Row 1
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    # Row 2
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    # Row 3
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
    return s


def _inv_shift_rows(state: list) -> list:
    """Inverse ShiftRows."""
    s = list(state)
    # Row 1: shift right by 1
    s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
    # Row 2: shift right by 2
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    # Row 3: shift right by 3
    s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]
    return s


def _mix_columns(state: list) -> list:
    """
    MixColumns: multiply each column by the fixed polynomial in GF(2^8).
    Matrix: [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
    """
    s = list(state)
    for col in range(4):
        c = col * 4
        a0, a1, a2, a3 = s[c], s[c+1], s[c+2], s[c+3]
        s[c]   = _MUL2[a0] ^ _MUL3[a1] ^ a2 ^ a3
        s[c+1] = a0 ^ _MUL2[a1] ^ _MUL3[a2] ^ a3
        s[c+2] = a0 ^ a1 ^ _MUL2[a2] ^ _MUL3[a3]
        s[c+3] = _MUL3[a0] ^ a1 ^ a2 ^ _MUL2[a3]
    return s


def _inv_mix_columns(state: list) -> list:
    """
    Inverse MixColumns.
    Matrix: [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]
    """
    s = list(state)
    for col in range(4):
        c = col * 4
        a0, a1, a2, a3 = s[c], s[c+1], s[c+2], s[c+3]
        s[c]   = _MUL14[a0] ^ _MUL11[a1] ^ _MUL13[a2] ^ _MUL9[a3]
        s[c+1] = _MUL9[a0] ^ _MUL14[a1] ^ _MUL11[a2] ^ _MUL13[a3]
        s[c+2] = _MUL13[a0] ^ _MUL9[a1] ^ _MUL14[a2] ^ _MUL11[a3]
        s[c+3] = _MUL11[a0] ^ _MUL13[a1] ^ _MUL9[a2] ^ _MUL14[a3]
    return s


def _add_round_key(state: list, round_key: bytes) -> list:
    """XOR state with round key."""
    return [s ^ k for s, k in zip(state, round_key)]


# ─────────────────────────────────────────────
# AES-128 Encrypt / Decrypt
# ─────────────────────────────────────────────

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-128 encryption of a single 16-byte block.
    
    Args:
        key: 16-byte encryption key
        plaintext: 16-byte plaintext block
    
    Returns:
        16-byte ciphertext block
    """
    assert len(key) == 16, "Key must be 16 bytes"
    assert len(plaintext) == 16, "Plaintext must be 16 bytes"
    
    round_keys = _key_expansion(key)
    
    # Convert plaintext to column-major state
    state = list(plaintext)
    
    # Initial round key addition
    state = _add_round_key(state, round_keys[0])
    
    # Rounds 1-9
    for r in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[r])
    
    # Final round (no MixColumns)
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[10])
    
    return bytes(state)


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    AES-128 decryption of a single 16-byte block.
    
    Args:
        key: 16-byte decryption key
        ciphertext: 16-byte ciphertext block
    
    Returns:
        16-byte plaintext block
    """
    assert len(key) == 16, "Key must be 16 bytes"
    assert len(ciphertext) == 16, "Ciphertext must be 16 bytes"
    
    round_keys = _key_expansion(key)
    
    state = list(ciphertext)
    
    # Initial round key (round 10)
    state = _add_round_key(state, round_keys[10])
    
    # Rounds 9-1 (inverse)
    for r in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[r])
        state = _inv_mix_columns(state)
    
    # Final round (inverse, no InvMixColumns)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])
    
    return bytes(state)


# ─────────────────────────────────────────────
# AES as OWF (Davies-Meyer construction)
# ─────────────────────────────────────────────

def aes_owf(key: bytes) -> bytes:
    """
    Davies-Meyer OWF: f(k) = AES_k(0^128) ⊕ k
    One-way because inverting requires breaking AES.
    """
    assert len(key) == 16
    zero_block = b'\x00' * 16
    enc = aes_encrypt(key, zero_block)
    return bytes(e ^ k for e, k in zip(enc, key))


def aes_prf(key: bytes, x: bytes) -> bytes:
    """
    Use AES directly as a PRF: F_k(x) = AES_k(x).
    By the PRP/PRF switching lemma, AES (a PRP on {0,1}^128)
    is computationally indistinguishable from a PRF.
    """
    assert len(key) == 16 and len(x) == 16
    return aes_encrypt(key, x)
