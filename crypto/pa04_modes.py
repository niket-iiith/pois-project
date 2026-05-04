"""
CS8.401 — PA#4: Modes of Operation (CBC, OFB, CTR)
====================================================
Implements:
  1. ECB mode (insecure baseline — pattern leakage demo)
  2. CBC mode: C_i = E_k(P_i ⊕ C_{i-1}), with PKCS#7 padding
  3. OFB mode: O_i = E_k(O_{i-1}), C_i = P_i ⊕ O_i (stream cipher)
  4. CTR mode: C_i = P_i ⊕ E_k(nonce || ctr_i) (parallelizable stream cipher)
  5. ECB penguin demo (visual pattern leakage)
  6. Error propagation comparison between modes
  7. Bit-flip attack demo on CTR mode

Uses PA#2 PRF (AES) as the underlying block cipher E_k.
"""

from crypto.utils import random_bytes, xor_bytes, int_to_bytes, bytes_to_int, pad_bytes, unpad_bytes
from crypto.aes import aes_encrypt, aes_decrypt


BLOCK_SIZE = 16  # AES block size in bytes


# ─────────────────────────────────────────────
# ECB Mode (Electronic Codebook) — INSECURE
# ─────────────────────────────────────────────

def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    ECB mode encryption. Each block encrypted independently.
    INSECURE: identical plaintext blocks → identical ciphertext blocks.
    Included only as a baseline to demonstrate pattern leakage.
    """
    padded = pad_bytes(plaintext, BLOCK_SIZE)
    ciphertext = bytearray()
    
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        ciphertext.extend(aes_encrypt(key, block))
    
    return bytes(ciphertext)


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """ECB mode decryption."""
    plaintext = bytearray()
    
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        plaintext.extend(aes_decrypt(key, block))
    
    return unpad_bytes(bytes(plaintext))


# ─────────────────────────────────────────────
# CBC Mode (Cipher Block Chaining)
# ─────────────────────────────────────────────

def cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes = None) -> tuple:
    """
    CBC mode encryption.
    C_0 = IV
    C_i = E_k(P_i ⊕ C_{i-1})
    
    Args:
        key: 16-byte key
        plaintext: arbitrary-length plaintext
        iv: 16-byte IV (random if not provided)
    
    Returns:
        (iv, ciphertext)
    """
    if iv is None:
        iv = random_bytes(BLOCK_SIZE)
    
    padded = pad_bytes(plaintext, BLOCK_SIZE)
    ciphertext = bytearray()
    prev = iv
    
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        # XOR with previous ciphertext block
        xored = xor_bytes(block, prev)
        # Encrypt
        encrypted = aes_encrypt(key, xored)
        ciphertext.extend(encrypted)
        prev = encrypted
    
    return iv, bytes(ciphertext)


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    CBC mode decryption.
    P_i = D_k(C_i) ⊕ C_{i-1}
    """
    plaintext = bytearray()
    prev = iv
    
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted = aes_decrypt(key, block)
        pt_block = xor_bytes(decrypted, prev)
        plaintext.extend(pt_block)
        prev = block
    
    return unpad_bytes(bytes(plaintext))


# ─────────────────────────────────────────────
# OFB Mode (Output Feedback)
# ─────────────────────────────────────────────

def ofb_encrypt(key: bytes, plaintext: bytes, iv: bytes = None) -> tuple:
    """
    OFB mode encryption (stream cipher mode).
    O_0 = IV
    O_i = E_k(O_{i-1})
    C_i = P_i ⊕ O_i
    
    Properties:
    - No padding needed (stream cipher)
    - No error propagation
    - Keystream independent of plaintext
    """
    if iv is None:
        iv = random_bytes(BLOCK_SIZE)
    
    ciphertext = bytearray()
    output_block = iv
    
    for i in range(0, len(plaintext), BLOCK_SIZE):
        # Generate keystream block
        output_block = aes_encrypt(key, output_block)
        
        # XOR with plaintext (handle last partial block)
        pt_block = plaintext[i:i + BLOCK_SIZE]
        ct_block = xor_bytes(output_block[:len(pt_block)],
                             pt_block + b'\x00' * (len(output_block) - len(pt_block)))
        ciphertext.extend(ct_block[:len(pt_block)])
    
    return iv, bytes(ciphertext)


def ofb_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """OFB mode decryption (same as encryption since XOR is its own inverse)."""
    return ofb_encrypt(key, ciphertext, iv)[1]


# ─────────────────────────────────────────────
# CTR Mode (Counter)
# ─────────────────────────────────────────────

def ctr_encrypt(key: bytes, plaintext: bytes, nonce: bytes = None) -> tuple:
    """
    CTR mode encryption (parallelizable stream cipher).
    C_i = P_i ⊕ E_k(nonce || ctr_i)
    
    Properties:
    - No padding needed
    - Parallelizable (unlike CBC, OFB)
    - Random access decryption
    - No error propagation
    """
    if nonce is None:
        nonce = random_bytes(8)  # 8-byte nonce + 8-byte counter
    
    ciphertext = bytearray()
    
    for i in range(0, len(plaintext), BLOCK_SIZE):
        # Construct counter block
        counter_block = nonce + int_to_bytes(i // BLOCK_SIZE, 8)
        
        # Generate keystream
        keystream = aes_encrypt(key, counter_block)
        
        # XOR with plaintext
        pt_block = plaintext[i:i + BLOCK_SIZE]
        ct_block = bytes(k ^ p for k, p in zip(keystream[:len(pt_block)], pt_block))
        ciphertext.extend(ct_block)
    
    return nonce, bytes(ciphertext)


def ctr_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """CTR mode decryption (same as encryption)."""
    return ctr_encrypt(key, ciphertext, nonce)[1]


# ─────────────────────────────────────────────
# ECB Penguin Demo (Pattern Leakage)
# ─────────────────────────────────────────────

def ecb_penguin_demo(key: bytes = None) -> dict:
    """
    Demonstrate ECB pattern leakage.
    
    Encrypt a message with repeated blocks using ECB and CBC.
    Show that ECB produces identical ciphertext blocks for identical
    plaintext blocks, while CBC does not.
    """
    if key is None:
        key = random_bytes(16)
    
    # Create a message with repeated blocks
    block_a = b"AAAAAAAAAAAAAAAA"  # 16 bytes
    block_b = b"BBBBBBBBBBBBBBBB"
    
    # Pattern: A A B A A B
    plaintext = block_a + block_a + block_b + block_a + block_a + block_b
    
    # ECB encryption
    ecb_ct = ecb_encrypt(key, plaintext)
    
    # CBC encryption
    iv, cbc_ct = cbc_encrypt(key, plaintext)
    
    # Analyze ECB blocks for patterns
    ecb_blocks = [ecb_ct[i:i+16].hex() for i in range(0, len(ecb_ct), 16)]
    cbc_blocks = [cbc_ct[i:i+16].hex() for i in range(0, len(cbc_ct), 16)]
    
    # Check for repeated blocks
    ecb_unique = len(set(ecb_blocks[:6]))  # First 6 blocks (before padding)
    cbc_unique = len(set(cbc_blocks[:6]))
    
    return {
        'plaintext_pattern': 'A A B A A B',
        'ecb_blocks': ecb_blocks[:6],
        'cbc_blocks': cbc_blocks[:6],
        'ecb_unique_blocks': ecb_unique,
        'cbc_unique_blocks': cbc_unique,
        'ecb_leaks_pattern': ecb_unique < 6,  # Should be True (only 2 unique)
        'cbc_hides_pattern': cbc_unique == 6   # Should be True (all unique)
    }


# ─────────────────────────────────────────────
# Error Propagation Comparison
# ─────────────────────────────────────────────

def error_propagation_demo(key: bytes = None) -> dict:
    """
    Compare error propagation across modes.
    
    Flip one bit in the ciphertext and see how many plaintext blocks
    are affected after decryption.
    """
    if key is None:
        key = random_bytes(16)
    
    plaintext = b"Block1----------Block2----------Block3----------Block4----------"
    assert len(plaintext) == 64  # 4 blocks
    
    results = {}
    
    # CBC
    iv, cbc_ct = cbc_encrypt(key, plaintext)
    modified_cbc_ct = bytearray(cbc_ct)
    modified_cbc_ct[16] ^= 0x01  # Flip bit in block 2
    try:
        cbc_dec = cbc_decrypt(key, iv, bytes(modified_cbc_ct))
        cbc_affected = sum(1 for a, b in zip(plaintext, cbc_dec) if a != b)
    except:
        cbc_affected = -1
    results['cbc'] = {'affected_bytes': cbc_affected, 'note': 'Affects block 2 (garbled) and block 3 (1 bit)'}
    
    # OFB
    iv, ofb_ct = ofb_encrypt(key, plaintext)
    modified_ofb_ct = bytearray(ofb_ct)
    modified_ofb_ct[16] ^= 0x01
    ofb_dec = ofb_decrypt(key, iv, bytes(modified_ofb_ct))
    ofb_affected = sum(1 for a, b in zip(plaintext, ofb_dec) if a != b)
    results['ofb'] = {'affected_bytes': ofb_affected, 'note': 'Only 1 bit affected (no propagation)'}
    
    # CTR
    nonce, ctr_ct = ctr_encrypt(key, plaintext)
    modified_ctr_ct = bytearray(ctr_ct)
    modified_ctr_ct[16] ^= 0x01
    ctr_dec = ctr_decrypt(key, nonce, bytes(modified_ctr_ct))
    ctr_affected = sum(1 for a, b in zip(plaintext, ctr_dec) if a != b)
    results['ctr'] = {'affected_bytes': ctr_affected, 'note': 'Only 1 bit affected (no propagation)'}
    
    return results
