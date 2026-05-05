"""
CS8.401 — Flask API Server
============================
Bridges the React web frontend with Python crypto implementations.
Each PA has endpoints for its demo operations.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import traceback

app = Flask(__name__)
CORS(app)


def safe_run(func, *args, **kwargs):
    """Run a function and catch errors, returning JSON-safe results."""
    try:
        result = func(*args, **kwargs)
        return {'success': True, 'data': result}
    except Exception as e:
        return {'success': False, 'error': str(e), 'traceback': traceback.format_exc()}


# ─── PA#1: OWF + PRG ───
@app.route('/api/pa1/prg', methods=['POST'])
def pa1_prg():
    data = request.json or {}
    seed_hex = data.get('seed', 'deadbeefcafebabe' * 2)
    output_length = data.get('output_length', 64)
    
    from crypto.pa01_owf_prg import PRG, run_statistical_tests
    
    seed = bytes.fromhex(seed_hex[:32])
    prg = PRG(mode='aes')
    bits = prg.generate(seed, min(output_length, 1024))
    stats = run_statistical_tests(bits)
    
    return jsonify(safe_run(lambda: {
        'bits': bits,
        'hex': ''.join(str(b) for b in bits),
        'stats': stats
    }))


@app.route('/api/pa1/owf', methods=['POST'])
def pa1_owf():
    from crypto.pa01_owf_prg import AES_OWF
    owf = AES_OWF()
    result = owf.verify_hardness(trials=50)
    return jsonify(safe_run(lambda: result))


# ─── PA#2: PRF / GGM ───
@app.route('/api/pa2/ggm', methods=['POST'])
def pa2_ggm():
    data = request.json or {}
    key_hex = data.get('key', '00' * 16)
    query = data.get('query', 0)
    depth = data.get('depth', 4)
    
    from crypto.pa02_prf_ggm import GGM_PRF
    
    key = bytes.fromhex(key_hex[:32])
    prf = GGM_PRF(key=key, depth=depth)
    result = prf.evaluate_with_path(query)
    
    return jsonify(safe_run(lambda: result))


@app.route('/api/pa2/distinguish', methods=['POST'])
def pa2_distinguish():
    from crypto.pa02_prf_ggm import PRF, distinguishing_game
    prf = PRF()
    result = distinguishing_game(prf, num_queries=100)
    return jsonify(safe_run(lambda: result))


# ─── PA#3: CPA Encryption ───
@app.route('/api/pa3/encrypt', methods=['POST'])
def pa3_encrypt():
    data = request.json or {}
    message = data.get('message', 'Hello, World!')
    
    from crypto.pa03_cpa_enc import cpa_encrypt, cpa_decrypt
    from crypto.utils import random_bytes
    
    key = random_bytes(16)
    nonce, ct = cpa_encrypt(key, message.encode())
    dec = cpa_decrypt(key, nonce, ct)
    
    return jsonify(safe_run(lambda: {
        'message': message,
        'key': key.hex(),
        'nonce': nonce.hex(),
        'ciphertext': ct.hex(),
        'decrypted': dec.decode()
    }))


@app.route('/api/pa3/cpa_game', methods=['POST'])
def pa3_cpa_game():
    from crypto.pa03_cpa_enc import ind_cpa_game
    result = ind_cpa_game(num_trials=100)
    return jsonify(safe_run(lambda: result))


# ─── PA#4: Modes ───
@app.route('/api/pa4/ecb_penguin', methods=['POST'])
def pa4_ecb_penguin():
    from crypto.pa04_modes import ecb_penguin_demo
    return jsonify(safe_run(ecb_penguin_demo))


@app.route('/api/pa4/error_propagation', methods=['POST'])
def pa4_error_propagation():
    from crypto.pa04_modes import error_propagation_demo
    return jsonify(safe_run(error_propagation_demo))


# ─── PA#5: MAC ───
@app.route('/api/pa5/euf_cma', methods=['POST'])
def pa5_euf_cma():
    from crypto.pa05_mac import euf_cma_game
    result = euf_cma_game(num_queries=50, num_attempts=20)
    return jsonify(safe_run(lambda: result))


@app.route('/api/pa5/mac', methods=['POST'])
def pa5_mac():
    data = request.json or {}
    message = data.get('message', 'Hello')
    
    from crypto.pa05_mac import PRF_MAC
    from crypto.utils import random_bytes
    
    key = random_bytes(16)
    mac_obj = PRF_MAC(key=key)
    tag = mac_obj.mac(message.encode())
    valid = mac_obj.verify(message.encode(), tag)
    
    return jsonify(safe_run(lambda: {
        'message': message,
        'tag': tag.hex(),
        'valid': valid
    }))


# ─── PA#6: CCA ───
@app.route('/api/pa6/malleability', methods=['POST'])
def pa6_malleability():
    from crypto.pa06_cca_enc import malleability_demo
    return jsonify(safe_run(malleability_demo))


@app.route('/api/pa6/cca2_game', methods=['POST'])
def pa6_cca2_game():
    from crypto.pa06_cca_enc import ind_cca2_game
    result = ind_cca2_game(num_trials=50)
    return jsonify(safe_run(lambda: result))


# ─── PA#7: Merkle-Damgård ───
@app.route('/api/pa7/hash', methods=['POST'])
def pa7_hash():
    data = request.json or {}
    message = data.get('message', 'Hello')
    
    from crypto.pa07_merkle_damgard import create_dummy_hasher
    h = create_dummy_hasher()
    result = h.hash_with_steps(message.encode())
    return jsonify(safe_run(lambda: result))


# ─── PA#8: DLP Hash ───
@app.route('/api/pa8/hash', methods=['POST'])
def pa8_hash():
    data = request.json or {}
    message = data.get('message', 'Hello')
    
    from crypto.pa08_dlp_hash import DLPHash
    h = DLPHash()
    result = h.hash_with_steps(message.encode())
    return jsonify(safe_run(lambda: result))


@app.route('/api/pa8/avalanche', methods=['POST'])
def pa8_avalanche():
    from crypto.pa08_dlp_hash import avalanche_demo
    return jsonify(safe_run(avalanche_demo))


# ─── PA#9: Birthday Attack ───
@app.route('/api/pa9/attack', methods=['POST'])
def pa9_attack():
    data = request.json or {}
    output_bits = data.get('output_bits', 12)
    
    from crypto.pa09_birthday import live_birthday_attack
    result = live_birthday_attack(output_bits)
    return jsonify(safe_run(lambda: result))


@app.route('/api/pa9/context', methods=['POST'])
def pa9_context():
    from crypto.pa09_birthday import real_world_context
    return jsonify(safe_run(real_world_context))


# ─── PA#10: HMAC ───
@app.route('/api/pa10/length_extension', methods=['POST'])
def pa10_length_extension():
    from crypto.pa10_hmac import length_extension_vs_hmac
    return jsonify(safe_run(length_extension_vs_hmac))


@app.route('/api/pa10/timing', methods=['POST'])
def pa10_timing():
    from crypto.pa10_hmac import timing_attack_demo
    result = timing_attack_demo(num_measurements=50)
    return jsonify(safe_run(lambda: result))


# ─── PA#11: DH ───
@app.route('/api/pa11/exchange', methods=['POST'])
def pa11_exchange():
    from crypto.pa11_diffie_hellman import dh_exchange
    return jsonify(safe_run(lambda: dh_exchange(64)))


@app.route('/api/pa11/mitm', methods=['POST'])
def pa11_mitm():
    from crypto.pa11_diffie_hellman import mitm_attack_demo
    return jsonify(safe_run(lambda: mitm_attack_demo(64)))


# ─── PA#12: RSA ───
@app.route('/api/pa12/demo', methods=['POST'])
def pa12_demo():
    data = request.json or {}
    try:
        message = int(data.get('message', 42))
    except (ValueError, TypeError):
        message = 42
    
    from crypto.pa12_rsa import rsa_keygen, rsa_encrypt, rsa_decrypt
    
    keys = rsa_keygen(256)
    pk, sk = keys['public_key'], keys['private_key']
    c = rsa_encrypt(pk, message)
    m = rsa_decrypt(sk, c)
    
    return jsonify(safe_run(lambda: {
        'message': message,
        'N': hex(pk['N']),
        'e': pk['e'],
        'ciphertext': hex(c),
        'decrypted': m,
        'correct': m == message
    }))


# ─── PA#13: Miller-Rabin ───
@app.route('/api/pa13/test', methods=['POST'])
def pa13_test():
    data = request.json or {}
    n = data.get('n', 561)
    k = data.get('rounds', 10)
    
    from crypto.pa13_miller_rabin import miller_rabin_trace
    result = miller_rabin_trace(n, k)
    return jsonify(safe_run(lambda: result))


# ─── PA#14: CRT ───
@app.route('/api/pa14/hastad', methods=['POST'])
def pa14_hastad():
    from crypto.pa14_crt import hastad_demo
    return jsonify(safe_run(lambda: hastad_demo(e=3, bits=256)))


# ─── PA#15: Signatures ───
@app.route('/api/pa15/sign', methods=['POST'])
def pa15_sign():
    data = request.json or {}
    message = data.get('message', 'Hello, World!')
    
    from crypto.pa15_signatures import sign_verify_demo
    result = sign_verify_demo(message)
    return jsonify(safe_run(lambda: result))


# ─── PA#16: ElGamal ───
@app.route('/api/pa16/demo', methods=['POST'])
def pa16_demo():
    data = request.json or {}
    try:
        message = int(data.get('message', 42))
    except (ValueError, TypeError):
        message = 42
    
    from crypto.pa16_elgamal import elgamal_keygen, elgamal_encrypt, elgamal_decrypt
    
    keys = elgamal_keygen(64)
    pk, sk = keys['public_key'], keys['private_key']
    c1, c2 = elgamal_encrypt(pk, message)
    dec = elgamal_decrypt(sk, c1, c2)
    
    return jsonify(safe_run(lambda: {
        'message': message,
        'c1': hex(c1),
        'c2': hex(c2),
        'decrypted': dec,
        'correct': dec == message
    }))


# ─── PA#18: OT ───
@app.route('/api/pa18/ot', methods=['POST'])
def pa18_ot():
    data = request.json or {}
    m0 = data.get('m0', 42)
    m1 = data.get('m1', 99)
    b = data.get('b', 0)
    
    from crypto.pa18_ot import ot_step_by_step
    result = ot_step_by_step(m0, m1, b)
    return jsonify(safe_run(lambda: result))


# ─── PA#19: Secure AND ───
@app.route('/api/pa19/and', methods=['POST'])
def pa19_and():
    data = request.json or {}
    a = data.get('a', 1)
    b = data.get('b', 1)
    
    from crypto.pa19_secure_and import secure_and, secure_xor
    
    and_result = secure_and(a, b)
    xor_result = secure_xor(a, b)
    
    return jsonify(safe_run(lambda: {
        'and': and_result,
        'xor': xor_result
    }))


@app.route('/api/pa19/truth_table', methods=['POST'])
def pa19_truth_table():
    from crypto.pa19_secure_and import truth_table_test
    result = truth_table_test(num_runs=5)
    return jsonify(safe_run(lambda: result))


# ─── PA#20: MPC ───
@app.route('/api/pa20/millionaire', methods=['POST'])
def pa20_millionaire():
    data = request.json or {}
    x = data.get('x', 7)
    y = data.get('y', 12)
    n = data.get('n', 4)
    
    from crypto.pa20_mpc import millionaire_problem
    result = millionaire_problem(x, y, n)
    return jsonify(safe_run(lambda: result))


@app.route('/api/pa20/equality', methods=['POST'])
def pa20_equality():
    data = request.json or {}
    x = data.get('x', 5)
    y = data.get('y', 5)
    n = data.get('n', 4)
    
    from crypto.pa20_mpc import secure_equality
    result = secure_equality(x, y, n)
    return jsonify(safe_run(lambda: result))


@app.route('/api/pa20/addition', methods=['POST'])
def pa20_addition():
    data = request.json or {}
    x = data.get('x', 5)
    y = data.get('y', 3)
    n = data.get('n', 4)
    
    from crypto.pa20_mpc import secure_addition
    result = secure_addition(x, y, n)
    return jsonify(safe_run(lambda: result))


@app.route('/api/pa20/lineage', methods=['POST'])
def pa20_lineage():
    from crypto.pa20_mpc import lineage_trace
    return jsonify(safe_run(lineage_trace))


@app.route('/api/pa20/performance', methods=['POST'])
def pa20_performance():
    data = request.json or {}
    n = data.get('n', 4)
    
    from crypto.pa20_mpc import performance_report
    result = performance_report(n)
    return jsonify(safe_run(lambda: result))


# ─── Health Check ───
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'message': 'CS8.401 Crypto API is running'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
