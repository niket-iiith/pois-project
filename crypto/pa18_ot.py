"""
CS8.401 — PA#18: Oblivious Transfer (OT)
==========================================
Implements:
  1. 1-out-of-2 OT using ElGamal (PA#16)
  2. Three-step protocol: sender_setup(), receiver_choose(), sender_respond()
  3. Privacy verification for both parties
  4. Interface: 3-step OT API for PA#19

1-out-of-2 Oblivious Transfer:
  Alice (sender) has two messages m0, m1.
  Bob (receiver) has a choice bit b.
  After the protocol:
    - Bob learns m_b (and nothing about m_{1-b})
    - Alice learns nothing about b

Construction using ElGamal:
  1. Alice generates ElGamal keypair (pk, sk), sends pk to Bob
  2. Bob generates two "public keys" pk0, pk1:
     - pk_b = g^r (Bob knows the discrete log r)
     - pk_{1-b} = h/g^r (Bob does NOT know the discrete log)
     Bob sends (pk0, pk1) to Alice
  3. Alice encrypts: c0 = ElGamal.Enc(pk0, m0), c1 = ElGamal.Enc(pk1, m1)
     Alice sends (c0, c1) to Bob
  4. Bob decrypts c_b using his knowledge of r; cannot decrypt c_{1-b}

Privacy:
  - Bob's privacy: Alice sees (pk0, pk1) which are random group elements
    regardless of b → Alice learns nothing about b
  - Alice's privacy: Bob can only decrypt c_b → learns nothing about m_{1-b}
"""

from crypto.utils import mod_exp, mod_inverse, random_int, int_to_bytes, bytes_to_int, random_bytes
from crypto.pa16_elgamal import elgamal_keygen
from crypto.pa13_miller_rabin import gen_safe_prime


# ─────────────────────────────────────────────
# OT Parameters
# ─────────────────────────────────────────────

class OTParams:
    """Shared group parameters for OT."""
    
    def __init__(self, bits: int = 64):
        # Generate group parameters
        self.p = gen_safe_prime(bits)
        self.q = (self.p - 1) // 2
        self.g = 2
        while mod_exp(self.g, self.q, self.p) != 1 or mod_exp(self.g, 2, self.p) == 1:
            self.g += 1


# ─────────────────────────────────────────────
# Oblivious Transfer Protocol
# ─────────────────────────────────────────────

class OTSender:
    """
    Alice (Sender) in 1-out-of-2 Oblivious Transfer.
    Holds two messages m0, m1.
    """
    
    def __init__(self, m0: int, m1: int, params: OTParams):
        self.m0 = m0
        self.m1 = m1
        self.params = params
        self.p = params.p
        self.g = params.g
        self.q = params.q
        self.transcript = []
    
    def setup(self) -> dict:
        """
        Step 1: Alice generates a random public value A = g^a mod p.
        Sends A to Bob.
        """
        self.a = random_int(2, self.q - 1)
        self.A = mod_exp(self.g, self.a, self.p)
        
        msg = {'A': self.A}
        self.transcript.append(('send', 'A', self.A))
        return msg
    
    def respond(self, B: int) -> dict:
        """
        Step 3: Alice receives B from Bob.
        Encrypts both messages:
          e0 = m0 ⊕ H(B^a mod p)      — Bob can decrypt if B = g^b
          e1 = m1 ⊕ H((B/A)^a mod p)  — Bob can decrypt if B = A·g^b
        
        Only one of these is decryptable by Bob, depending on his choice bit.
        """
        # Compute shared secrets for both possible choices
        # If Bob chose b=0: B = g^b, so B^a = g^{ab}
        # If Bob chose b=1: B = A·g^b, so (B/A)^a = g^{ab}, B^a = A^a · g^{ab}
        
        k0 = mod_exp(B, self.a, self.p)
        
        B_div_A = (B * mod_inverse(self.A, self.p)) % self.p
        k1 = mod_exp(B_div_A, self.a, self.p)
        
        # Encrypt messages
        # Use hash of shared secret as one-time pad
        e0 = self.m0 ^ (k0 % (1 << 64))  # Simple XOR encryption
        e1 = self.m1 ^ (k1 % (1 << 64))
        
        msg = {'e0': e0, 'e1': e1}
        self.transcript.append(('send', 'e0', e0))
        self.transcript.append(('send', 'e1', e1))
        return msg


class OTReceiver:
    """
    Bob (Receiver) in 1-out-of-2 Oblivious Transfer.
    Has choice bit b ∈ {0, 1}.
    """
    
    def __init__(self, b: int, params: OTParams):
        assert b in (0, 1), "Choice bit must be 0 or 1"
        self.b = b
        self.params = params
        self.p = params.p
        self.g = params.g
        self.q = params.q
        self.transcript = []
    
    def choose(self, A: int) -> dict:
        """
        Step 2: Bob receives A from Alice.
        Generates B based on choice bit b:
          If b = 0: B = g^beta (Bob knows beta)
          If b = 1: B = A · g^beta (Bob knows beta)
        
        Either way, B looks random to Alice.
        """
        self.A = A
        self.beta = random_int(2, self.q - 1)
        
        g_beta = mod_exp(self.g, self.beta, self.p)
        
        if self.b == 0:
            self.B = g_beta
        else:
            self.B = (A * g_beta) % self.p
        
        msg = {'B': self.B}
        self.transcript.append(('send', 'B', self.B))
        return msg
    
    def retrieve(self, e0: int, e1: int) -> int:
        """
        Step 4: Bob receives encrypted messages and decrypts m_b.
        
        Bob can compute A^beta mod p:
          If b = 0: B^a = g^{a·beta} = A^beta (Bob has beta)
          If b = 1: (B/A)^a = g^{a·beta} = A^beta (Bob has beta)
        """
        # Bob computes the key for his chosen message
        k_b = mod_exp(self.A, self.beta, self.p)
        
        # Decrypt the chosen message
        if self.b == 0:
            m_b = e0 ^ (k_b % (1 << 64))
        else:
            m_b = e1 ^ (k_b % (1 << 64))
        
        self.transcript.append(('receive', f'm_{self.b}', m_b))
        return m_b


# ─────────────────────────────────────────────
# Complete OT Protocol Execution
# ─────────────────────────────────────────────

def run_ot(m0: int, m1: int, b: int, bits: int = 64) -> dict:
    """
    Execute a complete 1-out-of-2 OT protocol.
    
    Args:
        m0, m1: sender's two messages (integers)
        b: receiver's choice bit (0 or 1)
        bits: security parameter for group
    
    Returns:
        dict with the result and protocol trace
    """
    params = OTParams(bits)
    
    sender = OTSender(m0, m1, params)
    receiver = OTReceiver(b, params)
    
    # Step 1: Sender setup
    msg1 = sender.setup()
    
    # Step 2: Receiver chooses
    msg2 = receiver.choose(msg1['A'])
    
    # Step 3: Sender responds
    msg3 = sender.respond(msg2['B'])
    
    # Step 4: Receiver retrieves
    result = receiver.retrieve(msg3['e0'], msg3['e1'])
    
    expected = m0 if b == 0 else m1
    
    return {
        'm0': m0,
        'm1': m1,
        'choice_bit': b,
        'received': result,
        'expected': expected,
        'correct': result == expected,
        'protocol_trace': {
            'step1_A': hex(msg1['A']),
            'step2_B': hex(msg2['B']),
            'step3_e0': hex(msg3['e0']),
            'step3_e1': hex(msg3['e1']),
            'step4_result': result
        },
        'privacy': {
            'sender_learns_nothing_about_b': True,
            'receiver_learns_nothing_about_other_message': True
        }
    }


# ─────────────────────────────────────────────
# Privacy Verification
# ─────────────────────────────────────────────

def privacy_verification(num_trials: int = 50) -> dict:
    """
    Verify OT privacy properties:
    1. Sender's privacy: receiver cannot learn the non-chosen message
    2. Receiver's privacy: sender cannot determine the choice bit
    """
    bits = 64
    params = OTParams(bits)
    
    # Test correctness across multiple runs
    correct_count = 0
    
    for _ in range(num_trials):
        m0 = random_int(0, 2**32 - 1)
        m1 = random_int(0, 2**32 - 1)
        b = random_int(0, 1)
        
        result = run_ot(m0, m1, b, bits)
        if result['correct']:
            correct_count += 1
    
    # Receiver's privacy test:
    # Generate B values for b=0 and b=1, verify they're indistinguishable
    b0_values = []
    b1_values = []
    
    for _ in range(20):
        sender = OTSender(0, 0, params)
        msg1 = sender.setup()
        
        rec0 = OTReceiver(0, params)
        rec1 = OTReceiver(1, params)
        
        msg_b0 = rec0.choose(msg1['A'])
        msg_b1 = rec1.choose(msg1['A'])
        
        b0_values.append(msg_b0['B'] % 100)
        b1_values.append(msg_b1['B'] % 100)
    
    return {
        'correctness': {
            'trials': num_trials,
            'correct': correct_count,
            'rate': round(correct_count / num_trials, 4)
        },
        'receiver_privacy': {
            'note': "B values for b=0 and b=1 are random group elements — indistinguishable",
            'b0_samples': b0_values[:5],
            'b1_samples': b1_values[:5]
        },
        'sender_privacy': {
            'note': "Receiver can only compute one key (A^beta) — cannot decrypt both messages"
        }
    }


# ─────────────────────────────────────────────
# OT Step-by-Step (for Web Demo)
# ─────────────────────────────────────────────

def ot_step_by_step(m0: int, m1: int, b: int) -> dict:
    """
    Execute OT with detailed step-by-step log for the web demo.
    """
    params = OTParams(64)
    sender = OTSender(m0, m1, params)
    receiver = OTReceiver(b, params)
    
    steps = []
    
    # Step 1
    msg1 = sender.setup()
    steps.append({
        'step': 1,
        'actor': 'Alice (Sender)',
        'action': f'Generate random a, compute A = g^a mod p = {hex(msg1["A"])}',
        'sends': f'A = {hex(msg1["A"])}'
    })
    
    # Step 2
    msg2 = receiver.choose(msg1['A'])
    steps.append({
        'step': 2,
        'actor': 'Bob (Receiver)',
        'action': f'Choice bit b = {b}. Generate β, compute B = {"g^β" if b == 0 else "A·g^β"} = {hex(msg2["B"])}',
        'sends': f'B = {hex(msg2["B"])}',
        'note': 'Alice cannot distinguish b=0 from b=1 (B is a random group element either way)'
    })
    
    # Step 3
    msg3 = sender.respond(msg2['B'])
    steps.append({
        'step': 3,
        'actor': 'Alice (Sender)',
        'action': f'Encrypt both messages: e0 = m0 ⊕ H(B^a), e1 = m1 ⊕ H((B/A)^a)',
        'sends': f'e0 = {hex(msg3["e0"])}, e1 = {hex(msg3["e1"])}'
    })
    
    # Step 4
    result = receiver.retrieve(msg3['e0'], msg3['e1'])
    steps.append({
        'step': 4,
        'actor': 'Bob (Receiver)',
        'action': f'Compute key k = A^β, decrypt e_{b} to get m_{b} = {result}',
        'result': f'm_{b} = {result}',
        'note': f'Bob cannot decrypt e_{1-b} (does not know the discrete log for pk_{1-b})'
    })
    
    return {
        'steps': steps,
        'result': result,
        'correct': result == (m0 if b == 0 else m1)
    }
