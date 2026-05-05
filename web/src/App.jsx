import { useState, useEffect } from 'react'
import './App.css'

const API = 'http://localhost:5000/api'

/**
 * Safe fetch wrapper: always resolves (never leaves loading=true).
 * Returns parsed JSON on success, or an error object on failure.
 */
async function safeFetch(url, options = {}) {
  try {
    const r = await fetch(url, options)
    if (!r.ok) {
      const text = await r.text().catch(() => 'Unknown server error')
      return { success: false, error: `HTTP ${r.status}: ${text.slice(0, 200)}` }
    }
    return await r.json()
  } catch (e) {
    return { success: false, error: `Network error: ${e.message}. Is the API running? (python3 api/server.py)` }
  }
}

function Section({ title, children, id }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="section" id={id}>
      <div className="section-header" onClick={() => setOpen(!open)}>
        <h2>{title}</h2>
        <span className="toggle">{open ? '▼' : '▶'}</span>
      </div>
      {open && <div className="section-body">{children}</div>}
    </div>
  )
}

function ResultBox({ data, loading }) {
  if (loading) return <div className="result loading">⏳ Computing...</div>
  if (!data) return null
  if (data.success === false) {
    return <pre className="result error">❌ Error: {data.error || 'Unknown error'}{data.traceback ? '\n\n' + data.traceback : ''}</pre>
  }
  return <pre className="result">{JSON.stringify(data, null, 2)}</pre>
}

function DemoButton({ label, onClick, loading }) {
  return <button className="demo-btn" onClick={onClick} disabled={loading}>{loading ? '⏳' : '▶'} {label}</button>
}

// PA Demo Components
function PA1Demo() {
  const [result, setResult] = useState(null), [loading, setLoading] = useState(false)
  const [seed, setSeed] = useState('deadbeefcafebabe12345678abcdef01')
  const [len, setLen] = useState(128)
  const run = async () => {
    setLoading(true)
    const data = await safeFetch(`${API}/pa1/prg`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({seed, output_length: len}) })
    setResult(data); setLoading(false)
  }
  return (<div>
    <label>Seed (hex): <input value={seed} onChange={e=>setSeed(e.target.value)} className="hex-input"/></label>
    <label>Output bits: <input type="range" min="8" max="256" value={len} onChange={e=>setLen(+e.target.value)}/> {len}</label>
    <DemoButton label="Generate PRG Output" onClick={run} loading={loading}/>
    <ResultBox data={result} loading={loading}/>
  </div>)
}

function PA2Demo() {
  const [result, setResult] = useState(null), [loading, setLoading] = useState(false)
  const [key, setKey] = useState('00112233445566778899aabbccddeeff')
  const [query, setQuery] = useState(5)
  const run = async () => {
    setLoading(true)
    const data = await safeFetch(`${API}/pa2/ggm`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({key, query, depth:4}) })
    setResult(data); setLoading(false)
  }
  return (<div>
    <label>Key (hex): <input value={key} onChange={e=>setKey(e.target.value)} className="hex-input"/></label>
    <label>Query x: <input type="number" min="0" max="15" value={query} onChange={e=>setQuery(+e.target.value)}/></label>
    <DemoButton label="Evaluate GGM Tree" onClick={run} loading={loading}/>
    <ResultBox data={result} loading={loading}/>
  </div>)
}

function PA3Demo() {
  const [result, setResult] = useState(null), [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('Hello, World!')
  const run = async () => {
    setLoading(true)
    const data = await safeFetch(`${API}/pa3/encrypt`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({message}) })
    setResult(data); setLoading(false)
  }
  return (<div>
    <p className="info">Enc(k,m) = (r, F_k(r) ⊕ m). Random nonce ensures CPA security.</p>
    <label>Message: <input value={message} onChange={e=>setMessage(e.target.value)} className="hex-input"/></label>
    <DemoButton label="Encrypt & Decrypt" onClick={run} loading={loading}/>
    <ResultBox data={result} loading={loading}/>
  </div>)
}

function PA4Demo() {
  const [result, setResult] = useState(null), [loading, setLoading] = useState(false)
  const run = async () => {
    setLoading(true)
    const data = await safeFetch(`${API}/pa4/ecb_penguin`, { method:'POST' })
    setResult(data); setLoading(false)
  }
  return (<div>
    <DemoButton label="Run ECB Penguin Demo" onClick={run} loading={loading}/>
    <ResultBox data={result} loading={loading}/>
  </div>)
}

function PA6Demo() {
  const [result, setResult] = useState(null), [loading, setLoading] = useState(false)
  const run = async () => {
    setLoading(true)
    const data = await safeFetch(`${API}/pa6/malleability`, { method:'POST' })
    setResult(data); setLoading(false)
  }
  return (<div>
    <p className="info">CPA encryption is <strong>malleable</strong> — flipping a ciphertext bit flips the plaintext bit. CCA (Encrypt-then-MAC) detects and rejects tampering.</p>
    <DemoButton label="Malleability Attack Demo" onClick={run} loading={loading}/>
    <ResultBox data={result} loading={loading}/>
  </div>)
}

function PA9Demo() {
  const [result, setResult] = useState(null), [loading, setLoading] = useState(false)
  const [bits, setBits] = useState(12)
  const run = async () => {
    setLoading(true)
    const data = await safeFetch(`${API}/pa9/attack`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({output_bits: bits}) })
    setResult(data); setLoading(false)
  }
  return (<div>
    <label>Output bits n: <input type="range" min="8" max="16" value={bits} onChange={e=>setBits(+e.target.value)}/> {bits} (expected collision at ~2^{bits/2} = {Math.round(Math.pow(2, bits/2))} evals)</label>
    <DemoButton label="Run Birthday Attack" onClick={run} loading={loading}/>
    <ResultBox data={result} loading={loading}/>
  </div>)
}

function PA13Demo() {
  const [result, setResult] = useState(null), [loading, setLoading] = useState(false)
  const [n, setN] = useState('561')
  const [rounds, setRounds] = useState(10)
  const run = async () => {
    setLoading(true)
    const data = await safeFetch(`${API}/pa13/test`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({n: parseInt(n), rounds}) })
    setResult(data); setLoading(false)
  }
  return (<div>
    <label>Number to test: <input value={n} onChange={e=>setN(e.target.value)} className="hex-input"/></label>
    <label>Rounds k: <input type="range" min="1" max="40" value={rounds} onChange={e=>setRounds(+e.target.value)}/> {rounds}</label>
    <p className="info">Pre-loaded: <button className="chip" onClick={()=>setN('561')}>561 (Carmichael)</button> <button className="chip" onClick={()=>setN('104729')}>104729 (prime)</button> <button className="chip" onClick={()=>setN('15485863')}>15485863 (prime)</button></p>
    <DemoButton label="Test Primality" onClick={run} loading={loading}/>
    <ResultBox data={result} loading={loading}/>
  </div>)
}

function PA18Demo() {
  const [result, setResult] = useState(null), [loading, setLoading] = useState(false)
  const [m0, setM0] = useState(42), [m1, setM1] = useState(99), [b, setB] = useState(0)
  const run = async () => {
    setLoading(true)
    const data = await safeFetch(`${API}/pa18/ot`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({m0,m1,b}) })
    setResult(data); setLoading(false)
  }
  return (<div>
    <div className="ot-panels">
      <div className="panel alice"><h4>Alice (Sender)</h4><label>m₀: <input type="number" value={m0} onChange={e=>setM0(+e.target.value)}/></label><label>m₁: <input type="number" value={m1} onChange={e=>setM1(+e.target.value)}/></label></div>
      <div className="panel bob"><h4>Bob (Receiver)</h4><label>Choice bit b: <select value={b} onChange={e=>setB(+e.target.value)}><option value={0}>0</option><option value={1}>1</option></select></label></div>
    </div>
    <DemoButton label="Run OT Protocol" onClick={run} loading={loading}/>
    <ResultBox data={result} loading={loading}/>
  </div>)
}

function PA19Demo() {
  const [result, setResult] = useState(null), [loading, setLoading] = useState(false)
  const [a, setA] = useState(1), [b, setB] = useState(1)
  const run = async () => {
    setLoading(true)
    const data = await safeFetch(`${API}/pa19/and`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({a,b}) })
    setResult(data); setLoading(false)
  }
  return (<div>
    <div className="ot-panels">
      <div className="panel alice"><h4>Alice</h4><label>Bit a: <select value={a} onChange={e=>setA(+e.target.value)}><option value={0}>0</option><option value={1}>1</option></select></label></div>
      <div className="panel bob"><h4>Bob</h4><label>Bit b: <select value={b} onChange={e=>setB(+e.target.value)}><option value={0}>0</option><option value={1}>1</option></select></label></div>
    </div>
    <DemoButton label="Compute Secure AND & XOR" onClick={run} loading={loading}/>
    <ResultBox data={result} loading={loading}/>
  </div>)
}

function PA20Demo() {
  const [result, setResult] = useState(null), [loading, setLoading] = useState(false)
  const [x, setX] = useState(7), [y, setY] = useState(12)
  const run = async () => {
    setLoading(true)
    const data = await safeFetch(`${API}/pa20/millionaire`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({x,y,n:4}) })
    setResult(data); setLoading(false)
  }
  return (<div>
    <p className="info">Yao's Millionaire Problem: securely compute who is richer without revealing actual values.</p>
    <div className="ot-panels">
      <div className="panel alice"><h4>Alice's Wealth</h4><input type="range" min="0" max="15" value={x} onChange={e=>setX(+e.target.value)}/><span className="hidden-val">Hidden ({x})</span></div>
      <div className="panel bob"><h4>Bob's Wealth</h4><input type="range" min="0" max="15" value={y} onChange={e=>setY(+e.target.value)}/><span className="hidden-val">Hidden ({y})</span></div>
    </div>
    <DemoButton label="Who Is Richer?" onClick={run} loading={loading}/>
    <ResultBox data={result} loading={loading}/>
  </div>)
}

function SimpleDemo({ endpoint, label, info, hasInput, inputLabel, inputPlaceholder }) {
  const [result, setResult] = useState(null), [loading, setLoading] = useState(false)
  const [inputVal, setInputVal] = useState('')
  const run = async () => {
    setLoading(true)
    const opts = { method: 'POST' }
    if (hasInput && inputVal) {
      opts.headers = { 'Content-Type': 'application/json' }
      opts.body = JSON.stringify({ message: inputVal })
    }
    const data = await safeFetch(`${API}/${endpoint}`, opts)
    setResult(data); setLoading(false)
  }
  return (<div>
    {info && <p className="info">{info}</p>}
    {hasInput && <label>{inputLabel || 'Input'}: <input value={inputVal} onChange={e=>setInputVal(e.target.value)} placeholder={inputPlaceholder} className="hex-input"/></label>}
    <DemoButton label={label} onClick={run} loading={loading}/>
    <ResultBox data={result} loading={loading}/>
  </div>)
}

const REDUCTION_CHAIN = `OWF (PA#1) → PRG (PA#1) → PRF (PA#2) → CPA-Enc (PA#3) → CCA-Enc (PA#6)
                     ↕           ↕           ↕         ↓
                    PRP (AES)  MAC (PA#5) ← PRF    Modes (PA#4)
                                  ↕
                            CRHF (PA#7+8) ↔ HMAC (PA#10) → CCA-Enc (PA#10)
                                  ↓
                          Birthday Floor (PA#9)

PKC: DH (PA#11) → RSA (PA#12) → CRT (PA#14) → Signatures (PA#15) → ElGamal (PA#16) → CCA-PKC (PA#17)
                   ↑                                                                          ↓
             Miller-Rabin (PA#13)                                                        OT (PA#18)
                                                                                               ↓
                                                                                     Secure AND (PA#19)
                                                                                               ↓
                                                                                    All 2-Party MPC (PA#20)`

function App() {
  const [foundation, setFoundation] = useState('AES')
  const [apiUp, setApiUp] = useState(false)

  useEffect(() => {
    fetch(`${API}/health`).then(r=>r.json()).then(()=>setApiUp(true)).catch(()=>setApiUp(false))
  }, [])

  return (
    <div className="app">
      <header>
        <h1>🔐 CS8.401 — Principles of Information Security</h1>
        <p className="subtitle">Complete Cryptographic Reduction Chain: OWF → MPC</p>
        <div className="foundation-toggle">
          <span>Foundation:</span>
          <button className={foundation==='AES'?'active':''} onClick={()=>setFoundation('AES')}>AES</button>
          <button className={foundation==='DLP'?'active':''} onClick={()=>setFoundation('DLP')}>DLP</button>
        </div>
        <div className={`api-status ${apiUp?'up':'down'}`}>{apiUp ? '🟢 API Connected' : '🔴 API Offline — start with: python3 api/server.py'}</div>
      </header>

      <div className="chain-box">
        <h3>Full Reduction Chain</h3>
        <pre className="chain">{REDUCTION_CHAIN}</pre>
      </div>

      <main>
        <h2 className="part-title">Part I: Minicrypt Clique</h2>
        <Section title="PA#1 — One-Way Functions & PRG" id="pa1"><PA1Demo/></Section>
        <Section title="PA#2 — PRF via GGM Tree" id="pa2"><PA2Demo/></Section>
        <Section title="PA#3 — CPA-Secure Encryption" id="pa3"><PA3Demo/></Section>
        <Section title="PA#4 — Modes of Operation" id="pa4"><PA4Demo/></Section>
        <Section title="PA#5 — MACs (PRF-MAC, CBC-MAC)" id="pa5"><SimpleDemo endpoint="pa5/euf_cma" label="EUF-CMA Forgery Game" info="50 queries to MAC oracle, then 20 forgery attempts. Should all fail."/></Section>
        <Section title="PA#6 — CCA-Secure Encryption" id="pa6"><PA6Demo/></Section>

        <h2 className="part-title">Part II: Hashing & Data Integrity</h2>
        <Section title="PA#7 — Merkle-Damgård Transform" id="pa7"><SimpleDemo endpoint="pa7/hash" label="Hash Step-by-Step" info="Generic hash framework: pad → compress → chain." hasInput inputLabel="Message" inputPlaceholder="Hello"/></Section>
        <Section title="PA#8 — DLP-Based CRHF" id="pa8"><SimpleDemo endpoint="pa8/avalanche" label="Avalanche Effect Demo" info="1-bit input change → ~50% output bits change."/></Section>
        <Section title="PA#9 — Birthday Attack" id="pa9"><PA9Demo/></Section>
        <Section title="PA#10 — HMAC + Encrypt-then-HMAC" id="pa10"><SimpleDemo endpoint="pa10/length_extension" label="Length Extension vs HMAC" info="Naive H(k||m) is vulnerable; HMAC's double-hash blocks the attack."/></Section>

        <h2 className="part-title">Part III: Public-Key Cryptography</h2>
        <Section title="PA#11 — Diffie-Hellman Key Exchange" id="pa11"><SimpleDemo endpoint="pa11/exchange" label="DH Key Exchange" info="Alice & Bob establish shared secret over public channel."/></Section>
        <Section title="PA#12 — Textbook RSA" id="pa12"><SimpleDemo endpoint="pa12/demo" label="RSA Encrypt/Decrypt" info="c = m^e mod N, m = c^d mod N" hasInput inputLabel="Message (integer)" inputPlaceholder="42"/></Section>
        <Section title="PA#13 — Miller-Rabin Primality" id="pa13"><PA13Demo/></Section>
        <Section title="PA#14 — CRT & Håstad Attack" id="pa14"><SimpleDemo endpoint="pa14/hastad" label="Håstad Broadcast Attack" info="3 recipients, same message, e=3 → CRT recovers plaintext!"/></Section>
        <Section title="PA#15 — Digital Signatures" id="pa15"><SimpleDemo endpoint="pa15/sign" label="Sign & Verify" info="RSA signature: sig = H(m)^d mod N" hasInput inputLabel="Message" inputPlaceholder="Hello, World!"/></Section>
        <Section title="PA#16 — ElGamal PKC" id="pa16"><SimpleDemo endpoint="pa16/demo" label="ElGamal Demo" info="Encrypt: (g^r, m·h^r). Decrypt: c2 · c1^{-x}." hasInput inputLabel="Message (integer)" inputPlaceholder="42"/></Section>
        <Section title="PA#17 — CCA-Secure PKC" id="pa17"><SimpleDemo endpoint="pa6/cca2_game" label="CCA2 Game" info="ElGamal + RSA Signatures = CCA-secure PKC"/></Section>

        <h2 className="part-title">Part IV: Secure Multi-Party Computation</h2>
        <Section title="PA#18 — Oblivious Transfer" id="pa18"><PA18Demo/></Section>
        <Section title="PA#19 — Secure AND Gate" id="pa19"><PA19Demo/></Section>
        <Section title="PA#20 — All 2-Party MPC (Yao/GMW)" id="pa20"><PA20Demo/></Section>
      </main>

      <footer>
        <p>CS8.401 · No external crypto libraries · Full reduction chain from OWF to MPC</p>
        <p>Stack: OWF → PRG → PRF → CPA → CCA → CRHF → HMAC → PKC → OT → AND → MPC</p>
      </footer>
    </div>
  )
}

export default App
