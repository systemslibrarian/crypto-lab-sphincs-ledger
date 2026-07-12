# crypto-lab-sphincs-ledger

Browser-based cryptographic demo for **SLH-DSA (SPHINCS+)** — the hash-based signature scheme standardized as [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).

Part of the [crypto-compare](https://github.com/systemslibrarian/crypto-compare) portfolio.

**[Live Demo →](https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/)**

## What This Demo Shows

1. **Hash-only security** — SPHINCS+ security reduces entirely to SHA-256 collision resistance. No algebraic assumptions (factoring, discrete log, lattice problems).
2. **Merkle tree mechanics** — Real SHA-256 Merkle trees built and verified in the browser, with authentication path visualization and step-by-step root recomputation.
3. **WOTS+ one-time property — and its catastrophic failure on reuse** — Winternitz hash-chain demonstration that now shows the *actual* reuse failure, not just a warning: revealed chain points accumulate across signatures, and a **Forge & Verify** control reconstructs a higher chain value by hashing the lowest revealed point forward (no private seed) and verifies the forgery against the real public key. Reuse detection is per-chain and honest.
4. **FORS (Forest Of Random Subsets), FIPS 205 §8** — The message digest is sliced into *k* fields of *a* bits via `base_2b` (implemented exactly per FIPS 205 Algorithm 4), each selecting one leaf per tree; *k* roots are hashed into the FORS public key. This is where the real `k`, `a`, `t` finally surface in the UI.
5. **Hypertree** — The *d* layers of XMSS trees, each root signed by a WOTS+ leaf one layer up, climbing to the top root = public key. Annotates the size story (FORS sig + *d* × (WOTS+ sig + auth path)) that explains the 8 KB–50 KB signatures.
6. **Collision tolerance** — Signs two messages with the same key, compares the two *k*-index vectors, and contrasts FORS's graceful degradation (few-time security → why SLH-DSA is stateless) against WOTS+'s catastrophic reuse.
7. **Ledger signing** — Append-only ledger of SPHINCS+ signed entries with tamper detection. Each entry generates a fresh keypair — no shared keys or PKI required.
8. **Parameter set comparison** — All four SHA-2 parameter sets (128f, 128s, 256f, 256s) with measured signing times and size comparisons against RSA, Ed25519, and ML-DSA.

### Where the real parameters now come from

The FORS and Hypertree tabs surface the internal parameters (`k`, `a`, `t`, `d`, `h`, `h′`) that were previously invisible. **These values are read directly from `@noble/post-quantum`'s exported `PARAMS` table** — the same library that performs the actual signing — not re-typed by hand. The noble *signer* object only exposes `keygen`/`sign`/`verify`/`lengths`; the numeric parameters live in the separately-exported `PARAMS` record, which `src/crypto/params.ts` imports.

## Run Locally

```bash
cd demos/sphincs-ledger
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

## Build

```bash
npm run build
```

Output goes to `dist/`. The demo runs fully offline — no external CDN dependencies at runtime.

## Tests

```bash
npm test        # vitest — crypto unit tests (run once)
npm run test:a11y   # Playwright + axe-core WCAG A/AA gate
```

`npm test` runs a [vitest](https://vitest.dev) suite over the crypto layer and is
part of the CI build (it runs before `npm run build` in `.github/workflows/deploy.yml`,
so a broken crypto path fails the deploy). It covers:

- **Real SLH-DSA (`@noble/post-quantum`)** — keygen/sign/verify round-trip, exact
  FIPS 205 key/signature sizes, single-bit signature tamper rejection, message
  tamper rejection, and cross-key rejection, across **all four** SHA-2 parameter
  sets (128f/128s/256f/256s) — not just the fast one.
- **`base_2b` (FIPS 205 Algorithm 4)** — worked-example vectors, the real FORS
  `(k, a)` widths, and the too-few-bytes guard (must throw, never zero-pad).
- **MGF1-SHA-256** — exact output length across block boundaries, prefix-stability,
  and the reference first block `SHA-256(seed ‖ 0x00000000)`.
- **FORS model** (`computeForsIndices` / `buildFors`) — indices in range,
  determinism, randomizer- and seed-sensitivity, and that the selected leaf feeds
  the derived FORS public key.
- **WOTS+ reuse forgery** — the genuine hash-forward forgery reconstructs the
  honest signer's higher chain value and **verifies against the real public key**,
  cannot go below the lowest reveal, and reuse detection fires only on a second
  distinct reveal.
- **Merkle auth paths** — every leaf verifies via its path (round-trip), and a
  tampered leaf, wrong index, or tampered path is rejected.

The a11y suite (`test:a11y`) runs against the production build and asserts zero
WCAG 2.0/2.1 A + AA violations in both themes.

## SPHINCS+ Implementation

- **Package:** [`@noble/post-quantum`](https://www.npmjs.com/package/@noble/post-quantum) v0.6.0 by Paul Miller
- **Import:** `@noble/post-quantum/slh-dsa.js`
- **Functions:** `keygen()`, `sign(msg, secretKey)`, `verify(sig, msg, publicKey)`

## Parameter Set Reference (NIST FIPS 205 Table 1)

| Parameter Set | Public Key | Private Key | Signature | Security Level |
|---|---|---|---|---|
| SLH-DSA-SHA2-128f | 32 B | 64 B | 17,088 B | 128-bit |
| SLH-DSA-SHA2-128s | 32 B | 64 B | 7,856 B | 128-bit |
| SLH-DSA-SHA2-256f | 64 B | 128 B | 49,856 B | 256-bit |
| SLH-DSA-SHA2-256s | 64 B | 128 B | 29,792 B | 256-bit |

- **f (fast):** Larger signatures, faster signing
- **s (small):** Smaller signatures, slower signing

### Internal Structural Parameters (FIPS 205 Table 2, surfaced in the FORS/Hypertree tabs)

Read live from `@noble/post-quantum`'s `PARAMS`. Note that the FORS parameters differ
substantially between the `f` and `s` variants — the `f` sets use **many short** FORS trees,
the `s` sets use **fewer tall** ones:

| Parameter Set | FORS k | FORS a | FORS t=2^a | Layers d | Height h | h′=h/d |
|---|---|---|---|---|---|---|
| SLH-DSA-SHA2-128s | 14 | 12 | 4,096 | 7 | 63 | 9 |
| SLH-DSA-SHA2-128f | 33 | 6 | 64 | 22 | 66 | 3 |
| SLH-DSA-SHA2-256s | 22 | 14 | 16,384 | 8 | 64 | 8 |
| SLH-DSA-SHA2-256f | 35 | 9 | 512 | 17 | 68 | 4 |

## What Is Illustrative vs Production

| Component | Status |
|---|---|
| SPHINCS+ sign/verify (`@noble/post-quantum`) | **Production** — audited library implementing FIPS 205 |
| SHA-256 hashing (Web Crypto API) | **Production** — browser-native implementation |
| Parameter values `k, a, t, d, h, h′` | **Real** — read live from noble's exported `PARAMS` (FIPS 205 Table 2) |
| `base_2b` digest→index slicing (FORS) | **Spec-exact** — FIPS 205 Algorithm 4, unit-tested |
| Merkle tree visualization | **Illustrative** — real SHA-256, simplified structure (up to 16 leaves) |
| WOTS+ chain + reuse forgery | **Illustrative** — real SHA-256 chains; the forgery is a genuine hash-forward that verifies against the public key, but on a simplified single-chain (no Winternitz checksum) |
| FORS trees + public key | **Parallel reconstruction** — our own model (noble exposes no FORS internals); trees drawn/rooted at reduced height, digest modeled with SHA-256 + MGF1 |
| Hypertree diagram | **Illustrative** — real `d`/`h`/`h′`; XMSS trees drawn as schematic triangles |
| Collision security margin | **Illustrative estimate** — a rough bound, explicitly not a proof |
| Ledger | **Demo** — sessionStorage persistence, no consensus or networking |

## Honesty Notes / KNOWN-GAPS

- **Parameter internals are now surfaced, and they are real.** The FORS and Hypertree tabs read `k, a, t, d, h, h′` from `@noble/post-quantum`'s exported `PARAMS` — the same library that signs. They are not hand-typed constants.
- **FORS/Hypertree are a *parallel pedagogical reconstruction*, not an inspection of noble.** noble's public API exposes only `keygen`/`sign`/`verify`/`lengths` on the signer — never its internal FORS leaves, trees, or hypertree nodes. So those structures are an independent educational model in `src/crypto/fors.ts` and `src/visualization/`. Only the parameter *values* come from noble; the constructions do not.
- **SHA-2 only. No SHAKE/SHA-3 anywhere.** Every hash in this demo is SHA-256 (Web Crypto). The four parameter sets are the SHA-2 variants only.
- **No 192-bit tier.** Only 128- and 256-bit, each in `f` (fast) and `s` (small). This matches the four sets wired to noble in Tab 1.
- **Display-scaled / reconstructed values** are enumerated in `NOTES-scaled-values.md`. In short: FORS trees are drawn and rooted at a reduced height (real `t` = 64–16,384 leaves is too many to draw or hash literally — the real index/`t` is always printed on the amber leaf); the FORS digest is modeled with SHA-256 + MGF1 rather than the full FIPS 205 transcript hash; XMSS trees in the hypertree are schematic triangles; and the WOTS+ chain omits the Winternitz checksum, so the forgery demo shows the "reveal a low value → forge higher values" failure directly.
- **The collision security-margin counter is illustrative**, computed as `[1 − (1 − 1/t)^N]^k`. Real SPHINCS+ bounds are tighter and account for randomized `H_msg` and grafting.

## Stack

| Layer | Choice |
|---|---|
| Frontend | Vite + TypeScript |
| SPHINCS+ | `@noble/post-quantum` (FIPS 205) |
| Hash function | SHA-256 via Web Crypto API |
| Visualization | SVG — vanilla TypeScript |
| UI | Vanilla TypeScript — no framework |

## Specification References

- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) — SLH-DSA standard
- [SPHINCS+ specification v3.1](https://sphincs.org/data/sphincs+-r3.1-specification.pdf)
- [sphincs.org](https://sphincs.org)

## Cross-References

- **[ratchet-wire](https://github.com/systemslibrarian/crypto-compare):** SPHINCS+ could sign the initial X3DH pre-keys for a fully post-quantum messaging handshake.
- **[quantum-vault-kpqc](https://github.com/systemslibrarian/crypto-compare):** Korean KpqC (HAETAE) is a lattice-based alternative occupying a similar role to ML-DSA, while SPHINCS+ occupies a distinct hash-only niche.
