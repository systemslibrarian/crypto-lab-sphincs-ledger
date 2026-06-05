# NOTES — Display-Scaled & Reconstructed Values

This file enumerates every value in the FORS / Hypertree / Collision / WOTS+-reuse
work that is **display-scaled**, **modeled**, or **pedagogically reconstructed**,
and why. Anything not listed here is either real (sourced from
`@noble/post-quantum`) or computed exactly per spec.

Each item is also surfaced in-UI (inline labels) and summarized in `README.md`
under "Honesty Notes / KNOWN-GAPS".

---

## Real (NOT scaled) — for contrast

- **`k, a, t, d, h, h′`** — read live from noble's exported `PARAMS`
  (`src/crypto/params.ts`). These are the genuine FIPS 205 Table 2 values used by
  the library that signs in Tab 1.
- **`base_2b` digest→index slicing** — implemented exactly per FIPS 205
  Algorithm 4 (`src/crypto/fors.ts`), unit-tested in `src/__tests__/fors.test.ts`
  (e.g. `base_2b([0x12,0x34,0x56], 12, 2) === [0x123, 0x456]`). The only
  deviation is an implementation detail: `total` is truncated to its unconsumed
  low bits each iteration to avoid BigInt — bit-for-bit equivalent to the spec.
- **WOTS+ forgery** — the forged value is a genuine `SHA-256`-forward computation
  from the lowest revealed point; it equals the honest signer's value exactly and
  verifies against the real public key. The *forgery* is real; only the
  *surrounding chain* is simplified (see below).

---

## Display-scaled / reconstructed values

### 1. FORS trees drawn & rooted at reduced height
- **What:** Each FORS tree is drawn and its root computed over a reduced height
  `aDisplay = min(a, 4)` (≤ 16 leaves) instead of the real `a` (6–14).
- **Why:** Real `t = 2^a` is 64–16,384 leaves per tree — too many to draw, and
  with `k` up to 35 trees, too many to hash on every click.
- **Labeled:** The amber selected leaf always prints its **real** index and `t`
  (e.g. `2847/4096`); the trees-heading states the reduced height and real `a`/`t`.
- **Where:** `src/crypto/fors.ts` (`buildFors`, `maxDrawHeight`), `src/visualization/fors.ts`.

### 2. FORS message digest modeled with SHA-256 + MGF1
- **What:** The FORS portion of the message digest is modeled as
  `MGF1-SHA-256(SHA-256(R ‖ message))`, expanded to `⌈k·a/8⌉` bytes.
- **Why real differs:** FIPS 205's `H_msg` is a longer transcript hash over
  `R ‖ PK.seed ‖ PK.root ‖ M`, and SHA-2 sets use MGF1 over SHA-256 (128-bit) or
  **SHA-512** (192/256-bit). We use SHA-256 uniformly. The MGF1 step is genuinely
  needed because `k·a` can exceed one SHA-256 block (e.g. 256s: 22×14 = 308 bits
  = 39 bytes > 32).
- **Labeled:** The digest panel says "pedagogical H_msg = MGF1-SHA-256".
- **Where:** `src/crypto/fors.ts` (`computeForsIndices`, `mgf1Sha256`).

### 3. FORS secrets / leaves / public key modeled with SHA-256
- **What:** `sk[i][j] = SHA-256(skSeed ‖ i ‖ j)`, leaf `= SHA-256(sk)`, FORS
  public key `= SHA-256(root₀ ‖ … ‖ root₍ₖ₋₁₎)`.
- **Why real differs:** Real FORS uses keyed tweakable hashes (`PRF`, `F`,
  `T_k`) with domain-separating addresses (`ADRS`); we use plain SHA-256.
- **Labeled:** Tab intro states "parallel pedagogical reconstruction".
- **Where:** `src/crypto/fors.ts` (`buildFors`).

### 4. Hypertree XMSS trees drawn as schematic triangles
- **What:** Each of the `d` XMSS layers is a triangle glyph, not its `2^h′`
  leaves; one highlighted leaf→root path is illustrative (fixed fraction), not
  derived from a real signature.
- **Why:** `2^h′` is 8–512 leaves per layer across `d` = 7–22 layers.
- **Labeled:** Tab intro + the per-layer "2^h′ = N leaves" annotation print the
  real counts; the params card shows real `d`, `h`, `h′`.
- **Where:** `src/visualization/hypertree.ts`.

### 5. WOTS+ chain omits the Winternitz checksum
- **What:** The WOTS+ tab uses independent 16-step chains with no checksum chains.
- **Why it matters:** In real WOTS+, a checksum prevents forging *higher* digits
  by construction (forging up on one chain forces forging down on a checksum
  chain). Our simplified model deliberately omits this so the core hash-chain
  one-wayness — "reveal a low value → an attacker can forge any higher value" — is
  shown directly and unobscured. This is the intended teaching point of the reuse
  demo, and it is labeled as illustrative in the tab.
- **Where:** `src/crypto/wots.ts`, `src/visualization/wots-chain.ts`.

### 6. Collision-tolerance security margin
- **What:** `P(forgeable) ≈ [1 − (1 − 1/t)^N]^k`.
- **Why:** A rough independence-assuming estimate, **not** a proof. Real bounds
  are tighter and account for randomized `H_msg` and grafting.
- **Labeled:** The tab heading and output both say "illustrative … NOT a proof".
- **Where:** `src/crypto/fors.ts` (`illustrativeForgeryProbability`).

### 7. Collision tab uses a deterministic (empty) randomizer
- **What:** The two-message comparison uses `R = ∅` so identical messages map
  identically and the comparison is purely message-driven.
- **Why real differs:** Real SLH-DSA randomizes `R` per signature, which further
  frustrates collision-targeting.
- **Labeled:** A note in the comparison output states this.
- **Where:** `src/main.ts` (collision handler).

### 8. FORS/collision demo seeds are fixed
- **What:** `R` and `skSeed` in the FORS tab are derived from fixed demo strings
  for reproducibility (so the same message always yields the same picture).
- **Why:** Pedagogical determinism; not a security property.
- **Where:** `src/main.ts` (FORS handler).

---

## Spec discrepancy flagged during the build

The original build brief listed FORS parameters as "128f/128s: k=14, a=12" and
"256f/256s: k=22, a=14". That is correct **only for the `s` variants**. Per FIPS
205 Table 2 (and noble's `PARAMS`), the `f` variants differ sharply:

| Set | k | a | t |
|---|---|---|---|
| 128f | 33 | 6 | 64 |
| 256f | 35 | 9 | 512 |

The implementation uses the **real noble values** for all four sets, so the `f`
variants are correct, not the brief's grouped figures.
