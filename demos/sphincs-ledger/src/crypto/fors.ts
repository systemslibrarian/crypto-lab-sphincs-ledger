// FORS (Forest Of Random Subsets) — pedagogical reconstruction. FIPS 205 §8.
//
// PARALLEL vs INSPECT: @noble/post-quantum does NOT expose its internal FORS
// leaves, trees, or the message-digest split through its public API (only
// keygen/sign/verify/lengths). So the construction below is an INDEPENDENT
// educational model, NOT a read-out of noble's state. The parameter VALUES it
// uses (k, a, t) come from noble's exported PARAMS via params.ts and are real.
//
// What is exact here: the digest -> k indices bit-slicing (base_2b), verified
// against FIPS 205 Algorithm 4 below.
// What is reduced/labeled: trees are drawn/rooted at a reduced height for
// tractability (a real FORS tree has t = 2^a leaves: 64–16384, too many to draw
// or hash literally), and H_msg is modeled with SHA-256 + MGF1 rather than the
// full FIPS 205 transcript hash. Both reductions are surfaced in the UI.

import { sha256, concatBytes } from './hash';

// ── base_2b — FIPS 205 Algorithm 4 ───────────────────────────────────────────
// Converts a byte string X into `outLen` integers, each `b` bits wide, consuming
// bits most-significant-first. This is the exact routine SLH-DSA uses to turn the
// FORS portion of the message digest (`md`) into k leaf indices in [0, 2^a).
//
// The reference keeps an ever-growing `total` (a bignum). We instead truncate
// `total` to just the unconsumed low bits after each output. That is bit-for-bit
// equivalent (the discarded high bits were already emitted and would be masked
// off by `% 2^b` anyway) and keeps every value < 2^(b+8) ≤ 2^22, so it is safe in
// JS Number/bitwise without BigInt. Verified by unit tests (see fors.test.ts):
//   base_2b([0x12,0x34], 4, 4)            -> [1, 2, 3, 4]
//   base_2b([0x12,0x34,0x56], 12, 2)      -> [0x123, 0x456] = [291, 1110]
export function base2b(X: Uint8Array, b: number, outLen: number): number[] {
  const out: number[] = [];
  let inPos = 0;
  let bits = 0;
  let total = 0;
  const mask = (1 << b) - 1;
  for (let i = 0; i < outLen; i++) {
    while (bits < b) {
      if (inPos >= X.length) {
        // Would otherwise read undefined → silent zero-padding and corrupt indices.
        throw new Error(`base2b: need ≥${Math.ceil((outLen * b) / 8)} bytes for ${outLen}×${b}-bit fields, got ${X.length}`);
      }
      total = ((total << 8) | X[inPos]) >>> 0;
      inPos++;
      bits += 8;
    }
    bits -= b;
    out.push((total >>> bits) & mask);
    total = total & ((1 << bits) - 1); // keep only unconsumed low bits (no bignum)
  }
  return out;
}

// ── MGF1-SHA-256 — counter-mode hash expansion (RFC 8017 / used by SLH-DSA-SHA2)
// Produces `length` bytes from `seed`. Real SLH-DSA-SHA2 H_msg uses MGF1 over
// SHA-256 (128-bit sets) or SHA-512 (192/256-bit sets); we use SHA-256 uniformly
// here and label it. We need this because k*a bits can exceed one SHA-256 block
// (e.g. 256s: 22*14 = 308 bits = 39 bytes > 32).
export async function mgf1Sha256(seed: Uint8Array, length: number): Promise<Uint8Array> {
  const blocks: Uint8Array[] = [];
  let produced = 0;
  let counter = 0;
  while (produced < length) {
    const c = new Uint8Array([
      (counter >>> 24) & 0xff,
      (counter >>> 16) & 0xff,
      (counter >>> 8) & 0xff,
      counter & 0xff,
    ]);
    const block = await sha256(concatBytes(seed, c));
    blocks.push(block);
    produced += block.length;
    counter++;
  }
  return concatBytes(...blocks).subarray(0, length);
}

export interface ForsDigest {
  digestSeed: Uint8Array; // SHA-256(R || message) — the pedagogical H_msg seed
  mdBytes: Uint8Array;    // ceil(k*a/8) bytes fed to base_2b
  indices: number[];      // k leaf indices, each in [0, 2^a)
}

// Compute the k FORS leaf indices for a message (FIPS 205 §8 split).
// randomizer R models the per-signature randomness in SLH-DSA's H_msg.
export async function computeForsIndices(
  message: Uint8Array,
  randomizer: Uint8Array,
  k: number,
  a: number
): Promise<ForsDigest> {
  const digestSeed = await sha256(concatBytes(randomizer, message));
  const mdBytes = await mgf1Sha256(digestSeed, Math.ceil((k * a) / 8));
  const indices = base2b(mdBytes, a, k);
  return { digestSeed, mdBytes, indices };
}

export interface ForsTreeResult {
  treeIndex: number;
  leafIndex: number;       // REAL index in [0, t) selected by the digest
  secret: Uint8Array;      // revealed FORS secret sk[treeIndex][leafIndex]
  leaf: Uint8Array;        // F(secret) — the leaf node
  root: Uint8Array;        // root over a REDUCED tree of height aDisplay
  reducedHeight: number;   // aDisplay actually built (≤ a)
  reducedLeafIndex: number; // leafIndex mapped into the reduced tree
}

export interface ForsResult {
  digest: ForsDigest;
  trees: ForsTreeResult[];
  publicKey: Uint8Array;   // SHA-256( root_0 || … || root_{k-1} ) — feeds the hypertree
  reducedHeight: number;
}

// Build a reduced FORS over the selected indices and derive the FORS public key.
// `skSeed` deterministically derives every secret so the result is reproducible.
// Trees are built at height `aDisplay = min(a, maxDrawHeight)` so they can be both
// hashed and drawn; the REAL index/height are reported alongside.
export async function buildFors(
  digest: ForsDigest,
  skSeed: Uint8Array,
  a: number,
  maxDrawHeight = 4
): Promise<ForsResult> {
  const aDisplay = Math.min(a, maxDrawHeight);
  const reducedT = 2 ** aDisplay;
  const trees: ForsTreeResult[] = [];

  for (let i = 0; i < digest.indices.length; i++) {
    const leafIndex = digest.indices[i];
    const reducedLeafIndex = leafIndex % reducedT;

    // sk[i][leafIndex] = PRF(skSeed, i, leafIndex)  (modeled with SHA-256)
    const secret = await sha256(
      concatBytes(skSeed, u32(i), u32(leafIndex))
    );
    const leaf = await sha256(secret); // FORS leaf = F(sk)

    // Build a reduced Merkle tree of `reducedT` deterministic leaves with our
    // real leaf placed at reducedLeafIndex, then take the root.
    let layer: Uint8Array[] = [];
    for (let j = 0; j < reducedT; j++) {
      layer.push(
        j === reducedLeafIndex ? leaf : await sha256(concatBytes(skSeed, u32(i), u32(0xffff0000 + j)))
      );
    }
    while (layer.length > 1) {
      const next: Uint8Array[] = [];
      for (let j = 0; j < layer.length; j += 2) {
        next.push(await sha256(concatBytes(layer[j], layer[j + 1])));
      }
      layer = next;
    }

    trees.push({
      treeIndex: i,
      leafIndex,
      secret,
      leaf,
      root: layer[0],
      reducedHeight: aDisplay,
      reducedLeafIndex,
    });
  }

  // FORS public key = thash(root_0 || … || root_{k-1}); modeled with SHA-256.
  const publicKey = await sha256(concatBytes(...trees.map((t) => t.root)));
  return { digest, trees, publicKey, reducedHeight: aDisplay };
}

function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

// ── Illustrative few-time-security margin (PIECE 4) ──────────────────────────
// NOT a proof. A rough estimate of the chance a fresh target message is already
// forgeable after N honest signatures, under the simplifying assumption that each
// signature reveals one uniformly-random leaf per tree independently:
//   P(a given tree's needed leaf already revealed) ≈ 1 - (1 - 1/t)^N
//   P(all k needed leaves already revealed)        ≈ [1 - (1 - 1/t)^N]^k
// Real SPHINCS+ bounds are tighter and account for randomized H_msg and grafting.
export function illustrativeForgeryProbability(n: number, t: number, k: number): number {
  const perTree = 1 - Math.pow(1 - 1 / t, n);
  return Math.pow(perTree, k);
}
