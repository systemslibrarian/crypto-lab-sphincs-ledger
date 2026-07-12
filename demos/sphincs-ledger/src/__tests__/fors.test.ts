// FORS test suite (vitest) — covers the demo-owned pedagogical FORS model in
// src/crypto/fors.ts:
//   • base_2b digest→index bit-slicing (FIPS 205 Algorithm 4), incl. its guard
//   • MGF1-SHA-256 counter-mode expansion (RFC 8017)
//   • computeForsIndices: k indices in range, deterministic, randomizer-sensitive
//   • buildFors: real selected leaf sits at the reduced index and feeds the root
//   • the illustrative few-time-security margin (monotone, bounded, edge cases)

import { describe, it, expect } from 'vitest';
import {
  base2b,
  mgf1Sha256,
  computeForsIndices,
  buildFors,
  illustrativeForgeryProbability,
} from '../crypto/fors.js';
import { sha256, concatBytes } from '../crypto/hash.js';

describe('base_2b (FIPS 205 Algorithm 4)', () => {
  it('b=4 splits into nibbles, MSB first', () => {
    expect(base2b(new Uint8Array([0x12, 0x34]), 4, 4)).toEqual([1, 2, 3, 4]);
  });

  it('b=8 returns the bytes themselves', () => {
    expect(base2b(new Uint8Array([0xde, 0xad, 0xbe, 0xef]), 8, 4)).toEqual([
      0xde, 0xad, 0xbe, 0xef,
    ]);
  });

  it('b=12 crosses byte boundaries: 0x12 0x34 0x56 → [0x123, 0x456]', () => {
    expect(base2b(new Uint8Array([0x12, 0x34, 0x56]), 12, 2)).toEqual([0x123, 0x456]);
  });

  // Real FORS widths from FIPS 205 Table 2 — verify count and range, no precision loss.
  it.each([
    { name: '128s', a: 12, k: 14, t: 4096 },
    { name: '256s', a: 14, k: 22, t: 16384 },
    { name: '256f', a: 9, k: 35, t: 512 },
    { name: '128f', a: 6, k: 33, t: 64 },
  ])('$name (a=$a,k=$k) → $k indices in [0,$t)', ({ a, k, t }) => {
    const md = new Uint8Array(Math.ceil((k * a) / 8)).map((_, i) => (i * 37 + 11) & 0xff);
    const idx = base2b(md, a, k);
    expect(idx).toHaveLength(k);
    expect(idx.every((v) => v >= 0 && v < t)).toBe(true);
  });

  it('throws (does not silently zero-pad) when given too few bytes', () => {
    // 4 outputs × 12 bits = 48 bits = 6 bytes required; give it 2.
    expect(() => base2b(new Uint8Array([0x12, 0x34]), 12, 4)).toThrow(/need/);
  });
});

describe('MGF1-SHA-256 (RFC 8017)', () => {
  it('produces exactly the requested length across multiple SHA-256 blocks', async () => {
    const seed = new Uint8Array([1, 2, 3, 4]);
    for (const len of [1, 32, 33, 39, 64, 100]) {
      const out = await mgf1Sha256(seed, len);
      expect(out).toHaveLength(len);
    }
  });

  it('is a prefix-stable stream: a shorter request is a prefix of a longer one', async () => {
    const seed = new Uint8Array([9, 9, 9]);
    const short = await mgf1Sha256(seed, 20);
    const long = await mgf1Sha256(seed, 80);
    expect(Array.from(long.subarray(0, 20))).toEqual(Array.from(short));
  });

  it('matches the reference: first block = SHA-256(seed || 0x00000000)', async () => {
    const seed = new Uint8Array([0xaa, 0xbb]);
    const expected = await sha256(concatBytes(seed, new Uint8Array([0, 0, 0, 0])));
    const out = await mgf1Sha256(seed, 32);
    expect(Array.from(out)).toEqual(Array.from(expected));
  });
});

describe('computeForsIndices', () => {
  it('yields k indices each in [0, 2^a) for a real (k,a)', async () => {
    const k = 14;
    const a = 12;
    const { indices } = await computeForsIndices(
      new TextEncoder().encode('ledger entry'),
      new Uint8Array(16).fill(7),
      k,
      a,
    );
    expect(indices).toHaveLength(k);
    expect(indices.every((v) => v >= 0 && v < 2 ** a)).toBe(true);
  });

  it('is deterministic for fixed (message, randomizer)', async () => {
    const msg = new TextEncoder().encode('same');
    const r = new Uint8Array(16).fill(3);
    const a = await computeForsIndices(msg, r, 10, 9);
    const b = await computeForsIndices(msg, r, 10, 9);
    expect(a.indices).toEqual(b.indices);
  });

  it('changing the randomizer changes the index vector (H_msg is randomized)', async () => {
    const msg = new TextEncoder().encode('same');
    const a = await computeForsIndices(msg, new Uint8Array(16).fill(1), 22, 14);
    const b = await computeForsIndices(msg, new Uint8Array(16).fill(2), 22, 14);
    expect(a.indices).not.toEqual(b.indices);
  });
});

describe('buildFors (reduced pedagogical tree)', () => {
  it('places the real selected leaf at reducedLeafIndex and derives one root per tree', async () => {
    const k = 6;
    const a = 12;
    const digest = await computeForsIndices(
      new TextEncoder().encode('m'),
      new Uint8Array(16).fill(5),
      k,
      a,
    );
    const skSeed = new Uint8Array(32).fill(42);
    const result = await buildFors(digest, skSeed, a, 4);

    expect(result.trees).toHaveLength(k);
    expect(result.reducedHeight).toBe(4); // min(a=12, maxDrawHeight=4)

    for (const tree of result.trees) {
      // The REAL index is reported and maps into the reduced tree correctly.
      expect(tree.leafIndex).toBe(digest.indices[tree.treeIndex]);
      expect(tree.reducedLeafIndex).toBe(tree.leafIndex % 2 ** 4);
      // Leaf = F(secret) = SHA-256(secret) in this model.
      const expectedLeaf = await sha256(tree.secret);
      expect(Array.from(tree.leaf)).toEqual(Array.from(expectedLeaf));
      expect(tree.root).toHaveLength(32);
    }

    // FORS public key = SHA-256(root_0 || … || root_{k-1}).
    const expectedPk = await sha256(concatBytes(...result.trees.map((t) => t.root)));
    expect(Array.from(result.publicKey)).toEqual(Array.from(expectedPk));
  });

  it('is deterministic in skSeed and sensitive to it', async () => {
    const digest = await computeForsIndices(
      new TextEncoder().encode('m'),
      new Uint8Array(16).fill(5),
      4,
      9,
    );
    const a = await buildFors(digest, new Uint8Array(32).fill(1), 9, 4);
    const b = await buildFors(digest, new Uint8Array(32).fill(1), 9, 4);
    const c = await buildFors(digest, new Uint8Array(32).fill(2), 9, 4);
    expect(Array.from(a.publicKey)).toEqual(Array.from(b.publicKey));
    expect(Array.from(a.publicKey)).not.toEqual(Array.from(c.publicKey));
  });
});

describe('illustrative few-time-security margin', () => {
  it('is bounded in [0,1] and monotone increasing in the number of signatures', () => {
    const p1 = illustrativeForgeryProbability(10, 4096, 14);
    const p2 = illustrativeForgeryProbability(100_000, 4096, 14);
    expect(p1).toBeGreaterThanOrEqual(0);
    expect(p2).toBeLessThanOrEqual(1);
    expect(p2).toBeGreaterThan(p1);
  });

  it('is ~0 with no signatures and grows toward 1 as reuse explodes', () => {
    expect(illustrativeForgeryProbability(0, 4096, 14)).toBe(0);
    expect(illustrativeForgeryProbability(1e9, 64, 33)).toBeGreaterThan(0.99);
  });
});
