// Merkle tree test suite (vitest) — guards the demo-owned SHA-256 Merkle logic
// used by the "Merkle tree mechanics" tab: root construction, authentication-path
// extraction, and path verification (round-trip + forgery rejection).

import { describe, it, expect } from 'vitest';
import {
  buildMerkleTree,
  getMerkleRoot,
  getAuthPath,
  verifyAuthPath,
} from '../crypto/merkle.js';
import { sha256Hex } from '../crypto/hash.js';

function leaves(n: number): Uint8Array[] {
  return Array.from({ length: n }, (_, i) => new Uint8Array(32).fill(i + 1));
}

describe('Merkle construction', () => {
  it('rejects an empty leaf set', async () => {
    await expect(buildMerkleTree([])).rejects.toThrow();
  });

  it('a single leaf pads to a valid tree whose root is the hash of that leaf', async () => {
    const only = new Uint8Array(32).fill(9);
    const root = await getMerkleRoot([only]);
    expect(root).toBe(await sha256Hex(only));
  });

  it('is deterministic and diverges when a leaf changes', async () => {
    const a = await getMerkleRoot(leaves(4));
    const b = await getMerkleRoot(leaves(4));
    expect(a).toBe(b);

    const mutated = leaves(4);
    mutated[2] = new Uint8Array(32).fill(200);
    expect(await getMerkleRoot(mutated)).not.toBe(a);
  });
});

describe('authentication path', () => {
  it('every leaf verifies against the root via its auth path (round-trip)', async () => {
    const ls = leaves(8);
    const root = await getMerkleRoot(ls);
    for (let i = 0; i < ls.length; i++) {
      const path = await getAuthPath(ls, i);
      const leafHash = await sha256Hex(ls[i]);
      const { valid, intermediates } = await verifyAuthPath(leafHash, i, path, root);
      expect(valid).toBe(true);
      // The recomputation's final value equals the published root.
      expect(intermediates[intermediates.length - 1]).toBe(root);
    }
  });

  it('rejects a leaf presented at the wrong index (forged position)', async () => {
    const ls = leaves(8);
    const root = await getMerkleRoot(ls);
    const path = await getAuthPath(ls, 3);
    const leafHash = await sha256Hex(ls[3]);
    const { valid } = await verifyAuthPath(leafHash, 4 /* wrong */, path, root);
    expect(valid).toBe(false);
  });

  it('rejects a tampered leaf value', async () => {
    const ls = leaves(8);
    const root = await getMerkleRoot(ls);
    const path = await getAuthPath(ls, 2);
    const forgedLeafHash = await sha256Hex(new Uint8Array(32).fill(0xff));
    const { valid } = await verifyAuthPath(forgedLeafHash, 2, path, root);
    expect(valid).toBe(false);
  });

  it('rejects a tampered authentication path', async () => {
    const ls = leaves(8);
    const root = await getMerkleRoot(ls);
    const path = await getAuthPath(ls, 5);
    const leafHash = await sha256Hex(ls[5]);
    const badPath = [...path];
    badPath[0] = await sha256Hex(new Uint8Array(32).fill(0xaa)); // wrong sibling
    const { valid } = await verifyAuthPath(leafHash, 5, badPath, root);
    expect(valid).toBe(false);
  });
});
