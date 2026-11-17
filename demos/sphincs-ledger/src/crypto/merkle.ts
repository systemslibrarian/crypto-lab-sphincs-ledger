// Merkle tree construction using real SHA-256 via Web Crypto API
// Used to demonstrate the hash-tree structure underlying SPHINCS+ / SLH-DSA
// Reference: NIST FIPS 205, Section 6.1 — Generating a Merkle Hash Tree,
// in Section 6 "eXtended Merkle Signature Scheme (XMSS)"

import { sha256Hex, concatBytes, hexToBytes } from './hash';

export interface MerkleNode {
  hash: string;       // hex SHA-256
  left?: MerkleNode;
  right?: MerkleNode;
  isLeaf: boolean;
  index: number;
}

export async function buildMerkleTree(leaves: Uint8Array[]): Promise<MerkleNode> {
  if (leaves.length === 0) {
    throw new Error('Cannot build Merkle tree with zero leaves');
  }
  // Pad to next power of 2
  let paddedLeaves = [...leaves];
  while (paddedLeaves.length & (paddedLeaves.length - 1)) {
    paddedLeaves.push(new Uint8Array(32)); // zero-pad
  }

  // Build leaf nodes
  let nodes: MerkleNode[] = await Promise.all(
    paddedLeaves.map(async (leaf, i) => ({
      hash: await sha256Hex(leaf),
      isLeaf: true,
      index: i,
    }))
  );

  let indexCounter = nodes.length;

  // Build tree bottom-up
  while (nodes.length > 1) {
    const parentNodes: MerkleNode[] = [];
    for (let i = 0; i < nodes.length; i += 2) {
      const left = nodes[i];
      const right = nodes[i + 1];
      const combined = concatBytes(hexToBytes(left.hash), hexToBytes(right.hash));
      const hash = await sha256Hex(combined);
      parentNodes.push({
        hash,
        left,
        right,
        isLeaf: false,
        index: indexCounter++,
      });
    }
    nodes = parentNodes;
  }

  return nodes[0];
}

export async function getMerkleRoot(leaves: Uint8Array[]): Promise<string> {
  const tree = await buildMerkleTree(leaves);
  return tree.hash;
}

export async function getAuthPath(leaves: Uint8Array[], leafIndex: number): Promise<string[]> {
  if (leaves.length === 0) throw new Error('No leaves');

  // Pad to next power of 2
  let paddedLeaves = [...leaves];
  while (paddedLeaves.length & (paddedLeaves.length - 1)) {
    paddedLeaves.push(new Uint8Array(32));
  }

  // Build layers
  let currentLayer: string[] = await Promise.all(
    paddedLeaves.map((leaf) => sha256Hex(leaf))
  );

  const authPath: string[] = [];
  let idx = leafIndex;

  while (currentLayer.length > 1) {
    // Sibling index
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    authPath.push(currentLayer[siblingIdx]);

    // Build next layer
    const nextLayer: string[] = [];
    for (let i = 0; i < currentLayer.length; i += 2) {
      const combined = concatBytes(
        hexToBytes(currentLayer[i]),
        hexToBytes(currentLayer[i + 1])
      );
      nextLayer.push(await sha256Hex(combined));
    }
    currentLayer = nextLayer;
    idx = Math.floor(idx / 2);
  }

  return authPath;
}

export async function verifyAuthPath(
  leafHash: string,
  leafIndex: number,
  authPath: string[],
  expectedRoot: string
): Promise<{ valid: boolean; intermediates: string[] }> {
  let currentHash = leafHash;
  let idx = leafIndex;
  const intermediates: string[] = [currentHash];

  for (const sibling of authPath) {
    const left = idx % 2 === 0 ? currentHash : sibling;
    const right = idx % 2 === 0 ? sibling : currentHash;
    const combined = concatBytes(hexToBytes(left), hexToBytes(right));
    currentHash = await sha256Hex(combined);
    intermediates.push(currentHash);
    idx = Math.floor(idx / 2);
  }

  return { valid: currentHash === expectedRoot, intermediates };
}
