// WOTS+ (Winternitz One-Time Signature) — Simplified Demonstration
// This is an ILLUSTRATIVE implementation showing the hash-chain concept,
// NOT a production WOTS+ implementation.
// Reference: NIST FIPS 205, Section 4 — WOTS+ one-time signatures
// https://csrc.nist.gov/pubs/fips/205/final

import { sha256, sha256Hex } from './hash';

// Winternitz parameter w=16 for illustration
export const W = 16;

export interface WotsChain {
  privateKey: Uint8Array;     // random 32-byte seed
  publicKey: Uint8Array;      // SHA-256^W(privateKey)
  chainLength: number;        // W iterations
  chainValues: Uint8Array[];  // all intermediate values for visualization
  revealedSteps: Set<number>; // every step ever revealed on THIS chain (accumulates across signs)
}

export interface WotsKeyPair {
  chains: WotsChain[];
  signedMessages: string[];   // track messages signed with this key
}

export async function buildChain(seed: Uint8Array, steps: number): Promise<Uint8Array[]> {
  const chain: Uint8Array[] = [seed];
  let current = seed;
  for (let i = 0; i < steps; i++) {
    current = await sha256(current);
    chain.push(current);
  }
  return chain;
}

export async function generateWotsKeyPair(numChains: number = 4): Promise<WotsKeyPair> {
  const chains: WotsChain[] = [];
  for (let i = 0; i < numChains; i++) {
    const privateKey = crypto.getRandomValues(new Uint8Array(32));
    const chainValues = await buildChain(privateKey, W);
    chains.push({
      privateKey,
      publicKey: chainValues[chainValues.length - 1],
      chainLength: W,
      chainValues,
      revealedSteps: new Set<number>(),
    });
  }
  return { chains, signedMessages: [] };
}

export interface WotsSignatureResult {
  chainIndex: number;
  revealedStep: number;
  revealedValue: Uint8Array;
  stepsToPublicKey: number;
}

export function wotsSign(
  keyPair: WotsKeyPair,
  messageNibble: number,
  chainIndex: number
): WotsSignatureResult {
  // In real WOTS+, each nibble of the message hash determines how far
  // up the chain to reveal. For illustration, we use the nibble directly.
  const step = messageNibble % W;
  const chain = keyPair.chains[chainIndex];
  return {
    chainIndex,
    revealedStep: step,
    revealedValue: chain.chainValues[step],
    stepsToPublicKey: W - step,
  };
}

export async function wotsVerify(
  publicKey: Uint8Array,
  sigResult: WotsSignatureResult
): Promise<boolean> {
  // Hash forward from the revealed value to see if we reach the public key
  let current = sigResult.revealedValue;
  for (let i = 0; i < sigResult.stepsToPublicKey; i++) {
    current = await sha256(current);
  }
  // Compare
  if (current.length !== publicKey.length) return false;
  for (let i = 0; i < current.length; i++) {
    if (current[i] !== publicKey[i]) return false;
  }
  return true;
}

// Honest reuse detection (PIECE 1).
// Exposure is tracked PER CHAIN from the actual revealed steps, not from a
// synthetic whole-key flag. A chain becomes dangerous once two *different* steps
// have been revealed on it: an attacker holding the lower revealed value can hash
// forward to reconstruct every higher value on that chain (see wotsForge).
export function checkReuseWarning(
  keyPair: WotsKeyPair
): { isReuse: boolean; warning: string; exposedChains: number[] } {
  // A chain is flagged once it has been genuinely REUSED: two or more distinct
  // steps revealed on it. (A single reveal already enables forging higher steps,
  // but we reserve the "reuse" alarm for the second distinct signature, which is
  // the moment a one-time key is actually misused.)
  const exposedChains = keyPair.chains
    .map((c, i) => ({ i, c }))
    .filter(({ c }) => c.revealedSteps.size >= 2)
    .map(({ i }) => i);

  if (exposedChains.length === 0) {
    return { isReuse: false, warning: '', exposedChains: [] };
  }

  return {
    isReuse: true,
    warning:
      `WOTS+ KEY REUSE DETECTED on chain(s) ${exposedChains.join(', ')}. ` +
      `Each signature reveals one point on a chain. Once two different steps are ` +
      `revealed on the same chain, an attacker who holds the LOWER revealed value ` +
      `can hash it forward (SHA-256) to reconstruct every higher value on that chain — ` +
      `forging a valid signature for any step above the lowest reveal. ` +
      `Use the "Forge" control below to do exactly that against the public key. ` +
      `SPHINCS+ avoids this by using each WOTS+ key exactly once via its hypertree.`,
    exposedChains,
  };
}

export interface WotsForgeResult {
  chainIndex: number;
  targetStep: number;
  basisStep: number;          // lowest legitimately-revealed step the attacker exploited
  forgedValue: Uint8Array;    // reconstructed chainValues[targetStep]
  stepsToPublicKey: number;
  matchesReal: boolean;       // forgedValue === the honest signer's chainValues[targetStep]
}

// Catastrophic-reuse forgery (PIECE 1).
// Given a chain on which at least one step `basisStep` has been revealed, an
// attacker forges the signature for any `targetStep >= basisStep` by hashing the
// lower revealed value forward (targetStep - basisStep) times. The result equals
// the honest signer's chainValues[targetStep] EXACTLY, so it verifies against the
// public key. This is the real failure that the old code only described in text.
export async function wotsForge(
  chain: WotsChain,
  chainIndex: number,
  targetStep: number
): Promise<WotsForgeResult | { error: string }> {
  if (chain.revealedSteps.size === 0) {
    return { error: 'No chain points revealed yet — nothing to forge from.' };
  }
  if (!Number.isInteger(targetStep) || targetStep < 0 || targetStep > chain.chainLength) {
    return { error: `Forge step must be an integer in [0, ${chain.chainLength}].` };
  }
  const basisStep = Math.min(...chain.revealedSteps);
  if (targetStep < basisStep) {
    return {
      error:
        `Cannot forge step ${targetStep}: it is BELOW the lowest revealed step ` +
        `(${basisStep}). Hash chains are one-way — an attacker can only go ` +
        `forward (up), never backward. This is exactly why revealing a LOW value ` +
        `is the dangerous one.`,
    };
  }
  // Attacker only ever touches the revealed value, never the private seed.
  let forged = chain.chainValues[basisStep];
  for (let i = 0; i < targetStep - basisStep; i++) {
    forged = await sha256(forged);
  }
  const real = chain.chainValues[targetStep];
  let matchesReal = forged.length === real.length;
  for (let i = 0; matchesReal && i < forged.length; i++) {
    if (forged[i] !== real[i]) matchesReal = false;
  }
  return {
    chainIndex,
    targetStep,
    basisStep,
    forgedValue: forged,
    stepsToPublicKey: chain.chainLength - targetStep,
    matchesReal,
  };
}

export async function getChainHexValues(chain: WotsChain): Promise<string[]> {
  return Promise.all(chain.chainValues.map((v) => sha256Hex(v).then(() =>
    Array.from(v).map((b) => b.toString(16).padStart(2, '0')).join('')
  )));
}
