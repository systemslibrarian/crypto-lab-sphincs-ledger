// WOTS+ illustrative-chain test suite (vitest).
//
// This guards the honesty claim the README makes for the WOTS+ tab: that the
// "Forge & Verify" control is a GENUINE hash-forward forgery — reconstructing a
// higher chain value from the lowest revealed point (no private seed) that
// verifies against the real public key — and that reuse detection is real.

import { describe, it, expect } from 'vitest';
import {
  buildChain,
  generateWotsKeyPair,
  wotsSign,
  wotsVerify,
  checkReuseWarning,
  wotsForge,
  W,
} from '../crypto/wots.js';
import { sha256 } from '../crypto/hash.js';

describe('WOTS+ hash chain', () => {
  it('buildChain iterates SHA-256 exactly `steps` times', async () => {
    const seed = new Uint8Array(32).fill(1);
    const chain = await buildChain(seed, W);
    expect(chain).toHaveLength(W + 1);
    expect(Array.from(chain[0])).toEqual(Array.from(seed));
    // Each element is SHA-256 of the previous one.
    for (let i = 1; i < chain.length; i++) {
      const expected = await sha256(chain[i - 1]);
      expect(Array.from(chain[i])).toEqual(Array.from(expected));
    }
  });

  it('an honest signature verifies against the chain public key', async () => {
    const kp = await generateWotsKeyPair(1);
    const sig = wotsSign(kp, /* nibble */ 5, /* chainIndex */ 0);
    expect(await wotsVerify(kp.chains[0].publicKey, sig)).toBe(true);
  });
});

describe('reuse detection', () => {
  it('does not warn before a chain is reused', async () => {
    const kp = await generateWotsKeyPair(2);
    // Reveal one step on chain 0.
    const s = wotsSign(kp, 3, 0);
    kp.chains[0].revealedSteps.add(s.revealedStep);
    expect(checkReuseWarning(kp).isReuse).toBe(false);
  });

  it('warns once two DISTINCT steps are revealed on the same chain', async () => {
    const kp = await generateWotsKeyPair(2);
    kp.chains[1].revealedSteps.add(3);
    kp.chains[1].revealedSteps.add(9);
    const w = checkReuseWarning(kp);
    expect(w.isReuse).toBe(true);
    expect(w.exposedChains).toContain(1);
    expect(w.exposedChains).not.toContain(0);
  });

  it('does not warn if the same step is revealed twice (no new information)', async () => {
    const kp = await generateWotsKeyPair(1);
    kp.chains[0].revealedSteps.add(4);
    kp.chains[0].revealedSteps.add(4); // Set → still size 1
    expect(checkReuseWarning(kp).isReuse).toBe(false);
  });
});

describe('reuse forgery (the core honesty claim)', () => {
  it('forges a higher chain value from the lowest reveal and it verifies', async () => {
    const kp = await generateWotsKeyPair(1);
    const chain = kp.chains[0];
    // Attacker legitimately observed step 2 (a LOW reveal).
    chain.revealedSteps.add(2);

    const targetStep = 7;
    const forge = await wotsForge(chain, 0, targetStep);
    expect('error' in forge).toBe(false);
    if ('error' in forge) return;

    // The forged value equals the honest signer's real chainValues[targetStep] …
    expect(forge.matchesReal).toBe(true);
    expect(Array.from(forge.forgedValue)).toEqual(Array.from(chain.chainValues[targetStep]));

    // … so a signature built from it verifies against the true public key.
    const forgedSig = {
      chainIndex: 0,
      revealedStep: targetStep,
      revealedValue: forge.forgedValue,
      stepsToPublicKey: forge.stepsToPublicKey,
    };
    expect(await wotsVerify(chain.publicKey, forgedSig)).toBe(true);
  });

  it('cannot forge BELOW the lowest reveal — hash chains are one-way', async () => {
    const kp = await generateWotsKeyPair(1);
    const chain = kp.chains[0];
    chain.revealedSteps.add(5);
    const forge = await wotsForge(chain, 0, 3); // below the basis
    expect('error' in forge).toBe(true);
  });

  it('refuses to forge from a chain with nothing revealed', async () => {
    const kp = await generateWotsKeyPair(1);
    const forge = await wotsForge(kp.chains[0], 0, 4);
    expect('error' in forge).toBe(true);
  });

  it('rejects out-of-range target steps', async () => {
    const kp = await generateWotsKeyPair(1);
    kp.chains[0].revealedSteps.add(1);
    expect('error' in (await wotsForge(kp.chains[0], 0, -1))).toBe(true);
    expect('error' in (await wotsForge(kp.chains[0], 0, W + 1))).toBe(true);
  });
});
