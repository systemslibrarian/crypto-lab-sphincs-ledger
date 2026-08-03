import { describe, it, expect } from 'vitest';
import {
  WP_W,
  WP_LEN,
  WP_LEN1,
  WP_LEN2,
  WP_MAX_STEP,
  chain,
  messageDigits,
  checksumDigits,
  allDigits,
  generateWotsPlusKeyPair,
  wotsPlusSign,
  wotsPlusVerify,
  observeSignatures,
  forgeAttempt,
  searchForgeableMessage,
} from '../crypto/wotsplus.js';

describe('WOTS+ parameters', () => {
  it('derives len2 by the FIPS 205 formula and totals len', () => {
    // len2 = floor(log2(len1 * (w-1)) / log2 w) + 1
    expect(WP_LEN2).toBe(Math.floor(Math.log2(WP_LEN1 * (WP_W - 1)) / Math.log2(WP_W)) + 1);
    expect(WP_LEN).toBe(WP_LEN1 + WP_LEN2);
    expect(WP_MAX_STEP).toBe(WP_W - 1);
  });

  it('sizes the checksum chains wide enough for the largest possible checksum', () => {
    // The all-zero message digest maximises the checksum at len1 * (w-1).
    const maxCsum = WP_LEN1 * (WP_W - 1);
    expect(maxCsum).toBeLessThan(WP_W ** WP_LEN2);
    const digits = checksumDigits(new Array(WP_LEN1).fill(0));
    expect(digits).toHaveLength(WP_LEN2);
    // Reading the digits back must reproduce the checksum exactly.
    expect(digits.reduce((acc, d) => acc * WP_W + d, 0)).toBe(maxCsum);
  });
});

describe('message and checksum digits', () => {
  it('produces len1 digits in range, deterministic per message', async () => {
    const a = await messageDigits('invoice 001');
    const b = await messageDigits('invoice 001');
    expect(a).toEqual(b);
    expect(a).toHaveLength(WP_LEN1);
    for (const d of a) {
      expect(Number.isInteger(d)).toBe(true);
      expect(d).toBeGreaterThanOrEqual(0);
      expect(d).toBeLessThan(WP_W);
    }
    expect(await messageDigits('invoice 002')).not.toEqual(a);
  });

  it('matches SHA-256 nibbles computed independently', async () => {
    const msg = 'pay Bob 5 coins';
    const digest = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg)),
    );
    const expected: number[] = [];
    for (let i = 0; i < WP_LEN1; i++) {
      expected.push(i % 2 === 0 ? digest[i >> 1] >> 4 : digest[i >> 1] & 0x0f);
    }
    expect(await messageDigits(msg)).toEqual(expected);
  });

  it('encodes sum(w-1-d) in base w, big-endian', () => {
    const msg = [1, 2, 3, 4, 5, 6];
    const csum = msg.reduce((acc, d) => acc + (WP_W - 1 - d), 0);
    const digits = checksumDigits(msg);
    expect(digits.reduce((acc, d) => acc * WP_W + d, 0)).toBe(csum);
    for (const d of digits) expect(d).toBeLessThan(WP_W);
  });

  it('moves the checksum DOWN whenever any message digit moves UP', () => {
    const base = [8, 8, 8, 8, 8, 8];
    const baseCsum = checksumDigits(base).reduce((a, d) => a * WP_W + d, 0);
    for (let i = 0; i < WP_LEN1; i++) {
      const raised = base.slice();
      raised[i] += 1;
      const csum = checksumDigits(raised).reduce((a, d) => a * WP_W + d, 0);
      expect(csum).toBeLessThan(baseCsum);
    }
  });

  it('concatenates message digits then checksum digits', async () => {
    const msg = await messageDigits('ledger entry');
    expect(await allDigits('ledger entry')).toEqual(msg.concat(checksumDigits(msg)));
  });
});

describe('sign and verify', () => {
  it('verifies an honest signature against the real public key', async () => {
    const kp = await generateWotsPlusKeyPair();
    const sig = await wotsPlusSign(kp, 'transfer 10 to Alice');
    expect(sig.sig).toHaveLength(WP_LEN);
    expect(await wotsPlusVerify(kp.pkSeed, kp.publicKey, sig.message, sig.sig)).toBe(true);
  });

  it('rejects the signature when the message is changed', async () => {
    const kp = await generateWotsPlusKeyPair();
    const sig = await wotsPlusSign(kp, 'transfer 10 to Alice');
    expect(await wotsPlusVerify(kp.pkSeed, kp.publicKey, 'transfer 90 to Mallory', sig.sig)).toBe(
      false,
    );
  });

  it('rejects a signature with any single element tampered', async () => {
    const kp = await generateWotsPlusKeyPair();
    const sig = await wotsPlusSign(kp, 'transfer 10 to Alice');
    for (let i = 0; i < WP_LEN; i++) {
      const mangled = sig.sig.map((v) => v.slice());
      mangled[i][0] ^= 0xff;
      expect(await wotsPlusVerify(kp.pkSeed, kp.publicKey, sig.message, mangled)).toBe(false);
    }
  });

  it('rejects a signature of the wrong length', async () => {
    const kp = await generateWotsPlusKeyPair();
    const sig = await wotsPlusSign(kp, 'transfer 10 to Alice');
    expect(await wotsPlusVerify(kp.pkSeed, kp.publicKey, sig.message, sig.sig.slice(1))).toBe(false);
    expect(
      await wotsPlusVerify(kp.pkSeed, kp.publicKey, sig.message, sig.sig.concat([sig.sig[0]])),
    ).toBe(false);
  });

  it('rejects a signature made under a different key', async () => {
    const a = await generateWotsPlusKeyPair();
    const b = await generateWotsPlusKeyPair();
    const sig = await wotsPlusSign(a, 'transfer 10 to Alice');
    expect(await wotsPlusVerify(b.pkSeed, b.publicKey, sig.message, sig.sig)).toBe(false);
  });

  it('walks each chain from the signed digit to the keygen endpoint', async () => {
    const kp = await generateWotsPlusKeyPair();
    const sig = await wotsPlusSign(kp, 'chain walk');
    for (let i = 0; i < WP_LEN; i++) {
      const d = sig.digits[i];
      expect(sig.sig[i]).toEqual(kp.chainValues[i][d]);
      const end = await chain(kp.pkSeed, i, d, WP_MAX_STEP - d, sig.sig[i]);
      expect(end).toEqual(kp.chainValues[i][WP_MAX_STEP]);
    }
  });
});

describe('the checksum is what stops a one-signature forgery', () => {
  it('blocks every candidate reachable within a real search budget', async () => {
    // With ONE signature observed the attacker holds exactly that message's
    // digit vector. Raising any message digit lowers the checksum, so at least
    // one checksum chain drops below what the attacker can reach.
    const kp = await generateWotsPlusKeyPair();
    const sig = await wotsPlusSign(kp, 'invoice 001: pay 10 to Alice');
    const knowledge = observeSignatures([sig]);
    const result = await searchForgeableMessage(
      kp.pkSeed,
      knowledge,
      'invoice 001: pay 10000 to Mallory',
      4000,
    );
    // A hit here would be a 24-bit digest collision, not a checksum break, and
    // the search must say so rather than claim the checksum fell.
    if (result.found) {
      expect(result.attempt!.collidesWithObserved).toBeGreaterThanOrEqual(0);
    } else {
      expect(result.tried).toBe(4000);
      expect(result.bestBlockCount).toBeGreaterThan(0);
      expect(result.bestCandidate).not.toBe('');
    }
  });

  it('proves the theorem: forgeable from one signature IMPLIES a digest collision', async () => {
    // Not a probabilistic claim. If every message digit is >= the signed one,
    // the checksum can only fall; if every checksum digit is also >=, the
    // checksum can only rise. Both hold only when the digests are identical.
    const kp = await generateWotsPlusKeyPair();
    const sig = await wotsPlusSign(kp, 'invoice 001');
    const knowledge = observeSignatures([sig]);
    for (let n = 0; n < 3000; n++) {
      const attempt = await forgeAttempt(kp.pkSeed, knowledge, `candidate ${n}`);
      if (attempt.forgeable) {
        expect(attempt.collidesWithObserved).toBeGreaterThanOrEqual(0);
        expect(attempt.digits.slice(0, WP_LEN1)).toEqual(
          knowledge.observedMsgDigits[attempt.collidesWithObserved],
        );
      }
    }
  });

  it('reports the blocked chains, and names the checksum chains among them', async () => {
    const kp = await generateWotsPlusKeyPair();
    const sig = await wotsPlusSign(kp, 'invoice 001');
    const knowledge = observeSignatures([sig]);
    let sawChecksumBlock = false;
    let sawAnyBlock = false;
    for (let n = 0; n < 200; n++) {
      const attempt = await forgeAttempt(kp.pkSeed, knowledge, `candidate ${n}`);
      for (const b of attempt.blocks) {
        sawAnyBlock = true;
        expect(b.needed).toBeLessThan(b.lowest);
        expect(b.isChecksumChain).toBe(b.chainIndex >= WP_LEN1);
        if (b.isChecksumChain) sawChecksumBlock = true;
      }
    }
    expect(sawAnyBlock).toBe(true);
    expect(sawChecksumBlock).toBe(true);
  });

  it('counts the candidates the checksum personally stopped', async () => {
    const kp = await generateWotsPlusKeyPair();
    const sig = await wotsPlusSign(kp, 'invoice 001');
    const knowledge = observeSignatures([sig]);
    const result = await searchForgeableMessage(kp.pkSeed, knowledge, 'steal it', 8000);
    expect(result.found).toBe(false);

    // Plenty of candidates clear all six message chains -- roughly 2% of them.
    // If none did, the page would be showing a wall, not the checksum at work.
    expect(result.msgChainsCleared).toBeGreaterThan(0);
    expect(result.msgChainsCleared).toBeLessThanOrEqual(result.tried);

    // On a failed search, EVERY candidate that cleared the message chains must
    // have been stopped by a checksum chain -- had one not been, it would have
    // been forgeable and the search would have returned found.
    expect(result.blockedOnChecksum).toBe(result.msgChainsCleared);
  });

  it('refuses a target whose digits it cannot reach, and returns no signature', async () => {
    const kp = await generateWotsPlusKeyPair();
    // Sign the all-highest reachable message we can find, so most targets sit
    // below it on at least one chain.
    const sig = await wotsPlusSign(kp, 'invoice 001');
    const knowledge = observeSignatures([sig]);
    let refused = 0;
    for (let n = 0; n < 50; n++) {
      const attempt = await forgeAttempt(kp.pkSeed, knowledge, `target ${n}`);
      if (!attempt.forgeable) {
        refused++;
        expect(attempt.sig).toBeUndefined();
        expect(attempt.blocks.length).toBeGreaterThan(0);
      }
    }
    expect(refused).toBeGreaterThan(0);
  });
});

describe('two signatures under one key break it for real', () => {
  it('finds a forgeable message and the REAL verifier accepts the forgery', async () => {
    const kp = await generateWotsPlusKeyPair();
    const s1 = await wotsPlusSign(kp, 'invoice 001: pay 10 to Alice');
    const s2 = await wotsPlusSign(kp, 'invoice 002: pay 25 to Bob');
    const knowledge = observeSignatures([s1, s2]);
    expect(knowledge.observed).toBe(2);

    const result = await searchForgeableMessage(
      kp.pkSeed,
      knowledge,
      'pay 1000000 to Mallory',
      60000,
    );
    expect(result.found).toBe(true);
    const attempt = result.attempt!;
    expect(attempt.forgeable).toBe(true);
    expect(attempt.blocks).toEqual([]);

    // The forged message must be genuinely NEW, not a replay of either signature.
    expect(attempt.target).not.toBe(s1.message);
    expect(attempt.target).not.toBe(s2.message);
    // ...and it must not be riding on a digest collision.
    expect(attempt.collidesWithObserved).toBe(-1);

    // The verdict comes from the same verifier that accepts honest signatures.
    expect(await wotsPlusVerify(kp.pkSeed, kp.publicKey, attempt.target, attempt.sig!)).toBe(true);
  });

  it('builds the forgery only from observed values, never from the private chains', async () => {
    const kp = await generateWotsPlusKeyPair();
    const s1 = await wotsPlusSign(kp, 'invoice 001');
    const s2 = await wotsPlusSign(kp, 'invoice 002');
    const knowledge = observeSignatures([s1, s2]);

    // Every value the attacker starts from was published in a signature.
    for (let i = 0; i < WP_LEN; i++) {
      const fromS1 = knowledge.lowestDigit[i] === s1.digits[i];
      const fromS2 = knowledge.lowestDigit[i] === s2.digits[i];
      expect(fromS1 || fromS2).toBe(true);
      expect(knowledge.lowestDigit[i]).toBe(Math.min(s1.digits[i], s2.digits[i]));
      expect(knowledge.value[i]).toEqual(kp.chainValues[i][knowledge.lowestDigit[i]]);
    }

    const result = await searchForgeableMessage(kp.pkSeed, knowledge, 'steal the vault', 60000);
    expect(result.found).toBe(true);
    // Each forged element equals the honest signer's value at the same digit --
    // reached by hashing forward from a revealed one, never by inverting.
    const attempt = result.attempt!;
    for (let i = 0; i < WP_LEN; i++) {
      expect(attempt.digits[i]).toBeGreaterThanOrEqual(knowledge.lowestDigit[i]);
      expect(attempt.sig![i]).toEqual(kp.chainValues[i][attempt.digits[i]]);
    }
  });

  it('still cannot reach a digit below every observed one', async () => {
    const kp = await generateWotsPlusKeyPair();
    const s1 = await wotsPlusSign(kp, 'invoice 001');
    const s2 = await wotsPlusSign(kp, 'invoice 002');
    const knowledge = observeSignatures([s1, s2]);
    let refusals = 0;
    for (let n = 0; n < 400 && refusals === 0; n++) {
      const attempt = await forgeAttempt(kp.pkSeed, knowledge, `unreachable ${n}`);
      if (!attempt.forgeable) {
        refusals++;
        for (const b of attempt.blocks) expect(b.needed).toBeLessThan(b.lowest);
        expect(attempt.sig).toBeUndefined();
      }
    }
    expect(refusals).toBeGreaterThan(0);
  });
});

describe('observeSignatures', () => {
  it('rejects an empty observation set', () => {
    expect(() => observeSignatures([])).toThrow(/at least one signature/);
  });

  it('takes the componentwise minimum across observations', async () => {
    const kp = await generateWotsPlusKeyPair();
    const sigs = [
      await wotsPlusSign(kp, 'a'),
      await wotsPlusSign(kp, 'b'),
      await wotsPlusSign(kp, 'c'),
    ];
    const knowledge = observeSignatures(sigs);
    expect(knowledge.observed).toBe(3);
    expect(knowledge.observedMessages).toEqual(['a', 'b', 'c']);
    for (let i = 0; i < WP_LEN; i++) {
      expect(knowledge.lowestDigit[i]).toBe(Math.min(...sigs.map((s) => s.digits[i])));
    }
    // More observations can only lower the floor, never raise it.
    const fewer = observeSignatures(sigs.slice(0, 2));
    for (let i = 0; i < WP_LEN; i++) {
      expect(knowledge.lowestDigit[i]).toBeLessThanOrEqual(fewer.lowestDigit[i]);
    }
  });
});
