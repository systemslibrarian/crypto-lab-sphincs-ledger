// The measurement that sets the exhibit's search budget, kept as a gate rather
// than a printout. It answers one question: how many nonces must a forger grind
// before a reachable message turns up, with one signature observed versus two?
//
// The answer is the whole exhibit. With one signature the checksum holds and the
// search exhausts its budget; with two it collapses in tens of tries. If either
// side of that ever stops being true, this fails and the page's claim is wrong.

import { describe, it, expect } from 'vitest';
import {
  WP_LEN,
  generateWotsPlusKeyPair,
  wotsPlusSign,
  wotsPlusVerify,
  observeSignatures,
  searchForgeableMessage,
} from '../crypto/wotsplus.js';

// The budget the UI offers the learner for the one-signature attempt.
const ONE_SIG_BUDGET = 3000;
// The budget the UI offers for the two-signature attempt.
const TWO_SIG_BUDGET = 20000;

describe('forgery search cost', () => {
  it('measures search cost for 1 and 2 signatures', async () => {
    const trials = 20;
    let found1 = 0;
    let collisions1 = 0;
    const tries2: number[] = [];
    let found2 = 0;
    for (let t = 0; t < trials; t++) {
      const kp = await generateWotsPlusKeyPair();
      const s1 = await wotsPlusSign(kp, `invoice A ${t}`);
      const s2 = await wotsPlusSign(kp, `invoice B ${t}`);

      const k1 = observeSignatures([s1]);
      const r1 = await searchForgeableMessage(kp.pkSeed, k1, 'attack', ONE_SIG_BUDGET);
      if (r1.found) {
        found1++;
        // The only way through with one signature is a toy-width digest
        // collision. The search must attribute it there, not to the checksum.
        expect(r1.attempt!.collidesWithObserved).toBeGreaterThanOrEqual(0);
      } else {
        expect(r1.tried).toBe(ONE_SIG_BUDGET);
        expect(r1.bestBlockCount).toBeGreaterThan(0);
        expect(r1.bestBlockCount).toBeLessThanOrEqual(WP_LEN);
      }

      const k2 = observeSignatures([s1, s2]);
      const r2 = await searchForgeableMessage(kp.pkSeed, k2, 'attack', TWO_SIG_BUDGET);
      if (r2.found) {
        found2++;
        tries2.push(r2.tried);
        // The forgery is only interesting if the real verifier accepts it.
        const a = r2.attempt!;
        expect(await wotsPlusVerify(kp.pkSeed, kp.publicKey, a.target, a.sig!)).toBe(true);
        expect(a.target).not.toBe(s1.message);
        expect(a.target).not.toBe(s2.message);
      }
    }
    console.log('one-sig forgeries found:', found1, '/', trials);
    console.log('two-sig forgeries found:', found2, '/', trials, 'tries:', tries2.join(','));

    // One signature: the checksum must hold across the board. A stray hit is
    // allowed only as a collision, which the loop above already asserted.
    expect(found1).toBeLessThanOrEqual(1);

    // Two signatures: key reuse must break it every single time, well inside
    // the budget the page hands the learner.
    expect(found2).toBe(trials);
    expect(Math.max(...tries2)).toBeLessThan(TWO_SIG_BUDGET);

    // Cheap enough that the page can honestly call it interactive.
    const median = tries2.slice().sort((a, b) => a - b)[Math.floor(tries2.length / 2)];
    expect(median).toBeLessThan(1000);
  }, 600000);
});
