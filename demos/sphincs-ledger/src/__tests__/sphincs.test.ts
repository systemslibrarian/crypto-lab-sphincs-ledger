// SPHINCS+ / SLH-DSA test suite (vitest)
// Exercises the REAL @noble/post-quantum signer that this demo ships:
//   keygen → sign → verify round-trip, exact key/signature sizes,
//   and single-byte tamper detection on both the signature and the message.
// All FOUR SHA-2 parameter sets are covered by default — this is the crypto gate
// that runs on every `npm test` / CI build.
//
// One keypair + signature is generated per parameter set (256s signing is genuinely
// slow), then shared across the assertions in that set.

import { describe, it, expect, beforeAll } from 'vitest';
import {
  generateKeyPair,
  sign,
  verify,
  PARAM_SIZES,
  type SphincsKeyPair,
  type SphincsParamSet,
} from '../crypto/sphincs.js';

const PARAM_SETS: SphincsParamSet[] = ['sha2-128f', 'sha2-128s', 'sha2-256f', 'sha2-256s'];
const MESSAGE = new TextEncoder().encode('test message');

describe.each(PARAM_SETS)('SLH-DSA %s', (params) => {
  const sizes = PARAM_SIZES[params];
  let kp: SphincsKeyPair;
  let other: SphincsKeyPair;
  let sig: Uint8Array;

  beforeAll(async () => {
    kp = await generateKeyPair(params);
    other = await generateKeyPair(params);
    sig = await sign(kp.privateKey, MESSAGE, params);
  });

  it('generates a keypair with the FIPS 205 key sizes', () => {
    expect(kp.publicKey.length).toBe(sizes.publicKey);
    expect(kp.privateKey.length).toBe(sizes.privateKey);
    expect(kp.paramSet).toBe(params);
  });

  it('sign → verify → true, with the FIPS 205 signature size', async () => {
    expect(sig.length).toBe(sizes.signature);
    expect(await verify(kp.publicKey, MESSAGE, sig, params)).toBe(true);
  });

  it('flipping one bit of the signature makes verify reject', async () => {
    const tampered = new Uint8Array(sig);
    tampered[0] ^= 0x01;
    expect(await verify(kp.publicKey, MESSAGE, tampered, params)).toBe(false);
  });

  it('changing one byte of the message makes verify reject', async () => {
    const tamperedMsg = new TextEncoder().encode('Test message'); // capital T
    expect(await verify(kp.publicKey, tamperedMsg, sig, params)).toBe(false);
  });

  it('a signature is bound to its own key (cross-key verify fails)', async () => {
    expect(await verify(kp.publicKey, MESSAGE, sig, params)).toBe(true);
    expect(await verify(other.publicKey, MESSAGE, sig, params)).toBe(false);
  });
});
