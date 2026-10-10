import { describe, expect, it } from 'vitest';
import { getStructuralParams, getWotsDimensions } from '../crypto/params.js';
import type { SphincsParamSet } from '../crypto/sphincs.js';
import { FIPS_LEN1, FIPS_LEN2, WP_LEN1, WP_LEN2, WP_LEN } from '../crypto/wotsplus.js';

describe('FIPS 205 comparison dimensions', () => {
  // Independently transcribed FIPS 205 Table 2 + §5 expected values, not a
  // second copy of the calculation under test. No unsupported 192-bit UI tier.
  it.each([
    ['sha2-128f', 16, 128, 32, 35],
    ['sha2-128s', 16, 128, 32, 35],
    ['sha2-256f', 32, 256, 64, 67],
    ['sha2-256s', 32, 256, 64, 67],
  ] as const)('%s matches the standard dimensions and fits its maximum checksum', (set, n, bits, len1, len) => {
    const actual = getWotsDimensions(set as SphincsParamSet);
    expect(actual).toEqual({ n, w: 16, messageBits: bits, len1, len2: 3, len });
    expect(16 ** actual.len2 - 1).toBeGreaterThanOrEqual(len1 * 15);
    expect(16 ** (actual.len2 - 1) - 1).toBeLessThan(len1 * 15);
  });

  it('names the legacy SHA2-128s comparison using n=16, not SHA-256 output width', () => {
    expect(getStructuralParams('sha2-128s').n).toBe(16);
    expect(FIPS_LEN1).toBe(32);
    expect(FIPS_LEN2).toBe(3);
    expect(FIPS_LEN1 + FIPS_LEN2).toBe(35);
    // The reference change must not widen the actual teaching model.
    expect([WP_LEN1, WP_LEN2, WP_LEN]).toEqual([6, 2, 8]);
  });
});
