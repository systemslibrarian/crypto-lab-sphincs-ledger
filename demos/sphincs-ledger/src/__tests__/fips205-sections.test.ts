// Section numbers the page and the crypto modules attribute to FIPS 205.
//
// FIPS 205 numbers its sections:
//   4 Functions and Addressing
//   5 Winternitz One-Time Signature Plus Scheme   (5.1-5.3)
//   6 eXtended Merkle Signature Scheme (XMSS)     (6.1 Generating a Merkle Hash Tree)
//   7 The SLH-DSA Hypertree
//   8 Forest of Random Subsets (FORS)
//
// The WOTS+ schematic caption and src/crypto/wots.ts both cited "Section 4",
// which is the address and hash-function section; merkle.ts cited "Section 5",
// which is WOTS+. Read as text rather than through the DOM because the WOTS+
// caption lives in a tab panel that is not mounted on first paint.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');

const html = read('../../index.html');
const wots = read('../crypto/wots.ts');
const merkle = read('../crypto/merkle.ts');

describe('FIPS 205 section attributions', () => {
  it('cites WOTS+ at Section 5 on the page', () => {
    expect(html).toContain('WOTS+</span> (FIPS 205, Section 5)');
    expect(html).not.toContain('FIPS 205, Section 4');
  });

  it('cites WOTS+ at Section 5 in the module that implements the chain', () => {
    expect(wots).toContain('FIPS 205, Section 5');
    expect(wots).not.toContain('FIPS 205, Section 4');
  });

  it('cites the Merkle hash tree at Section 6.1, inside XMSS', () => {
    expect(merkle).toContain('FIPS 205, Section 6.1');
    expect(merkle).toContain('eXtended Merkle Signature Scheme (XMSS)');
    expect(merkle).not.toContain('FIPS 205, Section 5');
  });
});
