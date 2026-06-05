// SLH-DSA structural parameters — sourced DIRECTLY from @noble/post-quantum.
//
// These are the REAL FIPS 205 Table 2 values used by the audited library that
// performs the actual signing in this demo. We read them out of noble's exported
// `PARAMS` map rather than re-typing them, so the FORS / hypertree tabs surface
// the genuine k, a, t, d, h, h' that were previously invisible in the UI.
//
// IMPORTANT — noble's public signer object (slh_dsa_sha2_128f, …) exposes only
// `info`, `lengths`, `keygen`, `sign`, `verify`, `getPublicKey`. It does NOT
// expose K/A/D/H on the signer itself. The numeric parameters live in the
// separately-exported `PARAMS` record, which is what we import here. The FORS and
// hypertree *structures/animations* are therefore a parallel pedagogical
// reconstruction (see fors.ts) — but the parameter VALUES below are real.
//
// Reference: NIST FIPS 205 Table 2 — https://csrc.nist.gov/pubs/fips/205/final

import { PARAMS } from '@noble/post-quantum/slh-dsa.js';
import type { SphincsParamSet } from './sphincs';

export interface SphincsStructuralParams {
  n: number;            // security parameter (bytes)
  w: number;            // Winternitz parameter
  h: number;            // total hypertree height
  d: number;            // number of hypertree layers
  hPrime: number;       // height of each XMSS subtree = h / d
  k: number;            // number of FORS trees
  a: number;            // height of each FORS tree
  t: number;            // leaves per FORS tree = 2^a
  securityLevel: number;
  forsMdBits: number;   // bits consumed from the digest for FORS indices = k * a
  forsMdBytes: number;  // ceil(k*a / 8) — bytes sliced into k indices
  leavesPerLayer: number; // 2^h' WOTS+ instances per XMSS subtree
}

// Our four UI parameter sets map onto noble's internal PARAMS keys.
// Only SHA-2, only 128/256 — no SHAKE, no 192 tier (consistent with sphincs.ts).
const NOBLE_KEY: Record<SphincsParamSet, string> = {
  'sha2-128f': '128f',
  'sha2-128s': '128s',
  'sha2-256f': '256f',
  'sha2-256s': '256s',
};

export function getStructuralParams(set: SphincsParamSet): SphincsStructuralParams {
  const p = PARAMS[NOBLE_KEY[set]];
  const hPrime = p.H / p.D;
  return {
    n: p.N,
    w: p.W,
    h: p.H,
    d: p.D,
    hPrime,
    k: p.K,
    a: p.A,
    t: 2 ** p.A,
    securityLevel: p.securityLevel,
    forsMdBits: p.K * p.A,
    forsMdBytes: Math.ceil((p.K * p.A) / 8),
    leavesPerLayer: 2 ** hPrime,
  };
}
