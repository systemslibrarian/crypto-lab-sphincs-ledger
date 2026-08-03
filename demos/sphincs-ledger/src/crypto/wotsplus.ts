// WOTS+ WITH the Winternitz checksum — a complete one-time signature.
//
// The `wots.ts` module in this repo is a single-chain teaching model that
// deliberately omits the checksum. This module is the other half: a full
// Winternitz one-time signature over `len = len1 + len2` chains, where the
// len2 checksum chains encode sum(w-1-d_i) in base w. That checksum is the
// entire reason a WOTS+ signature on one message cannot be turned into a
// signature on another: raising any message digit lowers the checksum, and a
// lower number cannot have every base-w digit greater than or equal to a
// higher one.
//
// SCALE. Everything here is real SHA-256 with real chains; only the width of
// the message digest is reduced. This lab hashes a message to a 24-bit digest
// (LEN1 = 6 base-16 digits) plus LEN2 = 2 checksum digits = 8 chains, where
// FIPS 205's SHA2-128s parameter set uses a 256-bit digest (64 digits) plus 3
// checksum digits = 67 chains. The reduction is what makes the key-reuse
// forgery *search* finish in a browser; the checksum mechanism, the signing
// rule, and the verification rule are identical at both sizes. One consequence
// of the narrow digest is honest and reported rather than hidden: a 24-bit
// digest is collision-findable, so the search separates "beat the checksum"
// from "hit a digest collision" (see `collidesWithObserved`).
//
// Reference: NIST FIPS 205 §5 (WOTS+). The address/tweak scheme here is a
// simplified domain separation (pkSeed || tag || chain index || step) rather
// than FIPS 205's full ADRS structure.

import { sha256, concatBytes } from './hash';

export const WP_W = 16; // Winternitz parameter
export const WP_LOG_W = 4; // log2(w) — one base-w digit is one nibble
export const WP_LEN1 = 6; // toy-scale message digest: 6 nibbles = 24 bits
// len2 = floor(log2(len1 * (w-1)) / log2 w) + 1  (FIPS 205 §5)
export const WP_LEN2 = Math.floor(Math.log2(WP_LEN1 * (WP_W - 1)) / WP_LOG_W) + 1;
export const WP_LEN = WP_LEN1 + WP_LEN2;
export const WP_MAX_STEP = WP_W - 1; // chain endpoint index

// Real FIPS 205 SHA2-128s widths, quoted on the page for the scale contrast.
export const FIPS_LEN1 = 64;
export const FIPS_LEN2 = 3;

const ASCII = new TextEncoder();

export interface WotsPlusKeyPair {
  skSeed: Uint8Array;
  pkSeed: Uint8Array;
  /** chainValues[i][s] = the value at step s of chain i (s = 0..w-1). */
  chainValues: Uint8Array[][];
  /** Compressed public key: SHA-256 over pkSeed and all chain endpoints. */
  publicKey: Uint8Array;
}

export interface WotsPlusSignature {
  message: string;
  /** len digits: LEN1 message digits followed by LEN2 checksum digits. */
  digits: number[];
  /** sig[i] = chainValues[i][digits[i]] */
  sig: Uint8Array[];
}

/** One step of the chain, domain-separated by chain index and step number. */
async function chainStep(
  pkSeed: Uint8Array,
  chainIdx: number,
  step: number,
  x: Uint8Array,
): Promise<Uint8Array> {
  return sha256(concatBytes(pkSeed, ASCII.encode('F'), new Uint8Array([chainIdx, step]), x));
}

/** Iterate the chain `steps` times starting from step `start`. */
export async function chain(
  pkSeed: Uint8Array,
  chainIdx: number,
  start: number,
  steps: number,
  x: Uint8Array,
): Promise<Uint8Array> {
  let current = x;
  for (let i = 0; i < steps; i++) {
    current = await chainStep(pkSeed, chainIdx, start + i, current);
  }
  return current;
}

/** SHA-256(message) truncated to LEN1 base-w digits, big-endian nibbles. */
export async function messageDigits(message: string): Promise<number[]> {
  const digest = await sha256(ASCII.encode(message));
  const digits: number[] = [];
  for (let i = 0; i < WP_LEN1; i++) {
    const byte = digest[i >> 1];
    digits.push(i % 2 === 0 ? byte >> 4 : byte & 0x0f);
  }
  return digits;
}

/** The Winternitz checksum: sum(w-1-d_i), written as LEN2 base-w digits. */
export function checksumDigits(msgDigits: number[]): number[] {
  let csum = 0;
  for (const d of msgDigits) csum += WP_W - 1 - d;
  const out: number[] = new Array(WP_LEN2).fill(0);
  for (let i = WP_LEN2 - 1; i >= 0; i--) {
    out[i] = csum % WP_W;
    csum = Math.floor(csum / WP_W);
  }
  return out;
}

/** Full digit vector a signature commits to: message digits then checksum. */
export async function allDigits(message: string): Promise<number[]> {
  const msg = await messageDigits(message);
  return msg.concat(checksumDigits(msg));
}

export async function generateWotsPlusKeyPair(): Promise<WotsPlusKeyPair> {
  const skSeed = crypto.getRandomValues(new Uint8Array(32));
  const pkSeed = crypto.getRandomValues(new Uint8Array(32));
  const chainValues: Uint8Array[][] = [];
  const endpoints: Uint8Array[] = [];
  for (let i = 0; i < WP_LEN; i++) {
    const sk = await sha256(concatBytes(skSeed, ASCII.encode('SK'), new Uint8Array([i])));
    const values: Uint8Array[] = [sk];
    for (let s = 0; s < WP_MAX_STEP; s++) {
      values.push(await chainStep(pkSeed, i, s, values[s]));
    }
    chainValues.push(values);
    endpoints.push(values[WP_MAX_STEP]);
  }
  const publicKey = await sha256(concatBytes(pkSeed, ASCII.encode('PK'), ...endpoints));
  return { skSeed, pkSeed, chainValues, publicKey };
}

export async function wotsPlusSign(
  kp: WotsPlusKeyPair,
  message: string,
): Promise<WotsPlusSignature> {
  const digits = await allDigits(message);
  const sig = digits.map((d, i) => kp.chainValues[i][d]);
  return { message, digits, sig };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Verify by recomputing the digits FROM THE MESSAGE (checksum included),
 * walking each signature element to the chain endpoint, and comparing the
 * compressed public key. A forger who cannot produce every element at the
 * digit the verifier recomputes cannot pass this.
 */
export async function wotsPlusVerify(
  pkSeed: Uint8Array,
  publicKey: Uint8Array,
  message: string,
  sig: Uint8Array[],
): Promise<boolean> {
  if (sig.length !== WP_LEN) return false;
  const digits = await allDigits(message);
  const endpoints: Uint8Array[] = [];
  for (let i = 0; i < WP_LEN; i++) {
    endpoints.push(await chain(pkSeed, i, digits[i], WP_MAX_STEP - digits[i], sig[i]));
  }
  const candidate = await sha256(concatBytes(pkSeed, ASCII.encode('PK'), ...endpoints));
  return bytesEqual(candidate, publicKey);
}

/**
 * What an attacker holds after observing one or more signatures under the same
 * key: for each chain, the LOWEST digit ever revealed and its chain value.
 * From (i, lowestDigit) the attacker can reach any step >= lowestDigit by
 * hashing forward — and nothing below it.
 */
export interface AttackerKnowledge {
  lowestDigit: number[];
  value: Uint8Array[];
  observed: number;
  /** Message strings and their message-digit vectors, for collision reporting. */
  observedMessages: string[];
  observedMsgDigits: number[][];
}

export function observeSignatures(sigs: WotsPlusSignature[]): AttackerKnowledge {
  if (sigs.length === 0) throw new Error('observeSignatures needs at least one signature');
  const lowestDigit = sigs[0].digits.slice();
  const value = sigs[0].sig.slice();
  for (const s of sigs.slice(1)) {
    for (let i = 0; i < WP_LEN; i++) {
      if (s.digits[i] < lowestDigit[i]) {
        lowestDigit[i] = s.digits[i];
        value[i] = s.sig[i];
      }
    }
  }
  return {
    lowestDigit,
    value,
    observed: sigs.length,
    observedMessages: sigs.map((s) => s.message),
    observedMsgDigits: sigs.map((s) => s.digits.slice(0, WP_LEN1)),
  };
}

/**
 * True when `digits` reproduces an observed message's digest exactly. At this
 * lab's toy digest width that is reachable by luck, and it is a HASH collision,
 * not a defeat of the checksum — the two are reported separately so the page
 * never credits the checksum break for a collision.
 */
function digestCollisionIndex(knowledge: AttackerKnowledge, msgDigits: number[]): number {
  for (let k = 0; k < knowledge.observedMsgDigits.length; k++) {
    const obs = knowledge.observedMsgDigits[k];
    let same = true;
    for (let i = 0; i < WP_LEN1 && same; i++) if (obs[i] !== msgDigits[i]) same = false;
    if (same) return k;
  }
  return -1;
}

export interface ForgeBlock {
  chainIndex: number;
  needed: number; // digit the target message requires
  lowest: number; // lowest digit the attacker holds on that chain
  isChecksumChain: boolean;
}

export interface ForgeAttempt {
  target: string;
  digits: number[];
  forgeable: boolean;
  blocks: ForgeBlock[];
  sig?: Uint8Array[];
  /**
   * -1 normally. >= 0 when the target's message digest equals that observed
   * message's digest: a toy-width hash collision, reported separately because
   * it is not the checksum being beaten.
   */
  collidesWithObserved: number;
}

/**
 * Try to forge a signature on `target` from what the attacker observed. The
 * attacker can only hash forward, so the attempt succeeds exactly when every
 * required digit is >= the lowest digit held on that chain.
 */
export async function forgeAttempt(
  pkSeed: Uint8Array,
  knowledge: AttackerKnowledge,
  target: string,
): Promise<ForgeAttempt> {
  const digits = await allDigits(target);
  const collidesWithObserved = digestCollisionIndex(knowledge, digits.slice(0, WP_LEN1));
  const blocks: ForgeBlock[] = [];
  for (let i = 0; i < WP_LEN; i++) {
    if (digits[i] < knowledge.lowestDigit[i]) {
      blocks.push({
        chainIndex: i,
        needed: digits[i],
        lowest: knowledge.lowestDigit[i],
        isChecksumChain: i >= WP_LEN1,
      });
    }
  }
  if (blocks.length > 0) {
    return { target, digits, forgeable: false, blocks, collidesWithObserved };
  }
  const sig: Uint8Array[] = [];
  for (let i = 0; i < WP_LEN; i++) {
    sig.push(
      await chain(
        pkSeed,
        i,
        knowledge.lowestDigit[i],
        digits[i] - knowledge.lowestDigit[i],
        knowledge.value[i],
      ),
    );
  }
  return { target, digits, forgeable: true, blocks, sig, collidesWithObserved };
}

export interface ForgeSearchResult {
  found: boolean;
  tried: number;
  attempt?: ForgeAttempt;
  /** Fewest blocked chains seen across the whole search (0 means found). */
  bestBlockCount: number;
  /** The closest candidate the search reached, kept for the refusal message. */
  bestCandidate: string;
  /**
   * How many candidates cleared every MESSAGE chain — i.e. had all len1 message
   * digits at or above the attacker's floor. This is the number that exposes the
   * checksum's work: clearing the message chains is exactly what drives the
   * checksum down, so on a failed search every one of these was then stopped by
   * a checksum chain. Reporting it turns "the search failed" into "the search
   * got this far this often, and the checksum is what ended it every time".
   */
  msgChainsCleared: number;
  /** Of `msgChainsCleared`, how many were then blocked on a checksum chain. */
  blockedOnChecksum: number;
}

/**
 * Grind nonces onto `base` until a message turns up whose digit vector the
 * attacker can reach. This is the real attack: the forger does not get to pick
 * an arbitrary message, only to search until one is reachable.
 */
export async function searchForgeableMessage(
  pkSeed: Uint8Array,
  knowledge: AttackerKnowledge,
  base: string,
  budget = 20000,
): Promise<ForgeSearchResult> {
  let bestBlockCount = Infinity;
  let bestCandidate = '';
  let msgChainsCleared = 0;
  let blockedOnChecksum = 0;
  for (let n = 0; n < budget; n++) {
    const candidate = `${base} [nonce ${n}]`;
    const digits = await allDigits(candidate);
    let blocked = 0;
    let msgBlocked = 0;
    let csumBlocked = 0;
    for (let i = 0; i < WP_LEN; i++) {
      if (digits[i] < knowledge.lowestDigit[i]) {
        blocked++;
        if (i < WP_LEN1) msgBlocked++;
        else csumBlocked++;
      }
    }
    if (msgBlocked === 0) {
      msgChainsCleared++;
      if (csumBlocked > 0) blockedOnChecksum++;
    }
    if (blocked < bestBlockCount) {
      bestBlockCount = blocked;
      bestCandidate = candidate;
    }
    if (blocked === 0) {
      const attempt = await forgeAttempt(pkSeed, knowledge, candidate);
      return {
        found: true,
        tried: n + 1,
        attempt,
        bestBlockCount: 0,
        bestCandidate: candidate,
        msgChainsCleared,
        blockedOnChecksum,
      };
    }
  }
  return {
    found: false,
    tried: budget,
    bestBlockCount,
    bestCandidate,
    msgChainsCleared,
    blockedOnChecksum,
  };
}
