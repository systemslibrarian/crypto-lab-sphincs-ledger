// FORS test suite — verifies the FIPS 205 §8 digest→index bit-slicing (base_2b)
// and the few-time-security illustrative bound. Run via:
//   npx tsx src/__tests__/fors.test.ts

import { base2b, illustrativeForgeryProbability } from '../crypto/fors.js';

function assert(condition: boolean, message: string) {
  if (!condition) throw new Error(message);
}

function eq(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function test(name: string, fn: () => void) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
  } catch (e: unknown) {
    console.error(`  ✗ ${name}: ${e instanceof Error ? e.message : String(e)}`);
    process.exitCode = 1;
  }
}

console.log('\nFORS base_2b (FIPS 205 Algorithm 4)');

// b=4 → nibbles, MSB first
test('4-bit fields = nibbles', () => {
  assert(eq(base2b(new Uint8Array([0x12, 0x34]), 4, 4), [1, 2, 3, 4]), 'nibble split');
});

// b=8 → the bytes themselves
test('8-bit fields = bytes', () => {
  assert(eq(base2b(new Uint8Array([0xde, 0xad, 0xbe, 0xef]), 8, 4), [0xde, 0xad, 0xbe, 0xef]), 'byte split');
});

// b=12 worked example: 0x12 0x34 0x56 → [0x123, 0x456]
test('12-bit fields cross byte boundaries', () => {
  assert(eq(base2b(new Uint8Array([0x12, 0x34, 0x56]), 12, 2), [0x123, 0x456]), '12-bit split');
});

// real set widths produce in-range indices and correct count
test('128s (a=12,k=14) → 14 indices in [0,4096)', () => {
  const md = new Uint8Array(Math.ceil((14 * 12) / 8)).map((_, i) => (i * 37 + 11) & 0xff);
  const idx = base2b(md, 12, 14);
  assert(idx.length === 14, 'count');
  assert(idx.every((v) => v >= 0 && v < 4096), 'range');
});

test('256s (a=14,k=22) → 22 indices in [0,16384), no precision loss', () => {
  const md = new Uint8Array(Math.ceil((22 * 14) / 8)).map((_, i) => (i * 53 + 7) & 0xff);
  const idx = base2b(md, 14, 22);
  assert(idx.length === 22, 'count');
  assert(idx.every((v) => v >= 0 && v < 16384), 'range');
});

test('256f (a=9,k=35) → 35 indices in [0,512)', () => {
  const md = new Uint8Array(Math.ceil((35 * 9) / 8)).map((_, i) => (i * 29 + 3) & 0xff);
  const idx = base2b(md, 9, 35);
  assert(idx.length === 35, 'count');
  assert(idx.every((v) => v >= 0 && v < 512), 'range');
});

console.log('\nFORS illustrative margin');
test('forgery probability increases with N and stays in [0,1]', () => {
  const p1 = illustrativeForgeryProbability(10, 4096, 14);
  const p2 = illustrativeForgeryProbability(100000, 4096, 14);
  assert(p1 >= 0 && p1 <= 1 && p2 >= 0 && p2 <= 1, 'range');
  assert(p2 > p1, 'monotonic in N');
});

console.log('\nFORS tests complete.');
