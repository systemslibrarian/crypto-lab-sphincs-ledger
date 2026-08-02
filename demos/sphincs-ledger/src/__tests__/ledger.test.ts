import { beforeEach, describe, expect, it } from 'vitest';
import { Ledger } from '../ledger/ledger.js';

const stored = new Map<string, string>();
Object.defineProperty(globalThis, 'sessionStorage', {
  configurable: true,
  value: {
    getItem: (key: string) => stored.get(key) ?? null,
    setItem: (key: string, value: string) => stored.set(key, value),
    removeItem: (key: string) => stored.delete(key),
  },
});

describe('ledger tamper verification', () => {
  beforeEach(() => stored.clear());

  it('runs the real verifier on changed message bytes before marking the entry invalid', async () => {
    const ledger = new Ledger();
    const entry = await ledger.addEntry('Auditor', 'original', 'sha2-128f');
    expect(await ledger.verifyEntry(entry)).toBe(true);

    const result = await ledger.tamperEntry(entry.id, 'changed');
    expect(result).toBe(false);
    expect(entry.valid).toBe(false);
    expect(await ledger.verifyEntry(entry)).toBe(false);
  });
});
