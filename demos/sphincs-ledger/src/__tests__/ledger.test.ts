import { beforeEach, describe, expect, it } from 'vitest';
import { Ledger } from '../ledger/ledger.js';
import { generateKeyPair, sign, type SphincsParamSet } from '../crypto/sphincs.js';

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

  for (const params of ['sha2-128f', 'sha2-128s', 'sha2-256f', 'sha2-256s'] as SphincsParamSet[]) {
    it(`${params}: signatures authenticate message bytes, not metadata, ordering, completeness or identity`, async () => {
      const collection = new Ledger();
      const first = await collection.addEntry('Alice', 'first message', params);
      const second = await collection.addEntry('Bob', 'second message', params);
      expect((await collection.verifyAll()).valid).toBe(2);
      first.author = 'Mallory'; first.timestamp = '1900-01-01'; first.id = 99;
      expect(await collection.verifyEntry(first)).toBe(true);
      collection.entries.reverse();
      expect((await collection.verifyAll()).valid).toBe(2);
      expect(collection.entries[0]).toBe(second);
      collection.entries.splice(0, 1);
      expect((await collection.verifyAll()).valid).toBe(1);
      // A genuinely new signer using its own private key can replace both
      // supplied key and signature. This is ordinary signing, not a break of
      // SLH-DSA or a signature made under Alice's original key.
      const replacement = await generateKeyPair(params);
      first.publicKey = replacement.publicKey;
      expect(await collection.verifyEntry(first)).toBe(false);
      first.signature = await sign(replacement.privateKey, new TextEncoder().encode(first.message), params);
      expect(await collection.verifyEntry(first)).toBe(true);
      first.message = 'changed unsigned message';
      expect(await collection.verifyEntry(first)).toBe(false);
    }, 60_000);
  }

  it('treats reloaded signatures as unverified even when a saved valid flag claims success', async () => {
    const collection = new Ledger();
    await collection.addEntry('Alice', 'original message', 'sha2-128f');
    let persisted = JSON.parse(stored.get('sphincs-ledger')!);
    persisted[0].valid = true;
    stored.set('sphincs-ledger', JSON.stringify(persisted));
    const honestReload = new Ledger();
    expect(honestReload.entries[0].valid).toBeNull();
    expect((await honestReload.verifyAll()).valid).toBe(1);
    persisted = JSON.parse(stored.get('sphincs-ledger')!);
    persisted[0].message = 'changed message'; persisted[0].valid = true;
    stored.set('sphincs-ledger', JSON.stringify(persisted));
    const changedReload = new Ledger();
    expect(changedReload.entries[0].valid).toBeNull();
    expect((await changedReload.verifyAll()).invalid).toBe(1);
    expect(changedReload.entries[0].valid).toBe(false);
  });
});
