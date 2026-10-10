// Independently signed message bytes under supplied per-entry public keys.
// Metadata, order, completeness and key-to-identity binding are not signed.
// The historical Ledger API name does not imply authenticated append-only state.

import { generateKeyPair, sign, verify, type SphincsParamSet } from '../crypto/sphincs';
import { bytesToHex } from '../crypto/hash';

export interface LedgerEntry {
  id: number;
  author: string;
  message: string;
  timestamp: string;
  publicKey: Uint8Array;
  signature: Uint8Array;
  paramSet: SphincsParamSet;
  valid: boolean | null; // null = not verified in this instance
}

interface SerializedEntry {
  id: number;
  author: string;
  message: string;
  timestamp: string;
  publicKey: string;
  signature: string;
  paramSet: SphincsParamSet;
  valid: boolean | null;
}

function hexToUint8(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export class Ledger {
  entries: LedgerEntry[] = [];
  private nextId = 1;

  constructor() {
    this.loadFromSession();
  }

  async addEntry(author: string, message: string, params: SphincsParamSet): Promise<LedgerEntry> {
    const keyPair = await generateKeyPair(params);
    const msgBytes = new TextEncoder().encode(message);
    const signature = await sign(keyPair.privateKey, msgBytes, params);

    const entry: LedgerEntry = {
      id: this.nextId++,
      author,
      message,
      timestamp: new Date().toISOString(),
      publicKey: keyPair.publicKey,
      signature,
      paramSet: params,
      valid: await verify(keyPair.publicKey, msgBytes, signature, params),
    };

    this.entries.push(entry);
    this.saveToSession();
    return entry;
  }

  async verifyEntry(entry: LedgerEntry): Promise<boolean> {
    const msgBytes = new TextEncoder().encode(entry.message);
    return verify(entry.publicKey, msgBytes, entry.signature, entry.paramSet);
  }

  async verifyAll(): Promise<{ valid: number; invalid: number; entries: LedgerEntry[] }> {
    let validCount = 0;
    let invalidCount = 0;
    for (const entry of this.entries) {
      const isValid = await this.verifyEntry(entry);
      entry.valid = isValid;
      if (isValid) validCount++;
      else invalidCount++;
    }
    this.saveToSession();
    return { valid: validCount, invalid: invalidCount, entries: this.entries };
  }

  async tamperEntry(id: number, newMessage: string): Promise<boolean | null> {
    const entry = this.entries.find((e) => e.id === id);
    if (!entry) return null;
    entry.message = newMessage;
    entry.valid = await this.verifyEntry(entry);
    this.saveToSession();
    return entry.valid;
  }

  clearAll(): void {
    this.entries = [];
    this.nextId = 1;
    sessionStorage.removeItem('sphincs-ledger');
  }

  private saveToSession(): void {
    const serialized: SerializedEntry[] = this.entries.map((e) => ({
      ...e,
      publicKey: bytesToHex(e.publicKey),
      signature: bytesToHex(e.signature),
    }));
    sessionStorage.setItem('sphincs-ledger', JSON.stringify(serialized));
  }

  private loadFromSession(): void {
    const data = sessionStorage.getItem('sphincs-ledger');
    if (!data) return;
    try {
      const parsed: SerializedEntry[] = JSON.parse(data);
      this.entries = parsed.map((e) => ({
        ...e,
        publicKey: hexToUint8(e.publicKey),
        signature: hexToUint8(e.signature),
        // Stored flags are not evidence about the bytes loaded now. A real
        // verification is required before showing a success or failure badge.
        valid: null,
      }));
      this.nextId = this.entries.length > 0
        ? Math.max(...this.entries.map((e) => e.id)) + 1
        : 1;
    } catch {
      // Corrupted session data — start fresh
      this.entries = [];
      this.nextId = 1;
    }
  }
}
