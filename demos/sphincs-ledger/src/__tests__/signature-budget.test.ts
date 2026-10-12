import { describe, it, expect } from 'vitest';
import { assessSignatureBudget, DRAFT_SIGNATURE_LIMIT as limit } from '../signature-budget';
describe('draft per-key signature budget', () => {
  it('distinguishes the exact boundary', () => {
    expect(assessSignatureBudget(limit - 1n, 1n).status).toBe('within-model-budget');
    expect(assessSignatureBudget(limit, 1n).status).toBe('at-limit');
    expect(assessSignatureBudget(limit + 1n, 1n).status).toBe('exceeded');
  });
  it('counts same-key replica activity together and only splits across independent keys', () => {
    const totalFromTwoWorkers = (limit / 2n + 1n) * 2n;
    expect(assessSignatureBudget(totalFromTwoWorkers, 1n).status).toBe('exceeded');
    expect(assessSignatureBudget(totalFromTwoWorkers, 2n).status).toBe('within-model-budget');
    expect(assessSignatureBudget(3n, 2n).perKey).toBe(2n);
  });
  it('refuses invalid key counts or negative usage', () => {
    expect(() => assessSignatureBudget(0n, 0n)).toThrow();
    expect(() => assessSignatureBudget(-1n, 1n)).toThrow();
    expect(assessSignatureBudget(0n, 1n).perKey).toBe(0n);
  });
});
