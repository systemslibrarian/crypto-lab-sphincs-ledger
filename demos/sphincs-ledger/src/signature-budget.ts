/** Operational teaching model only; not a persistent signing-key counter. */
export const DRAFT_SIGNATURE_LIMIT = 1n << 24n;
export function assessSignatureBudget(total: bigint, independentlyManagedKeys: bigint) {
  if (total < 0n || independentlyManagedKeys < 1n) throw new Error('Use a nonnegative signature count and at least one independent key.');
  const perKey = (total + independentlyManagedKeys - 1n) / independentlyManagedKeys;
  return { perKey, status: perKey > DRAFT_SIGNATURE_LIMIT ? 'exceeded' : perKey === DRAFT_SIGNATURE_LIMIT ? 'at-limit' : 'within-model-budget' } as const;
}
export function bindSignatureBudget(): void {
  const fields = ['budget-daily', 'budget-years', 'budget-keys'];
  const inputs = fields.map(id => document.getElementById(id) as HTMLInputElement);
  const output = document.getElementById('budget-result')!;
  const update = () => {
    if (inputs.some(input => input.value.trim() === '' || !input.checkValidity())) {
      output.textContent = 'Enter whole, nonnegative daily volume and positive years and independent key count.';
      return;
    }
    try {
      const [daily, years, keys] = inputs.map(input => BigInt(input.value));
      const total = daily * years * 365n;
      const { perKey, status } = assessSignatureBudget(total, keys);
      output.textContent = `Model total: ${total.toLocaleString()} signatures. Assuming balanced distribution, each independent key receives up to ${perKey.toLocaleString()}. Draft limit: ${DRAFT_SIGNATURE_LIMIT.toLocaleString()} per key. ${status === 'exceeded' ? 'Budget exceeded — shorten use or distribute workload across truly independent keys.' : status === 'at-limit' ? 'Exactly at the limit — no remaining budget.' : 'Within this modeled budget; this does not authorize use of the draft profile.'}`;
    } catch { output.textContent = 'Use whole numeric inputs; fractional counts are not accepted.'; }
  };
  for (const input of inputs) input.addEventListener('input', update);
  update();
}
