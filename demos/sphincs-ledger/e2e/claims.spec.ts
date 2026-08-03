import { expect, test } from '@playwright/test';

test('schematics and checksum-free chain demo state their actual evidence boundary', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#peek-card')).toContainText('illustrative leaf-to-root path');

  await page.locator('#tab-btn-wots').click();
  const panel = page.locator('#tab-wots');
  await expect(panel).toContainText('not a complete WOTS+ signature forgery');
  await expect(page.locator('#wots-forge-step')).toHaveAttribute('max', '15');

  await page.locator('#btn-gen-wots').click();
  await page.locator('#btn-wots-sign').click();
  await page.locator('#wots-forge-step').evaluate((input) => { (input as HTMLInputElement).value = '16'; });
  await page.locator('#btn-wots-forge').click();
  await expect(page.locator('#wots-forge-output')).toContainText('CANNOT FORGE');
  await expect(page.locator('#wots-forge-output')).not.toContainText('VALID FORGERY');
});

test('complete WOTS+ states its reduced scale next to the forgery it offers', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-btn-wots').click();

  const scale = page.locator('#wp-scale-note');
  await expect(scale).toContainText('deliberately shrunk WOTS+');
  await expect(scale).toContainText('24-bit digest');
  await expect(scale).toContainText('256-bit digest');
  // The stated parameters are filled in from the constants the code runs on.
  await expect(page.locator('#wp-scale-len')).toHaveText('8');
  await expect(page.locator('#wp-scale-fips-len')).toHaveText('67');
  await expect(page.locator('#wp-scale-len1')).toHaveText('6');
  await expect(page.locator('#wp-scale-len2')).toHaveText('2');
});

test('one signature: the forgery search genuinely FAILS and names the checksum', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('#tab-btn-wots').click();
  await page.locator('#btn-wp-gen').click();

  await page.locator('#wp-message').fill('invoice 001: pay 10 to Alice');
  await page.locator('#btn-wp-sign').click();
  // The honest signature's verdict is the real verifier's, not a label.
  await expect(page.locator('#wp-digits')).toContainText('Honest signature verifies:');
  await expect(page.locator('#wp-digits')).toContainText('VALID');
  // One signature is not reuse, so no reuse alarm yet.
  await expect(page.locator('#wp-reuse-warning')).toBeHidden();

  await page.locator('#wp-target').fill('pay 1000000 to Mallory');
  await page.locator('#btn-wp-forge').click();

  const out = page.locator('#wp-forge-output');
  await expect(out).toContainText('FORGERY FAILED', { timeout: 60_000 });
  await expect(out).not.toContainText('FORGERY SUCCEEDED');
  await expect(out).toContainText('20,000 candidate messages');
  await expect(out).toContainText('Chains still out of reach');
  await expect(out).toContainText('Where the checksum did the work');

  const text = (await out.textContent()) ?? '';

  // The mechanism claim must rest on the page's own counts: candidates that
  // cleared every message chain, and how many of those the checksum then killed.
  const cleared = /([\d,]+) of ([\d,]+) candidates cleared every one of the 6 message chains/.exec(
    text,
  );
  expect(cleared).not.toBeNull();
  const clearedN = Number(cleared![1].replace(/,/g, ''));
  const triedN = Number(cleared![2].replace(/,/g, ''));
  expect(triedN).toBe(20000);
  // Some candidates must actually get past the message digits, or the exhibit
  // is showing a wall rather than the checksum.
  expect(clearedN).toBeGreaterThan(0);

  const killed = /([\d,]+) of those ([\d,]+)\s+were then blocked by a checksum chain/.exec(text);
  expect(killed).not.toBeNull();
  expect(Number(killed![2].replace(/,/g, ''))).toBe(clearedN);
  // With one signature observed, every candidate that cleared the message
  // chains must die on the checksum -- otherwise it would have been forgeable.
  expect(Number(killed![1].replace(/,/g, ''))).toBe(clearedN);

  // And every chain the page lists as blocked must really need a digit below
  // the floor it printed.
  const floor = /Attacker's floor:\s*([0-9A-F ]+)/.exec(text);
  expect(floor).not.toBeNull();
  const floorDigits = floor![1]
    .trim()
    .split(/\s+/)
    .map((d) => parseInt(d, 16));
  expect(floorDigits).toHaveLength(8);

  const blocks = [
    ...text.matchAll(/chain (\d)(?: \(checksum\))? needs ([0-9A-F]), lowest value held is ([0-9A-F])/g),
  ];
  expect(blocks.length).toBeGreaterThan(0);
  for (const [, idx, needed, lowest] of blocks) {
    expect(parseInt(needed, 16)).toBeLessThan(parseInt(lowest, 16));
    expect(parseInt(lowest, 16)).toBe(floorDigits[Number(idx)]);
  }
});

test('two signatures on one key: the forgery SUCCEEDS and the page runs the verifier', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('#tab-btn-wots').click();
  await page.locator('#btn-wp-gen').click();

  await page.locator('#wp-message').fill('invoice 001: pay 10 to Alice');
  await page.locator('#btn-wp-sign').click();
  await expect(page.locator('#wp-digits')).toContainText('observed under this key: 1');

  // Reuse the SAME key on a second, different message.
  await page.locator('#wp-message').fill('invoice 002: pay 25 to Bob');
  await page.locator('#btn-wp-sign').click();
  await expect(page.locator('#wp-digits')).toContainText('observed under this key: 2');
  await expect(page.locator('#wp-reuse-warning')).toBeVisible();
  await expect(page.locator('#wp-reuse-warning')).toContainText('KEY REUSE');

  await page.locator('#wp-target').fill('pay 1000000 to Mallory');
  await page.locator('#btn-wp-forge').click();

  const out = page.locator('#wp-forge-output');
  await expect(out).toContainText('FORGERY SUCCEEDED', { timeout: 60_000 });
  await expect(out).toContainText('wotsPlusVerify() against the honest public key returned: true');
  await expect(out).toContainText('Signer ever approved it: no');
  await expect(out).toContainText('checksum was genuinely satisfied');
  // A digest collision is a different finding and must not be sold as this one.
  await expect(out).not.toContainText('DIGEST COLLISION');

  // Assert the verdict against what the page itself computed: the forged
  // message's digits must sit at or above the floor the page printed, on
  // every chain. That is the whole reason the verifier accepted it.
  const text = (await out.textContent()) ?? '';
  const digits = /Its digits:\s*([0-9A-F ]+)/.exec(text);
  const floor = /Attacker's floor:\s*([0-9A-F ]+)/.exec(text);
  expect(digits).not.toBeNull();
  expect(floor).not.toBeNull();
  const d = digits![1].trim().split(/\s+/).map((x) => parseInt(x, 16));
  const f = floor![1].trim().split(/\s+/).map((x) => parseInt(x, 16));
  expect(d).toHaveLength(8);
  expect(f).toHaveLength(8);
  for (let i = 0; i < 8; i++) expect(d[i]).toBeGreaterThanOrEqual(f[i]);

  // The forged message is a real message, carrying the attacker's target text.
  expect(text).toContain('pay 1000000 to Mallory');
});

test('ledger tampering reports the real verifier result', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-btn-ledger').click();
  await page.locator('#btn-ledger-add').click();
  await expect(page.locator('#btn-ledger-add')).toBeEnabled({ timeout: 60_000 });
  await page.locator('#btn-ledger-tamper').click();

  await expect(page.locator('#ledger-tamper-explanation')).toContainText('ran SPHINCS+ verify()');
  await expect(page.locator('#ledger-tamper-explanation')).toContainText('returned false');
  await expect(page.locator('#ledger-entries .badge-invalid').last()).toHaveText('INVALID');
});
