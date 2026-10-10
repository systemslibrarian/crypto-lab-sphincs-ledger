import { expect, test } from '@playwright/test';

for (const width of [1280, 380, 320]) {
  test(`independent message collection scopes its verdict and exercises at ${width}px`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    await page.locator('#tab-btn-ledger').click();
    const scope = page.locator('#ledger-scope');
    await expect(scope).toContainText('independently signed message bytes');
    await expect(scope).toContainText('not an append-only authenticated ledger');
    await expect(scope).toContainText('author and timestamp are unsigned');
    await expect(scope).toContainText('ordering or completeness');
    await expect(scope).toContainText('trusted identity');
    await page.locator('#ledger-message').fill('first message');
    await page.locator('#btn-ledger-add').click();
    await expect(page.locator('.ledger-entry .badge-valid')).toHaveText('VALID MESSAGE SIGNATURE');
    await page.locator('#ledger-message').fill('second message');
    await page.locator('#btn-ledger-add').click();
    await expect(page.locator('.ledger-entry')).toHaveCount(2);
    await page.locator('#btn-ledger-metadata').click();
    await expect(page.locator('.ledger-entry').last()).toContainText('Mallory');
    await expect(page.locator('.ledger-entry').last()).toContainText('1900-01-01');
    await expect(page.locator('#ledger-tamper-explanation')).toContainText('author/time were never signed');
    await expect(page.locator('.ledger-entry .badge-valid')).toHaveCount(2);
    await page.locator('#btn-ledger-reverse').click();
    await expect(page.locator('.ledger-entry').first()).toContainText('second message');
    await expect(page.locator('#ledger-tamper-explanation')).toContainText('No signed sequence');
    await page.locator('#btn-ledger-remove').click();
    await expect(page.locator('.ledger-entry')).toHaveCount(1);
    await expect(page.locator('#ledger-tamper-explanation')).toContainText('no trusted checkpoint');
    await expect(page.locator('.ledger-entry .badge-valid')).toHaveCount(1);
    const keyBefore = await page.evaluate(() => JSON.parse(sessionStorage.getItem('sphincs-ledger')!)[0].publicKey);
    await page.locator('#btn-ledger-replace-key').click();
    await expect(page.locator('#ledger-tamper-explanation')).toContainText('newly generated key and signature');
    await expect(page.locator('.ledger-entry .badge-valid')).toHaveCount(1);
    expect(await page.evaluate(() => JSON.parse(sessionStorage.getItem('sphincs-ledger')!)[0].publicKey)).not.toBe(keyBefore);
    await page.reload(); await page.locator('#tab-btn-ledger').click();
    await expect(page.locator('.ledger-entry .badge-valid')).toHaveCount(0);
    await expect(page.locator('.ledger-entry .badge')).toHaveText('NOT VERIFIED');
    await page.locator('#btn-ledger-verify').click();
    await expect(page.locator('.ledger-entry .badge-valid')).toHaveCount(1);
    await expect(page.locator('#ledger-entries .output')).toContainText('Message signatures checked');
    await page.locator('#btn-ledger-tamper').click();
    await expect(page.locator('.ledger-entry .badge-invalid')).toHaveText('INVALID MESSAGE SIGNATURE');
    await expect(page.locator('.ledger-entry .badge-valid')).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
    expect(errors).toEqual([]);
  });
}

test('changed persisted message is not rendered as valid before real verification; metadata is escaped', async ({ page }) => {
  await page.goto('.'); await page.locator('#tab-btn-ledger').click();
  await page.locator('#btn-ledger-add').click();
  await expect(page.locator('.ledger-entry .badge-valid')).toHaveCount(1);
  await page.evaluate(() => {
    const data = JSON.parse(sessionStorage.getItem('sphincs-ledger')!);
    data[0].message = 'changed'; data[0].valid = true;
    data[0].timestamp = '<img src="/missing" onerror="window.metadataExecuted=true">';
    sessionStorage.setItem('sphincs-ledger', JSON.stringify(data));
  });
  await page.reload(); await page.locator('#tab-btn-ledger').click();
  await expect(page.locator('.ledger-entry .badge')).toHaveText('NOT VERIFIED');
  await expect(page.locator('.ledger-entry .entry-meta')).toContainText('<img');
  await expect(page.locator('.ledger-entry img')).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { metadataExecuted?: boolean }).metadataExecuted)).toBeUndefined();
  await page.locator('#btn-ledger-verify').click();
  await expect(page.locator('.ledger-entry .badge-invalid')).toHaveText('INVALID MESSAGE SIGNATURE');
});

test('an incomplete verification action does not retain success or a completed summary', async ({ page }) => {
  await page.goto('.'); await page.locator('#tab-btn-ledger').click();
  await page.locator('#btn-ledger-add').click();
  await expect(page.locator('.ledger-entry .badge-valid')).toHaveCount(1);
  await page.evaluate(() => {
    const setItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) {
      if (key === 'sphincs-ledger') throw new DOMException('Controlled persistence failure', 'QuotaExceededError');
      setItem.call(this, key, value);
    };
  });
  await page.locator('#btn-ledger-verify').click();
  await expect(page.locator('.ledger-entry .badge-valid')).toHaveCount(0);
  await expect(page.locator('.ledger-entry .badge')).toHaveText('NOT VERIFIED');
  await expect(page.locator('#ledger-tamper-explanation')).toContainText('This action did not finish');
  await expect(page.locator('#ledger-entries .output')).toHaveCount(0);
  await expect(page.locator('#btn-ledger-verify')).toBeEnabled();
});
