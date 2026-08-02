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
