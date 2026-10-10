import { expect, test } from '@playwright/test';

for (const width of [1280, 380, 320]) {
  test(`standard WOTS comparison follows each selected signer at ${width}px`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    // Non-monotonic order checks both growth and shrinkage, avoiding stale UI.
    for (const [set, bits, digits, chains] of [
      ['sha2-128s', '128', '32', '35'], ['sha2-256f', '256', '64', '67'],
      ['sha2-256s', '256', '64', '67'], ['sha2-128f', '128', '32', '35'],
    ]) {
      await page.locator('#tab-btn-sign').click();
      await page.locator('#param-select').selectOption(set);
      await page.locator('#tab-btn-wots').click();
      await expect(page.locator('#wp-scale-fips-set')).toHaveText(`SLH-DSA-${set.replace('sha2-', 'SHA2-')}`);
      await expect(page.locator('#wp-scale-fips-bits')).toHaveText(bits);
      await expect(page.locator('#wp-scale-fips-len1')).toHaveText(digits);
      await expect(page.locator('#wp-scale-fips-len2')).toHaveText('3');
      await expect(page.locator('#wp-scale-fips-len')).toHaveText(chains);
      await expect(page.locator('#wp-scale-len1')).toHaveText('6');
      await expect(page.locator('#wp-scale-len2')).toHaveText('2');
      await expect(page.locator('#wp-scale-len')).toHaveText('8');
      await expect(page.locator('#wp-scale-note')).toContainText('not a FIPS-conforming WOTS+ implementation');
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
    expect(errors).toEqual([]);
  });
}
