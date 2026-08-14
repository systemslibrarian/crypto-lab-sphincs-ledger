import { expect, test, type Page } from '@playwright/test';

/**
 * Whatever is marked hidden must actually be hidden.
 *
 * `[hidden] { display: none }` is a UA rule whose attribute selector has
 * specificity (0,1,0) — exactly a class's — so any author rule that also sets
 * `display` outranks it, and the element paints while the code that set
 * `hidden` believes it is gone. `.theme-toggle { display: inline-flex }` on a
 * button that ships carrying `hidden` is exactly that shape; this fleet has had
 * four live instances of the bug, and this page previously relied on five
 * separate per-element patches (`.tab-panel.hidden`, `.output.hidden`,
 * `.spinner.hidden`, `.warning.hidden`, `.viz-caption[hidden]`) — one written
 * after each discovery. styles.css now states it once, for both mechanisms, and
 * this asserts it.
 *
 * Asserted over the ATTRIBUTE and the CLASS rather than over named elements: a
 * per-element assertion would have to be written again for the next thing that
 * sets `display`, which is the pattern being replaced. `[hidden]` does not
 * match `class="hidden"` and vice versa, and this page uses both.
 *
 * And asserted with each tab open, because `.tab-panel { display: none }` hides
 * eight of the nine subtrees at first paint: an element inside a closed panel
 * measures 0x0 and reads as clean no matter what its own rules say, so a
 * first-paint-only sweep would look straight past a defect living in any panel
 * but the first. That is precisely how bike-vault's real defect stayed hidden.
 */

const TABS = [
  'sign',
  'tree',
  'wots',
  'fors',
  'hypertree',
  'collision',
  'ledger',
  'security',
  'compare',
] as const;

/** Every element marked hidden — by attribute or by class — that is nonetheless painting. */
async function painted(page: Page) {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>('[hidden], .hidden')).
      map((el) => {
        const r = el.getBoundingClientRect();
        return {
          who: el.id || el.className || el.tagName,
          via: el.hasAttribute('hidden') ? 'attribute' : 'class',
          display: getComputedStyle(el).display,
          box: `${Math.round(r.width)}x${Math.round(r.height)}`,
        };
      }).
      filter((x) => x.display !== 'none')
  );
}

test('nothing marked hidden is painted, in any tab', async ({ page }) => {
  await page.goto('.');

  for (const tab of TABS) {
    await page.locator(`#tab-btn-${tab}`).click();
    await expect(page.locator(`#tab-${tab}`)).toBeVisible();

    // Non-vacuity: an empty hidden set would make the assertion below pass
    // having checked nothing at all.
    const total = await page.locator('[hidden], .hidden').count();
    expect(total, `tab ${tab}: nothing is marked hidden, so this proves nothing`).toBeGreaterThan(0);

    expect(await painted(page), `tab ${tab}: marked hidden but still painting`).toEqual([]);
  }
});

test('both hiding mechanisms are actually exercised by the page', async ({ page }) => {
  // The sweep above is only as good as the set it sweeps. If the page stopped
  // using one of the two mechanisms the sweep would still pass, having silently
  // stopped covering it — so pin that both are present and both are honored.
  await page.goto('.');

  const byAttribute = page.locator('#peek-body'); // hidden="" in markup, toggled by main.ts
  await expect(byAttribute).toHaveAttribute('hidden', '');
  await expect(byAttribute).toBeHidden();

  const byClass = page.locator('#sign-output'); // class="output hidden" until a run completes
  await expect(byClass).toHaveClass(/\bhidden\b/);
  await expect(byClass).toBeHidden();
});

test('hiding is reversible — the rule is not just permanently blanking things', async ({ page }) => {
  // `display: none !important` would be trivially satisfiable by content that
  // never appears at all. Each mechanism must still reveal on demand.
  test.setTimeout(120_000);
  await page.goto('.');

  await expect(page.locator('#sign-output')).toBeHidden(); // by class
  await expect(page.locator('#peek-card')).toBeHidden(); // by attribute

  // Signing clears `.hidden` from the result region and drops the `hidden`
  // attribute from the Peek-inside card: one run exercises both directions.
  await page.locator('#btn-generate').click();
  await expect(page.locator('#sign-output')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#peek-card')).toBeVisible();

  // The disclosure inside it still hides its body until asked.
  await expect(page.locator('#peek-body')).toBeHidden();
  await page.locator('#btn-peek').click();
  await expect(page.locator('#peek-body')).toBeVisible();

  expect(await painted(page), 'marked hidden but still painting after a run').toEqual([]);
});
