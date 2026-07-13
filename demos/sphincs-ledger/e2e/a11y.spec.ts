import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate for the SLH-DSA (SPHINCS+) demo.
 *
 * The app is a single-page, tab-based SPA (nine tab panels rendered from
 * index.html + main.ts). Inactive tab panels are display:none, and most panels
 * inject their result regions only after a "run" button is clicked. So we DRIVE
 * every live demo, then force ALL tab panels visible, so the dynamically-injected
 * output regions (signing result, Merkle tree SVG, WOTS+ chains, FORS forest,
 * hypertree, collision table, ledger entries, speed chart) are in the DOM and
 * rendered when axe runs.
 *
 * There are no <details> here (collapsibles are class-toggled); we still
 * generically expand any collapsibles for robustness. Scans both themes with
 * WCAG 2.0/2.1 A + AA rules; asserts zero violations.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animation/transition/opacity so mid-flight states (spinner, tree
// path animation, tab fade) can't hide text from the contrast checker.
async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      opacity:1!important;scroll-behavior:auto!important;
    }`,
  });
}

// Force every tab panel + any [hidden]/collapsible into the visible tree so axe
// scans the whole page in one pass (panels are display:none until .active).
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) el.removeAttribute('hidden');
    for (const el of document.querySelectorAll<HTMLElement>('.hidden')) el.classList.remove('hidden');
    for (const p of document.querySelectorAll<HTMLElement>('.tab-panel')) {
      p.classList.add('active');
      p.classList.remove('hidden');
      p.style.display = 'block';
    }
  });
}

// Drive every live demo so injected output regions exist during the scan.
async function driveDemos(page: Page): Promise<void> {
  // Tab: Sign & Verify — generate + sign, then verify + tamper.
  await page.locator('#tab-btn-sign').click();
  await page.locator('#btn-generate').click();
  await expect(page.locator('#sign-output')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#btn-generate')).toBeEnabled({ timeout: 60_000 });
  await page.locator('#btn-verify').click();
  await expect(page.locator('#verify-output')).toBeVisible({ timeout: 30_000 });
  await page.locator('#btn-tamper-sig').click();
  await expect(page.locator('#tamper-output')).toBeVisible({ timeout: 30_000 });
  // Peek-inside mechanism bridge — expand its schematic + pipeline steps.
  await page.locator('#btn-peek').click();
  await expect(page.locator('#peek-schematic svg').first()).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#peek-steps .peek-step').first()).toBeVisible({ timeout: 30_000 });

  // Tab: Hash Tree — build tree, then verify a leaf (animates the auth path).
  await page.locator('#tab-btn-tree').click();
  await page.locator('#btn-build-tree').click();
  await expect(page.locator('#tree-container svg')).toBeVisible({ timeout: 30_000 });
  await page.locator('#btn-verify-leaf').click();
  await expect(page.locator('#tree-verify-output')).toBeVisible({ timeout: 30_000 });

  // Tab: WOTS+ — generate key, sign twice (trigger reuse warning), forge.
  await page.locator('#tab-btn-wots').click();
  await page.locator('#btn-gen-wots').click();
  await expect(page.locator('#wots-chains svg').first()).toBeVisible({ timeout: 30_000 });
  await page.locator('#btn-wots-sign').click();
  await expect(page.locator('#wots-output')).toBeVisible({ timeout: 30_000 });
  await page.locator('#wots-nibble').fill('9');
  await page.locator('#btn-wots-sign').click();
  await page.locator('#btn-wots-verify').click();
  await page.locator('#btn-wots-forge').click();
  await expect(page.locator('#wots-forge-output')).toBeVisible({ timeout: 30_000 });

  // Tab: FORS — build the forest.
  await page.locator('#tab-btn-fors').click();
  await page.locator('#btn-fors-build').click();
  await expect(page.locator('#fors-output svg').first()).toBeVisible({ timeout: 30_000 });

  // Tab: Hypertree — renders on load; re-render for good measure.
  await page.locator('#tab-btn-hypertree').click();
  await page.locator('#btn-hypertree-build').click();
  await expect(page.locator('#hypertree-container svg').first()).toBeVisible({ timeout: 30_000 });

  // Tab: Collision Tolerance — compare + estimate margin.
  await page.locator('#tab-btn-collision').click();
  await page.locator('#btn-collision-compare').click();
  await expect(page.locator('#collision-output table')).toBeVisible({ timeout: 30_000 });
  await page.locator('#btn-collision-margin').click();
  await expect(page.locator('#collision-margin')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#collision-coverage svg')).toBeVisible({ timeout: 30_000 });

  // Tab: Ledger — add an entry, verify all, tamper.
  await page.locator('#tab-btn-ledger').click();
  await page.locator('#btn-ledger-add').click();
  await expect(page.locator('#ledger-entries .ledger-entry').first()).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#btn-ledger-add')).toBeEnabled({ timeout: 60_000 });
  await page.locator('#btn-ledger-verify').click();
  await page.locator('#btn-ledger-tamper').click();
  await expect(page.locator('#ledger-tamper-explanation')).toBeVisible({ timeout: 30_000 });

  // Tab: Security Basis + Comparison render on load (static tables).
  await page.locator('#tab-btn-security').click();
  await expect(page.locator('#security-content table').first()).toBeVisible();
  await page.locator('#tab-btn-compare').click();
  await expect(page.locator('#compare-content table').first()).toBeVisible();
  // Speed chart was populated by the signing run above.
  await expect(page.locator('#speed-chart .speed-bar-fill').first()).toBeVisible();
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await expect(page.locator('#tab-btn-sign')).toBeVisible();
  await killMotion(page);
});

test('no WCAG A/AA violations in dark theme (all demos driven)', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme (all demos driven)', async ({ page }) => {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});
