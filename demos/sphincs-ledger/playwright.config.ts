import { defineConfig } from '@playwright/test';

/**
 * E2E accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 */
export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  webServer: {
    // Build first. `vite preview` serves whatever is already sitting in
    // dist/, so without this the suite tests the last bundle that built:
    // a failing build leaves the previous one in place and the gate passes
    // green against source that no longer compiles, and a mutation check is
    // meaningless because the mutation never reaches the served bundle.
    command: 'npm run build && npm run preview -- --port 4304 --strictPort',
    url: 'http://localhost:4304/crypto-lab-sphincs-ledger/',
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: 'http://localhost:4304/crypto-lab-sphincs-ledger/',
    colorScheme: 'dark',
  },
  projects: [
    {
      name: 'chromium',
      use: { channel: undefined, browserName: 'chromium' },
    },
  ],
});
