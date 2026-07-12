import { defineConfig } from 'vitest/config';

// Unit-test config for the crypto layer. Runs in Node (which provides
// globalThis.crypto.subtle, used by src/crypto/hash.ts). The Playwright a11y
// suite in e2e/ is explicitly excluded so `npm test` never tries to collect it.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
    // SLH-DSA-256s does real, slow hash-based signing; a single test performs
    // several keygen/sign/verify cycles. The default 5s timeout is not enough.
    testTimeout: 60_000,
  },
});
