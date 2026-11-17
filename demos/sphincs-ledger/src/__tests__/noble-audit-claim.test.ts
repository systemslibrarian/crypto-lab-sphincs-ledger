/* What this lab says about the library that does the signing.
 *
 * The component table called @noble/post-quantum an "audited library
 * implementing FIPS 205", and src/crypto/params.ts called it "the audited
 * library". The library says otherwise about itself. Its own README, under
 * "Security":
 *
 *   The library has not been independently audited yet.
 *   - at version 0.6.1, in Apr 2026, it was audited by ourselves (self-audited)
 *
 * and this lab pins a later version than that self-audit covers.
 *
 * Both sides are read here — the lab's claim and the installed library's own
 * README — so an upgrade that changes the library's audit status, or an edit
 * that restores the old wording, fails rather than passing quietly.
 */
import { describe, expect, it } from 'vitest';

import readme from '../../README.md?raw';
import params from '../crypto/params.ts?raw';
import nobleReadme from '../../node_modules/@noble/post-quantum/README.md?raw';
import lock from '../../package-lock.json';

describe('the @noble/post-quantum audit claim', () => {
  it('still matches what the installed library says about itself', () => {
    expect(nobleReadme).toContain('The library has not been independently audited yet');
    expect(nobleReadme).toContain('at version 0.6.1, in Apr 2026, it was audited by ourselves');
  });

  it('pins a version later than the self-audit, and says so', () => {
    const pinned = (lock as { packages: Record<string, { version?: string }> }).packages[
      'node_modules/@noble/post-quantum'
    ]?.version;
    expect(pinned).toBe('0.7.1');
    expect(readme).toContain('v0.7.1 pinned here');
    expect(params).toContain('this lab pins v0.7.1');
  });

  it('calls the library unaudited in both places that used to call it audited', () => {
    for (const [name, text] of [
      ['README.md', readme],
      ['src/crypto/params.ts', params],
    ] as const) {
      expect(text, `${name} quotes the library's own status`).toContain(
        'has not been independently audited yet',
      );
      expect(text, `${name} no longer calls it audited`).not.toContain('audited library implementing');
      expect(text, `${name} no longer calls it "the audited library"`).not.toContain(
        'the audited library',
      );
    }
  });
});
