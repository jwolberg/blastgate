import { describe, expect, it } from 'vitest';
import { VERSION } from './index';

describe('blastgate package', () => {
  it('exposes a semver version string', () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
