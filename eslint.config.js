import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  // Fixtures are intentionally-suspicious sample repos (e.g. a dropper's
  // `require('child_process')`), not project source — never lint them.
  { ignores: ['dist/**', 'node_modules/**', 'plugin/**', 'coverage/**', 'test/fixtures/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: { ...globals.node },
    },
  },
);
